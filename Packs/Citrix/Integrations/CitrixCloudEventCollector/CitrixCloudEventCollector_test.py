import pytest
from CommonServerPython import *
from unittest.mock import MagicMock
from freezegun import freeze_time
import CitrixCloudEventCollector
from CitrixCloudEventCollector import Client, get_events_command, fetch_events_command, module_test_command, main


@pytest.fixture
def client() -> Client:
    """
    Fixture to create and return a Client instance for testing.
    Uses mock credentials defined at the top of the file.
    """
    return Client(
        base_url="https://api.citrixcloud.com",
        customer_id="cust",
        client_id="id",
        client_secret="secret",
        verify=True,
        proxy=False,
    )


@pytest.fixture(autouse=True)
def mock_demisto(mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")


# ----------------------------------------------------------------------
# CLIENT TESTS
# ----------------------------------------------------------------------


def test_request_access_token(mocker):
    """
    Given:
        - A Citrix Cloud Client with mocked HTTP response.
    When:
        - Calling `request_access_token` to obtain an OAuth2 token.
    Then:
        - The token should be returned and stored in integration context.
    """
    client = Client("https://api.citrixcloud.com", "cust", "id", "secret", False, True)

    mock_http = mocker.patch.object(client, "_http_request", return_value={"access_token": "abc123"})
    token = client.request_access_token()

    assert token == "abc123"
    mock_http.assert_called_once()
    demisto.setIntegrationContext.assert_called_once_with({"access_token": "abc123"})


def test_get_records_with_valid_token(mocker):
    """
    Given:
        - A valid access token in integration context.
    When:
        - Calling `get_records` with valid parameters.
    Then:
        - The function should return a JSON response with event records.
    """
    client = Client("https://api.citrixcloud.com", "cust", "id", "secret", False, True)
    demisto.getIntegrationContext.return_value = {"access_token": "token123"}

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"items": [{"id": 1}], "continuationToken": None}

    mocker.patch.object(client, "_http_request", return_value=mock_resp)

    res = client.get_records("2024-01-01", "2024-01-02")
    assert res["items"][0]["id"] == 1


def test_get_records_refreshes_token_on_401(mocker):
    """
    Given:
        - A client with an expired access token.
    When:
        - The first HTTP request returns 401 Unauthorized.
    Then:
        - The client should request a new token and retry successfully.
    """
    client = Client("https://api.citrixcloud.com", "cust", "id", "secret", False, True)

    def side_effect(*args, **kwargs):
        if not hasattr(side_effect, "called"):
            side_effect.called = True
            mock_resp = MagicMock(status_code=401)
            return mock_resp
        return {"items": [{"id": 2}], "continuationToken": None}

    mocker.patch.object(client, "_http_request", side_effect=side_effect)
    mocker.patch.object(client, "request_access_token", return_value="newtoken")

    res = client.get_records("2024-01-01", "2024-01-02")

    assert res["items"][0]["id"] == 2
    assert client.request_access_token.call_count == 2


def test_get_records_with_pagination(mocker):
    """
    Given:
        - A client that returns multiple pages of records.
    When:
        - Calling `get_records_with_pagination` with limit=10.
    Then:
        - The function should merge pages and return all records with `_time` set.
    """
    client = Client("https://api.citrixcloud.com", "cust", "id", "secret", False, True)

    responses = [
        {"items": [{"utcTimestamp": "2024-01-01T00:00:00Z"}], "continuationToken": "abc"},
        {"items": [{"utcTimestamp": "2024-01-01T01:00:00Z"}], "continuationToken": None},
    ]

    mocker.patch.object(client, "get_records", side_effect=responses)

    records, raw_res = client.get_records_with_pagination(limit=10, start_date_time=None)
    assert len(records) == 2
    assert records[0]["_time"] == "2024-01-01T00:00:00Z"
    assert raw_res["continuationToken"] is None


# ----------------------------------------------------------------------
# COMMAND TESTS
# ----------------------------------------------------------------------


def test_get_events_command_returns_results(mocker):
    """
    Given:
        - A client returning mocked event records.
    When:
        - Running the `citrix-cloud-get-events` command.
    Then:
        - A CommandResults object is returned containing the event data.
    """
    client = Client("url", "cust", "id", "secret", False, True)
    mocker.patch.object(
        client,
        "get_records_with_pagination",
        return_value=([{"recordId": "r1", "utcTimestamp": "2024-01-01T00:00:00Z"}], {"meta": "ok"}),
    )

    results = get_events_command(client, {"limit": "1", "should_push_events": "false"})
    assert isinstance(results, CommandResults)
    assert results.outputs[0]["recordId"] == "r1"


@freeze_time("2025-01-14T00:00:00Z")
def test_fetch_events_command_first_run(mocker):
    """
    Given:
        - A client returning 2 event records in ascending order (oldest first, as produced in production).
    When:
        - Running `fetch_events_command` for the first time (empty last_run) to retrieve events.
    Then:
        - LastRun is set to the newest (last) event, and start_date_time uses the look-back window
            (5 minutes ago), not the exact current second.
    """
    client = Client("url", "cust", "id", "secret", False, True)
    get_records_mocker = mocker.patch.object(
        client,
        "get_records_with_pagination",
        return_value=(
            [{"_time": "2024-01-01T00:00:00Z", "recordId": "id1"}, {"_time": "2025-01-01T00:00:00Z", "recordId": "id2"}],
            {},
        ),
    )

    events, last_run = fetch_events_command(client, 5, {})

    assert len(events) == 2
    assert last_run["LastRun"] == "2025-01-01T00:00:00Z"
    assert last_run["RecordId"] == "id2"
    assert get_records_mocker.call_args.kwargs["start_date_time"] == "2025-01-13T23:55:00.000Z"


@freeze_time("2025-01-14T00:00:00Z")
def test_fetch_events_command_first_run_no_events(mocker):
    """
    Given:
        - A client returning no event records on the first fetch (empty last_run).
    When:
        - Running `fetch_events_command`.
    Then:
        - No LastRun is set, so the next cycle looks back FIRST_FETCH_LOOKBACK from "now" again
            (rolling window) instead of getting stuck querying "now".
    """
    client = Client("url", "cust", "id", "secret", False, True)
    get_records_mocker = mocker.patch.object(client, "get_records_with_pagination", return_value=([], {}))

    events, last_run = fetch_events_command(client, 5, {})

    assert events == []
    assert get_records_mocker.call_args.kwargs["start_date_time"] == "2025-01-13T23:55:00.000Z"
    assert "LastRun" not in last_run


def test_fetch_events_command_no_events_keeps_existing_last_run(mocker):
    """
    Given:
        - An existing LastRun (past events) and no new events this cycle.
    When:
        - Running `fetch_events_command`.
    Then:
        - The window continues from the existing LastRun and last_run is returned unchanged.
    """
    client = Client("url", "cust", "id", "secret", False, True)
    get_records_mocker = mocker.patch.object(client, "get_records_with_pagination", return_value=([], {}))

    prev_last_run = {"LastRun": "2024-06-01T00:00:00Z", "RecordId": "prev_id"}
    events, last_run = fetch_events_command(client, 5, prev_last_run)

    assert events == []
    assert get_records_mocker.call_args.kwargs["start_date_time"] == "2024-06-01T00:00:00Z"
    assert last_run == {"LastRun": "2024-06-01T00:00:00Z", "RecordId": "prev_id"}


def test_fetch_events_command_sets_last_run(mocker):
    """
    Given:
        - A client returning one event record with a timestamp.
    When:
        - Running `fetch_events_command` to retrieve events.
    Then:
        - The function should return events and set a new LastRun value.
    """
    client = Client("url", "cust", "id", "secret", False, True)
    mocker.patch.object(
        client, "get_records_with_pagination", return_value=([{"_time": "2024-01-01T00:00:00Z", "recordId": "id1"}], {})
    )

    events, last_run = fetch_events_command(client, 5, {"LastRun": "2024-01-01T00:00:00Z"})

    assert len(events) == 1
    assert "LastRun" in last_run


def test_module_test_command_returns_ok(mocker):
    """
    Given:
        - A Client with mocked event data.
    When:
        - Running the `module_test_command` function.
    Then:
        - The result should be 'ok', indicating a successful connection and fetch logic.
    """
    client = Client("url", "cust", "id", "secret", False, True)
    mocker.patch("CitrixCloudEventCollector.get_events_command", return_value="ok")

    result = module_test_command(client, {})
    assert result == "ok"


@freeze_time("2025-01-14T00:00:00Z")
def test_main_fetch_events_first_run_no_events(mocker):
    """
    Given:
        - A fresh instance (empty getLastRun) where the API returns no events.
    When:
        - Running main() with the `fetch-events` command.
    Then:
        - The look-back window is queried (not "now") and no LastRun is saved, so the next cycle
            rolls back again instead of getting stuck (XSUP-74934 regression).
    """
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": "https://api.cloud.com",
            "customer_id": "cust",
            "client_id": "id",
            "credentials": {"password": "secret"},
            "insecure": True,
            "proxy": False,
            "max_fetch": "2000",
        },
    )
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "getLastRun", return_value={})
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    send_events = mocker.patch.object(CitrixCloudEventCollector, "send_events_to_xsiam")
    get_records = mocker.patch.object(Client, "get_records_with_pagination", return_value=([], {}))

    main()

    assert get_records.call_args.kwargs["start_date_time"] == "2025-01-13T23:55:00.000Z"
    set_last_run.assert_called_once()
    assert "LastRun" not in set_last_run.call_args.args[0]
    send_events.assert_called_once()
    assert send_events.call_args.args[0] == []


@freeze_time("2025-01-14T00:00:00Z")
def test_main_fetch_events_with_events(mocker):
    """
    Given:
        - A fresh instance where the API returns events.
    When:
        - Running main() with the `fetch-events` command.
    Then:
        - Events are sent to XSIAM and last run advances to the last event's timestamp/recordId.
    """
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": "https://api.cloud.com",
            "customer_id": "cust",
            "client_id": "id",
            "credentials": {"password": "secret"},
            "insecure": True,
            "proxy": False,
        },
    )
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "getLastRun", return_value={})
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    send_events = mocker.patch.object(CitrixCloudEventCollector, "send_events_to_xsiam")
    records = [
        {"_time": "2025-01-13T23:57:00Z", "recordId": "r1"},
        {"_time": "2025-01-13T23:58:00Z", "recordId": "r2"},
    ]
    mocker.patch.object(Client, "get_records_with_pagination", return_value=(records, {}))

    main()

    send_events.assert_called_once()
    assert send_events.call_args.args[0] == records
    set_last_run.assert_called_once_with({"LastRun": "2025-01-13T23:58:00Z", "RecordId": "r2"})


def test_main_test_module(mocker):
    """
    Given:
        - A configured instance.
    When:
        - Running main() with the `test-module` command.
    Then:
        - return_results is called with 'ok'.
    """
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": "https://api.cloud.com",
            "customer_id": "cust",
            "client_id": "id",
            "credentials": {"password": "secret"},
            "insecure": True,
            "proxy": False,
        },
    )
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(CitrixCloudEventCollector, "get_events_command", return_value=None)
    return_results = mocker.patch.object(CitrixCloudEventCollector, "return_results")

    main()

    return_results.assert_called_once_with("ok")


def test_get_records_default_limit_capping(mocker):
    """
    Given:
        - A client with a valid token and a requested limit larger than the API max.
    When:
        - Calling get_records with limit greater than RECORDS_REQUEST_LIMIT.
    Then:
        - The Limit param sent to the API is capped at RECORDS_REQUEST_LIMIT.
    """
    client = Client("https://api.citrixcloud.com", "cust", "id", "secret", False, True)
    demisto.getIntegrationContext.return_value = {"access_token": "token123"}

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"items": [], "continuationToken": None}
    http = mocker.patch.object(client, "_http_request", return_value=mock_resp)

    client.get_records("2024-01-01", None, limit=99999)

    sent_params = http.call_args.kwargs["params"]
    assert sent_params["Limit"] == CitrixCloudEventCollector.RECORDS_REQUEST_LIMIT
