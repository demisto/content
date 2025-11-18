import pytest
from CommonServerPython import *
from unittest.mock import MagicMock
from freezegun import freeze_time
from CitrixCloudEventCollector import Client, get_events_command, fetch_events_command, test_module_command


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
        - A client returning 2 event records.
    When:
        - Running `fetch_events_command` for the first time to retrieve events.
    Then:
        - The function should return events and set a new LastRun value with the timestamp and record id of
            the first event in the list(descending order).
        - The function get_records_with_pagination start_date_time argument value is datetime.utcnow.
    """
    client = Client("url", "cust", "id", "secret", False, True)
    get_records_mocker = mocker.patch.object(
        client,
        "get_records_with_pagination",
        return_value=(
            [{"_time": "2025-01-01T00:00:00Z", "recordId": "id2"}, {"_time": "2024-01-01T00:00:00Z", "recordId": "id1"}],
            {},
        ),
    )

    events, last_run = fetch_events_command(client, 5, {})

    assert len(events) == 2
    assert "LastRun" in last_run
    assert last_run["LastRun"] == "2025-01-01T00:00:00Z"
    assert last_run["RecordId"] == "id2"
    assert get_records_mocker.call_args.kwargs["start_date_time"] == "2025-01-14T00:00:00.000Z"


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


def test_test_module_returns_ok(mocker):
    """
    Given:
        - A Client with mocked event data.
    When:
        - Running the `test_module` function.
    Then:
        - The result should be 'ok', indicating a successful connection and fetch logic.
    """
    client = Client("url", "cust", "id", "secret", False, True)
    mocker.patch("CitrixCloudEventCollector.get_events_command", return_value="ok")

    result = test_module_command(client, {})
    assert result == "ok"
