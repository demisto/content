import pytest
from CommonServerPython import *
from unittest.mock import MagicMock
from freezegun import freeze_time
from CitrixDaasEventCollector import Client, get_events_command, fetch_events_command, module_test_command, days_since


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
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "info")


# ----------------------------------------------------------------------
# CLIENT TESTS
# ----------------------------------------------------------------------


def test_request_access_token(mocker):
    """
    Given:
        - A Citrix Daas Client with mocked HTTP response.
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


def test_get_site_id(mocker):
    """
    Given:
        - A valid access token in integration context.
    When:
        - Calling `get_site_id` to obtain the site ID.
    Then:
        - The site ID should be returned and stored in integration context.
    """
    client = Client("https://api.citrixcloud.com", "cust", "id", "secret", False, True)
    demisto.getIntegrationContext.return_value = {"access_token": "token123"}

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"sites": [{"id": "site123"}]}

    mocker.patch.object(client, "_http_request", return_value=mock_resp)

    site_id = client.get_site_id()
    assert site_id == "site123"
    demisto.setIntegrationContext.assert_called_once_with({"site_id": "site123"})


def test_get_operations(mocker):
    """
    Given:
        - A valid access token and site ID in integration context.
    When:
        - Calling `get_operations` with valid parameters.
    Then:
        - The function should return a JSON response with operation records.
    """
    client = Client("https://api.citrixcloud.com", "cust", "id", "secret", False, True)
    demisto.getIntegrationContext.return_value = {"access_token": "token123", "site_id": "site123"}

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"Items": [{"Id": "op1"}], "ContinuationToken": None}

    mocker.patch.object(client, "_http_request", return_value=mock_resp)

    res = client.get_operations(search_date_option="LastHour")
    assert res["Items"][0]["Id"] == "op1"


def test_get_operations_with_pagination(mocker):
    """
    Given:
        - A client that returns multiple pages of operations.
    When:
        - Calling `get_operations_with_pagination` with limit=10.
    Then:
        - The function should merge pages and return all operations with `_time` set.
    """
    client = Client("https://api.citrixcloud.com", "cust", "id", "secret", False, True)

    responses = [
        {"Items": [{"Id": "op1", "FormattedStartTime": "2024-01-01T00:00:00Z"}], "ContinuationToken": "abc"},
        {"Items": [{"Id": "op2", "FormattedStartTime": "2024-01-01T01:00:00Z"}], "ContinuationToken": None},
    ]

    mocker.patch.object(client, "get_operations", side_effect=responses)
    demisto.getIntegrationContext.return_value = {"access_token": "token123", "site_id": "site123"}

    operations, raw_res = client.get_operations_with_pagination(limit=10, search_date_option="LastHour")
    assert len(operations) == 2
    assert operations[0]["_time"] == "2024-01-01T00:00:00Z"
    assert raw_res["ContinuationToken"] is None


# ----------------------------------------------------------------------
# COMMAND TESTS
# ----------------------------------------------------------------------


def test_get_events_command_returns_results(mocker):
    """
    Given:
        - A client returning mocked event operations.
    When:
        - Running the `citrix-daas-get-events` command.
    Then:
        - A CommandResults object is returned containing the event data.
    """
    client = Client("url", "cust", "id", "secret", False, True)
    mocker.patch.object(
        client,
        "get_operations_with_pagination",
        return_value=([{"Id": "op1", "FormattedStartTime": "2024-01-01T00:00:00Z"}], {"meta": "ok"}),
    )
    mocker.patch("CitrixDaasEventCollector.send_events_to_xsiam")

    results = get_events_command(client, {"limit": "1", "should_push_events": "false"})
    assert isinstance(results, CommandResults)
    assert results.outputs[0]["Id"] == "op1"


@freeze_time("2025-01-14T00:00:00Z")
def test_fetch_events_command_first_run(mocker):
    """
    Given:
        - A client returning 2 event operations.
    When:
        - Running `fetch_events_command` for the first time to retrieve events.
    Then:
        - The function should return events and set a new LastRun value with the timestamp and record id of
            the first event in the list (descending order).
        - The function get_operations_with_pagination search_date_option argument value is "LastMinute".
    """
    client = Client("url", "cust", "id", "secret", False, True)
    get_operations_mocker = mocker.patch.object(
        client,
        "get_operations_with_pagination",
        return_value=(
            [{"_time": "2025-01-01T00:00:00Z", "Id": "id2"}, {"_time": "2024-01-01T00:00:00Z", "Id": "id1"}],
            {},
        ),
    )
    mocker.patch("CitrixDaasEventCollector.send_events_to_xsiam")

    events, last_run = fetch_events_command(client, 5, {})

    assert len(events) == 2
    assert "LastRun" in last_run
    assert last_run["LastRun"] == "2025-01-01T00:00:00Z"
    assert last_run["Id"] == "id2"
    assert get_operations_mocker.call_args.kwargs["search_date_option"] == "LastMinute"


def test_fetch_events_command_sets_last_run(mocker):
    """
    Given:
        - A client returning one event operation with a timestamp.
    When:
        - Running `fetch_events_command` to retrieve events.
    Then:
        - The function should return events and set a new LastRun value.
    """
    client = Client("url", "cust", "id", "secret", False, True)
    mocker.patch.object(
        client, "get_operations_with_pagination", return_value=([{"_time": "2024-01-01T00:00:00Z", "Id": "id1"}], {})
    )
    mocker.patch("CitrixDaasEventCollector.send_events_to_xsiam")

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
    mocker.patch("CitrixDaasEventCollector.get_events_command", return_value="ok")

    result = module_test_command(client, {})
    assert result == "ok"

@freeze_time("2025-01-16T00:00:00Z")
def test_days_since():
    """
    Given:
        - A ISO-8601 timestamp.
    When:
        - Running the `days_since` function.
    Then:
        - The result should be 5 days ago.
    """

    result = days_since("2025-01-10T16:44:35.470Z")
    assert result == 5