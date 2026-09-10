from unittest.mock import MagicMock, patch
import pytest
from datetime import datetime, UTC, timedelta
from CommonServerPython import DemistoException


from CiscoETDConnector import (
    ETDClient,
    get_credential,
    generate_intervals,
    get_event_time,
    get_event_id,
    deduplicate_events,
)


def test_get_credential_string():
    assert get_credential("secret") == "secret"


def test_get_credential_dict():
    assert get_credential({"password": "secret"}) == "secret"


def test_get_credential_nested():
    assert get_credential({"credentials": {"password": "secret"}}) == "secret"


def test_generate_intervals():
    start = datetime(2026, 7, 1, 0, 0, tzinfo=UTC)
    end = datetime(2026, 7, 1, 6, 0, tzinfo=UTC)
    intervals = generate_intervals(start, end)
    assert len(intervals) == 2
    assert intervals[0][0] == start
    assert intervals[-1][1] == end


def test_generate_intervals_partial():
    start = datetime(2026, 7, 1, 0, 0, tzinfo=UTC)
    end = datetime(2026, 7, 1, 5, 0, tzinfo=UTC)
    intervals = generate_intervals(start, end)
    assert intervals == [
        (start, datetime(2026, 7, 1, 3, 0, tzinfo=UTC)),
        (datetime(2026, 7, 1, 3, 0, tzinfo=UTC), end),
    ]


def test_get_credential_none():
    assert get_credential(None) == ""


def test_get_event_time_invalid():
    event = {"message": {"timestamp": "invalid-timestamp"}}
    value = get_event_time(event, "message")
    assert value.endswith("Z")


def test_get_event_time():
    event = {"message": {"timestamp": "2026-07-01T10:30:45Z"}}
    assert get_event_time(event, "message") == "2026-07-01T10:30:45Z"


@patch.object(ETDClient, "get_access_token", return_value="dummy")
def test_get_links_invalid_chunk(mock_token):
    client = ETDClient(base_url="dummy", params={})
    response = {
        "data": {
            "message": "invalid",
            "audit": None,
            "connection": {},
        }
    }
    assert client.get_links(response, ["message", "audit", "connection"]) == []


def test_get_event_id():
    event = {"message": {"id": "123"}}
    id1 = get_event_id(event, "message")
    id2 = get_event_id(event, "message")
    assert id1 == id2


def test_deduplicate_events():
    events = [{"_event_id": "1", "_time": "2026-07-01T10:00:00Z"}, {"_event_id": "1", "_time": "2026-07-01T10:00:00Z"}]
    result = deduplicate_events(events, None, set())
    assert len(result) == 1


@patch("CiscoETDConnector.demisto.getIntegrationContext")
@patch.object(ETDClient, "_http_request")
def test_get_access_token_cached(mock_request, mock_context):
    mock_context.return_value = {
        "access_token": "cached-token",
        "token_expiry": (datetime.now(UTC) + timedelta(minutes=10)).timestamp(),
    }
    client = ETDClient.__new__(ETDClient)
    client.params = {
        "api_key": "api-key",
        "client_id": "client-id",
        "client_secret": "client-secret",
    }
    client._headers = {}
    token = client.get_access_token()
    assert token == "cached-token"
    mock_request.assert_not_called()


@patch("CiscoETDConnector.demisto.getIntegrationContext", return_value={})
@patch.object(ETDClient, "_http_request")
def test_get_access_token_missing_token(mock_request, mock_context):
    mock_request.return_value = {}
    client = ETDClient.__new__(ETDClient)
    client.params = {
        "api_key": "api-key",
        "client_id": "client-id",
        "client_secret": "client-secret",
    }
    client._headers = {}
    with pytest.raises(DemistoException, match="Token not found"):
        client.get_access_token()


@patch.object(ETDClient, "get_access_token", return_value="dummy")
def test_get_links(mock_token):
    response = {"data": {"message": ["link1"], "audit": ["link2"], "connection": ["link3"]}}
    client = ETDClient(base_url="dummy", params={})
    assert client.get_links(response, ["message", "audit", "connection"]) == [
        ("message", "link1"),
        ("audit", "link2"),
        ("connection", "link3"),
    ]


def test_deduplicate_old_events():
    events = [{"_event_id": "1", "_time": "2026-07-01T09:00:00Z"}]
    result = deduplicate_events(events, "2026-07-01T10:00:00Z", set())
    assert result == []


@patch("CiscoETDConnector.requests.get")
@patch.object(ETDClient, "get_access_token", return_value="dummy")
def test_download_logs(mock_token, mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = '{"message":{"id":"1","timestamp":"2026-07-01T10:00:00Z"}}'
    mock_get.return_value = mock_response
    client = ETDClient(base_url="dummy", params={})
    events = client.download_logs([("message", "https://example.com/log")])
    assert len(events) == 1
    assert events[0]["_source_log_type"] == "message"


def test_get_event_time_missing():
    event = {"message": {}}
    value = get_event_time(event, "message")
    assert value.endswith("Z")


def test_get_event_id_audit():
    event = {
        "timestamp": "2026-07-01T10:00:00Z",
        "action": "login",
        "category": "auth",
        "user": "admin",
        "metadata": {"awsRequestId": "123"},
    }
    value = get_event_id(event, "audit")
    assert isinstance(value, str)
    assert len(value) == 64


def test_get_event_id_connection():
    event = {"connection_id": "conn123"}
    assert get_event_id(event, "connection") == "conn123"


@patch.object(ETDClient, "get_access_token", return_value="dummy")
def test_get_links_empty(mock_token):
    client = ETDClient(base_url="dummy", params={})
    assert client.get_links({"data": {}}, ["message"]) == []


def test_deduplicate_same_checkpoint():
    events = [{"_event_id": "1", "_time": "2026-07-01T10:00:00Z"}]
    result = deduplicate_events(events, "2026-07-01T10:00:00Z", {"1"})
    assert result == []


@patch("CiscoETDConnector.demisto.error")
@patch("CiscoETDConnector.requests.get")
@patch.object(ETDClient, "get_access_token", return_value="dummy")
def test_download_logs_invalid_json(
    mock_token,
    mock_get,
    mock_error,
):
    response = MagicMock()
    response.status_code = 200
    response.text = "invalid json"
    mock_get.return_value = response
    client = ETDClient(base_url="dummy", params={})
    events = client.download_logs([("message", "https://example.com/log")])
    assert events == []
    mock_error.assert_called_once()


@patch("CiscoETDConnector.requests.get")
@patch.object(ETDClient, "get_access_token", return_value="dummy")
def test_download_logs_http_error(mock_token, mock_get):
    response = MagicMock()
    response.status_code = 500
    response.text = "error"
    mock_get.return_value = response
    client = ETDClient(base_url="dummy", params={})
    with pytest.raises(DemistoException):
        client.download_logs([("message", "https://example.com/log")])


@patch("CiscoETDConnector.send_events_to_xsiam")
@patch("CiscoETDConnector.demisto.setLastRun")
@patch("CiscoETDConnector.demisto.getLastRun")
@patch.object(ETDClient, "download_logs")
@patch.object(ETDClient, "get_links")
@patch.object(ETDClient, "request_log_export")
@patch.object(ETDClient, "get_access_token", return_value="dummy")
def test_fetch_and_ingest_logs_success(
    mock_token, mock_request, mock_links, mock_download, mock_last_run, mock_set_last_run, mock_send
):
    from CiscoETDConnector import fetch_and_ingest_logs

    mock_last_run.return_value = {}
    mock_request.return_value = {"data": {}}
    mock_links.return_value = [("message", "https://example.com/log")]
    mock_download.return_value = [
        {
            "_time": "2026-07-01T10:00:00Z",
            "_event_id": "1",
            "message": {},
        }
    ]
    client = ETDClient(base_url="dummy", params={})
    fetch_and_ingest_logs(client, {"max_fetch": 100})
    mock_send.assert_called_once()
    mock_set_last_run.assert_called_once()


@patch.object(ETDClient, "download_logs", return_value=[])
@patch.object(ETDClient, "get_links", return_value=[])
@patch.object(ETDClient, "request_log_export")
@patch.object(ETDClient, "get_access_token", return_value="dummy")
@patch("CiscoETDConnector.demisto.getLastRun", return_value={})
def test_fetch_and_ingest_logs_no_events(mock_last_run, mock_token, mock_request, mock_links, mock_download):
    from CiscoETDConnector import fetch_and_ingest_logs

    client = ETDClient(base_url="dummy", params={})
    fetch_and_ingest_logs(client, {"max_fetch": 100, "event_type": ["message"]})
    mock_request.assert_called()


@patch("CiscoETDConnector.demisto.getLastRun")
@patch.object(ETDClient, "get_access_token", return_value="dummy")
def test_fetch_and_ingest_logs_invalid_last_fetch(mock_token, mock_last_run):
    from CiscoETDConnector import fetch_and_ingest_logs

    mock_last_run.return_value = {
        "last_fetch": "invalid-date",
        "last_ids": [],
    }
    client = ETDClient(base_url="dummy", params={})
    with pytest.raises(DemistoException, match="Invalid last_fetch"):
        fetch_and_ingest_logs(client, {"max_fetch": 100})


@patch("CiscoETDConnector.demisto.error")
@patch.object(ETDClient, "request_log_export")
@patch.object(ETDClient, "get_access_token", return_value="dummy")
def test_fetch_and_ingest_logs_request_error(mock_token, mock_request, mock_error):
    from CiscoETDConnector import fetch_and_ingest_logs

    mock_request.side_effect = Exception("ETD API error")
    client = ETDClient(base_url="dummy", params={})
    fetch_and_ingest_logs(client, {"max_fetch": 100})
    mock_error.assert_called_once()


@patch("CiscoETDConnector.send_events_to_xsiam")
@patch("CiscoETDConnector.demisto.setLastRun")
@patch("CiscoETDConnector.demisto.getLastRun")
@patch.object(ETDClient, "download_logs")
@patch.object(ETDClient, "get_links")
@patch.object(ETDClient, "request_log_export")
@patch.object(ETDClient, "get_access_token", return_value="dummy")
def test_fetch_and_ingest_logs_max_fetch(
    mock_token, mock_request, mock_links, mock_download, mock_last_run, mock_set_last_run, mock_send
):
    from CiscoETDConnector import fetch_and_ingest_logs

    mock_last_run.return_value = {}
    mock_request.return_value = {"data": {}}
    mock_links.return_value = [("message", "https://example.com/log")]
    mock_download.return_value = [
        {
            "_time": "2026-07-01T10:00:00Z",
            "_event_id": "1",
            "message": {},
        },
        {
            "_time": "2026-07-01T10:01:00Z",
            "_event_id": "2",
            "message": {},
        },
    ]
    client = ETDClient(base_url="dummy", params={})
    fetch_and_ingest_logs(client, {"max_fetch": 2, "event_type": ["message"]})
    mock_send.assert_called_once()


@patch("CiscoETDConnector.demisto.getLastRun")
@patch.object(ETDClient, "download_logs")
@patch.object(ETDClient, "get_links")
@patch.object(ETDClient, "request_log_export")
@patch.object(ETDClient, "get_access_token", return_value="dummy")
def test_fetch_and_ingest_logs_all_duplicates(mock_token, mock_request, mock_links, mock_download, mock_last_run):
    from CiscoETDConnector import fetch_and_ingest_logs

    mock_last_run.return_value = {
        "last_fetch": "2026-07-01T10:00:00Z",
        "last_ids": ["1"],
    }
    mock_request.return_value = {"data": {}}
    mock_links.return_value = [("message", "https://example.com/log")]
    mock_download.return_value = [
        {
            "_time": "2026-07-01T10:00:00Z",
            "_event_id": "1",
            "message": {},
        }
    ]
    client = ETDClient(base_url="dummy", params={})
    fetch_and_ingest_logs(client, {"max_fetch": 100, "event_type": ["message"]})
