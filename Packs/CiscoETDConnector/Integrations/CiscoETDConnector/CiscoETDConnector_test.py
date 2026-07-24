from unittest.mock import MagicMock, patch
import pytest
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
    from datetime import datetime, UTC

    start = datetime(2026, 7, 1, 0, 0, tzinfo=UTC)
    end = datetime(2026, 7, 1, 6, 0, tzinfo=UTC)
    intervals = generate_intervals(start, end)
    assert len(intervals) == 2
    assert intervals[0][0] == start
    assert intervals[-1][1] == end


def test_get_event_time():
    event = {"message": {"timestamp": "2026-07-01T10:30:45Z"}}
    assert get_event_time(event, "message") == "2026-07-01T10:30:45Z"


def test_get_event_id():
    event = {"message": {"id": "123"}}
    id1 = get_event_id(event, "message")
    id2 = get_event_id(event, "message")
    assert id1 == id2


def test_deduplicate_events():
    events = [{"_event_id": "1", "_time": "2026-07-01T10:00:00Z"}, {"_event_id": "1", "_time": "2026-07-01T10:00:00Z"}]
    result = deduplicate_events(events, None, set())
    assert len(result) == 1


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
