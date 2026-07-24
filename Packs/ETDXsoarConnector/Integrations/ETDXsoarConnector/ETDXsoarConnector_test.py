from datetime import datetime, UTC
import requests

from ETDXsoarConnector import (
    ETDClient,
    get_credential,
    generate_intervals,
    get_event_time,
    get_event_id,
    fetch_incidents,
    cisco_etd_move_message_command,
)
from ETDXsoarConnector import test_module as integration_test_module


def test_get_links():
    response = {"data": {"message": ["https://example.com/log1", "https://example.com/log2"]}}
    client = ETDClient.__new__(ETDClient)
    links = client.get_links(response)
    assert links == [
        "https://example.com/log1",
        "https://example.com/log2",
    ]


def test_get_credential_password():
    cred = {"password": "secret"}
    assert get_credential(cred) == "secret"


def test_get_credential_nested():
    cred = {"credentials": {"password": "mypassword"}}
    assert get_credential(cred) == "mypassword"


def test_get_credential_string():
    assert get_credential("apikey") == "apikey"


def test_generate_intervals():
    start = datetime(2026, 1, 1, 0, 0, tzinfo=UTC)
    end = datetime(2026, 1, 1, 9, 0, tzinfo=UTC)
    intervals = generate_intervals(start, end)
    assert len(intervals) == 3
    assert intervals[0][0] == start
    assert intervals[0][1] == datetime(2026, 1, 1, 3, tzinfo=UTC)


def test_test_module(mocker):
    client = mocker.Mock()
    client.request_log_export.return_value = {"data": {"message": ["dummy"]}}
    client.get_links.return_value = ["dummy"]
    client.download_logs.return_value = []
    assert integration_test_module(client) == "ok"


def test_get_event_time():
    event = {"message": {"timestamp": "2026-01-01T10:00:00Z"}}
    assert get_event_time(event) == "2026-01-01T10:00:00Z"


def test_get_event_id():
    event = {"message": {"id": "123"}}
    id1 = get_event_id(event)
    id2 = get_event_id(event)
    assert id1 == id2


def test_cisco_etd_move_message_command(mocker):
    client = ETDClient.__new__(ETDClient)
    client._http_request = mocker.Mock(return_value={"status": "success"})
    result = cisco_etd_move_message_command(
        client,
        {
            "message_id": "123",
            "verdict": "phishing",
            "folder": "quarantine",
        },
    )
    client._http_request.assert_called_once()
    assert "ETD message updated" in result.readable_output


def test_fetch_incidents_no_logs(mocker):
    client = mocker.Mock()
    client.request_log_export.return_value = {"data": {"message": []}}
    client.get_links.return_value = []
    mocker.patch("ETDXsoarConnector.demisto.getLastRun", return_value={})
    mocker.patch("ETDXsoarConnector.demisto.setLastRun")
    mocker.patch("ETDXsoarConnector.demisto.incidents")
    incidents = fetch_incidents(client, {"max_fetch": 10})
    assert incidents == []


def test_fetch_incidents(mocker):
    client = mocker.Mock()
    client.request_log_export.return_value = {"data": {"message": ["dummy"]}}
    client.get_links.return_value = ["dummy"]
    client.download_logs.return_value = [
        {
            "message": {
                "id": "123",
                "timestamp": "2026-07-01T10:00:00Z",
                "fromAddresses": "alice@example.com",
                "verdict": {"verdict": "phishing"},
            }
        }
    ]
    mocker.patch("ETDXsoarConnector.demisto.getLastRun", return_value={})
    mocker.patch("ETDXsoarConnector.demisto.setLastRun")
    mocker.patch("ETDXsoarConnector.demisto.incidents")
    incidents = fetch_incidents(client, {"max_fetch": 10})
    assert len(incidents) == 1
    assert incidents[0]["CustomFields"]["etdmessageid"] == "123"


class MockResponse:
    status_code = 200
    text = '{"logType":"message","message":{"id":"1"}}\n'

    def raise_for_status(self):
        pass


def test_download_logs(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: MockResponse())
    client = ETDClient.__new__(ETDClient)
    client.params = {"insecure": False, "proxy": False}
    events = client.download_logs(["https://example.com/log"])
    assert len(events) == 1
    assert events[0]["message"]["id"] == "1"


def test_fetch_incidents_duplicate_event(mocker):
    event = {
        "message": {
            "id": "123",
            "timestamp": "2026-07-01T10:00:00Z",
            "fromAddresses": "alice@example.com",
            "verdict": {"verdict": "phishing"},
        }
    }
    client = mocker.create_autospec(ETDClient)
    client.request_log_export.return_value = {"data": {"message": ["dummy"]}}
    client.get_links.return_value = ["dummy"]
    client.download_logs.return_value = [event, event]
    mocker.patch("ETDXsoarConnector.demisto.getLastRun", return_value={})
    mocker.patch("ETDXsoarConnector.demisto.setLastRun")
    mocker.patch("ETDXsoarConnector.demisto.incidents")
    incidents = fetch_incidents(client, {"max_fetch": 10})
    assert len(incidents) == 1
