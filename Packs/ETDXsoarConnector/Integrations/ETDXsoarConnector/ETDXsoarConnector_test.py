from datetime import datetime, UTC
import requests

from ETDXsoarConnector import (
    ETDClient,
    get_credential,
    generate_intervals,
    get_event_time,
    get_event_id,
)


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


def test_get_event_time():
    event = {"message": {"timestamp": "2026-01-01T10:00:00Z"}}
    assert get_event_time(event) == "2026-01-01T10:00:00Z"


def test_get_event_id():
    event = {"message": {"id": "123"}}
    id1 = get_event_id(event)
    id2 = get_event_id(event)
    assert id1 == id2


class MockResponse:
    status_code = 200
    text = '{"logType":"message","message":{"id":"1"}}\n' '{"logType":"audit"}'


def test_download_logs(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: MockResponse())
    client = ETDClient.__new__(ETDClient)
    events = client.download_logs(["https://example.com/log"])
    assert len(events) == 1
    assert events[0]["message"]["id"] == "1"
