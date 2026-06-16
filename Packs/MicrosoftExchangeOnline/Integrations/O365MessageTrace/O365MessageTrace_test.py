import json

import pytest
from O365MessageTrace import Client, add_time_field, fetch_events, get_events_command, test_module

BASE_URL = "https://reports.office365.com/ecp/reportingwebservice/reporting.svc"

MESSAGE_TRACE_RESPONSE = {
    "d": {
        "results": [
            {
                "MessageId": "<msg-1@contoso.com>",
                "Received": "2024-05-18T13:45:14Z",
                "SenderAddress": "alice@contoso.com",
                "RecipientAddress": "bob@contoso.com",
                "Subject": "Hello",
                "Status": "Delivered",
            },
            {
                "MessageId": "<msg-2@contoso.com>",
                "Received": "2024-05-18T13:46:20Z",
                "SenderAddress": "carol@contoso.com",
                "RecipientAddress": "dave@contoso.com",
                "Subject": "World",
                "Status": "Delivered",
            },
        ]
    }
}


@pytest.fixture
def client() -> Client:
    return Client(base_url=BASE_URL, username="user", password="pass", verify=False, proxy=False)


def test_add_time_field_sets_time_from_received():
    """
    Given a list of raw message trace events with a Received field.
    When add_time_field is called.
    Then each event gets a _time field equal to Received.
    """
    events = [{"Received": "2024-05-18T13:45:14Z"}, {"Received": "2024-05-18T13:46:20Z"}]
    result = add_time_field(events)
    assert all(event["_time"] == event["Received"] for event in result)


def test_add_time_field_skips_missing_received():
    """
    Given an event without a Received field.
    When add_time_field is called.
    Then no _time field is added for that event.
    """
    events = [{"MessageId": "no-received"}]
    result = add_time_field(events)
    assert "_time" not in result[0]


def test_test_module(client, requests_mock):
    """
    Given a healthy Reporting Web Service.
    When test_module is called.
    Then it returns 'ok'.
    """
    requests_mock.get(f"{BASE_URL}/MessageTrace", json=MESSAGE_TRACE_RESPONSE)
    assert test_module(client) == "ok"


def test_get_events_command(client, requests_mock):
    """
    Given the Reporting Web Service returns two records.
    When get_events_command is called.
    Then both events are returned and rendered with _time set.
    """
    requests_mock.get(f"{BASE_URL}/MessageTrace", json=MESSAGE_TRACE_RESPONSE)
    events, results = get_events_command(client, {"limit": "50"})
    assert len(events) == 2
    assert events[0]["_time"] == "2024-05-18T13:45:14Z"
    assert "O365 Message Trace Events" in results.readable_output


def test_fetch_events_first_run(client, requests_mock):
    """
    Given an empty last_run (first run).
    When fetch_events is called.
    Then events are returned and next_run records last_fetch.
    """
    requests_mock.get(f"{BASE_URL}/MessageTrace", json=MESSAGE_TRACE_RESPONSE)
    next_run, events = fetch_events(client, last_run={}, first_fetch="3 days", max_fetch=5000)
    assert len(events) == 2
    assert "last_fetch" in next_run


def test_fetch_events_uses_last_fetch(client, requests_mock):
    """
    Given a last_run with an existing last_fetch timestamp.
    When fetch_events is called.
    Then the request filter uses that timestamp as the start date.
    """
    mock = requests_mock.get(f"{BASE_URL}/MessageTrace", json=MESSAGE_TRACE_RESPONSE)
    last_run = {"last_fetch": "2024-05-18T00:00:00Z"}
    fetch_events(client, last_run=last_run, first_fetch="3 days", max_fetch=100)
    assert "2024-05-18T00:00:00Z" in mock.last_request.query


def test_fetch_events_empty_response(client, requests_mock):
    """
    Given the Reporting Web Service returns no records.
    When fetch_events is called.
    Then an empty event list is returned and next_run is still advanced.
    """
    requests_mock.get(f"{BASE_URL}/MessageTrace", json={"d": {"results": []}})
    next_run, events = fetch_events(client, last_run={}, first_fetch="1 day", max_fetch=10)
    assert events == []
    assert "last_fetch" in next_run


def test_util_load_json_roundtrip():
    """
    Given the mock response object.
    When serialized and deserialized.
    Then the structure is preserved.
    """
    serialized = json.dumps(MESSAGE_TRACE_RESPONSE)
    assert json.loads(serialized) == MESSAGE_TRACE_RESPONSE
