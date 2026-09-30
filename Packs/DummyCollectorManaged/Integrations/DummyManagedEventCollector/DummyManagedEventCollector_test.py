import ipaddress
from datetime import datetime

import demistomock as demisto
import pytest
from CommonServerPython import CommandResults, DemistoException

import DummyManagedEventCollector
from DummyManagedEventCollector import (
    COLLECTOR_SOURCE,
    DATE_FORMAT,
    EVENT_TYPES,
    INTEGRATION_ID,
    PACK_NAME,
    PRODUCT,
    SEVERITIES,
    VENDOR,
    Client,
    add_time_to_events,
    fetch_events,
    get_events_command,
    main,
    parse_limit,
)

EXPECTED_EVENT_KEYS = {
    "id",
    "collector_source",
    "integration_id",
    "pack_name",
    "event_type",
    "severity",
    "user",
    "source_ip",
    "message",
    "created_time",
}


@pytest.fixture
def client() -> Client:
    return Client(collector_source=COLLECTOR_SOURCE, integration_id=INTEGRATION_ID, pack_name=PACK_NAME)


def test_constants():
    """
    Given: the module constants.
    Then: they match the shared dataset and the managed pack identity.
    """
    assert VENDOR == "dummy"
    assert PRODUCT == "collector"
    assert COLLECTOR_SOURCE == "managed"
    assert INTEGRATION_ID == "DummyManagedEventCollector"
    assert PACK_NAME == "DummyCollectorManaged"


def test_generate_events_fields(client: Client):
    """
    Given: a last ID of 10 and a limit of 3.
    When: generating events.
    Then: 3 events are returned with continuing IDs and all expected fields populated.
    """
    events = client.generate_events(last_id=10, limit=3)

    assert len(events) == 3
    assert [event["id"] for event in events] == [11, 12, 13]
    for event in events:
        assert set(event.keys()) == EXPECTED_EVENT_KEYS
        assert event["collector_source"] == "managed"
        assert event["integration_id"] == INTEGRATION_ID
        assert event["pack_name"] == PACK_NAME
        assert event["event_type"] in EVENT_TYPES
        assert event["severity"] in SEVERITIES
        assert event["user"].endswith("@dummy.local")
        assert ipaddress.ip_address(event["source_ip"]).is_private
        assert event["message"] == f"[managed] Dummy event #{event['id']}"
        datetime.strptime(event["created_time"], DATE_FORMAT)


def test_fetch_events_first_run(client: Client):
    """
    Given: an empty last run.
    When: fetching events.
    Then: IDs start at 1 and the next run holds the last generated ID.
    """
    next_run, events = fetch_events(client, last_run={}, max_events_per_fetch=5)

    assert [event["id"] for event in events] == [1, 2, 3, 4, 5]
    assert next_run == {"last_id": 5}


def test_fetch_events_continues_from_last_id(client: Client):
    """
    Given: a last run with last_id 7.
    When: fetching events.
    Then: IDs continue from 8 and the next run is updated.
    """
    next_run, events = fetch_events(client, last_run={"last_id": 7}, max_events_per_fetch=2)

    assert [event["id"] for event in events] == [8, 9]
    assert next_run == {"last_id": 9}


def test_add_time_to_events(client: Client):
    """
    Given: generated events.
    When: adding the _time key.
    Then: _time equals created_time.
    """
    events = client.generate_events(last_id=0, limit=2)
    add_time_to_events(events)

    for event in events:
        assert event["_time"] == event["created_time"]


def test_get_events_command(client: Client):
    """
    Given: a limit argument of 3.
    When: running the get-events command function.
    Then: 3 events are returned with a markdown table.
    """
    events, results = get_events_command(client, {"limit": "3"})

    assert len(events) == 3
    assert isinstance(results, CommandResults)
    readable_output = results.readable_output or ""
    assert "Dummy Events (managed)" in readable_output
    assert "[managed] Dummy event #1" in readable_output


@pytest.mark.parametrize("value, expected", [(None, 5), ("", 5), ("7", 7), (3, 3)])
def test_parse_limit(value, expected):
    assert parse_limit(value) == expected


def test_parse_limit_negative():
    with pytest.raises(DemistoException):
        parse_limit("-1")


def test_test_module(client: Client):
    assert DummyManagedEventCollector.test_module(client) == "ok"


def test_main_test_module(mocker):
    """
    Given: the test-module command.
    When: running main.
    Then: 'ok' is returned.
    """
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "params", return_value={})
    mocker.patch.object(demisto, "args", return_value={})
    return_results_mock = mocker.patch.object(DummyManagedEventCollector, "return_results")

    main()

    return_results_mock.assert_called_once_with("ok")


def test_main_fetch_events(mocker):
    """
    Given: the fetch-events command with last_id 4 and max_events_per_fetch 3.
    When: running main.
    Then: events are sent with vendor 'dummy'/product 'collector' and the last run is updated.
    """
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "params", return_value={"max_events_per_fetch": "3"})
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "getLastRun", return_value={"last_id": 4})
    set_last_run_mock = mocker.patch.object(demisto, "setLastRun")
    send_events_mock = mocker.patch.object(DummyManagedEventCollector, "send_events_to_xsiam")

    main()

    send_events_mock.assert_called_once()
    sent_events = send_events_mock.call_args.args[0]
    assert send_events_mock.call_args.kwargs == {"vendor": "dummy", "product": "collector"}
    assert [event["id"] for event in sent_events] == [5, 6, 7]
    assert all(event["_time"] for event in sent_events)
    set_last_run_mock.assert_called_once_with({"last_id": 7})


@pytest.mark.parametrize("should_push_events, expected_push_calls", [("true", 1), ("false", 0)])
def test_main_get_events(mocker, should_push_events: str, expected_push_calls: int):
    """
    Given: the dummy-managed-get-events command with should_push_events true/false.
    When: running main.
    Then: results are returned, and events are pushed only when should_push_events is true.
    """
    mocker.patch.object(demisto, "command", return_value="dummy-managed-get-events")
    mocker.patch.object(demisto, "params", return_value={})
    mocker.patch.object(demisto, "args", return_value={"limit": "2", "should_push_events": should_push_events})
    return_results_mock = mocker.patch.object(DummyManagedEventCollector, "return_results")
    send_events_mock = mocker.patch.object(DummyManagedEventCollector, "send_events_to_xsiam")

    main()

    return_results_mock.assert_called_once()
    assert "Dummy Events (managed)" in return_results_mock.call_args.args[0].readable_output
    assert send_events_mock.call_count == expected_push_calls
    if expected_push_calls:
        assert len(send_events_mock.call_args.args[0]) == 2
        assert send_events_mock.call_args.kwargs == {"vendor": "dummy", "product": "collector"}
