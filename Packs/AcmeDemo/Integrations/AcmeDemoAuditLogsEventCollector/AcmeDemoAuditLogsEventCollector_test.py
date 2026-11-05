from datetime import datetime, timezone

import pytest
from CommonServerPython import DemistoException

import AcmeDemoAuditLogsEventCollector as collector
from AcmeDemoAuditLogsEventCollector import Client, fetch_events, get_events_command

FIXED_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def client() -> Client:
    return Client(base_url="https://api.acmedemo.example.com", api_key="dummy-key", verify=True, proxy=False)


@pytest.fixture(autouse=True)
def fixed_now(mocker):
    mocker.patch.object(collector, "utc_now", return_value=FIXED_NOW)


def test_test_module_ok(client: Client):
    assert collector.test_module(client) == "ok"


def test_test_module_missing_api_key():
    empty_client = Client(base_url="https://api.acmedemo.example.com", api_key="", verify=True, proxy=False)
    with pytest.raises(DemistoException, match="API Key is required"):
        collector.test_module(empty_client)


def test_fetch_events_sets_last_run_and_dedups(client: Client):
    """
    Given: an empty last run and a first fetch time one hour before now.
    When: fetching twice - once from scratch and once with a last run pointing before the newest event.
    Then: the first fetch is capped and ascending with a correct last run; the second fetch skips already fetched ids.
    """
    first_fetch_time = datetime(2026, 1, 1, 11, 0, 0, tzinfo=timezone.utc)

    next_run, events = fetch_events(client, last_run={}, first_fetch_time=first_fetch_time, max_fetch=5)

    created_times = [event["created_time"] for event in events]
    assert len(events) == 5
    assert created_times == sorted(created_times) and len(set(created_times)) == 5
    assert next_run == {"last_fetch_time": "2026-01-01T11:05:00Z", "last_ids": [events[-1]["id"]]}

    # Same window again (boundary one minute earlier) - the already fetched boundary event must be dropped.
    replay_run = {"last_fetch_time": "2026-01-01T11:04:00Z", "last_ids": [events[-1]["id"]]}
    _, replayed_events = fetch_events(client, last_run=replay_run, first_fetch_time=first_fetch_time, max_fetch=5)

    assert events[-1]["id"] not in {event["id"] for event in replayed_events}
    assert len(replayed_events) == 4


def test_get_events_command(client: Client, mocker):
    """
    Given: limit=3.
    When: running acmedemo-get-events without and with pushing.
    Then: outputs go under AcmeDemo.Event when not pushing; events are sent to XSIAM with the right vendor/product when pushing.
    """
    send_mock = mocker.patch.object(collector, "send_events_to_xsiam")

    args = {"limit": "3", "start_time": "2026-01-01T11:00:00Z"}

    events, results = get_events_command(client, args | {"should_push_events": "false"})
    assert results.outputs_prefix == "AcmeDemo.Event"
    assert len(results.outputs) == 3
    send_mock.assert_not_called()

    events, _ = get_events_command(client, args | {"should_push_events": "true"})
    send_mock.assert_called_once_with(events, vendor="acmedemo", product="auditlogs")
    assert all(event["_time"] == event["created_time"] for event in events)
