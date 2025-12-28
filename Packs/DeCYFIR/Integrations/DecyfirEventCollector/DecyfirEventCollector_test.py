import pytest
from datetime import datetime, UTC

from CommonServerPython import arg_to_datetime
from DecyfirEventCollector import (
    Client,
    ACCESS_LOGS,
    DRK_LOGS,
    get_timestamp_from_datetime,
    extract_event_time,
    add_event_fields,
    remove_duplicate_logs,
    update_fetched_event_ids,
    compute_next_fetch_time,
    fetch_events,
    test_module,
    get_events_command,
)
import demistomock as demisto


@pytest.fixture(autouse=True)
def mock_demisto(monkeypatch):
    """Mock demisto functions and disable real network/debug actions."""
    monkeypatch.setattr(demisto, "debug", lambda *_, **__: None)
    monkeypatch.setattr("DecyfirEventCollector.return_results", lambda *_, **__: None)
    monkeypatch.setattr("DecyfirEventCollector.return_error", lambda x: (_ for _ in ()).throw(Exception(x)))
    monkeypatch.setattr("DecyfirEventCollector.send_events_to_xsiam", lambda *_, **__: None)


@pytest.fixture
def client(monkeypatch):
    """Create a fake Decyfir client returning mock Access Log events."""
    c = Client(base_url="https://test.com", verify=False, proxy=False, api_key="abc123")
    monkeypatch.setattr(
        c,
        "_http_request",
        lambda **_: [
            {
                "uid": "8f297095-9515-3f37-82fc-296a99fb8753",
                "event_date": "2025-11-06T04:24:12.000+00:00",
                "event_type": "AUTHENTICATION_ATTEMPT",
                "ip": "1.2.3.4",
                "principal": "test@gmail.com",
            }
        ],
    )
    return c


@pytest.fixture
def drk_event():
    """Fixture providing a realistic DRK event sample."""
    return {
        "event_action": "ORG_ASSETS_CREATE",
        "asset_comments": "",
        "asset_name": "test_name",
        "vendor": "",
        "asset_type": "LinkedIn",
        "modified_by": "xx@test.com",
        "created_date": "2025-06-10T13:18:35.001",
        "modified_date": "2025-06-10T13:18:35.001",
        "version": "",
        "created_by": "",
    }


@pytest.fixture
def access_event():
    """Fixture providing a realistic Access Log event sample."""
    return {
        "principal": "test@gmail.com",
        "uid": "8f297095-9515-3f37-82fc-296a99fb8753",
        "event_type": "AUTHENTICATION_ATTEMPT",
        "ip": "1.2.3.4",
        "event_date": "2025-11-06T04:24:12.000+00:00",
        "name": "client_ip",
    }


# --- Utility Tests ---


def test_get_timestamp_from_datetime_rounding():
    """
    GIVEN a datetime with fractional seconds
    WHEN get_timestamp_from_datetime is called
    THEN Access Logs timestamps are rounded to seconds
         and DRK logs retain millisecond precision.
    """
    dt = datetime(2025, 11, 6, 4, 24, 12, 500_000, tzinfo=UTC)
    ts_access = get_timestamp_from_datetime(dt, ACCESS_LOGS)
    ts_drk = get_timestamp_from_datetime(dt, DRK_LOGS)
    assert ts_access % 1000 == 0
    assert ts_drk % 1000 != 0


# --- Event Extraction & Enrichment ---


def test_extract_event_time_access(access_event):
    """
    GIVEN an Access Log event with event_date field
    WHEN extract_event_time is called
    THEN a timezone-aware datetime is returned with correct hour and minute.
    """
    dt = extract_event_time(access_event, ACCESS_LOGS)
    assert isinstance(dt, datetime)
    assert dt.tzinfo == UTC
    assert dt.hour == 4
    assert dt.minute == 24


def test_extract_event_time_drk(drk_event):
    """
    GIVEN a DRK log event with created_date field
    WHEN extract_event_time is called
    THEN it returns the proper UTC datetime object from created_date.
    """
    dt = extract_event_time(drk_event, DRK_LOGS)
    assert dt.year == 2025
    assert dt.month == 6
    assert dt.second == 35


def test_add_event_fields_access(access_event):
    """
    GIVEN an Access Log event
    WHEN add_event_fields is applied
    THEN _time and source_log_type are added,
         and _ENTRY_STATUS is not present (not applicable).
    """
    add_event_fields([access_event], ACCESS_LOGS)
    assert access_event["_time"].startswith("2025-11-06T04:24:12")
    assert access_event["source_log_type"] == "access_logs"
    assert "_ENTRY_STATUS" not in access_event


def test_add_event_fields_drk(drk_event):
    """
    GIVEN a DRK event where created_date == modified_date
    WHEN add_event_fields is applied
    THEN the event includes _time, source_log_type, and _ENTRY_STATUS='new'.
    """
    add_event_fields([drk_event], DRK_LOGS)
    assert drk_event["_time"].startswith("2025-06-10T13:18:35")
    assert drk_event["source_log_type"] == "dr_keywords_logs"
    assert drk_event["_ENTRY_STATUS"] == "new"


# --- Deduplication & ID Tracking ---


def test_remove_duplicate_logs():
    """
    GIVEN logs with previously fetched IDs
    WHEN remove_duplicate_logs is called
    THEN logs with duplicate UIDs are excluded from results.
    """
    logs = [{"uid": "1"}, {"uid": "2"}]
    last_run = {"Access Logs": {"fetched_events_ids": ["1"]}}
    result = remove_duplicate_logs(logs, last_run, ACCESS_LOGS)
    assert len(result) == 1
    assert result[0]["uid"] == "2"


def test_update_fetched_event_ids():
    """
    GIVEN a list of logs containing UIDs
    WHEN update_fetched_event_ids is called
    THEN the current_run dict stores fetched UIDs for deduplication.
    """
    current_run = {}
    logs = [
        {"uid": "A1", "event_date": "2025-11-13T05:30:59.000+00:00"},
        {"uid": "A2", "event_date": "2025-11-13T05:30:59" ".000+00:00"},
    ]
    update_fetched_event_ids(current_run, ACCESS_LOGS, logs, arg_to_datetime("2025-11-13T05:30:59.000+00:00"))
    assert current_run["Access Logs"]["fetched_events_ids"] == ["A1", "A2"]


# --- Compute Next Fetch Time ---


def test_compute_next_fetch_time_from_latest(access_event):
    """
    GIVEN a list of Access Log events
    WHEN compute_next_fetch_time is called
    THEN it returns the next fetch time slightly after the latest event timestamp.
    """
    events = [access_event]
    prev_time = datetime(2025, 11, 6, 4, 0, 0, tzinfo=UTC)
    ts = prev_time.timestamp()  # seconds (float)
    result = compute_next_fetch_time(events, int(ts * 1000), ACCESS_LOGS)
    assert "2025-11-06T04:24:12" in result


# --- Fetch Logic ---


def test_fetch_events_basic_flow(client):
    """
    GIVEN a mocked client returning one Access Log event
    WHEN fetch_events is executed
    THEN it returns updated current_run metadata and a list of fetched events.
    """
    first_fetch_time = datetime(2025, 11, 6, 0, 0, tzinfo=UTC)
    last_run = {}
    max_events = {ACCESS_LOGS: 10}

    current_run, events = fetch_events(client, last_run, first_fetch_time, [ACCESS_LOGS], max_events)
    assert isinstance(current_run, dict)
    assert "Access Logs" in current_run
    assert len(events) > 0
    assert "next_fetch_time" in current_run["Access Logs"]


def test_access_logs_fetch_with_same_second_overlap(monkeypatch):
    """
    GIVEN:
        - First fetch occurs with an event at t = 04:24:12.250
        - Next fetch is computed at t + 1ms = 04:24:12.251
        - Access Logs timestamps round down to seconds
        - Second fetch returns an event that happened at 04:24:12.750 (same second)
    WHEN:
        - fetch_events is called twice sequentially
    THEN:
        - The second event is fetched (not skipped)
        - Deduplication prevents re-fetch of the first event
    """

    from DecyfirEventCollector import (
        Client,
        fetch_events,
        ACCESS_LOGS,
        get_after_param,
    )
    from datetime import datetime, timedelta, UTC

    # --- Setup ---
    base_time = datetime(2025, 11, 6, 4, 24, 12, tzinfo=UTC)

    # Simulate a client returning one event at t=base_time
    first_event = {
        "uid": "event1",
        "event_date": base_time.isoformat(),
        "event_type": "AUTH",
    }
    second_event = {
        "uid": "event2",
        "event_date": base_time.isoformat(),  # same second!
        "event_type": "AUTH",
    }

    client = Client("https://test.com", verify=False, proxy=False, api_key="abc")

    # First _http_request returns event1
    monkeypatch.setattr(client, "_http_request", lambda **_: [first_event])

    first_fetch_time = base_time - timedelta(seconds=1)
    max_events = {ACCESS_LOGS: 10}

    # --- First fetch ---
    last_run = {}
    current_run, events = fetch_events(client, last_run, first_fetch_time, [ACCESS_LOGS], max_events)
    assert len(events) == 1
    assert events[0]["uid"] == "event1"

    # --- Second fetch ---
    # Now client returns event2 (same second but different UID)
    monkeypatch.setattr(client, "_http_request", lambda **_: [first_event, second_event])

    current_run2, events2 = fetch_events(client, current_run, first_fetch_time, [ACCESS_LOGS], max_events)

    # --- Assertions ---
    assert len(events2) == 1, "Should fetch the new event even if same second"
    assert events2[0]["uid"] == "event2"
    assert events2[0]["_time"].startswith("2025-11-06T04:24:12")
    # Ensure dedup did not remove this valid event
    assert current_run2[ACCESS_LOGS]["fetched_events_ids"] == ["event1", "event2"]

    # The 'after' timestamp used in the second fetch should be rounded down to nearest second
    after2 = get_after_param(current_run2, ACCESS_LOGS, first_fetch_time)
    assert after2 % 1000 == 0, "Access Logs timestamps must round to seconds"

    current_run3, events3 = fetch_events(client, current_run2, first_fetch_time, [ACCESS_LOGS], max_events)

    # --- Assertions ---
    assert len(events3) == 0, "Should fetch no events - all are duplicates"

    # Ensure dedup did not remove this valid event
    assert current_run3[ACCESS_LOGS]["fetched_events_ids"] == ["event1", "event2"]

    # The 'after' timestamp used in the third fetch should be rounded down to nearest second
    after3 = get_after_param(current_run3, ACCESS_LOGS, first_fetch_time)
    assert after3 % 1000 == 0, "Access Logs timestamps must round to seconds"


# --- Test Module ---


def test_test_module_returns_ok(client):
    """
    GIVEN a valid client and configuration
    WHEN test_module is called
    THEN it runs fetch_events successfully and returns 'ok'.
    """
    result = test_module(client)
    assert result == "ok"


# --- Manual get-events Command ---


def test_get_events_command_without_push(monkeypatch, client):
    """
    GIVEN should_push=False and mocked tableToMarkdown
    WHEN get_events_command is executed
    THEN human-readable tables are generated but no push occurs.
    """
    called = {}

    def fake_table(name, t):
        called["table"] = True
        return f"### {name}"

    monkeypatch.setattr("DecyfirEventCollector.tableToMarkdown", fake_table)
    get_events_command(client, [ACCESS_LOGS], {ACCESS_LOGS: 10}, None, should_push=False)
    assert "table" in called


def test_get_events_command_with_push(monkeypatch, client):
    """
    GIVEN should_push=True
    WHEN get_events_command is executed
    THEN send_events_to_xsiam is called with correct vendor and product.
    """
    called = {}

    def fake_send(events, vendor, product):
        called["sent"] = len(events)
        assert vendor == "decyfir"
        assert product == "decyfir"

    monkeypatch.setattr("DecyfirEventCollector.send_events_to_xsiam", fake_send)
    get_events_command(client, [ACCESS_LOGS], {ACCESS_LOGS: 10}, None, should_push=True)
    assert called["sent"] > 0
