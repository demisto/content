import pytest
from datetime import datetime, timezone
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
    """Patch demisto and common output utilities."""
    monkeypatch.setattr(demisto, "debug", lambda *_, **__: None)
    monkeypatch.setattr("DecyfirEventCollector.return_results", lambda *_, **__: None)
    monkeypatch.setattr("DecyfirEventCollector.return_error", lambda x: (_ for _ in ()).throw(Exception(x)))
    monkeypatch.setattr("DecyfirEventCollector.send_events_to_xsiam", lambda *_, **__: None)


@pytest.fixture
def client(monkeypatch):
    """Mocked API client with fake event response."""
    c = Client(base_url="https://api.fake", verify=False, proxy=False, api_key="abc123")
    # Simulate always returning a single Access Log event
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
    """Sample DRK event payload."""
    return {
        "event_action": "ORG_ASSETS_CREATE",
        "asset_comments": "",
        "asset_name": "test_name",
        "vendor": "",
        "asset_type": "LinkedIn",
        "modified_by": "xx@gmail.com",
        "created_date": "2025-06-10T13:18:35.001",
        "modified_date": "2025-06-10T13:18:35.001",
        "version": "",
        "created_by": ""
    }


@pytest.fixture
def access_event():
    """Sample Access Log event payload."""
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
    dt = datetime(2025, 11, 6, 4, 24, 12, 500_000, tzinfo=timezone.utc)
    ts_access = get_timestamp_from_datetime(dt, ACCESS_LOGS)
    ts_drk = get_timestamp_from_datetime(dt, DRK_LOGS)
    assert ts_access % 1000 == 0  # Rounded to seconds for access logs
    assert ts_drk % 1000 != 0  # DRK logs retain ms precision


# --- Event Extraction & Enrichment ---

def test_extract_event_time_access(access_event):
    dt = extract_event_time(access_event, ACCESS_LOGS)
    assert isinstance(dt, datetime)
    assert dt.tzinfo == timezone.utc
    assert dt.hour == 4 and dt.minute == 24


def test_extract_event_time_drk(drk_event):
    dt = extract_event_time(drk_event, DRK_LOGS)
    assert dt.year == 2025
    assert dt.month == 6
    assert dt.second == 35


def test_add_event_fields_access(access_event):
    add_event_fields([access_event], ACCESS_LOGS)
    assert access_event["_time"].startswith("2025-11-06T04:24:12")
    assert access_event["source_log_type"] == "access_logs"
    assert "_ENTRY_STATUS" not in access_event


def test_add_event_fields_drk(drk_event):
    add_event_fields([drk_event], DRK_LOGS)
    assert drk_event["_time"].startswith("2025-06-10T13:18:35")
    assert drk_event["source_log_type"] == "dr_keywords_logs"
    assert drk_event["_ENTRY_STATUS"] == "new"  # created_date == modified_date


# --- Deduplication & ID Tracking ---

def test_remove_duplicate_logs():
    logs = [{"uid": "1"}, {"uid": "2"}]
    last_run = {"Access Logs": {"fetched_events_ids": ["1"]}}
    result = remove_duplicate_logs(logs, last_run, ACCESS_LOGS)
    assert len(result) == 1
    assert result[0]["uid"] == "2"


def test_update_fetched_event_ids():
    current_run = {}
    logs = [{"uid": "A1"}, {"uid": "A2"}]
    update_fetched_event_ids(current_run, ACCESS_LOGS, logs)
    assert current_run["Access Logs"]["fetched_events_ids"] == ["A1", "A2"]


# --- Compute Next Fetch Time ---

def test_compute_next_fetch_time_from_latest(access_event):
    events = [access_event]
    prev_time = datetime(2025, 11, 6, 4, 0, 0, tzinfo=timezone.utc)
    result = compute_next_fetch_time(events, prev_time, ACCESS_LOGS)
    assert "2025-11-06T04:24:12" in result


# --- Fetch Logic ---

def test_fetch_events_basic_flow(client):
    first_fetch_time = datetime(2025, 11, 6, 0, 0, tzinfo=timezone.utc)
    last_run = {}
    max_events = {ACCESS_LOGS: 10}

    current_run, events = fetch_events(client, last_run, first_fetch_time, [ACCESS_LOGS], max_events)
    assert isinstance(current_run, dict)
    assert "Access Logs" in current_run
    assert len(events) > 0
    assert "next_fetch_time" in current_run["Access Logs"]


# --- Test Module ---

def test_test_module_returns_ok(client):
    first_fetch_time = datetime(2025, 11, 6, tzinfo=timezone.utc)
    result = test_module(client, first_fetch_time, [ACCESS_LOGS], {ACCESS_LOGS: 10})
    assert result == "ok"


# --- Manual get-events Command ---

def test_get_events_command_without_push(monkeypatch, client):
    called = {}

    def fake_table(name, t):
        called["table"] = True
        return f"### {name}"

    monkeypatch.setattr("DecyfirEventCollector.tableToMarkdown", fake_table)
    get_events_command(client, [ACCESS_LOGS], {ACCESS_LOGS: 10}, None, should_push=False)
    assert "table" in called


def test_get_events_command_with_push(monkeypatch, client):
    called = {}

    def fake_send(events, vendor, product):
        called["sent"] = len(events)
        assert vendor == "decyfir"
        assert product == "decyfir"

    monkeypatch.setattr("DecyfirEventCollector.send_events_to_xsiam", fake_send)
    get_events_command(client, [ACCESS_LOGS], {ACCESS_LOGS: 10}, None, should_push=True)
    assert called["sent"] > 0
