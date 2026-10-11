"""Unit tests for Halcyon integration."""

import copy
import json
from datetime import datetime, UTC

import pytest
from freezegun import freeze_time


def util_load_json(path: str) -> dict:
    """Load a JSON file for testing."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def mock_client(mocker):
    """Create a mock client for testing."""
    from Halcyon import Client, HalcyonAuthHandler

    # Mock the auth handler to avoid actual authentication
    mocker.patch.object(HalcyonAuthHandler, "_load_tokens_from_context")
    mocker.patch.object(HalcyonAuthHandler, "_save_tokens_to_context")

    # Mock ContentClient initialization
    mocker.patch("Halcyon.ContentClient.__init__", return_value=None)

    client = Client(
        base_url="https://api.halcyon.ai",
        username="test_user",
        password="test_password",
        tenant_id="test-tenant-id",
        verify=False,
        proxy=False,
        max_fetch=1000,
    )

    # Set required attributes that would be set by ContentClient.__init__
    client._base_url = "https://api.halcyon.ai"
    client._verify = False
    client.max_fetch = 1000

    return client


class TestHalcyonAuthHandler:
    """Test cases for the HalcyonAuthHandler class."""

    def test_auth_handler_requires_username(self, mocker):
        """Test that auth handler requires a username."""
        from Halcyon import HalcyonAuthHandler
        from ContentClientApiModule import ContentClientAuthenticationError

        mocker.patch("Halcyon.ContentClientContextStore")

        with pytest.raises(ContentClientAuthenticationError, match="non-empty username"):
            HalcyonAuthHandler(username="", password="test_password", tenant_id="test-tenant-id")

    def test_auth_handler_requires_password(self, mocker):
        """Test that auth handler requires a password."""
        from Halcyon import HalcyonAuthHandler
        from ContentClientApiModule import ContentClientAuthenticationError

        mocker.patch("Halcyon.ContentClientContextStore")

        with pytest.raises(ContentClientAuthenticationError, match="non-empty password"):
            HalcyonAuthHandler(username="test_user", password="", tenant_id="test-tenant-id")


class TestClient:
    """Test cases for the Client class."""

    def test_get_alerts(self, mock_client, mocker):
        """Test fetching alerts."""
        mock_response = {
            "data": [
                {
                    "alertId": "alert-1",
                    "firstOccurredAt": "2024-01-01T00:00:00.000Z",
                    "kind": "ThreatDetection",
                },
                {
                    "alertId": "alert-2",
                    "firstOccurredAt": "2024-01-01T01:00:00.000Z",
                    "kind": "PolicyViolation",
                },
            ]
        }

        mocker.patch.object(mock_client, "_http_request", return_value=mock_response)

        result = mock_client.get_alerts(
            last_seen_after="2024-01-01T00:00:00.000Z",
            page=1,
            page_size=100,
        )

        assert len(result["data"]) == 2
        assert result["data"][0]["alertId"] == "alert-1"

    def test_get_events(self, mock_client, mocker):
        """Test fetching events."""
        mock_response = {
            "data": [
                {
                    "eventId": "event-1",
                    "occurredAt": "2024-01-01T00:00:00.000Z",
                    "kind": "DeviceActivity",
                },
                {
                    "eventId": "event-2",
                    "occurredAt": "2024-01-01T01:00:00.000Z",
                    "kind": "SystemEvent",
                },
            ]
        }

        mocker.patch.object(mock_client, "_http_request", return_value=mock_response)

        result = mock_client.get_events(
            occurred_after="2024-01-01T00:00:00.000Z",
            page=1,
            page_size=100,
        )

        assert len(result["data"]) == 2
        assert result["data"][0]["eventId"] == "event-1"


class TestHelperFunctions:
    """Test cases for helper functions."""

    def test_get_log_types_from_titles_valid(self):
        """Test getting log types from valid titles."""
        from Halcyon import get_log_types_from_titles, LogType

        result = get_log_types_from_titles(["Alerts", "Events"])

        assert len(result) == 2
        assert LogType.ALERTS in result
        assert LogType.EVENTS in result

    def test_get_log_types_from_titles_single(self):
        """Test getting a single log type."""
        from Halcyon import get_log_types_from_titles, LogType

        result = get_log_types_from_titles(["Alerts"])

        assert len(result) == 1
        assert LogType.ALERTS in result

    def test_get_log_types_from_titles_invalid(self):
        """Test getting log types from invalid titles."""
        from Halcyon import get_log_types_from_titles
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException) as exc_info:
            get_log_types_from_titles(["InvalidType"])

        assert "Invalid event type(s) provided" in str(exc_info.value)

    def test_enrich_events_alerts(self):
        """Test enriching alert events."""
        from Halcyon import enrich_events, LogType

        events = [
            {
                "alertId": "alert-1",
                "firstOccurredAt": "2024-01-01T00:00:00.000Z",
            }
        ]

        result = enrich_events(events, LogType.ALERTS)

        assert result[0]["_time"] == "2024-01-01T00:00:00.000Z"
        assert result[0]["source_log_type"] == "alerts"

    def test_enrich_events_events(self):
        """Test enriching event events."""
        from Halcyon import enrich_events, LogType

        events = [
            {
                "eventId": "event-1",
                "occurredAt": "2024-01-01T00:00:00.000Z",
            }
        ]

        result = enrich_events(events, LogType.EVENTS)

        assert result[0]["_time"] == "2024-01-01T00:00:00.000Z"
        assert result[0]["source_log_type"] == "events"

    def test_enrich_events_missing_time_field(self):
        """Test enriching events with missing time field."""
        from Halcyon import enrich_events, LogType

        events = [
            {
                "alertId": "alert-1",
            }
        ]

        result = enrich_events(events, LogType.ALERTS)

        assert "_time" not in result[0]
        assert result[0]["source_log_type"] == "alerts"

    def test_deduplicate_events(self):
        """Test deduplicating events."""
        from Halcyon import deduplicate_events, LogType

        events = [
            {"alertId": "alert-1", "firstOccurredAt": "2024-01-01T00:00:00.000Z"},
            {"alertId": "alert-2", "firstOccurredAt": "2024-01-01T01:00:00.000Z"},
            {"alertId": "alert-3", "firstOccurredAt": "2024-01-01T02:00:00.000Z"},
        ]
        previous_run_ids = {"alert-1"}

        unique_events, new_ids, last_timestamp = deduplicate_events(
            events=events,
            previous_run_ids=previous_run_ids,
            previous_timestamp="2024-01-01T00:00:00.000Z",
            log_type=LogType.ALERTS,
        )

        assert len(unique_events) == 2
        assert "alert-2" in new_ids or "alert-3" in new_ids
        assert last_timestamp == "2024-01-01T02:00:00.000Z"

    def test_deduplicate_events_all_new(self):
        """Test deduplicating when all events are new."""
        from Halcyon import deduplicate_events, LogType

        events = [
            {"alertId": "alert-1", "firstOccurredAt": "2024-01-01T00:00:00.000Z"},
            {"alertId": "alert-2", "firstOccurredAt": "2024-01-01T01:00:00.000Z"},
        ]
        previous_run_ids: set = set()

        unique_events, new_ids, last_timestamp = deduplicate_events(
            events=events,
            previous_run_ids=previous_run_ids,
            previous_timestamp=None,
            log_type=LogType.ALERTS,
        )

        assert len(unique_events) == 2
        assert len(new_ids) == 1  # Only IDs sharing the last timestamp

    def test_deduplicate_events_all_duplicates(self):
        """Test deduplicating when all events are duplicates."""
        from Halcyon import deduplicate_events, LogType

        events = [
            {"alertId": "alert-1", "firstOccurredAt": "2024-01-01T00:00:00.000Z"},
            {"alertId": "alert-2", "firstOccurredAt": "2024-01-01T00:00:00.000Z"},
        ]
        previous_run_ids = {"alert-1", "alert-2"}

        unique_events, new_ids, last_timestamp = deduplicate_events(
            events=events,
            previous_run_ids=previous_run_ids,
            previous_timestamp="2024-01-01T00:00:00.000Z",
            log_type=LogType.ALERTS,
        )

        assert len(unique_events) == 0
        assert len(new_ids) == 0
        assert last_timestamp is None


class TestCommands:
    """Test cases for command functions."""

    def test_test_module_success(self, mock_client, mocker):
        """Test successful test-module command."""
        from Halcyon import test_module

        mocker.patch.object(mock_client, "get_alerts", return_value={"data": []})

        result = test_module(mock_client)

        assert result == "ok"

    def test_test_module_failure(self, mock_client, mocker):
        """Test failed test-module command."""
        from Halcyon import test_module
        from CommonServerPython import DemistoException

        mocker.patch.object(mock_client, "get_alerts", side_effect=Exception("Connection failed"))
        mocker.patch.object(mock_client, "diagnose_error", return_value={"issue": "Connection error"})

        with pytest.raises(DemistoException) as exc_info:
            test_module(mock_client)

        assert "Test failed" in str(exc_info.value)

    def test_get_events_command(self, mock_client, mocker):
        """Test get-events command."""
        from Halcyon import get_events_command

        mock_alerts_response = {
            "data": [
                {"alertId": "alert-1", "firstOccurredAt": "2024-01-01T00:00:00.000Z"},
            ]
        }
        mock_events_response = {
            "data": [
                {"eventId": "event-1", "occurredAt": "2024-01-01T00:00:00.000Z"},
            ]
        }

        def mock_get_alerts(*args, **kwargs):
            return mock_alerts_response

        def mock_get_events(*args, **kwargs):
            return mock_events_response

        mocker.patch.object(mock_client, "get_alerts", side_effect=mock_get_alerts)
        mocker.patch.object(mock_client, "get_events", side_effect=mock_get_events)

        events, results = get_events_command(
            client=mock_client,
            args={"limit": "10", "event_type": "Alerts,Events"},
            event_types_to_fetch=["Alerts", "Events"],
        )

        assert len(events) == 2
        assert any(e.get("alertId") == "alert-1" for e in events)
        assert any(e.get("eventId") == "event-1" for e in events)

    def test_get_events_command_with_time_args(self, mock_client, mocker):
        """Test get-events command with time arguments."""
        from Halcyon import get_events_command

        mock_response = {"data": []}

        mocker.patch.object(mock_client, "get_alerts", return_value=mock_response)
        mocker.patch.object(mock_client, "get_events", return_value=mock_response)

        events, results = get_events_command(
            client=mock_client,
            args={
                "limit": "10",
                "start_time": "2024-01-01T00:00:00Z",
                "end_time": "2024-01-02T00:00:00Z",
                "event_type": "Alerts",
            },
            event_types_to_fetch=["Alerts"],
        )

        assert len(events) == 0

    @freeze_time("2024-01-01T12:00:00Z")
    def test_fetch_events_command(self, mock_client, mocker):
        """Test fetch-events command."""
        from Halcyon import fetch_events_command, LogType

        mock_alerts_response = {
            "data": [
                {"alertId": "alert-1", "firstOccurredAt": "2024-01-01T10:00:00.000Z"},
            ]
        }
        mock_events_response = {
            "data": [
                {"eventId": "event-1", "occurredAt": "2024-01-01T11:00:00.000Z"},
            ]
        }

        def mock_get_alerts(*args, **kwargs):
            return mock_alerts_response

        def mock_get_events(*args, **kwargs):
            return mock_events_response

        mocker.patch.object(mock_client, "get_alerts", side_effect=mock_get_alerts)
        mocker.patch.object(mock_client, "get_events", side_effect=mock_get_events)

        last_run = {}
        events, next_run = fetch_events_command(
            client=mock_client,
            last_run=last_run,
            log_types=[LogType.ALERTS, LogType.EVENTS],
            max_fetch=1000,
        )

        assert len(events) == 2
        assert "last_fetch_alerts" in next_run
        assert "last_fetch_events" in next_run

    @freeze_time("2024-01-01T12:00:00Z")
    def test_fetch_events_command_with_last_run(self, mock_client, mocker):
        """Test fetch-events command with existing last run."""
        from Halcyon import fetch_events_command, LogType

        mock_alerts_response = {
            "data": [
                {"alertId": "alert-2", "firstOccurredAt": "2024-01-01T11:00:00.000Z"},
            ]
        }
        mock_events_response = {"data": []}

        mocker.patch.object(mock_client, "get_alerts", return_value=mock_alerts_response)
        mocker.patch.object(mock_client, "get_events", return_value=mock_events_response)

        last_run = {
            "last_fetch_alerts": "2024-01-01T10:00:00.000Z",
            "previous_ids_alerts": ["alert-1"],
            "last_fetch_events": "2024-01-01T10:00:00.000Z",
            "previous_ids_events": [],
        }

        events, next_run = fetch_events_command(
            client=mock_client,
            last_run=last_run,
            log_types=[LogType.ALERTS, LogType.EVENTS],
            max_fetch=1000,
        )

        assert len(events) == 1
        assert events[0]["alertId"] == "alert-2"

    @freeze_time("2024-01-01T12:00:00Z")
    def test_fetch_events_command_no_events(self, mock_client, mocker):
        """Test fetch-events command when no events are returned."""
        from Halcyon import fetch_events_command, LogType

        mock_response = {"data": []}

        mocker.patch.object(mock_client, "get_alerts", return_value=mock_response)
        mocker.patch.object(mock_client, "get_events", return_value=mock_response)

        last_run = {}
        events, next_run = fetch_events_command(
            client=mock_client,
            last_run=last_run,
            log_types=[LogType.ALERTS, LogType.EVENTS],
            max_fetch=1000,
        )

        assert len(events) == 0
        # Should still set last_fetch times
        assert "last_fetch_alerts" in next_run
        assert "last_fetch_events" in next_run


class TestFetchEventsForLogType:
    """Test cases for fetch_events_for_log_type function."""

    @freeze_time("2024-01-01T12:00:00Z")
    def test_fetch_with_pagination(self, mock_client, mocker):
        """Test fetching events with pagination."""
        from Halcyon import fetch_events_for_log_type, LogType

        # First page returns full page, second page returns partial
        page1_response = {
            "data": [{"alertId": f"alert-{i}", "firstOccurredAt": f"2024-01-01T{i:02d}:00:00.000Z"} for i in range(100)]
        }
        page2_response = {
            "data": [{"alertId": f"alert-{i}", "firstOccurredAt": f"2024-01-01T{i:02d}:00:00.000Z"} for i in range(100, 150)]
        }

        call_count = 0

        def mock_get_alerts(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return page1_response
            return page2_response

        mocker.patch.object(mock_client, "get_alerts", side_effect=mock_get_alerts)

        events, last_run = fetch_events_for_log_type(
            client=mock_client,
            log_type=LogType.ALERTS,
            last_run={},
            max_fetch=200,
        )

        assert len(events) == 150
        assert call_count == 2

    @freeze_time("2024-01-01T12:00:00Z")
    def test_fetch_respects_max_fetch(self, mock_client, mocker):
        """Test that fetching respects max_fetch limit."""
        from Halcyon import fetch_events_for_log_type, LogType

        # Return more events than max_fetch
        response = {"data": [{"alertId": f"alert-{i}", "firstOccurredAt": f"2024-01-01T{i:02d}:00:00.000Z"} for i in range(100)]}

        mocker.patch.object(mock_client, "get_alerts", return_value=response)

        events, last_run = fetch_events_for_log_type(
            client=mock_client,
            log_type=LogType.ALERTS,
            last_run={},
            max_fetch=50,
        )

        assert len(events) == 50


class TestLogTypeEnum:
    """Test cases for LogType enum."""

    def test_alerts_log_type(self):
        """Test ALERTS log type properties."""
        from Halcyon import LogType

        assert LogType.ALERTS.type_string == "alerts"
        assert LogType.ALERTS.title == "Alerts"
        assert LogType.ALERTS.api_endpoint == "/v2/alerts"
        assert LogType.ALERTS.time_field == "firstOccurredAt"

    def test_events_log_type(self):
        """Test EVENTS log type properties."""
        from Halcyon import LogType

        assert LogType.EVENTS.type_string == "events"
        assert LogType.EVENTS.title == "Events"
        assert LogType.EVENTS.api_endpoint == "/v2/events"
        assert LogType.EVENTS.time_field == "occurredAt"


class FakeHalcyonEventsApi:
    """Stateful fake of ``/v2/events``: inclusive occurredAfter/occurredBefore, ascending, paged.

    Each event has an ``indexed_at`` time: it is not returned before that time, which models the
    Halcyon indexing delay (an event can become queryable minutes after its occurredAt).
    """

    def __init__(self):
        self.rows: list[dict] = []
        self.now = ""
        self.calls: list[dict] = []

    def add(self, event_id: str | None, occurred_at: str, indexed_at: str | None = None, **extra) -> None:
        event = {"occurredAt": occurred_at, **extra}
        if event_id:
            event["eventId"] = event_id
        self.rows.append({"event": event, "indexed_at": indexed_at or occurred_at})

    def get_events(self, occurred_after=None, occurred_before=None, page=1, page_size=100, **_):
        from Halcyon import normalize_timestamp

        def time_of(value: str) -> str:
            return normalize_timestamp(value) or ""

        self.calls.append({"occurred_after": occurred_after, "occurred_before": occurred_before, "page": page})
        visible = [
            row["event"]
            for row in self.rows
            if time_of(row["indexed_at"]) <= self.now
            and (not occurred_after or time_of(row["event"]["occurredAt"]) >= occurred_after)
            and (not occurred_before or time_of(row["event"]["occurredAt"]) <= occurred_before)
        ]
        visible.sort(key=lambda e: (time_of(e["occurredAt"]), e.get("eventId", "")))
        # Fresh copies, like real JSON responses, so enrichment of a sent event does not leak into later cycles.
        visible = copy.deepcopy(visible)
        return {"data": visible[(page - 1) * page_size : page * page_size]}


def run_cycles(mock_client, mocker, api: FakeHalcyonEventsApi, cycle_starts: list[str], max_fetch=1000, last_run=None):
    """Run one events fetch per cycle start time. Returns (Counter of sent IDs, final last run)."""
    from collections import Counter
    from Halcyon import LogType, fetch_events_for_log_type

    mocker.patch.object(mock_client, "get_events", side_effect=api.get_events)
    sent: Counter = Counter()
    last_run = last_run if last_run is not None else {}
    for cycle_start in cycle_starts:
        api.now = cycle_start
        events, last_run = fetch_events_for_log_type(
            client=mock_client,
            log_type=LogType.EVENTS,
            last_run=last_run,
            max_fetch=max_fetch,
            cycle_start=datetime.strptime(cycle_start, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC),
        )
        sent.update(e.get("eventId", e["occurredAt"]) for e in events)
    return sent, last_run


def minute_cycles(start_minute: int, count: int) -> list[str]:
    return [f"2026-10-05T07:{start_minute + i:02d}:00.000000Z" for i in range(count)]


class TestEventsLookback:
    """Events re-read the last 5 minutes every cycle and are deduplicated against earlier cycles."""

    def test_late_indexed_event_is_collected_once(self, mock_client, mocker):
        """An event indexed 3 minutes late, behind events we already sent, is still collected - once."""
        api = FakeHalcyonEventsApi()
        api.add("on-time", "2026-10-05T07:00:30Z")
        api.add("late", "2026-10-05T07:00:10Z", indexed_at="2026-10-05T07:03:30Z")
        api.add("after", "2026-10-05T07:02:00Z")

        sent, _ = run_cycles(mock_client, mocker, api, minute_cycles(1, 6))

        assert dict(sent) == {"on-time": 1, "late": 1, "after": 1}

    def test_query_reads_lookback_window_up_to_now(self, mock_client, mocker):
        """Each cycle queries from now - 5 minutes up to now, not up to now - 5 minutes."""
        api = FakeHalcyonEventsApi()
        api.add("fresh", "2026-10-05T07:09:59Z")

        sent, _ = run_cycles(mock_client, mocker, api, ["2026-10-05T07:10:00.000000Z"])

        assert sent == {"fresh": 1}
        assert api.calls[0]["occurred_after"] == "2026-10-05T07:05:00.000000Z"
        assert api.calls[0]["occurred_before"] == "2026-10-05T07:10:00.000000Z"

    def test_event_indexed_after_lookback_is_lost(self, mock_client, mocker):
        """Documents the limit: an event indexed more than 5 minutes after it occurred is not collected."""
        api = FakeHalcyonEventsApi()
        api.add("too-late", "2026-10-05T07:00:10Z", indexed_at="2026-10-05T07:06:30Z")

        sent, _ = run_cycles(mock_client, mocker, api, minute_cycles(1, 8))

        assert "too-late" not in sent

    def test_dedup_cache_keeps_only_lookback_window(self, mock_client, mocker):
        api = FakeHalcyonEventsApi()
        for minute in range(10):
            api.add(f"evt-{minute}", f"2026-10-05T07:{minute:02d}:30Z")

        _, last_run = run_cycles(mock_client, mocker, api, minute_cycles(1, 10))

        # Last cycle 07:10 -> window starts 07:05:00, so only events from 07:05 on are kept.
        assert sorted(last_run["events_dedup_cache"]) == ["evt-5", "evt-6", "evt-7", "evt-8", "evt-9"]
        assert last_run["last_fetch_events"] == "2026-10-05T07:10:00.000000Z"

    def test_events_without_id_are_skipped(self, mock_client, mocker):
        """Events without an ID cannot be deduplicated, so they are skipped (same as the previous version)."""
        api = FakeHalcyonEventsApi()
        api.add(None, "2026-10-05T07:00:20Z", kind="NoId")
        api.add("with-id", "2026-10-05T07:00:30Z")

        sent, last_run = run_cycles(mock_client, mocker, api, minute_cycles(1, 5))

        assert dict(sent) == {"with-id": 1}
        assert list(last_run["events_dedup_cache"]) == ["with-id"]

    def test_mixed_timestamp_precision_is_deduplicated(self, mock_client, mocker):
        api = FakeHalcyonEventsApi()
        api.add("no-fraction", "2026-10-05T07:00:30Z")
        api.add("with-fraction", "2026-10-05T07:00:30.123Z")

        sent, _ = run_cycles(mock_client, mocker, api, minute_cycles(1, 5))

        assert dict(sent) == {"no-fraction": 1, "with-fraction": 1}

    def test_backlog_over_max_fetch_drains_without_gaps_or_duplicates(self, mock_client, mocker):
        """250 events in one cycle's window with max_fetch=100: drained over 3 cycles, each sent once."""
        api = FakeHalcyonEventsApi()
        for i in range(250):
            api.add(f"evt-{i:03d}", f"2026-10-05T07:00:{i % 60:02d}.{i:03d}Z")

        sent, _ = run_cycles(mock_client, mocker, api, minute_cycles(1, 4), max_fetch=100)

        assert len(sent) == 250
        assert set(sent.values()) == {1}

    def test_same_second_burst_over_max_fetch_drains(self, mock_client, mocker):
        api = FakeHalcyonEventsApi()
        for i in range(250):
            api.add(f"burst-{i:03d}", "2026-10-05T07:00:30Z")

        sent, _ = run_cycles(mock_client, mocker, api, minute_cycles(1, 4), max_fetch=100)

        assert len(sent) == 250
        assert set(sent.values()) == {1}

    def test_backlog_older_than_lookback_resumes_from_watermark(self, mock_client, mocker):
        """When max_fetch stops a cycle early, the next one continues from where it stopped, even
        if that point is older than the next cycle's lookback window."""
        api = FakeHalcyonEventsApi()
        for i in range(300):
            api.add(f"evt-{i:03d}", f"2026-10-05T07:00:{i % 60:02d}.{i:03d}Z")

        # Cycles 10 minutes apart, so the backlog falls out of the lookback window between cycles.
        cycles = ["2026-10-05T07:01:00.000000Z", "2026-10-05T07:11:00.000000Z", "2026-10-05T07:21:00.000000Z"]
        sent, _ = run_cycles(mock_client, mocker, api, cycles, max_fetch=100)

        assert len(sent) == 300
        assert set(sent.values()) == {1}


class TestFutureDatedEvents:
    """The API returns some events with occurredAt in the future. They wait for a later cycle."""

    def test_future_event_waits_for_its_time(self, mock_client, mocker):
        """A future-dated event is not sent early and does not move the watermark, and is sent once its time passes."""
        api = FakeHalcyonEventsApi()
        api.add("now", "2026-10-05T07:00:30Z")
        api.add("future", "2026-10-05T07:02:30Z", indexed_at="2026-10-05T07:00:31Z")

        sent, last_run = run_cycles(mock_client, mocker, api, ["2026-10-05T07:01:00.000000Z"])
        assert sent == {"now": 1}
        assert "future" not in last_run["events_dedup_cache"]

        sent, _ = run_cycles(mock_client, mocker, api, minute_cycles(2, 4), last_run=last_run)
        assert sent == {"future": 1}

    def test_future_event_returned_by_api_is_filtered(self, mock_client, mocker):
        """Even if the API ignores occurredBefore, an event after the cycle start is not sent."""
        from Halcyon import LogType, fetch_events_for_log_type

        response = {"data": [{"eventId": "future", "occurredAt": "2026-10-05T08:00:00Z"}]}
        mocker.patch.object(mock_client, "get_events", return_value=response)

        events, last_run = fetch_events_for_log_type(
            client=mock_client,
            log_type=LogType.EVENTS,
            last_run={},
            max_fetch=1000,
            cycle_start=datetime(2026, 10, 5, 7, 0, tzinfo=UTC),
        )

        assert events == []
        assert last_run["events_dedup_cache"] == {}

    def test_alerts_are_not_filtered(self, mock_client, mocker):
        from Halcyon import LogType, fetch_events_for_log_type

        response = {"data": [{"alertId": "alert-future", "firstOccurredAt": "2026-10-05T08:00:00.000Z"}]}
        mocker.patch.object(mock_client, "get_alerts", return_value=response)

        events, _ = fetch_events_for_log_type(
            client=mock_client,
            log_type=LogType.ALERTS,
            last_run={"last_fetch_alerts": "2026-10-05T06:00:00.000Z"},
            max_fetch=1000,
            cycle_start=datetime(2026, 10, 5, 7, 0, tzinfo=UTC),
        )

        assert [e["alertId"] for e in events] == ["alert-future"]


class TestEventsLastRunMigration:
    """A last run written by the previous version is converted without losing or re-sending events."""

    def test_migrates_legacy_keys(self):
        from Halcyon import migrate_events_last_run

        last_run = {
            "last_fetch_events": "2026-10-05T07:00:30Z",
            "previous_ids_events": ["a", "b"],
            "last_fetch_alerts": "2026-10-05T06:00:00.000Z",
            "previous_ids_alerts": ["alert-1"],
        }

        migrated = migrate_events_last_run(last_run)

        assert migrated == {
            "last_fetch_events": "2026-10-05T07:00:30.000000Z",
            "events_dedup_cache": {"a": "2026-10-05T07:00:30.000000Z", "b": "2026-10-05T07:00:30.000000Z"},
            "events_fetch_floor": "2026-10-05T07:00:30.000000Z",
            "last_fetch_alerts": "2026-10-05T06:00:00.000Z",
            "previous_ids_alerts": ["alert-1"],
        }

    def test_already_migrated_last_run_is_unchanged(self):
        from Halcyon import migrate_events_last_run

        last_run = {
            "last_fetch_events": "2026-10-05T07:00:30.000000Z",
            "events_dedup_cache": {"a": "2026-10-05T07:00:30.000000Z"},
        }

        assert migrate_events_last_run(dict(last_run)) == last_run

    def test_empty_last_run_is_unchanged(self):
        from Halcyon import migrate_events_last_run

        assert migrate_events_last_run({}) == {}

    def test_upgrade_does_not_resend_events_before_legacy_watermark(self, mock_client, mocker):
        """The old version already sent everything up to its watermark; the first lookback cycle must not send it again."""
        api = FakeHalcyonEventsApi()
        api.add("sent-by-old-version", "2026-10-05T07:00:10Z")
        api.add("boundary", "2026-10-05T07:00:30Z")
        api.add("new", "2026-10-05T07:00:45Z")
        legacy_last_run = {"last_fetch_events": "2026-10-05T07:00:30.000Z", "previous_ids_events": ["boundary"]}

        sent, last_run = run_cycles(mock_client, mocker, api, minute_cycles(1, 7), last_run=legacy_last_run)

        assert dict(sent) == {"new": 1}
        assert "previous_ids_events" not in last_run
        assert "events_fetch_floor" not in last_run  # Dropped once the window moved past it.

    def test_upgrade_with_old_watermark_resumes_from_it(self, mock_client, mocker):
        """A legacy watermark older than the lookback window: everything after it is collected, nothing before it."""
        api = FakeHalcyonEventsApi()
        api.add("before", "2026-10-05T06:00:00Z")
        api.add("after-1", "2026-10-05T06:30:00Z")
        api.add("after-2", "2026-10-05T06:59:00Z")
        legacy_last_run = {"last_fetch_events": "2026-10-05T06:10:00.000Z", "previous_ids_events": []}

        sent, _ = run_cycles(mock_client, mocker, api, ["2026-10-05T07:00:00.000000Z"], last_run=legacy_last_run)

        assert dict(sent) == {"after-1": 1, "after-2": 1}
