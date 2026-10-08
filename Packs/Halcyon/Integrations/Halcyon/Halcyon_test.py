"""Unit tests for Halcyon integration."""

import json
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
        mock_body = {
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
            ],
            "totalCount": 2,
            "totalPages": 1,
            "page": 1,
            "pageSize": 100,
        }
        mock_response = mocker.Mock()
        mock_response.json.return_value = mock_body
        mock_response.headers = {"Content-Type": "application/json", "X-RateLimit-Remaining": "99"}

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
        mock_body = {
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
            ],
            "totalCount": 2,
            "totalPages": 1,
            "page": 1,
            "pageSize": 100,
        }
        mock_response = mocker.Mock()
        mock_response.json.return_value = mock_body
        mock_response.headers = {"Content-Type": "application/json", "X-RateLimit-Remaining": "99"}

        mocker.patch.object(mock_client, "_http_request", return_value=mock_response)

        result = mock_client.get_events(
            occurred_after="2024-01-01T00:00:00.000Z",
            page=1,
            page_size=100,
        )

        assert len(result["data"]) == 2
        assert result["data"][0]["eventId"] == "event-1"

    def test_log_and_parse_response_logs_metadata_without_header_values(self, mock_client, mocker):
        """_log_and_parse_response returns the body unchanged and logs header NAMES only (no values)."""
        import demistomock as demisto
        from Halcyon import Client

        body = {
            "data": [{"id": "e1", "occurredAt": "2024-01-01T00:00:00.000Z"}],
            "totalCount": 5000,
            "totalPages": 50,
            "page": 1,
            "pageSize": 100,
        }
        response = mocker.Mock()
        response.json.return_value = body
        # A secret-bearing header value we must NEVER see in the logs.
        response.headers = {"Authorization": "Bearer super-secret-token", "X-RateLimit-Remaining": "7"}

        debug_mock = mocker.patch.object(demisto, "debug")

        result = Client._log_and_parse_response(response, "events")

        # Body is returned unchanged.
        assert result == body

        logged = " ".join(str(call.args[0]) for call in debug_mock.call_args_list)
        # Header names are logged.
        assert "Authorization" in logged
        assert "X-RateLimit-Remaining" in logged
        # Header VALUES (the secret) are never logged.
        assert "super-secret-token" not in logged
        # The pagination/volume envelope is surfaced for peak detection.
        assert "totalCount" in logged
        assert "5000" in logged

    def test_log_and_parse_response_never_raises(self, mocker):
        """_log_and_parse_response must never raise, no matter what the response looks like."""
        from Halcyon import Client

        mocker.patch("demistomock.debug")

        # 1) json() raises (e.g. non-JSON / empty body).
        r_bad_json = mocker.Mock()
        r_bad_json.json.side_effect = ValueError("not json")
        r_bad_json.headers = {"X-A": "1"}
        assert Client._log_and_parse_response(r_bad_json, "events") == {}

        # 2) headers attribute access raises.
        r_bad_headers = mocker.Mock()
        r_bad_headers.json.return_value = {"data": [], "totalCount": 0}
        type(r_bad_headers).headers = property(lambda self: (_ for _ in ()).throw(RuntimeError("boom")))
        assert Client._log_and_parse_response(r_bad_headers, "events") == {"data": [], "totalCount": 0}

        # 3) body is a list (not a dict).
        r_list = mocker.Mock()
        r_list.json.return_value = [1, 2, 3]
        r_list.headers = {}
        assert Client._log_and_parse_response(r_list, "alerts") == [1, 2, 3]

        # 4) body is None.
        r_none = mocker.Mock()
        r_none.json.return_value = None
        r_none.headers = {}
        assert Client._log_and_parse_response(r_none, "alerts") is None

        # 5) response is None entirely.
        assert Client._log_and_parse_response(None, "events") == {}

        # 6) records field is not a list.
        r_weird = mocker.Mock()
        r_weird.json.return_value = {"data": "oops", "page": 1}
        r_weird.headers = {"H": "v"}
        assert Client._log_and_parse_response(r_weird, "events") == {"data": "oops", "page": 1}


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
        # last_timestamp is now normalized to canonical 6-digit fractional seconds.
        assert last_timestamp == "2024-01-01T02:00:00.000000Z"

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
    """A stateful fake of the Halcyon ``/v2/events`` endpoint.

    This reproduces the real server contract that drives the reported bugs:

    * ``occurredAfter`` is an INCLUSIVE lower bound (events whose ``occurredAt``
      equals the value are returned again) - matching the live-log observation
      that the event sitting exactly on the watermark is re-fetched every cycle.
    * Results are sorted ascending by ``occurredAt`` (``sortOrder=Asc``).
    * ``page``/``pageSize`` paginate the filtered, sorted result set, and ``page``
      is supplied fresh (starting at 1) on every fetch cycle by the integration.

    It also supports injecting "late-arriving" events: rows that become queryable
    only after a given cycle index, while still carrying an older ``occurredAt``.
    This models source-side indexing lag (the watermark running minutes behind
    wall-clock that we saw in production logs).
    """

    def __init__(self):
        # Each entry: {"event": {...}, "visible_from_cycle": int}
        self._rows: list[dict] = []
        self.current_cycle = 0

    def add_event(self, event_id: str, occurred_at: str, visible_from_cycle: int = 0) -> None:
        self._rows.append(
            {
                "event": {
                    "eventId": event_id,
                    "occurredAt": occurred_at,
                    "kind": "BadAuthentication",
                },
                "visible_from_cycle": visible_from_cycle,
            }
        )

    def get_events(self, *args, **kwargs) -> dict:
        """Mimics ``Client.get_events``: inclusive occurredAfter, asc sort, paged."""
        occurred_after = kwargs.get("occurred_after")
        page = kwargs.get("page", 1)
        page_size = kwargs.get("page_size", 100)

        visible = [
            r["event"]
            for r in self._rows
            if r["visible_from_cycle"] <= self.current_cycle
            and (occurred_after is None or r["event"]["occurredAt"] >= occurred_after)  # INCLUSIVE
        ]
        visible.sort(key=lambda e: (e["occurredAt"], e["eventId"]))  # ascending

        start = (page - 1) * page_size
        end = start + page_size
        return {"data": visible[start:end]}


# These cursor tests freeze "now" BEFORE the events they create (the first watermark is
# "now"), so they pass a cycle start later than every event to keep the future-dated
# hold-back out of the way. The hold-back has its own tests in TestHoldBackFutureDatedEvents.
CYCLE_START_AFTER_ALL_TEST_EVENTS = "2099-01-01T00:00:00.000000Z"


def _run_fetch_cycles(mock_client, mocker, api: FakeHalcyonEventsApi, num_cycles: int, max_fetch: int):
    """Drive ``fetch_events_for_log_type`` across cycles, threading last_run.

    Returns a Counter mapping event_id -> number of times it was ingested across
    all cycles. A correct collector yields exactly 1 per real event (no dupes,
    no misses).
    """
    from collections import Counter
    from Halcyon import fetch_events_for_log_type, LogType

    mocker.patch.object(mock_client, "get_events", side_effect=api.get_events)

    ingested: Counter = Counter()
    last_run: dict = {}
    for cycle in range(num_cycles):
        api.current_cycle = cycle
        events, last_run = fetch_events_for_log_type(
            client=mock_client,
            log_type=LogType.EVENTS,
            last_run=last_run,
            max_fetch=max_fetch,
            cycle_start=CYCLE_START_AFTER_ALL_TEST_EVENTS,
        )
        for ev in events:
            ingested[ev["eventId"]] += 1
    return ingested


class TestHoldBackFutureDatedEvents:
    """Events dated after the cycle start are not sent and do not move the watermark."""

    def test_truncate_cuts_only_trailing_future_events(self):
        from Halcyon import LogType, truncate_events_after_cycle_start

        events = [
            {"id": "a", "occurredAt": "2026-10-06T05:09:00.000Z"},
            {"id": "b", "occurredAt": "2026-10-06T05:09:09Z"},  # exactly the cycle start: kept
            {"id": "c", "occurredAt": "2026-10-06T05:10:09.983Z"},  # future-dated: cut
        ]
        kept = truncate_events_after_cycle_start(events, "2026-10-06T05:09:09.000000Z", LogType.EVENTS)
        assert [e["id"] for e in kept] == ["a", "b"]

    def test_truncate_all_future_returns_empty(self):
        from Halcyon import LogType, truncate_events_after_cycle_start

        events = [{"id": "x", "occurredAt": "2026-10-06T06:00:00.000Z"}]
        assert truncate_events_after_cycle_start(events, "2026-10-06T05:00:00.000000Z", LogType.EVENTS) == []

    def test_future_event_held_back_then_collected_once(self, mock_client, mocker):
        """Reproduces the 2026-10-06 05:09:09 cycle: a future-dated event must not move the
        watermark past real events, and must itself be collected once its time has passed."""
        from Halcyon import LogType, fetch_events_for_log_type

        api = FakeHalcyonEventsApi()
        api.add_event("on-time-1", "2026-10-06T05:09:01.000Z", visible_from_cycle=0)
        api.add_event("on-time-2", "2026-10-06T05:09:05.000Z", visible_from_cycle=0)
        api.add_event("future", "2026-10-06T05:10:09.983Z", visible_from_cycle=0)  # clock ahead
        api.add_event("real-later", "2026-10-06T05:09:40.000Z", visible_from_cycle=1)
        mocker.patch.object(mock_client, "get_events", side_effect=api.get_events)

        last_run: dict = {"last_fetch_events": "2026-10-06T05:09:00.000000Z"}
        ingested: list[str] = []
        for cycle, cycle_start in enumerate(
            ["2026-10-06T05:09:09.000000Z", "2026-10-06T05:10:09.000000Z", "2026-10-06T05:11:09.000000Z"]
        ):
            api.current_cycle = cycle
            events, last_run = fetch_events_for_log_type(
                client=mock_client, log_type=LogType.EVENTS, last_run=last_run, max_fetch=1000, cycle_start=cycle_start
            )
            ingested += [e["eventId"] for e in events]
            if cycle == 0:
                # Watermark stays at the newest kept event; the future event is not remembered as seen.
                assert last_run["last_fetch_events"] == "2026-10-06T05:09:05.000000Z"
                assert "future" not in last_run["previous_ids_events"]

        assert sorted(ingested) == ["future", "on-time-1", "on-time-2", "real-later"]

    def test_all_events_future_keeps_previous_watermark(self, mock_client, mocker):
        from Halcyon import LogType, fetch_events_for_log_type

        api = FakeHalcyonEventsApi()
        api.add_event("future", "2026-10-06T06:00:00.000Z")
        mocker.patch.object(mock_client, "get_events", side_effect=api.get_events)

        last_run = {"last_fetch_events": "2026-10-06T05:00:00.000000Z", "previous_ids_events": ["old"]}
        events, last_run = fetch_events_for_log_type(
            client=mock_client,
            log_type=LogType.EVENTS,
            last_run=last_run,
            max_fetch=1000,
            cycle_start="2026-10-06T05:05:00.000000Z",
        )

        assert events == []
        assert last_run["last_fetch_events"] == "2026-10-06T05:00:00.000000Z"
        assert last_run["previous_ids_events"] == ["old"]

    def test_alerts_are_not_held_back(self, mock_client, mocker):
        from Halcyon import LogType, fetch_events_for_log_type

        response = {"data": [{"alertId": "alert-future", "firstOccurredAt": "2026-10-06T06:00:00.000Z"}]}
        mocker.patch.object(mock_client, "get_alerts", return_value=response)

        events, _ = fetch_events_for_log_type(
            client=mock_client,
            log_type=LogType.ALERTS,
            last_run={"last_fetch_alerts": "2026-10-06T05:00:00.000000Z"},
            max_fetch=1000,
            cycle_start="2026-10-06T05:05:00.000000Z",
        )

        assert [e["alertId"] for e in events] == ["alert-future"]


class TestFetchCursorDefects:
    """Reproduction tests for the reported duplication and missing-event defects.

    These tests exercise the real ``fetch_events_for_log_type`` cursor logic
    against a faithful fake of the Halcyon events API. They are written to FAIL
    on the current (buggy) implementation, documenting the exact mechanism, and
    to PASS once an overlap/lookback window + windowed dedup cache is introduced.
    """

    @freeze_time("2026-09-30T13:20:34Z")
    def test_backlog_larger_than_cap_causes_duplicate_reingestion(self, mock_client, mocker):
        """Backlog > max_fetch across many seconds must not re-ingest events.

        Mechanism under test: each cycle restarts pagination from page 1 with an
        INCLUSIVE ``occurredAfter`` watermark. When the backlog exceeds one capped
        cycle, the watermark advances only to the max timestamp of the truncated
        batch, and the narrow single-timestamp dedup (cleared on advance) cannot
        suppress the rows re-returned on the next cycle -> duplicates.

        Expected (correct behavior): every event ingested exactly once.
        """
        api = FakeHalcyonEventsApi()
        # 2500 events, each at a DISTINCT second (no >1000-per-second needed),
        # all present at enablement -> a backlog deeper than a single 1000 cap.
        for i in range(2500):
            # Spread across minutes/seconds so each has a unique occurredAt.
            minute = i // 60
            second = i % 60
            occurred_at = f"2026-09-30T13:{minute:02d}:{second:02d}.000Z"
            api.add_event(event_id=f"evt-{i}", occurred_at=occurred_at)

        ingested = _run_fetch_cycles(mock_client, mocker, api, num_cycles=5, max_fetch=1000)

        duplicated = {eid: n for eid, n in ingested.items() if n > 1}
        assert not duplicated, (
            f"{len(duplicated)} events were ingested more than once (duplication storm). "
            f"Example: {dict(list(duplicated.items())[:3])}"
        )

    @pytest.mark.xfail(reason="MISSING-events: no lookback; late events lost.")
    @freeze_time("2026-10-05T07:00:00Z")
    def test_late_arriving_event_behind_watermark_is_lost(self, mock_client, mocker):
        """A late-arriving event (older occurredAt, visible after watermark moved)
        must still be collected.

        Mechanism under test: once the watermark advances past second T, the
        collector only ever queries ``occurredAfter >= watermark`` and never looks
        back, so an event that becomes queryable later but carries an occurredAt
        behind the watermark is skipped permanently.

        This is a MISSING-events defect, separate from the duplication fix. Marked
        xfail until the lookback-window fix lands; flip to a hard assertion then.

        Expected (correct behavior): the late event is ingested exactly once.
        """
        api = FakeHalcyonEventsApi()
        # Cycle 0: two on-time events that advance the watermark to 07:00:05.
        api.add_event("on-time-a", "2026-10-05T07:00:03.000Z", visible_from_cycle=0)
        api.add_event("on-time-b", "2026-10-05T07:00:05.000Z", visible_from_cycle=0)
        # A later, higher-timestamp event in cycle 1 pushes the watermark further.
        api.add_event("on-time-c", "2026-10-05T07:00:09.000Z", visible_from_cycle=1)
        # The late arrival: occurredAt is BEHIND the advanced watermark, but it
        # only becomes queryable starting at cycle 2.
        api.add_event("late-x", "2026-10-05T07:00:04.000Z", visible_from_cycle=2)

        ingested = _run_fetch_cycles(mock_client, mocker, api, num_cycles=4, max_fetch=1000)

        assert ingested.get("late-x", 0) >= 1, (
            "Late-arriving event behind the watermark was never ingested (permanent loss). " f"Ingested counts: {dict(ingested)}"
        )

    @freeze_time("2026-10-05T07:00:00Z")
    def test_steady_state_single_event_not_duplicated(self, mock_client, mocker):
        """Steady-state sanity check that mirrors the live quiet-period logs.

        With one new event per cycle, the inclusive watermark re-returns the
        boundary event, and the single-timestamp dedup is expected to suppress it.
        This should already pass on the current code and documents the baseline
        behavior the live logs show (``Deduplicated events: 2 -> 1``).
        """
        api = FakeHalcyonEventsApi()
        api.add_event("steady-1", "2026-10-05T07:00:01.000Z", visible_from_cycle=0)
        api.add_event("steady-2", "2026-10-05T07:00:02.000Z", visible_from_cycle=1)
        api.add_event("steady-3", "2026-10-05T07:00:03.000Z", visible_from_cycle=2)

        ingested = _run_fetch_cycles(mock_client, mocker, api, num_cycles=4, max_fetch=1000)

        duplicated = {eid: n for eid, n in ingested.items() if n > 1}
        assert not duplicated, f"Steady-state events were duplicated: {duplicated}"
        assert set(ingested) == {"steady-1", "steady-2", "steady-3"}

    @freeze_time("2026-09-30T13:00:00Z")
    def test_over_cap_single_second_does_not_duplicate(self, mock_client, mocker):
        """THE storm condition: more than max_fetch events sharing ONE second.

        When a single ``occurredAt`` second holds more rows than ``max_fetch``, the
        capped batch cannot drain that second and the watermark cannot advance past
        it. The original defect re-ingested the same ~max_fetch batch every cycle
        (the ~9,590x enablement storm) because the dedup memory was cleared whenever
        the watermark failed to advance.

        After the duplicate fix (persisted, merged dedup IDs across non-advancing
        cycles + normalized timestamps), NO event is ingested more than once. This
        test asserts the duplication is gone.

        NOTE: this same-second-over-cap scenario ALSO starves the rows beyond the cap
        (they are never reached) - that is the separate MISSING-events defect, proven
        in ``test_over_cap_single_second_starves_rows_beyond_cap`` and not yet fixed.
        """
        api = FakeHalcyonEventsApi()
        # 1500 events ALL sharing the exact same occurredAt second, > max_fetch=1000.
        # The second is AFTER the frozen enablement "now" (13:00:00) so the initial
        # occurredAfter=now watermark does not filter the backlog out.
        same_second = "2026-09-30T13:05:00.000Z"
        for i in range(1500):
            api.add_event(event_id=f"burst-{i}", occurred_at=same_second)

        ingested = _run_fetch_cycles(mock_client, mocker, api, num_cycles=5, max_fetch=1000)

        over_ingested = {eid: n for eid, n in ingested.items() if n > 1}
        assert not over_ingested, (
            f"Duplication still occurring: {len(over_ingested)} ids re-ingested "
            f"(example: {dict(list(over_ingested.items())[:3])}). The duplicate fix "
            f"should ensure every event is ingested at most once."
        )

    @freeze_time("2026-09-30T13:00:00Z")
    def test_over_cap_single_second_starves_rows_beyond_cap(self, mock_client, mocker):
        """Rows beyond max_fetch at a single timestamp must eventually be ingested.

        With 1500 events sharing one occurredAt and max_fetch=1000, the old collector
        read the first 1000 and could never page to the remaining 500: it counted raw
        rows toward the cap and restarted pagination from page 1 each cycle, so the
        inclusive re-query kept re-reading the same head. Those 500 were lost.

        After the drain fix, deduplication happens DURING pagination and only NEW
        (previously unseen) events count toward max_fetch, so each cycle skips the
        already-ingested head and pages deeper to reach the tail. All 1500 are
        ingested exactly once across cycles.
        """
        api = FakeHalcyonEventsApi()
        same_second = "2026-09-30T13:05:00.000Z"
        for i in range(1500):
            api.add_event(event_id=f"burst-{i}", occurred_at=same_second)

        ingested = _run_fetch_cycles(mock_client, mocker, api, num_cycles=5, max_fetch=1000)

        assert len(ingested) == 1500, (
            f"Only {len(ingested)} of 1500 same-second events were ingested; "
            f"{1500 - len(ingested)} rows beyond the cap were starved (permanent loss)."
        )

    @freeze_time("2026-09-30T13:00:00Z")
    def test_second_straddling_cap_boundary_loses_tail_of_second(self, mock_client, mocker):
        """A second split by the max_fetch truncation loses its tail - at NORMAL volume.

        This reproduces the customer's dominant "28.4% of missing events share their
        exact second with an event we DID collect" signature, WITHOUT any 1000-event
        burst and WITHOUT late arrival.

        Setup: max_fetch=100. The backlog has events across distinct seconds, but the
        second at the cap boundary (``13:01:39``) holds several events that land at
        positions 99..104. The fetch loop truncates to exactly 100 (``all_events[:100]``),
        so the events at positions 100..104 - same second as position 99, which WAS
        collected - are dropped. The watermark then advances to that second and the
        dedup memory contains the boundary IDs, so on the next cycle the inclusive
        re-query returns those same-second rows but they are suppressed as "already
        seen"... except they were never actually ingested. They are lost permanently.

        Expected (correct behavior): all 105 events ingested exactly once.
        """
        api = FakeHalcyonEventsApi()
        # 95 events at distinct early seconds (positions 0..94).
        for i in range(95):
            api.add_event(event_id=f"early-{i}", occurred_at=f"2026-09-30T13:0{i // 60}:{i % 60:02d}.000Z")
        # 10 events ALL sharing one second (positions 95..104). max_fetch=100 cuts
        # this group at position 100, splitting the second across the cap boundary.
        boundary_second = "2026-09-30T13:05:00.000Z"
        for i in range(10):
            api.add_event(event_id=f"boundary-{i}", occurred_at=boundary_second)

        ingested = _run_fetch_cycles(mock_client, mocker, api, num_cycles=5, max_fetch=100)

        missing = [
            eid for eid in ([f"early-{i}" for i in range(95)] + [f"boundary-{i}" for i in range(10)]) if eid not in ingested
        ]
        assert not missing, (
            f"{len(missing)} events were never ingested (permanent loss at the cap-boundary second). "
            f"Missing sample: {missing[:5]}"
        )
