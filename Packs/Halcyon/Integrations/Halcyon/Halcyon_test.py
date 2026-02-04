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
        verify=False,
        proxy=False,
        max_fetch_alerts=1000,
        max_fetch_events=1000,
    )

    # Set required attributes that would be set by ContentClient.__init__
    client._base_url = "https://api.halcyon.ai"
    client._verify = False
    client.max_fetch_alerts = 1000
    client.max_fetch_events = 1000

    return client


class TestHalcyonAuthHandler:
    """Test cases for the HalcyonAuthHandler class."""

    def test_auth_handler_requires_username(self, mocker):
        """Test that auth handler requires a username."""
        from Halcyon import HalcyonAuthHandler
        from ContentClientApiModule import ContentClientAuthenticationError

        mocker.patch("Halcyon.ContentClientContextStore")

        with pytest.raises(ContentClientAuthenticationError, match="non-empty username"):
            HalcyonAuthHandler(username="", password="test_password")

    def test_auth_handler_requires_password(self, mocker):
        """Test that auth handler requires a password."""
        from Halcyon import HalcyonAuthHandler
        from ContentClientApiModule import ContentClientAuthenticationError

        mocker.patch("Halcyon.ContentClientContextStore")

        with pytest.raises(ContentClientAuthenticationError, match="non-empty password"):
            HalcyonAuthHandler(username="test_user", password="")


class TestClient:
    """Test cases for the Client class."""

    def test_get_alerts(self, mock_client, mocker):
        """Test fetching alerts."""
        mock_response = {
            "data": [
                {
                    "alertId": "alert-1",
                    "lastOccurredAt": "2024-01-01T00:00:00.000Z",
                    "kind": "ThreatDetection",
                },
                {
                    "alertId": "alert-2",
                    "lastOccurredAt": "2024-01-01T01:00:00.000Z",
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
                "lastOccurredAt": "2024-01-01T00:00:00.000Z",
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
            {"alertId": "alert-1", "lastOccurredAt": "2024-01-01T00:00:00.000Z"},
            {"alertId": "alert-2", "lastOccurredAt": "2024-01-01T01:00:00.000Z"},
            {"alertId": "alert-3", "lastOccurredAt": "2024-01-01T02:00:00.000Z"},
        ]
        previous_run_ids = {"alert-1"}

        unique_events, new_ids, last_timestamp = deduplicate_events(
            events=events,
            previous_run_ids=previous_run_ids,
            log_type=LogType.ALERTS,
        )

        assert len(unique_events) == 2
        assert "alert-2" in new_ids
        assert "alert-3" in new_ids
        assert "alert-1" not in new_ids
        assert last_timestamp == "2024-01-01T02:00:00.000Z"

    def test_deduplicate_events_all_new(self):
        """Test deduplicating when all events are new."""
        from Halcyon import deduplicate_events, LogType

        events = [
            {"alertId": "alert-1", "lastOccurredAt": "2024-01-01T00:00:00.000Z"},
            {"alertId": "alert-2", "lastOccurredAt": "2024-01-01T01:00:00.000Z"},
        ]
        previous_run_ids: set = set()

        unique_events, new_ids, last_timestamp = deduplicate_events(
            events=events,
            previous_run_ids=previous_run_ids,
            log_type=LogType.ALERTS,
        )

        assert len(unique_events) == 2
        assert len(new_ids) == 2

    def test_deduplicate_events_all_duplicates(self):
        """Test deduplicating when all events are duplicates."""
        from Halcyon import deduplicate_events, LogType

        events = [
            {"alertId": "alert-1", "lastOccurredAt": "2024-01-01T00:00:00.000Z"},
            {"alertId": "alert-2", "lastOccurredAt": "2024-01-01T01:00:00.000Z"},
        ]
        previous_run_ids = {"alert-1", "alert-2"}

        unique_events, new_ids, last_timestamp = deduplicate_events(
            events=events,
            previous_run_ids=previous_run_ids,
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
        from Halcyon import get_events_command, LogType

        mock_alerts_response = {
            "data": [
                {"alertId": "alert-1", "lastOccurredAt": "2024-01-01T00:00:00.000Z"},
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
            args={"limit": "10"},
            log_types=[LogType.ALERTS, LogType.EVENTS],
        )

        assert len(events) == 2
        assert any(e.get("alertId") == "alert-1" for e in events)
        assert any(e.get("eventId") == "event-1" for e in events)

    def test_get_events_command_with_time_args(self, mock_client, mocker):
        """Test get-events command with time arguments."""
        from Halcyon import get_events_command, LogType

        mock_response = {"data": []}

        mocker.patch.object(mock_client, "get_alerts", return_value=mock_response)
        mocker.patch.object(mock_client, "get_events", return_value=mock_response)

        events, results = get_events_command(
            client=mock_client,
            args={
                "limit": "10",
                "start_time": "2024-01-01T00:00:00Z",
                "end_time": "2024-01-02T00:00:00Z",
            },
            log_types=[LogType.ALERTS],
        )

        assert len(events) == 0

    @freeze_time("2024-01-01T12:00:00Z")
    def test_fetch_events_command(self, mock_client, mocker):
        """Test fetch-events command."""
        from Halcyon import fetch_events_command, LogType

        mock_alerts_response = {
            "data": [
                {"alertId": "alert-1", "lastOccurredAt": "2024-01-01T10:00:00.000Z"},
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
            max_fetch_alerts=1000,
            max_fetch_events=1000,
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
                {"alertId": "alert-2", "lastOccurredAt": "2024-01-01T11:00:00.000Z"},
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
            max_fetch_alerts=1000,
            max_fetch_events=1000,
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
            max_fetch_alerts=1000,
            max_fetch_events=1000,
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
            "data": [{"alertId": f"alert-{i}", "lastOccurredAt": f"2024-01-01T{i:02d}:00:00.000Z"} for i in range(100)]
        }
        page2_response = {
            "data": [{"alertId": f"alert-{i}", "lastOccurredAt": f"2024-01-01T{i:02d}:00:00.000Z"} for i in range(100, 150)]
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
        response = {
            "data": [{"alertId": f"alert-{i}", "lastOccurredAt": f"2024-01-01T{i:02d}:00:00.000Z"} for i in range(100)]
        }

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
        assert LogType.ALERTS.time_field == "lastOccurredAt"

    def test_events_log_type(self):
        """Test EVENTS log type properties."""
        from Halcyon import LogType

        assert LogType.EVENTS.type_string == "events"
        assert LogType.EVENTS.title == "Events"
        assert LogType.EVENTS.api_endpoint == "/v2/events"
        assert LogType.EVENTS.time_field == "occurredAt"
