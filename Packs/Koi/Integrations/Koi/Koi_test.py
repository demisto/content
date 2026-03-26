import json
from pathlib import Path

import pytest
import demistomock as demisto
from CommonServerPython import *  # noqa


# region Test Data Loading
TEST_DATA_DIR = Path(__file__).parent / "test_data"


def load_test_data(filename: str) -> dict:
    """Load test data from a JSON file in the test_data directory."""
    with open(TEST_DATA_DIR / filename) as f:
        return json.load(f)


# endregion

# region Fixtures


@pytest.fixture
def alerts_response() -> dict:
    """Fixture for a mock alerts API response."""
    return load_test_data("alerts_response.json")


@pytest.fixture
def audit_response() -> dict:
    """Fixture for a mock audit logs API response."""
    return load_test_data("audit_response.json")


@pytest.fixture
def empty_response() -> dict:
    """Fixture for an empty API response."""
    return load_test_data("empty_response.json")


@pytest.fixture
def mock_client(mocker):
    """Fixture for a mocked Koi Client."""
    from Koi import Client

    mocker.patch.object(Client, "__init__", return_value=None)
    client = Client.__new__(Client)
    return client


# endregion

# region get_log_types_from_titles tests


class TestGetLogTypesFromTitles:
    """Tests for the get_log_types_from_titles helper function."""

    @pytest.mark.parametrize(
        "titles, expected_type_strings",
        [
            (["Alerts"], ["alerts"]),
            (["Audit"], ["audit"]),
            (["Alerts", "Audit"], ["alerts", "audit"]),
        ],
        ids=["alerts_only", "audit_only", "both_types"],
    )
    def test_valid_titles(self, titles: list[str], expected_type_strings: list[str]):
        """Test converting valid user-facing titles to LogType enum members."""
        from Koi import get_log_types_from_titles

        result = get_log_types_from_titles(titles)
        assert [lt.type_string for lt in result] == expected_type_strings

    @pytest.mark.parametrize(
        "titles",
        [
            (["InvalidType"]),
            (["Alerts", "BadType"]),
            ([""]),
        ],
        ids=["single_invalid", "mixed_invalid", "empty_string"],
    )
    def test_invalid_titles(self, titles: list[str]):
        """Test that invalid titles raise DemistoException."""
        from Koi import get_log_types_from_titles

        with pytest.raises(Exception, match="Invalid event type"):
            get_log_types_from_titles(titles)


# endregion

# region extract_time_from_event tests


class TestExtractTimeFromEvent:
    """Tests for the extract_time_from_event helper function."""

    def test_alert_event_with_epoch_ms(self):
        """Test extracting time from an alert event with epoch ms timestamp."""
        from Koi import extract_time_from_event, LogType

        event = {"finding_info": {"created_time": 1704067200000}}
        result = extract_time_from_event(event, LogType.ALERTS)
        assert result == "2024-01-01T00:00:00Z"

    def test_audit_event_with_iso_string(self):
        """Test extracting time from an audit event with ISO 8601 string."""
        from Koi import extract_time_from_event, LogType

        event = {"created_at": "2024-01-01T00:00:00Z"}
        result = extract_time_from_event(event, LogType.AUDIT)
        assert result == "2024-01-01T00:00:00Z"

    @pytest.mark.parametrize(
        "event, log_type_name",
        [
            ({}, "ALERTS"),
            ({"finding_info": {}}, "ALERTS"),
            ({}, "AUDIT"),
        ],
        ids=["empty_alert", "missing_created_time", "empty_audit"],
    )
    def test_missing_time_field(self, event: dict, log_type_name: str):
        """Test extracting time when the field is missing returns None."""
        from Koi import extract_time_from_event, LogType

        log_type = LogType[log_type_name]
        result = extract_time_from_event(event, log_type)
        assert result is None


# endregion

# region add_time_to_events tests


class TestAddTimeToEvents:
    """Tests for the add_time_to_events helper function."""

    def test_alert_events(self):
        """Test enriching alert events with _time and source_log_type."""
        from Koi import add_time_to_events, LogType

        events = [{"id": "alert-001", "finding_info": {"created_time": 1704067200000}}]
        add_time_to_events(events, LogType.ALERTS)

        assert events[0]["_time"] == "1704067200000"
        assert events[0]["source_log_type"] == "Alerts"

    def test_audit_events(self):
        """Test enriching audit events with _time and source_log_type."""
        from Koi import add_time_to_events, LogType

        events = [{"id": "audit-001", "created_at": "2024-01-01T00:00:00Z"}]
        add_time_to_events(events, LogType.AUDIT)

        assert events[0]["_time"] == "2024-01-01T00:00:00Z"
        assert events[0]["source_log_type"] == "Audit"

    def test_missing_time_field(self):
        """Test enriching events when time field is missing still sets source_log_type."""
        from Koi import add_time_to_events, LogType

        events = [{"id": "audit-001"}]
        add_time_to_events(events, LogType.AUDIT)

        assert "_time" not in events[0]
        assert events[0]["source_log_type"] == "Audit"


# endregion

# region get_event_id tests


class TestGetEventId:
    """Tests for the get_event_id helper function."""

    @pytest.mark.parametrize(
        "event, expected_id",
        [
            ({"id": "123"}, "123"),
            ({"alert_id": "456"}, "456"),
            ({"log_id": "789"}, "789"),
            ({"uuid": "abc"}, "abc"),
            ({"id": 42}, "42"),
        ],
        ids=["id_field", "alert_id_field", "log_id_field", "uuid_field", "numeric_id"],
    )
    def test_valid_id_fields(self, event: dict, expected_id: str):
        """Test extracting event ID from various field names."""
        from Koi import get_event_id

        assert get_event_id(event) == expected_id

    def test_no_id_field(self):
        """Test that missing ID field returns None."""
        from Koi import get_event_id

        assert get_event_id({}) is None
        assert get_event_id({"name": "test"}) is None


# endregion

# region deduplicate_events tests


class TestDeduplicateEvents:
    """Tests for the deduplicate_events helper function."""

    def test_no_previous_ids(self):
        """Test deduplication with no previous run IDs returns all events."""
        from Koi import deduplicate_events

        events = [
            {"id": "1", "created_at": "2024-01-01T00:00:00Z"},
            {"id": "2", "created_at": "2024-01-01T00:01:00Z"},
        ]

        result = deduplicate_events(events, last_fetched_ids=[])
        assert len(result) == 2

    def test_with_duplicates(self):
        """Test deduplication removes previously seen events."""
        from Koi import deduplicate_events

        events = [
            {"id": "1", "created_at": "2024-01-01T00:00:00Z"},
            {"id": "2", "created_at": "2024-01-01T00:00:00Z"},
            {"id": "3", "created_at": "2024-01-01T00:01:00Z"},
        ]

        result = deduplicate_events(events, last_fetched_ids=["1"])
        assert len(result) == 2
        assert all(e["id"] != "1" for e in result)

    def test_all_duplicates(self):
        """Test deduplication when all events are duplicates."""
        from Koi import deduplicate_events

        events = [
            {"id": "1", "created_at": "2024-01-01T00:00:00Z"},
            {"id": "2", "created_at": "2024-01-01T00:00:00Z"},
        ]

        result = deduplicate_events(events, last_fetched_ids=["1", "2"])
        assert len(result) == 0

    def test_empty_events(self):
        """Test deduplication with empty events list."""
        from Koi import deduplicate_events

        result = deduplicate_events([], last_fetched_ids=["1"])
        assert len(result) == 0


# endregion

# region Client tests


class TestClient:
    """Tests for the Client class methods."""

    def test_get_events_page_alerts(self, mock_client, alerts_response, mocker):
        """Test fetching a page of alerts."""
        from Koi import LogType

        mocker.patch.object(mock_client, "_http_request", return_value=alerts_response)

        events = mock_client.get_events_page(
            log_type=LogType.ALERTS,
            created_at_gte="2024-01-01T00:00:00Z",
            page=1,
            page_size=100,
        )

        assert len(events) == 2
        assert events[0]["id"] == "alert-001"

    def test_get_events_page_audit(self, mock_client, audit_response, mocker):
        """Test fetching a page of audit logs."""
        from Koi import LogType

        mocker.patch.object(mock_client, "_http_request", return_value=audit_response)

        events = mock_client.get_events_page(
            log_type=LogType.AUDIT,
            created_at_gte="2024-01-01T00:00:00Z",
            page=1,
            page_size=100,
            audit_types=["policies", "settings"],
        )

        assert len(events) == 2
        assert events[0]["id"] == "audit-001"

    def test_get_events_page_empty(self, mock_client, empty_response, mocker):
        """Test fetching when no events are returned."""
        from Koi import LogType

        mocker.patch.object(mock_client, "_http_request", return_value=empty_response)

        events = mock_client.get_events_page(
            log_type=LogType.ALERTS,
            page=1,
            page_size=100,
        )

        assert len(events) == 0


# endregion

# region fetch_events_with_pagination tests


class TestFetchEventsWithPagination:
    """Tests for the fetch_events_with_pagination function."""

    def test_single_page(self, mock_client, alerts_response, mocker):
        """Test fetching events that fit in a single page."""
        from Koi import fetch_events_with_pagination, LogType

        mocker.patch.object(mock_client, "get_events_page", return_value=alerts_response["data"])

        events = fetch_events_with_pagination(
            mock_client,
            log_type=LogType.ALERTS,
            created_after="2024-01-01T00:00:00Z",
            max_events=100,
        )

        assert len(events) == 2

    def test_multiple_pages(self, mock_client, mocker):
        """Test fetching events across multiple pages."""
        from Koi import fetch_events_with_pagination, LogType, Config

        # page_size = min(MAX_PAGE_SIZE, max_events) = min(500, 1000) = 500
        # page1 must have exactly page_size items to trigger next page fetch
        page_size = Config.MAX_PAGE_SIZE
        page1 = [{"id": f"event-{i}", "created_at": f"2024-01-01T00:{i:02d}:00Z"} for i in range(page_size)]
        page2 = [{"id": f"event-{i}", "created_at": f"2024-01-01T01:{i:02d}:00Z"} for i in range(3)]

        mocker.patch.object(mock_client, "get_events_page", side_effect=[page1, page2])

        events = fetch_events_with_pagination(
            mock_client,
            log_type=LogType.AUDIT,
            created_after="2024-01-01T00:00:00Z",
            max_events=1000,
        )

        assert len(events) == page_size + 3

    def test_empty_response(self, mock_client, mocker):
        """Test fetching when API returns no events."""
        from Koi import fetch_events_with_pagination, LogType

        mocker.patch.object(mock_client, "get_events_page", return_value=[])

        events = fetch_events_with_pagination(
            mock_client,
            log_type=LogType.ALERTS,
            created_after="2024-01-01T00:00:00Z",
            max_events=100,
        )

        assert len(events) == 0

    def test_max_events_limit(self, mock_client, mocker):
        """Test that max_events limit is respected."""
        from Koi import fetch_events_with_pagination, LogType

        large_page = [{"id": f"event-{i}", "created_at": f"2024-01-01T00:00:{i:02d}Z"} for i in range(500)]
        mocker.patch.object(mock_client, "get_events_page", return_value=large_page)

        events = fetch_events_with_pagination(
            mock_client,
            log_type=LogType.AUDIT,
            created_after="2024-01-01T00:00:00Z",
            max_events=10,
        )

        assert len(events) == 10


# endregion

# region Command tests


class TestTestModule:
    """Tests for the test_module command."""

    def test_success(self, mock_client, mocker):
        """Test successful test-module."""
        from Koi import test_module

        mocker.patch.object(mock_client, "get_events_page", return_value=[{"id": "1"}])

        result = test_module(mock_client)
        assert result == "ok"

    def test_auth_failure(self, mock_client, mocker):
        """Test test-module with authentication failure."""
        from Koi import test_module

        mocker.patch.object(mock_client, "get_events_page", side_effect=Exception("401 Unauthorized"))

        result = test_module(mock_client)
        assert "Authorization Error" in result


class TestGetEventsCommand:
    """Tests for the koi-get-events command."""

    def test_get_events_alerts_and_audit(self, mock_client, alerts_response, audit_response, mocker):
        """Test get-events command fetching both alerts and audit logs."""
        from Koi import get_events_command

        mocker.patch.object(
            mock_client,
            "get_events_page",
            side_effect=[alerts_response["data"], audit_response["data"]],
        )

        args = {"limit": "50", "should_push_events": "false"}
        params = {"event_types_to_fetch": "Alerts,Audit"}

        result = get_events_command(mock_client, args, params)

        assert not isinstance(result, str)
        assert "Koi Event Collector Events" in result.readable_output  # type: ignore[union-attr]

    def test_get_events_push_to_xsiam(self, mock_client, alerts_response, mocker):
        """Test get-events command with push to XSIAM."""
        from Koi import get_events_command

        mocker.patch.object(mock_client, "get_events_page", return_value=alerts_response["data"])
        mock_send = mocker.patch("Koi.send_events_to_xsiam")

        args = {"limit": "50", "should_push_events": "true", "event_type": "Alerts"}
        params = {"event_types_to_fetch": "Alerts"}

        result = get_events_command(mock_client, args, params)

        assert isinstance(result, str)
        assert "Successfully retrieved and pushed" in result
        mock_send.assert_called_once()


class TestFetchEventsCommand:
    """Tests for the fetch-events command."""

    def test_first_run(self, mock_client, alerts_response, audit_response, mocker):
        """Test fetch-events on first run (no last_run state)."""
        from Koi import fetch_events_command

        mocker.patch.object(
            mock_client,
            "get_events_page",
            side_effect=[alerts_response["data"], audit_response["data"]],
        )
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "max_fetch": "5000",
                "event_types_to_fetch": "Alerts,Audit",
            },
        )
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mock_send = mocker.patch("Koi.send_events_to_xsiam")
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")

        fetch_events_command(mock_client)

        mock_send.assert_called_once()
        mock_set_last_run.assert_called_once()

        # Verify last_run contains state for both log types
        last_run_arg = mock_set_last_run.call_args[0][0]
        assert "last_fetch_alerts" in last_run_arg
        assert "last_fetch_audit" in last_run_arg

    def test_subsequent_run_with_dedup(self, mock_client, alerts_response, mocker):
        """Test fetch-events on subsequent run with deduplication."""
        from Koi import fetch_events_command

        mocker.patch.object(mock_client, "get_events_page", return_value=alerts_response["data"])
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "max_fetch": "5000",
                "event_types_to_fetch": "Alerts",
            },
        )
        mocker.patch.object(
            demisto,
            "getLastRun",
            return_value={
                "last_fetch_alerts": "2024-01-01T00:00:00Z",
                "previous_ids_alerts": ["alert-001"],
            },
        )
        mock_send = mocker.patch("Koi.send_events_to_xsiam")
        mocker.patch.object(demisto, "setLastRun")

        fetch_events_command(mock_client)

        # Should have sent only 1 event (alert-002, since alert-001 is deduped)
        mock_send.assert_called_once()
        sent_events = mock_send.call_args[1]["events"]
        assert len(sent_events) == 1
        assert sent_events[0]["id"] == "alert-002"

    def test_no_events(self, mock_client, mocker):
        """Test fetch-events when no events are returned."""
        from Koi import fetch_events_command

        mocker.patch.object(mock_client, "get_events_page", return_value=[])
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "max_fetch": "5000",
                "event_types_to_fetch": "Alerts",
            },
        )
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mock_send = mocker.patch("Koi.send_events_to_xsiam")
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")

        fetch_events_command(mock_client)

        mock_send.assert_not_called()
        mock_set_last_run.assert_called_once()


# endregion

# region Config and constants tests


class TestConfig:
    """Tests for configuration constants."""

    def test_valid_audit_types(self):
        """Test that VALID_AUDIT_TYPES contains all expected types."""
        from Koi import VALID_AUDIT_TYPES

        expected = [
            "approval_requests",
            "devices",
            "endpoints",
            "extensions",
            "firewall",
            "guardrails",
            "notifications",
            "policies",
            "remediation",
            "requests",
            "settings",
            "vetting",
        ]
        assert expected == VALID_AUDIT_TYPES

    def test_config_values(self):
        """Test that Config class has expected default values."""
        from Koi import Config

        assert Config.VENDOR == "koi"
        assert Config.PRODUCT == "koi"
        assert Config.MAX_PAGE_SIZE == 500
        assert Config.DEFAULT_MAX_FETCH == 5000
        assert Config.MAX_PAGES_PER_FETCH == 10
        assert Config.DEFAULT_FROM_TIME == "5 minutes ago"


# endregion
