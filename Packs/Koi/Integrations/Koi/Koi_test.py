import json
from datetime import datetime
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

    @pytest.mark.parametrize(
        "events, log_type_name, expected_time, expected_source",
        [
            (
                [{"id": "alert-001", "finding_info": {"created_time": 1704067200000}}],
                "ALERTS",
                "2024-01-01T00:00:00Z",
                "Alerts",
            ),
            (
                [{"id": "audit-001", "created_at": "2024-01-01T00:00:00Z"}],
                "AUDIT",
                "2024-01-01T00:00:00Z",
                "Audit",
            ),
        ],
        ids=["alert_events", "audit_events"],
    )
    def test_events_with_time(self, events, log_type_name, expected_time, expected_source):
        """Test enriching events with _time and source_log_type."""
        from Koi import add_time_to_events, LogType

        log_type = LogType[log_type_name]
        add_time_to_events(events, log_type)

        assert events[0]["_time"] == expected_time
        assert events[0]["source_log_type"] == expected_source

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

    @pytest.mark.parametrize(
        "events, last_ids, expected_count",
        [
            (
                [{"id": "1"}, {"id": "2"}],
                [],
                2,
            ),
            (
                [{"id": "1"}, {"id": "2"}, {"id": "3"}],
                ["1"],
                2,
            ),
            (
                [{"id": "1"}, {"id": "2"}],
                ["1", "2"],
                0,
            ),
            (
                [],
                ["1"],
                0,
            ),
        ],
        ids=["no_previous_ids", "with_duplicates", "all_duplicates", "empty_events"],
    )
    def test_deduplication(self, events: list, last_ids: list, expected_count: int):
        """Test deduplication with various scenarios."""
        from Koi import deduplicate_events

        result = deduplicate_events(events, last_fetched_ids=last_ids)
        assert len(result) == expected_count

    def test_no_duplicates_found(self):
        """Test dedup when none of the events match previous IDs (covers line 237)."""
        from Koi import deduplicate_events

        events = [{"id": "3"}, {"id": "4"}]
        result = deduplicate_events(events, last_fetched_ids=["1", "2"])
        assert len(result) == 2


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

    def test_get_events_page_with_created_at_lte(self, mock_client, alerts_response, mocker):
        """Test fetching events with created_at_lte parameter (covers line 322)."""
        from Koi import LogType

        mocker.patch.object(mock_client, "_http_request", return_value=alerts_response)

        events = mock_client.get_events_page(
            log_type=LogType.ALERTS,
            created_at_gte="2024-01-01T00:00:00Z",
            created_at_lte="2024-01-02T00:00:00Z",
            page=1,
            page_size=100,
        )

        assert len(events) == 2
        # Verify created_at_lte was passed in params
        call_kwargs = mock_client._http_request.call_args[1]
        assert call_kwargs["params"]["created_at_lte"] == "2024-01-02T00:00:00Z"

    def test_sort_direction_asc_alerts(self, mock_client, alerts_response, mocker):
        """Test that sort_direction=asc is passed to the API for alerts."""
        from Koi import LogType, Config

        mocker.patch.object(mock_client, "_http_request", return_value=alerts_response)

        mock_client.get_events_page(
            log_type=LogType.ALERTS,
            created_at_gte="2024-01-01T00:00:00Z",
            page=1,
            page_size=100,
        )

        call_kwargs = mock_client._http_request.call_args[1]
        assert call_kwargs["params"]["sort_direction"] == Config.SORT_DIRECTION

    def test_sort_direction_asc_audit(self, mock_client, audit_response, mocker):
        """Test that sort_direction=asc is passed to the API for audit logs."""
        from Koi import LogType, Config

        mocker.patch.object(mock_client, "_http_request", return_value=audit_response)

        mock_client.get_events_page(
            log_type=LogType.AUDIT,
            created_at_gte="2024-01-01T00:00:00Z",
            page=1,
            page_size=100,
        )

        call_kwargs = mock_client._http_request.call_args[1]
        assert call_kwargs["params"]["sort_direction"] == Config.SORT_DIRECTION

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

        mocker.patch.object(mock_client, "get_events_page", return_value=alerts_response["alerts"])

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

    def test_max_pages_limit(self, mock_client, mocker):
        """Test pagination stops at MAX_PAGES_PER_FETCH (covers lines 438-439)."""
        from Koi import fetch_events_with_pagination, LogType, Config

        page_size = Config.MAX_PAGE_SIZE
        # Return full pages every time to force pagination to continue
        full_page = [{"id": f"event-{i}", "created_at": f"2024-01-01T00:00:{i:02d}Z"} for i in range(page_size)]
        mocker.patch.object(mock_client, "get_events_page", return_value=full_page)

        fetch_events_with_pagination(
            mock_client,
            log_type=LogType.AUDIT,
            created_after="2024-01-01T00:00:00Z",
            max_events=999999,  # Very high limit so pages limit is hit first
        )

        # Should have fetched MAX_PAGES_PER_FETCH pages
        assert mock_client.get_events_page.call_count == Config.MAX_PAGES_PER_FETCH


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

    def test_non_auth_failure_reraises(self, mock_client, mocker):
        """Test test-module re-raises non-auth errors (covers line 378)."""
        from Koi import test_module

        mocker.patch.object(mock_client, "get_events_page", side_effect=Exception("Connection timeout"))

        with pytest.raises(Exception, match="Connection timeout"):
            test_module(mock_client)


class TestGetEventsCommand:
    """Tests for the koi-get-events command."""

    def test_get_events_alerts_and_audit(self, mock_client, alerts_response, audit_response, mocker):
        """Test get-events command fetching both alerts and audit logs."""
        from Koi import get_events_command

        mocker.patch.object(
            mock_client,
            "get_events_page",
            side_effect=[alerts_response["alerts"], audit_response["data"]],
        )

        args = {"limit": "50", "should_push_events": "false"}
        params = {"event_types_to_fetch": "Alerts,Audit"}

        result = get_events_command(mock_client, args, params)

        assert not isinstance(result, str)
        assert "KOI Events" in result.readable_output  # type: ignore[union-attr]

    def test_get_events_push_to_xsiam(self, mock_client, alerts_response, mocker):
        """Test get-events command with push to XSIAM."""
        from Koi import get_events_command

        mocker.patch.object(mock_client, "get_events_page", return_value=alerts_response["alerts"])
        mock_send = mocker.patch.object(mock_client, "send_events")

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
        from Koi import fetch_events_command, LogType

        def side_effect_get_events_page(**kwargs):
            log_type = kwargs.get("log_type")
            if log_type == LogType.ALERTS:
                return alerts_response["alerts"]
            return audit_response["data"]

        mocker.patch.object(mock_client, "get_events_page", side_effect=side_effect_get_events_page)
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "max_fetch": "5000",
                "event_types_to_fetch": "Alerts,Audit",
            },
        )
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mock_send = mocker.patch.object(mock_client, "send_events")
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

        mocker.patch.object(mock_client, "get_events_page", return_value=alerts_response["alerts"])
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
        mock_send = mocker.patch.object(mock_client, "send_events")
        mocker.patch.object(demisto, "setLastRun")

        fetch_events_command(mock_client)

        # Should have sent only 1 event (alert-002, since alert-001 is deduped)
        mock_send.assert_called_once()
        sent_events = mock_send.call_args[0][0]
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
        mock_send = mocker.patch.object(mock_client, "send_events")
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")

        fetch_events_command(mock_client)

        mock_send.assert_not_called()
        mock_set_last_run.assert_called_once()

    def test_all_events_are_duplicates(self, mock_client, alerts_response, mocker):
        """Test fetch-events when all returned events are duplicates (covers line 578)."""
        from Koi import fetch_events_command

        mocker.patch.object(mock_client, "get_events_page", return_value=alerts_response["alerts"])
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
                "previous_ids_alerts": ["alert-001", "alert-002"],
            },
        )
        mock_send = mocker.patch.object(mock_client, "send_events")
        mocker.patch.object(demisto, "setLastRun")

        fetch_events_command(mock_client)

        mock_send.assert_not_called()

    def test_hwm_timestamp_unchanged_merges_ids(self, mock_client, mocker):
        """Test that when HWM timestamp hasn't changed, IDs are merged (covers line 594)."""
        from Koi import fetch_events_command

        # Events with same timestamp as last_fetch
        events = [
            {"id": "alert-003", "finding_info": {"created_time": 1704067200000}},
        ]
        mocker.patch.object(mock_client, "get_events_page", return_value=events)
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
        mocker.patch.object(mock_client, "send_events")
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")

        fetch_events_command(mock_client)

        # Verify IDs were merged
        last_run_arg = mock_set_last_run.call_args[0][0]
        previous_ids = last_run_arg["previous_ids_alerts"]
        assert "alert-001" in previous_ids
        assert "alert-003" in previous_ids

    def test_last_event_missing_time(self, mock_client, mocker):
        """Test fetch-events when last event has no time field (covers line 600)."""
        from Koi import fetch_events_command

        # Audit event without created_at
        events = [{"id": "audit-no-time"}]
        mocker.patch.object(mock_client, "get_events_page", return_value=events)
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "max_fetch": "5000",
                "event_types_to_fetch": "Audit",
            },
        )
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mocker.patch.object(mock_client, "send_events")
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")

        fetch_events_command(mock_client)

        # Event should still be sent (it's new), but last_run should not have audit timestamp
        last_run_arg = mock_set_last_run.call_args[0][0]
        assert "last_fetch_audit" not in last_run_arg

    def test_alerts_failure_does_not_block_audit(self, mock_client, audit_response, mocker):
        """Test that if alerts fetching fails, audit logs are still fetched and sent."""
        from Koi import fetch_events_command, LogType

        # Alerts raises an exception, audit returns data
        def side_effect_get_events_page(**kwargs):
            if kwargs.get("log_type") == LogType.ALERTS:
                raise Exception("API timeout for alerts")
            return audit_response["data"]

        mocker.patch.object(mock_client, "get_events_page", side_effect=side_effect_get_events_page)
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "max_fetch": "5000",
                "event_types_to_fetch": "Alerts,Audit",
            },
        )
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mock_send = mocker.patch.object(mock_client, "send_events")
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")

        fetch_events_command(mock_client)

        # Audit events should still be sent despite alerts failure
        mock_send.assert_called_once()
        sent_events = mock_send.call_args[0][0]
        assert len(sent_events) == 2
        assert all(e.get("source_log_type") == "Audit" for e in sent_events)

        # Last run should have audit state but no alerts state
        last_run_arg = mock_set_last_run.call_args[0][0]
        assert "last_fetch_audit" in last_run_arg
        assert "last_fetch_alerts" not in last_run_arg

    def test_audit_failure_does_not_block_alerts(self, mock_client, alerts_response, mocker):
        """Test that if audit fetching fails, alerts are still fetched and sent."""
        from Koi import fetch_events_command, LogType

        # Alerts returns data, audit raises an exception
        def side_effect_get_events_page(**kwargs):
            if kwargs.get("log_type") == LogType.AUDIT:
                raise Exception("API timeout for audit")
            return alerts_response["alerts"]

        mocker.patch.object(mock_client, "get_events_page", side_effect=side_effect_get_events_page)
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "max_fetch": "5000",
                "event_types_to_fetch": "Alerts,Audit",
            },
        )
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mock_send = mocker.patch.object(mock_client, "send_events")
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")

        fetch_events_command(mock_client)

        # Alerts events should still be sent despite audit failure
        mock_send.assert_called_once()
        sent_events = mock_send.call_args[0][0]
        assert len(sent_events) == 2
        assert all(e.get("source_log_type") == "Alerts" for e in sent_events)

        # Last run should have alerts state but no audit state
        last_run_arg = mock_set_last_run.call_args[0][0]
        assert "last_fetch_alerts" in last_run_arg
        assert "last_fetch_audit" not in last_run_arg


class TestLastRunState:
    """Parametrized tests for last_run state management across all scenarios."""

    @pytest.mark.parametrize(
        "description, event_types, initial_last_run, alert_events, audit_events, "
        "expected_last_run_keys, expected_missing_keys, expected_event_count",
        [
            (
                "first_run_both_types",
                "Alerts,Audit",
                {},
                [{"id": "a1", "finding_info": {"created_time": 1704067200000}}],
                [{"id": "au1", "created_at": "2024-01-01T00:00:00Z"}],
                ["last_fetch_alerts", "previous_ids_alerts", "last_fetch_audit", "previous_ids_audit"],
                [],
                2,
            ),
            (
                "first_run_alerts_only",
                "Alerts",
                {},
                [{"id": "a1", "finding_info": {"created_time": 1704067200000}}],
                [],
                ["last_fetch_alerts", "previous_ids_alerts"],
                ["last_fetch_audit"],
                1,
            ),
            (
                "first_run_audit_only",
                "Audit",
                {},
                [],
                [{"id": "au1", "created_at": "2024-01-01T00:00:00Z"}],
                ["last_fetch_audit", "previous_ids_audit"],
                ["last_fetch_alerts"],
                1,
            ),
            (
                "subsequent_run_preserves_existing_state",
                "Alerts",
                {
                    "last_fetch_alerts": "2024-01-01T00:00:00Z",
                    "previous_ids_alerts": ["old-id"],
                    "last_fetch_audit": "2024-01-01T00:00:00Z",
                    "previous_ids_audit": ["old-audit-id"],
                },
                [{"id": "a2", "finding_info": {"created_time": 1704067260000}}],
                [],
                ["last_fetch_alerts", "previous_ids_alerts", "last_fetch_audit", "previous_ids_audit"],
                [],
                1,
            ),
            (
                "no_events_preserves_state",
                "Alerts,Audit",
                {
                    "last_fetch_alerts": "2024-01-01T00:00:00Z",
                    "previous_ids_alerts": ["existing-id"],
                },
                [],
                [],
                ["last_fetch_alerts", "previous_ids_alerts"],
                [],
                0,
            ),
            (
                "hwm_unchanged_merges_ids",
                "Alerts",
                {
                    "last_fetch_alerts": "2024-01-01T00:00:00Z",
                    "previous_ids_alerts": ["a1"],
                },
                [
                    {"id": "a1", "finding_info": {"created_time": 1704067200000}},
                    {"id": "a2", "finding_info": {"created_time": 1704067200000}},
                ],
                [],
                ["last_fetch_alerts", "previous_ids_alerts"],
                [],
                1,
            ),
        ],
        ids=[
            "first_run_both_types",
            "first_run_alerts_only",
            "first_run_audit_only",
            "subsequent_run_preserves_existing_state",
            "no_events_preserves_state",
            "hwm_unchanged_merges_ids",
        ],
    )
    def test_last_run_state(
        self,
        mock_client,
        mocker,
        description: str,
        event_types: str,
        initial_last_run: dict,
        alert_events: list,
        audit_events: list,
        expected_last_run_keys: list,
        expected_missing_keys: list,
        expected_event_count: int,
    ):
        """Parametrized test for last_run state management across all scenarios."""
        from Koi import fetch_events_command, LogType

        def side_effect_get_events_page(**kwargs):
            log_type = kwargs.get("log_type")
            if log_type == LogType.ALERTS:
                return alert_events
            return audit_events

        mocker.patch.object(mock_client, "get_events_page", side_effect=side_effect_get_events_page)
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "max_fetch": "5000",
                "event_types_to_fetch": event_types,
            },
        )
        mocker.patch.object(demisto, "getLastRun", return_value=initial_last_run)
        mock_send = mocker.patch.object(mock_client, "send_events")
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")

        fetch_events_command(mock_client)

        # Verify setLastRun was called exactly once (single write, no race condition)
        mock_set_last_run.assert_called_once()
        last_run_arg = mock_set_last_run.call_args[0][0]

        # Verify expected keys are present
        for key in expected_last_run_keys:
            assert key in last_run_arg, f"Expected key '{key}' missing from last_run: {last_run_arg}"

        # Verify expected missing keys are absent
        for key in expected_missing_keys:
            assert key not in last_run_arg, f"Unexpected key '{key}' found in last_run: {last_run_arg}"

        # Verify event count
        if expected_event_count > 0:
            mock_send.assert_called_once()
            assert len(mock_send.call_args[0][0]) == expected_event_count
        else:
            mock_send.assert_not_called()

    def test_last_run_ids_stored_per_type(self, mock_client, mocker):
        """Test that IDs are stored independently per event type in last_run."""
        from Koi import fetch_events_command, LogType

        def side_effect_get_events_page(**kwargs):
            log_type = kwargs.get("log_type")
            if log_type == LogType.ALERTS:
                return [{"id": "alert-100", "finding_info": {"created_time": 1704067200000}}]
            return [{"id": "audit-200", "created_at": "2024-01-01T00:00:00Z"}]

        mocker.patch.object(mock_client, "get_events_page", side_effect=side_effect_get_events_page)
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "max_fetch": "5000",
                "event_types_to_fetch": "Alerts,Audit",
            },
        )
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mocker.patch.object(mock_client, "send_events")
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")

        fetch_events_command(mock_client)

        last_run_arg = mock_set_last_run.call_args[0][0]

        # Verify IDs are stored per type, not mixed
        assert "alert-100" in last_run_arg["previous_ids_alerts"]
        assert "audit-200" in last_run_arg["previous_ids_audit"]
        assert "audit-200" not in last_run_arg["previous_ids_alerts"]
        assert "alert-100" not in last_run_arg["previous_ids_audit"]

    def test_last_run_single_get_single_set(self, mock_client, alerts_response, audit_response, mocker):
        """Test that getLastRun is called once and setLastRun is called once (no race condition)."""
        from Koi import fetch_events_command, LogType

        def side_effect_get_events_page(**kwargs):
            log_type = kwargs.get("log_type")
            if log_type == LogType.ALERTS:
                return alerts_response["alerts"]
            return audit_response["data"]

        mocker.patch.object(mock_client, "get_events_page", side_effect=side_effect_get_events_page)
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "max_fetch": "5000",
                "event_types_to_fetch": "Alerts,Audit",
            },
        )
        mock_get_last_run = mocker.patch.object(demisto, "getLastRun", return_value={})
        mocker.patch.object(mock_client, "send_events")
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")

        fetch_events_command(mock_client)

        # Single read, single write — no race condition
        mock_get_last_run.assert_called_once()
        mock_set_last_run.assert_called_once()

    def test_last_run_failure_preserves_successful_type_state(self, mock_client, mocker):
        """Test that when one type fails, the other type's state is still saved in last_run."""
        from Koi import fetch_events_command, LogType

        def side_effect_get_events_page(**kwargs):
            log_type = kwargs.get("log_type")
            if log_type == LogType.ALERTS:
                return [{"id": "alert-ok", "finding_info": {"created_time": 1704067200000}}]
            raise Exception("Audit API is down")

        mocker.patch.object(mock_client, "get_events_page", side_effect=side_effect_get_events_page)
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "max_fetch": "5000",
                "event_types_to_fetch": "Alerts,Audit",
            },
        )
        mocker.patch.object(
            demisto,
            "getLastRun",
            return_value={
                "last_fetch_audit": "2024-01-01T00:00:00Z",
                "previous_ids_audit": ["old-audit-id"],
            },
        )
        mocker.patch.object(mock_client, "send_events")
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")

        fetch_events_command(mock_client)

        last_run_arg = mock_set_last_run.call_args[0][0]

        # Alerts state should be updated (successful)
        assert "last_fetch_alerts" in last_run_arg
        assert "alert-ok" in last_run_arg["previous_ids_alerts"]

        # Audit state should be preserved from initial last_run (failed, not overwritten)
        assert last_run_arg["last_fetch_audit"] == "2024-01-01T00:00:00Z"
        assert last_run_arg["previous_ids_audit"] == ["old-audit-id"]


# endregion

# region Date helper tests


class TestParseDate:
    """Tests for parse_date_or_use_current and get_formatted_utc_time."""

    @pytest.mark.parametrize(
        "date_input, expected_contains",
        [
            ("2024-01-01T00:00:00Z", "2024-01-01"),
            ("2024-06-15T12:30:00Z", "2024-06-15"),
        ],
        ids=["iso_format", "iso_with_time"],
    )
    def test_get_formatted_utc_time_valid(self, date_input: str, expected_contains: str):
        """Test formatting valid date strings."""
        from Koi import get_formatted_utc_time

        result = get_formatted_utc_time(date_input)
        assert expected_contains in result

    def test_get_formatted_utc_time_none_returns_current(self):
        """Test that None input returns current UTC time."""
        from Koi import get_formatted_utc_time

        result = get_formatted_utc_time(None)
        assert result  # Should return a non-empty string

    @pytest.mark.parametrize(
        "date_input",
        [
            None,
            "",
        ],
        ids=["none_input", "empty_string"],
    )
    def test_parse_date_or_use_current_fallback(self, date_input):
        """Test that empty/None input falls back to current UTC."""
        from Koi import parse_date_or_use_current

        result = parse_date_or_use_current(date_input)
        assert isinstance(result, datetime)

    def test_parse_date_or_use_current_valid_iso(self):
        """Test parsing a valid ISO 8601 date string."""
        from Koi import parse_date_or_use_current

        result = parse_date_or_use_current("2024-01-01T00:00:00Z")
        assert isinstance(result, datetime)
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 1

    def test_parse_date_or_use_current_unparseable(self, mocker):
        """Test fallback when arg_to_datetime returns None (covers lines 115-116)."""
        from Koi import parse_date_or_use_current

        mocker.patch("Koi.arg_to_datetime", return_value=None)

        result = parse_date_or_use_current("completely-invalid-date")
        assert isinstance(result, datetime)


# endregion

# region get_events_command error tests


class TestGetEventsCommandErrors:
    """Tests for error handling in get_events_command."""

    def test_invalid_event_type(self, mock_client):
        """Test get-events command with invalid event type raises error."""
        from Koi import get_events_command

        args = {"event_type": "InvalidType", "limit": "10", "should_push_events": "false"}
        params = {"event_types_to_fetch": "Alerts"}

        with pytest.raises(Exception, match="Invalid event type"):
            get_events_command(mock_client, args, params)


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

# region Main tests


class TestMain:
    """Tests for the main entry point."""

    def test_main_test_module(self, mocker):
        """Test main routes test-module command correctly."""
        from Koi import main

        mocker.patch.object(demisto, "command", return_value="test-module")
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": "https://api.prod.koi.security/",
                "api_key": {"password": "test-key"},
                "insecure": False,
                "proxy": False,
            },
        )
        mocker.patch("Koi.Client")
        mock_return = mocker.patch("Koi.return_results")
        mocker.patch("Koi.test_module", return_value="ok")

        main()

        mock_return.assert_called_once_with("ok")

    def test_main_unknown_command(self, mocker):
        """Test main raises error for unknown command."""
        from Koi import main

        mocker.patch.object(demisto, "command", return_value="unknown-command")
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": "https://api.prod.koi.security/",
                "api_key": {"password": "test-key"},
            },
        )
        mocker.patch.object(demisto, "error")
        mock_return_error = mocker.patch("Koi.return_error")

        main()

        mock_return_error.assert_called_once()
        assert "not implemented" in mock_return_error.call_args[0][0]

    def test_main_fetch_events(self, mocker):
        """Test main routes fetch-events command correctly (covers lines 664-665)."""
        from Koi import main, COMMAND_MAP

        mocker.patch.object(demisto, "command", return_value="fetch-events")
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": "https://api.prod.koi.security/",
                "api_key": {"password": "test-key"},
                "insecure": False,
                "proxy": False,
            },
        )
        mocker.patch("Koi.Client")
        mock_fetch = mocker.MagicMock()
        COMMAND_MAP["fetch-events"] = mock_fetch

        main()

        mock_fetch.assert_called_once()

    def test_main_get_events(self, mocker):
        """Test main routes koi-get-events command correctly (covers lines 667-668)."""
        from Koi import main, COMMAND_MAP

        mocker.patch.object(demisto, "command", return_value="koi-get-events")
        mocker.patch.object(demisto, "args", return_value={"limit": "10", "should_push_events": "false"})
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": "https://api.prod.koi.security/",
                "api_key": {"password": "test-key"},
                "insecure": False,
                "proxy": False,
                "event_types_to_fetch": "Alerts",
            },
        )
        mocker.patch("Koi.Client")
        mock_return = mocker.patch("Koi.return_results")
        mock_get_events = mocker.MagicMock(return_value="mock_result")
        COMMAND_MAP["koi-get-events"] = mock_get_events

        main()

        mock_return.assert_called_once_with("mock_result")

    def test_main_invalid_audit_types(self, mocker):
        """Test main raises error for invalid audit types filter (covers lines 648-650)."""
        from Koi import main

        mocker.patch.object(demisto, "command", return_value="test-module")
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": "https://api.prod.koi.security/",
                "api_key": {"password": "test-key"},
                "insecure": False,
                "proxy": False,
                "audit_types_filter": "invalid_type",
            },
        )
        mocker.patch.object(demisto, "error")
        mock_return_error = mocker.patch("Koi.return_error")

        main()

        mock_return_error.assert_called_once()
        assert "Invalid audit log type" in mock_return_error.call_args[0][0]


# endregion
