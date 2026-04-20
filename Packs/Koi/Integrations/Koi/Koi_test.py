import json
from datetime import datetime
from pathlib import Path

import pytest
import demistomock as demisto
from CommonServerPython import *  # noqa

from Koi import (
    Client,
    Config,
    LogType,
    API_POLICIES,
    API_ALLOWLIST,
    API_BLOCKLIST,
    VALID_AUDIT_TYPES,
    VALID_MARKETPLACES,
    COMMAND_MAP,
    get_log_types_from_titles,
    extract_time_from_event,
    add_time_to_events,
    get_event_id,
    deduplicate_events,
    fetch_events_with_pagination,
    test_module as koi_test_module,
    get_events_command,
    fetch_events_command,
    koi_policy_list_command,
    koi_allowlist_get_command,
    koi_allowlist_item_remove_command,
    koi_allowlist_item_add_command,
    koi_blocklist_get_command,
    koi_blocklist_item_remove_command,
    parse_list_items_from_entry_id,
    get_formatted_utc_time,
    parse_date_or_use_current,
    main,
)


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
def policies_response() -> dict:
    """Fixture for a mock policies API response."""
    return load_test_data("policies_response.json")


@pytest.fixture
def allowlist_response() -> dict:
    """Fixture for a mock allowlist API response."""
    return load_test_data("allowlist_response.json")


@pytest.fixture
def blocklist_response() -> dict:
    """Fixture for a mock blocklist API response."""
    return load_test_data("blocklist_response.json")


@pytest.fixture
def mock_client(mocker):
    """Fixture for a mocked Koi Client."""
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
        with pytest.raises(Exception, match="Invalid event type"):
            get_log_types_from_titles(titles)


# endregion

# region extract_time_from_event tests


class TestExtractTimeFromEvent:
    """Tests for the extract_time_from_event helper function."""

    def test_alert_event_with_epoch_ms(self):
        """Test extracting time from an alert event with epoch ms timestamp."""
        event = {"finding_info": {"created_time": 1704067200000}}
        result = extract_time_from_event(event, LogType.ALERTS)
        assert result == "2024-01-01T00:00:00Z"

    def test_audit_event_with_iso_string(self):
        """Test extracting time from an audit event with ISO 8601 string."""
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
        log_type = LogType[log_type_name]
        add_time_to_events(events, log_type)

        assert events[0]["_time"] == expected_time
        assert events[0]["source_log_type"] == expected_source

    def test_missing_time_field(self):
        """Test enriching events when time field is missing still sets source_log_type."""
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
        assert get_event_id(event) == expected_id

    def test_no_id_field(self):
        """Test that missing ID field returns None."""
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
        result = deduplicate_events(events, last_fetched_ids=last_ids)
        assert len(result) == expected_count

    def test_no_duplicates_found(self):
        """Test dedup when none of the events match previous IDs (covers line 237)."""
        events = [{"id": "3"}, {"id": "4"}]
        result = deduplicate_events(events, last_fetched_ids=["1", "2"])
        assert len(result) == 2


# endregion

# region Client tests


class TestClient:
    """Tests for the Client class methods."""

    def test_get_events_page_alerts(self, mock_client, alerts_response, mocker):
        """Test fetching a page of alerts."""
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
        mocker.patch.object(mock_client, "get_events_page", return_value=[{"id": "1"}])

        result = koi_test_module(mock_client)
        assert result == "ok"

    def test_auth_failure(self, mock_client, mocker):
        """Test test-module with authentication failure."""
        mocker.patch.object(mock_client, "get_events_page", side_effect=Exception("401 Unauthorized"))

        result = koi_test_module(mock_client)
        assert "Authorization Error" in result

    def test_non_auth_failure_reraises(self, mock_client, mocker):
        """Test test-module re-raises non-auth errors (covers line 378)."""
        mocker.patch.object(mock_client, "get_events_page", side_effect=Exception("Connection timeout"))

        with pytest.raises(Exception, match="Connection timeout"):
            koi_test_module(mock_client)


class TestGetEventsCommand:
    """Tests for the koi-get-events command."""

    def test_get_events_alerts_and_audit(self, mock_client, alerts_response, audit_response, mocker):
        """Test get-events command fetching both alerts and audit logs."""
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
        result = get_formatted_utc_time(date_input)
        assert expected_contains in result

    def test_get_formatted_utc_time_none_returns_current(self):
        """Test that None input returns current UTC time."""
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
        result = parse_date_or_use_current(date_input)
        assert isinstance(result, datetime)

    def test_parse_date_or_use_current_valid_iso(self):
        """Test parsing a valid ISO 8601 date string."""
        result = parse_date_or_use_current("2024-01-01T00:00:00Z")
        assert isinstance(result, datetime)
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 1

    def test_parse_date_or_use_current_unparseable(self, mocker):
        """Test fallback when arg_to_datetime returns None (covers lines 115-116)."""
        mocker.patch("Koi.arg_to_datetime", return_value=None)

        result = parse_date_or_use_current("completely-invalid-date")
        assert isinstance(result, datetime)


# endregion

# region get_events_command error tests


class TestGetEventsCommandErrors:
    """Tests for error handling in get_events_command."""

    def test_invalid_event_type(self, mock_client):
        """Test get-events command with invalid event type raises error."""
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

    def test_main_routes_policy_list(self, mocker):
        """Test main routes koi-policy-list command correctly."""
        mocker.patch.object(demisto, "command", return_value="koi-policy-list")
        mocker.patch.object(demisto, "args", return_value={"page": "1", "limit": "10"})
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
        mock_policy_list = mocker.MagicMock(return_value="mock_policy_result")
        COMMAND_MAP["koi-policy-list"] = mock_policy_list

        main()

        mock_return.assert_called_once_with("mock_policy_result")

    def test_main_routes_allowlist_get(self, mocker):
        """Test main routes koi-allowlist-get command correctly."""
        mocker.patch.object(demisto, "command", return_value="koi-allowlist-get")
        mocker.patch.object(demisto, "args", return_value={})
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
        mock_allowlist_get = mocker.MagicMock(return_value="mock_allowlist_result")
        COMMAND_MAP["koi-allowlist-get"] = mock_allowlist_get

        main()

        mock_return.assert_called_once_with("mock_allowlist_result")

    def test_main_routes_allowlist_item_remove(self, mocker):
        """Test main routes koi-allowlist-item-remove command correctly."""
        mocker.patch.object(demisto, "command", return_value="koi-allowlist-item-remove")
        mocker.patch.object(demisto, "args", return_value={"item_id": "ext-123", "marketplace": "vscode"})
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
        mock_allowlist_remove = mocker.MagicMock(return_value="mock_allowlist_remove_result")
        COMMAND_MAP["koi-allowlist-item-remove"] = mock_allowlist_remove

        main()

        mock_return.assert_called_once_with("mock_allowlist_remove_result")

    def test_main_routes_allowlist_item_add(self, mocker):
        """Test main routes koi-allowlist-item-add command correctly."""
        mocker.patch.object(demisto, "command", return_value="koi-allowlist-item-add")
        mocker.patch.object(demisto, "args", return_value={"item_id": "ext-123", "marketplace": "vscode"})
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
        mock_allowlist_add = mocker.MagicMock(return_value="mock_allowlist_add_result")
        COMMAND_MAP["koi-allowlist-item-add"] = mock_allowlist_add

        main()

        mock_return.assert_called_once_with("mock_allowlist_add_result")

    def test_main_routes_blocklist_get(self, mocker):
        """Test main routes koi-blocklist-get command correctly."""
        mocker.patch.object(demisto, "command", return_value="koi-blocklist-get")
        mocker.patch.object(demisto, "args", return_value={})
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
        mock_blocklist_get = mocker.MagicMock(return_value="mock_blocklist_result")
        COMMAND_MAP["koi-blocklist-get"] = mock_blocklist_get

        main()

        mock_return.assert_called_once_with("mock_blocklist_result")

    def test_main_routes_blocklist_item_remove(self, mocker):
        """Test main routes koi-blocklist-item-remove command correctly."""
        mocker.patch.object(demisto, "command", return_value="koi-blocklist-item-remove")
        mocker.patch.object(demisto, "args", return_value={"item_id": "mal-001", "marketplace": "vscode"})
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
        mock_blocklist_remove = mocker.MagicMock(return_value="mock_blocklist_remove_result")
        COMMAND_MAP["koi-blocklist-item-remove"] = mock_blocklist_remove

        main()

        mock_return.assert_called_once_with("mock_blocklist_remove_result")


# endregion

# region Policy command tests


class TestKoiPolicyListCommand:
    """Tests for the koi-policy-list command."""

    def test_policy_list_single_page_mode(self, mock_client, policies_response, mocker):
        """Test koi-policy-list in single-page mode (page arg provided)."""
        mocker.patch.object(mock_client, "get_policies", return_value=policies_response)

        args = {"page": "1"}
        result = koi_policy_list_command(mock_client, args)

        assert result.outputs_prefix == "Koi.Policy"
        assert result.outputs_key_field == "id"
        assert len(result.outputs) == 2
        assert result.outputs[0]["id"] == 1
        assert result.outputs[0]["name"] == "My Policy"
        assert result.outputs[1]["id"] == 2

        # Single-page mode: called with page and default page_size
        mock_client.get_policies.assert_called_once_with(page=1, page_size=Config.DEFAULT_PAGE_SIZE)

    def test_policy_list_single_page_custom_page_size(self, mock_client, policies_response, mocker):
        """Test koi-policy-list in single-page mode with custom page_size."""
        mocker.patch.object(mock_client, "get_policies", return_value=policies_response)

        args = {"page": "2", "page_size": "50"}
        result = koi_policy_list_command(mock_client, args)

        assert result.outputs_prefix == "Koi.Policy"
        mock_client.get_policies.assert_called_once_with(page=2, page_size=50)

    def test_policy_list_single_page_ignores_limit(self, mock_client, policies_response, mocker):
        """Test that when page is provided, limit is ignored."""
        mocker.patch.object(mock_client, "get_policies", return_value=policies_response)

        args = {"page": "3", "page_size": "25", "limit": "200"}
        result = koi_policy_list_command(mock_client, args)

        # Should use single-page mode, not auto-paginate
        mock_client.get_policies.assert_called_once_with(page=3, page_size=25)
        assert len(result.outputs) == 2

    def test_policy_list_auto_paginate_default_limit(self, mock_client, policies_response, mocker):
        """Test koi-policy-list in auto-paginate mode with default limit (no args)."""
        mocker.patch.object(mock_client, "get_policies", return_value=policies_response)

        args: dict[str, str] = {}
        result = koi_policy_list_command(mock_client, args)

        assert result.outputs_prefix == "Koi.Policy"
        assert len(result.outputs) == 2

    def test_policy_list_auto_paginate_custom_limit(self, mock_client, mocker):
        """Test koi-policy-list auto-paginate with custom limit across multiple pages."""
        page1 = {"policies": [{"id": i} for i in range(Config.MAX_PAGE_SIZE)], "total_count": 600}
        page2 = {"policies": [{"id": i + Config.MAX_PAGE_SIZE} for i in range(100)], "total_count": 600}

        mocker.patch.object(mock_client, "get_policies", side_effect=[page1, page2])

        args = {"limit": "600"}
        result = koi_policy_list_command(mock_client, args)

        assert len(result.outputs) == 600
        assert mock_client.get_policies.call_count == 2

    def test_policy_list_auto_paginate_stops_on_empty(self, mock_client, mocker):
        """Test auto-paginate stops when API returns empty page after a full page."""
        # Page 1 returns a full page (MAX_PAGE_SIZE) so pagination continues
        page1 = {"policies": [{"id": i} for i in range(Config.MAX_PAGE_SIZE)], "total_count": 500}
        # Page 2 returns empty — pagination stops
        page2 = {"policies": [], "total_count": 500}

        mocker.patch.object(mock_client, "get_policies", side_effect=[page1, page2])

        args = {"limit": "1000"}
        result = koi_policy_list_command(mock_client, args)

        assert len(result.outputs) == Config.MAX_PAGE_SIZE
        assert mock_client.get_policies.call_count == 2

    def test_policy_list_auto_paginate_stops_on_partial_page(self, mock_client, mocker):
        """Test auto-paginate stops when API returns fewer results than page_size."""
        # Return fewer than MAX_PAGE_SIZE items — indicates last page
        partial_page = {"policies": [{"id": i} for i in range(50)], "total_count": 50}

        mocker.patch.object(mock_client, "get_policies", return_value=partial_page)

        args = {"limit": "500"}
        result = koi_policy_list_command(mock_client, args)

        assert len(result.outputs) == 50
        mock_client.get_policies.assert_called_once()

    def test_policy_list_auto_paginate_trims_to_limit(self, mock_client, mocker):
        """Test auto-paginate trims results to the requested limit."""
        # Return a full page of MAX_PAGE_SIZE items
        full_page = {"policies": [{"id": i} for i in range(Config.MAX_PAGE_SIZE)], "total_count": 1000}

        mocker.patch.object(mock_client, "get_policies", return_value=full_page)

        args = {"limit": "10"}
        result = koi_policy_list_command(mock_client, args)

        assert len(result.outputs) == 10

    def test_policy_list_empty_response(self, mock_client, mocker):
        """Test koi-policy-list when no policies are returned."""
        mocker.patch.object(mock_client, "get_policies", return_value={"policies": [], "total_count": 0})

        args: dict[str, str] = {}
        result = koi_policy_list_command(mock_client, args)

        assert result.outputs == []
        assert "Policies" in result.readable_output

    def test_policy_list_outputs_and_readable(self, mock_client, policies_response, mocker):
        """Test that all expected fields are present in outputs and readable output contains data."""
        mocker.patch.object(mock_client, "get_policies", return_value=policies_response)

        args = {"page": "1"}
        result = koi_policy_list_command(mock_client, args)

        # Verify readable output contains key data
        assert "My Policy" in result.readable_output
        assert "block" in result.readable_output
        assert "John Doe" in result.readable_output

        # Verify all fields in outputs
        policy = result.outputs[0]
        assert policy["id"] == 1
        assert policy["name"] == "My Policy"
        assert policy["description"] == "This policy blocks high-risk extensions"
        assert policy["action"] == "block"
        assert policy["enabled"] is True
        assert policy["group_ids"] == [1, 2, 3]
        assert policy["creator_fullname"] == "John Doe"
        assert policy["created_at"] == "2025-04-23T17:22:24.023Z"
        assert policy["updated_at"] == "2025-04-23T17:22:24.023Z"


class TestClientGetPolicies:
    """Tests for the Client.get_policies method."""

    def test_get_policies_params(self, mock_client, policies_response, mocker):
        """Test that get_policies passes correct params and does not send limit to the API."""
        mocker.patch.object(mock_client, "_http_request", return_value=policies_response)

        result = mock_client.get_policies(page=2, page_size=50)

        call_kwargs = mock_client._http_request.call_args[1]
        assert call_kwargs["method"] == "GET"
        assert call_kwargs["url_suffix"] == API_POLICIES
        assert call_kwargs["params"]["page"] == 2
        assert call_kwargs["params"]["page_size"] == 50
        assert "limit" not in call_kwargs["params"]
        assert result == policies_response

    def test_get_policies_max_page_size_cap(self, mock_client, policies_response, mocker):
        """Test that page_size is capped at MAX_PAGE_SIZE."""
        mocker.patch.object(mock_client, "_http_request", return_value=policies_response)

        mock_client.get_policies(page=1, page_size=1000)

        call_kwargs = mock_client._http_request.call_args[1]
        assert call_kwargs["params"]["page_size"] == Config.MAX_PAGE_SIZE


# endregion

# region Allowlist command tests


class TestKoiAllowlistGetCommand:
    """Tests for the koi-allowlist-get command."""

    def test_allowlist_get_returns_items(self, mock_client, allowlist_response, mocker):
        """Test koi-allowlist-get returns all allowlist items."""
        mocker.patch.object(mock_client, "get_allowlist", return_value=allowlist_response)

        args: dict[str, str] = {}
        result = koi_allowlist_get_command(mock_client, args)

        assert result.outputs_prefix == "Koi.Allowlist"
        assert result.outputs_key_field == "item_id"
        assert len(result.outputs) == 2
        assert result.outputs[0]["item_id"] == "ext-123"
        assert result.outputs[0]["item_name"] == "My Extension"
        assert result.outputs[1]["item_id"] == "ext-456"

    def test_allowlist_get_empty_response(self, mock_client, mocker):
        """Test koi-allowlist-get when no items are returned."""
        mocker.patch.object(mock_client, "get_allowlist", return_value={"items": []})

        args: dict[str, str] = {}
        result = koi_allowlist_get_command(mock_client, args)

        assert result.outputs == []
        assert "Allowlist" in result.readable_output

    def test_allowlist_get_outputs_and_readable(self, mock_client, allowlist_response, mocker):
        """Test that all expected fields are present in outputs and readable output contains data."""
        mocker.patch.object(mock_client, "get_allowlist", return_value=allowlist_response)

        args: dict[str, str] = {}
        result = koi_allowlist_get_command(mock_client, args)

        # Verify readable output contains key data
        assert "My Extension" in result.readable_output
        assert "admin@example.com" in result.readable_output
        assert "vscode" in result.readable_output

        # Verify all fields in outputs
        item = result.outputs[0]
        assert item["item_id"] == "ext-123"
        assert item["item_name"] == "My Extension"
        assert item["item_display_name"] == "My Extension Display Name"
        assert item["marketplace"] == "vscode"
        assert item["publisher_name"] == "My Publisher"
        assert item["package_name"] == "my-package"
        assert item["notes"] == "Approved for development purposes"
        assert item["created_by"] == "admin@example.com"
        assert item["created_at"] == "2025-04-23T17:22:24.023Z"


class TestClientGetAllowlist:
    """Tests for the Client.get_allowlist method."""

    def test_get_allowlist_params(self, mock_client, allowlist_response, mocker):
        """Test that get_allowlist calls the correct endpoint with no params."""
        mocker.patch.object(mock_client, "_http_request", return_value=allowlist_response)

        result = mock_client.get_allowlist()

        call_kwargs = mock_client._http_request.call_args[1]
        assert call_kwargs["method"] == "GET"
        assert call_kwargs["url_suffix"] == API_ALLOWLIST
        assert "params" not in call_kwargs
        assert result == allowlist_response

    def test_get_allowlist_empty(self, mock_client, mocker):
        """Test get_allowlist with empty response."""
        empty_response = {"items": []}
        mocker.patch.object(mock_client, "_http_request", return_value=empty_response)

        result = mock_client.get_allowlist()

        assert result == empty_response
        assert result["items"] == []


# endregion

# region Allowlist item remove command tests


class TestKoiAllowlistItemRemoveCommand:
    """Tests for the koi-allowlist-item-remove command."""

    def test_allowlist_item_remove_success(self, mock_client, mocker):
        """Test koi-allowlist-item-remove successfully removes an item."""
        mocker.patch.object(mock_client, "remove_allowlist_item", return_value=None)

        args = {"item_id": "ext-123", "marketplace": "vscode"}
        result = koi_allowlist_item_remove_command(mock_client, args)

        assert "was removed successfully" in result.readable_output
        assert "ext-123" in result.readable_output
        assert "vscode" in result.readable_output
        assert result.outputs is None
        mock_client.remove_allowlist_item.assert_called_once_with(
            item_id="ext-123",
            marketplace="vscode",
            created_by=None,
            notes=None,
        )

    def test_allowlist_item_remove_with_optional_params(self, mock_client, mocker):
        """Test koi-allowlist-item-remove with created_by and notes."""
        mocker.patch.object(mock_client, "remove_allowlist_item", return_value=None)

        args = {
            "item_id": "ext-456",
            "marketplace": "chrome_web_store",
            "created_by": "admin@example.com",
            "notes": "No longer needed",
        }
        result = koi_allowlist_item_remove_command(mock_client, args)

        assert "was removed successfully" in result.readable_output
        assert "ext-456" in result.readable_output
        assert "chrome_web_store" in result.readable_output
        mock_client.remove_allowlist_item.assert_called_once_with(
            item_id="ext-456",
            marketplace="chrome_web_store",
            created_by="admin@example.com",
            notes="No longer needed",
        )

    def test_allowlist_item_remove_invalid_marketplace(self, mock_client, mocker):
        """Test koi-allowlist-item-remove raises error for invalid marketplace."""
        args = {"item_id": "ext-123", "marketplace": "invalid_marketplace"}

        with pytest.raises(DemistoException, match="Invalid marketplace"):
            koi_allowlist_item_remove_command(mock_client, args)

    @pytest.mark.parametrize("marketplace", VALID_MARKETPLACES)
    def test_allowlist_item_remove_all_valid_marketplaces(self, mock_client, mocker, marketplace):
        """Test koi-allowlist-item-remove accepts all valid marketplace values."""
        mocker.patch.object(mock_client, "remove_allowlist_item", return_value=None)

        args = {"item_id": "test-item", "marketplace": marketplace}
        result = koi_allowlist_item_remove_command(mock_client, args)

        assert "was removed successfully" in result.readable_output


class TestClientRemoveAllowlistItem:
    """Tests for the Client.remove_allowlist_item method."""

    def test_remove_allowlist_item_required_params(self, mock_client, mocker):
        """Test that remove_allowlist_item sends correct DELETE request with required params."""
        mock_response = mocker.MagicMock()
        mock_response.status_code = 204
        mocker.patch.object(mock_client, "_http_request", return_value=mock_response)

        mock_client.remove_allowlist_item(item_id="ext-123", marketplace="vscode")

        call_kwargs = mock_client._http_request.call_args[1]
        assert call_kwargs["method"] == "DELETE"
        assert call_kwargs["url_suffix"] == API_ALLOWLIST
        assert call_kwargs["json_data"]["item_id"] == "ext-123"
        assert call_kwargs["json_data"]["marketplace"] == "vscode"
        assert "created_by" not in call_kwargs["json_data"]
        assert "notes" not in call_kwargs["json_data"]
        assert call_kwargs["resp_type"] == "response"
        assert call_kwargs["ok_codes"] == (204,)

    def test_remove_allowlist_item_all_params(self, mock_client, mocker):
        """Test that remove_allowlist_item sends all params when provided."""
        mock_response = mocker.MagicMock()
        mock_response.status_code = 204
        mocker.patch.object(mock_client, "_http_request", return_value=mock_response)

        mock_client.remove_allowlist_item(
            item_id="ext-456",
            marketplace="chrome_web_store",
            created_by="admin@example.com",
            notes="Removing for security reasons",
        )

        call_kwargs = mock_client._http_request.call_args[1]
        assert call_kwargs["json_data"]["item_id"] == "ext-456"
        assert call_kwargs["json_data"]["marketplace"] == "chrome_web_store"
        assert call_kwargs["json_data"]["created_by"] == "admin@example.com"
        assert call_kwargs["json_data"]["notes"] == "Removing for security reasons"

    def test_remove_allowlist_item_api_error(self, mock_client, mocker):
        """Test that remove_allowlist_item propagates API errors."""
        mocker.patch.object(
            mock_client,
            "_http_request",
            side_effect=DemistoException("Error in API call [404] - Not Found"),
        )

        with pytest.raises(DemistoException, match="Error in API call"):
            mock_client.remove_allowlist_item(item_id="nonexistent", marketplace="vscode")


# endregion

# region Allowlist item add command tests


class TestKoiAllowlistItemAddCommand:
    """Tests for the koi-allowlist-item-add command."""

    def test_allowlist_item_add_single_item_success(self, mock_client, mocker):
        """Test koi-allowlist-item-add successfully adds a single item via item_id/marketplace."""
        mocker.patch.object(mock_client, "add_allowlist_items", return_value=None)

        args = {"item_id": "ext-123", "marketplace": "vscode"}
        result = koi_allowlist_item_add_command(mock_client, args)

        assert "was added successfully" in result.readable_output
        assert "ext-123" in result.readable_output
        assert "vscode" in result.readable_output
        assert result.outputs is None
        mock_client.add_allowlist_items.assert_called_once_with([{"item_id": "ext-123", "marketplace": "vscode"}])

    def test_allowlist_item_add_single_item_with_optional_params(self, mock_client, mocker):
        """Test koi-allowlist-item-add with created_by and notes."""
        mocker.patch.object(mock_client, "add_allowlist_items", return_value=None)

        args = {
            "item_id": "ext-456",
            "marketplace": "chrome_web_store",
            "created_by": "admin@example.com",
            "notes": "Approved for development purposes",
        }
        result = koi_allowlist_item_add_command(mock_client, args)

        assert "was added successfully" in result.readable_output
        assert "ext-456" in result.readable_output
        assert "chrome_web_store" in result.readable_output
        mock_client.add_allowlist_items.assert_called_once_with(
            [
                {
                    "item_id": "ext-456",
                    "marketplace": "chrome_web_store",
                    "created_by": "admin@example.com",
                    "notes": "Approved for development purposes",
                }
            ]
        )

    def test_allowlist_item_add_invalid_marketplace(self, mock_client, mocker):
        """Test koi-allowlist-item-add raises error for invalid marketplace."""
        args = {"item_id": "ext-123", "marketplace": "invalid_marketplace"}

        with pytest.raises(DemistoException, match="Invalid marketplace"):
            koi_allowlist_item_add_command(mock_client, args)

    @pytest.mark.parametrize("marketplace", VALID_MARKETPLACES)
    def test_allowlist_item_add_all_valid_marketplaces(self, mock_client, mocker, marketplace):
        """Test koi-allowlist-item-add accepts all valid marketplace values."""
        mocker.patch.object(mock_client, "add_allowlist_items", return_value=None)

        args = {"item_id": "test-item", "marketplace": marketplace}
        result = koi_allowlist_item_add_command(mock_client, args)

        assert "was added successfully" in result.readable_output

    @pytest.mark.parametrize(
        "args",
        [
            {},
            {"item_id": "ext-123"},
            {"marketplace": "vscode"},
        ],
        ids=["no_args", "missing_marketplace", "missing_item_id"],
    )
    def test_allowlist_item_add_missing_required_args(self, mock_client, args):
        """Test koi-allowlist-item-add raises error when item_id/marketplace pair is incomplete."""
        with pytest.raises(DemistoException, match="Either 'item_id' and 'marketplace' must be provided"):
            koi_allowlist_item_add_command(mock_client, args)

    def test_allowlist_item_add_from_file(self, mock_client, mocker, tmp_path):
        """Test koi-allowlist-item-add from a JSON file entry ID."""
        mocker.patch.object(mock_client, "add_allowlist_items", return_value=None)

        items_data = [
            {"item_id": "ext-1", "marketplace": "vscode"},
            {"item_id": "ext-2", "marketplace": "npm", "created_by": "user@example.com"},
        ]
        json_file = tmp_path / "items.json"
        json_file.write_text(json.dumps(items_data))

        mocker.patch.object(demisto, "getFilePath", return_value={"path": str(json_file), "name": "items.json"})

        args = {"items_list_raw_json_entry_id": "entry-abc-123"}
        result = koi_allowlist_item_add_command(mock_client, args)

        assert "2 allowlist items were added successfully" in result.readable_output
        mock_client.add_allowlist_items.assert_called_once_with(items_data)

    def test_allowlist_item_add_from_file_single_item(self, mock_client, mocker, tmp_path):
        """Test koi-allowlist-item-add from a JSON file with a single item uses singular message."""
        mocker.patch.object(mock_client, "add_allowlist_items", return_value=None)

        items_data = [{"item_id": "ext-1", "marketplace": "vscode"}]
        json_file = tmp_path / "items.json"
        json_file.write_text(json.dumps(items_data))

        mocker.patch.object(demisto, "getFilePath", return_value={"path": str(json_file), "name": "items.json"})

        args = {"items_list_raw_json_entry_id": "entry-abc-123"}
        result = koi_allowlist_item_add_command(mock_client, args)

        assert "ext-1" in result.readable_output
        assert "vscode" in result.readable_output
        assert "was added successfully" in result.readable_output

    def test_allowlist_item_add_file_takes_priority_over_single_item(self, mock_client, mocker, tmp_path):
        """Test that when both entry_id and item_id/marketplace are provided, entry_id takes priority."""
        mocker.patch.object(mock_client, "add_allowlist_items", return_value=None)

        items_data = [{"item_id": "file-item", "marketplace": "npm"}]
        json_file = tmp_path / "items.json"
        json_file.write_text(json.dumps(items_data))

        mocker.patch.object(demisto, "getFilePath", return_value={"path": str(json_file), "name": "items.json"})

        args = {
            "items_list_raw_json_entry_id": "entry-abc-123",
            "item_id": "arg-item",
            "marketplace": "vscode",
        }
        result = koi_allowlist_item_add_command(mock_client, args)

        # File entry ID should take priority
        mock_client.add_allowlist_items.assert_called_once_with(items_data)
        assert "file-item" in result.readable_output


class TestParseItemsFromEntryId:
    """Tests for the parse_list_items_from_entry_id helper function."""

    def test_parse_valid_items(self, mocker, tmp_path):
        """Test parsing a valid JSON file with multiple items."""
        items_data = [
            {"item_id": "ext-1", "marketplace": "vscode"},
            {"item_id": "ext-2", "marketplace": "npm", "notes": "test"},
        ]
        json_file = tmp_path / "items.json"
        json_file.write_text(json.dumps(items_data))

        mocker.patch.object(demisto, "getFilePath", return_value={"path": str(json_file), "name": "items.json"})

        result = parse_list_items_from_entry_id("entry-123")
        assert result == items_data

    @pytest.mark.parametrize(
        "file_content, error_match",
        [
            ("not valid json {{{", "Failed to parse JSON"),
            (json.dumps({"item_id": "ext-1", "marketplace": "vscode"}), "expected a list of items"),
            (json.dumps([{"item_id": "ext-1"}]), "must contain 'item_id' and 'marketplace'"),
            (json.dumps([{"item_id": "ext-1", "marketplace": "invalid_store"}]), "Invalid marketplace"),
            (json.dumps(["not-a-dict"]), "expected a dictionary"),
        ],
        ids=[
            "invalid_json",
            "not_a_list",
            "missing_required_fields",
            "invalid_marketplace",
            "item_not_a_dict",
        ],
    )
    def test_parse_invalid_file_content(self, mocker, tmp_path, file_content, error_match):
        """Test that invalid file content raises DemistoException with the expected message."""
        json_file = tmp_path / "items.json"
        json_file.write_text(file_content)

        mocker.patch.object(demisto, "getFilePath", return_value={"path": str(json_file), "name": "items.json"})

        with pytest.raises(DemistoException, match=error_match):
            parse_list_items_from_entry_id("entry-123")

    @pytest.mark.parametrize(
        "mock_kwargs, error_match",
        [
            ({"side_effect": Exception("Entry not found")}, "Could not find file"),
            ({"return_value": {}}, "not a valid file entry"),
        ],
        ids=["entry_not_found", "entry_not_a_file"],
    )
    def test_parse_entry_resolution_errors(self, mocker, mock_kwargs, error_match):
        """Test that entry resolution errors raise DemistoException."""
        mocker.patch.object(demisto, "getFilePath", **mock_kwargs)

        with pytest.raises(DemistoException, match=error_match):
            parse_list_items_from_entry_id("entry-123")


class TestClientAddAllowlistItems:
    """Tests for the Client.add_allowlist_items method."""

    def test_add_allowlist_items_single_item(self, mock_client, mocker):
        """Test that add_allowlist_items sends correct POST request with a single item."""
        mock_response = mocker.MagicMock()
        mock_response.status_code = 204
        mocker.patch.object(mock_client, "_http_request", return_value=mock_response)

        items = [{"item_id": "ext-123", "marketplace": "vscode"}]
        mock_client.add_allowlist_items(items)

        call_kwargs = mock_client._http_request.call_args[1]
        assert call_kwargs["method"] == "POST"
        assert call_kwargs["url_suffix"] == API_ALLOWLIST
        assert call_kwargs["json_data"] == {"items": items}
        assert call_kwargs["resp_type"] == "response"
        assert call_kwargs["ok_codes"] == (204,)

    def test_add_allowlist_items_multiple_items(self, mock_client, mocker):
        """Test that add_allowlist_items sends multiple items in the body."""
        mock_response = mocker.MagicMock()
        mock_response.status_code = 204
        mocker.patch.object(mock_client, "_http_request", return_value=mock_response)

        items = [
            {"item_id": "ext-1", "marketplace": "vscode"},
            {"item_id": "ext-2", "marketplace": "npm", "created_by": "admin@example.com"},
            {"item_id": "ext-3", "marketplace": "chrome_web_store", "notes": "Approved"},
        ]
        mock_client.add_allowlist_items(items)

        call_kwargs = mock_client._http_request.call_args[1]
        assert call_kwargs["json_data"] == {"items": items}

    def test_add_allowlist_items_api_error(self, mock_client, mocker):
        """Test that add_allowlist_items propagates API errors."""
        mocker.patch.object(
            mock_client,
            "_http_request",
            side_effect=DemistoException("Error in API call [400] - Bad Request"),
        )

        with pytest.raises(DemistoException, match="Error in API call"):
            mock_client.add_allowlist_items([{"item_id": "bad-item", "marketplace": "vscode"}])


# endregion

# region koi-blocklist-get tests


class TestKoiBlocklistGetCommand:
    """Tests for the koi-blocklist-get command."""

    def test_blocklist_get_returns_items(self, mock_client, blocklist_response, mocker):
        """Test koi-blocklist-get returns all blocklist items."""
        mocker.patch.object(mock_client, "get_blocklist", return_value=blocklist_response)

        args: dict[str, str] = {}
        result = koi_blocklist_get_command(mock_client, args)

        assert result.outputs_prefix == "Koi.Blocklist"
        assert result.outputs_key_field == "item_id"
        assert len(result.outputs) == 2
        assert result.outputs[0]["item_id"] == "mal-001"
        assert result.outputs[0]["item_name"] == "Bad Extension"
        assert result.outputs[1]["item_id"] == "mal-002"

    def test_blocklist_get_empty_response(self, mock_client, mocker):
        """Test koi-blocklist-get when no items are returned."""
        mocker.patch.object(mock_client, "get_blocklist", return_value={"items": []})

        args: dict[str, str] = {}
        result = koi_blocklist_get_command(mock_client, args)

        assert result.outputs == []
        assert "Blocklist" in result.readable_output

    def test_blocklist_get_outputs_and_readable(self, mock_client, blocklist_response, mocker):
        """Test that all expected fields are present in outputs and readable output contains data."""
        mocker.patch.object(mock_client, "get_blocklist", return_value=blocklist_response)

        args: dict[str, str] = {}
        result = koi_blocklist_get_command(mock_client, args)

        # Verify readable output contains key data
        assert "Bad Extension" in result.readable_output
        assert "security@example.com" in result.readable_output
        assert "chrome_web_store" in result.readable_output

        # Verify all fields in outputs
        item = result.outputs[0]
        assert item["item_id"] == "mal-001"
        assert item["item_name"] == "Bad Extension"
        assert item["item_display_name"] == "Malicious Extension"
        assert item["marketplace"] == "chrome_web_store"
        assert item["publisher_name"] == "Suspicious Publisher"
        assert item["package_name"] == "bad-package"
        assert item["notes"] == "Known malware distribution"
        assert item["created_by"] == "security@example.com"
        assert item["created_at"] == "2025-05-01T09:15:00.000Z"


class TestClientGetBlocklist:
    """Tests for the Client.get_blocklist method."""

    def test_get_blocklist_params(self, mock_client, blocklist_response, mocker):
        """Test that get_blocklist calls the correct endpoint with no params."""
        mocker.patch.object(mock_client, "_http_request", return_value=blocklist_response)

        result = mock_client.get_blocklist()

        call_kwargs = mock_client._http_request.call_args[1]
        assert call_kwargs["method"] == "GET"
        assert call_kwargs["url_suffix"] == API_BLOCKLIST
        assert "params" not in call_kwargs
        assert result == blocklist_response

    def test_get_blocklist_empty(self, mock_client, mocker):
        """Test get_blocklist with empty response."""
        empty_response = {"items": []}
        mocker.patch.object(mock_client, "_http_request", return_value=empty_response)

        result = mock_client.get_blocklist()

        assert result == empty_response
        assert result["items"] == []


# endregion

# region koi-blocklist-item-remove tests


class TestKoiBlocklistItemRemoveCommand:
    """Tests for the koi-blocklist-item-remove command."""

    @pytest.mark.parametrize(
        "args, expected_items, readable_check",
        [
            (
                {"item_id": "mal-001", "marketplace": "vscode"},
                [{"item_id": "mal-001", "marketplace": "vscode"}],
                "mal-001",
            ),
            (
                {
                    "item_id": "mal-002",
                    "marketplace": "chrome_web_store",
                    "created_by": "security@example.com",
                    "notes": "Confirmed false positive",
                },
                [
                    {
                        "item_id": "mal-002",
                        "marketplace": "chrome_web_store",
                        "created_by": "security@example.com",
                        "notes": "Confirmed false positive",
                    }
                ],
                "mal-002",
            ),
        ],
        ids=["required_only", "with_optional_params"],
    )
    def test_blocklist_item_remove_single_item(self, mock_client, mocker, args, expected_items, readable_check):
        """Test koi-blocklist-item-remove with single item (required only and with optional params)."""
        mocker.patch.object(mock_client, "remove_blocklist_items", return_value=None)

        result = koi_blocklist_item_remove_command(mock_client, args)

        assert "was removed successfully" in result.readable_output
        assert readable_check in result.readable_output
        assert result.outputs is None
        mock_client.remove_blocklist_items.assert_called_once_with(expected_items)

    def test_blocklist_item_remove_invalid_marketplace(self, mock_client, mocker):
        """Test koi-blocklist-item-remove raises error for invalid marketplace."""
        args = {"item_id": "mal-001", "marketplace": "invalid_marketplace"}

        with pytest.raises(DemistoException, match="Invalid marketplace"):
            koi_blocklist_item_remove_command(mock_client, args)

    @pytest.mark.parametrize("marketplace", VALID_MARKETPLACES)
    def test_blocklist_item_remove_all_valid_marketplaces(self, mock_client, mocker, marketplace):
        """Test koi-blocklist-item-remove accepts all valid marketplace values."""
        mocker.patch.object(mock_client, "remove_blocklist_items", return_value=None)

        args = {"item_id": "test-item", "marketplace": marketplace}
        result = koi_blocklist_item_remove_command(mock_client, args)

        assert "was removed successfully" in result.readable_output

    @pytest.mark.parametrize(
        "args",
        [
            {},
            {"item_id": "mal-001"},
            {"marketplace": "vscode"},
        ],
        ids=["no_args", "missing_marketplace", "missing_item_id"],
    )
    def test_blocklist_item_remove_missing_required_args(self, mock_client, args):
        """Test koi-blocklist-item-remove raises error when item_id/marketplace pair is incomplete."""
        with pytest.raises(DemistoException, match="Either 'item_id' and 'marketplace' must be provided"):
            koi_blocklist_item_remove_command(mock_client, args)

    @pytest.mark.parametrize(
        "items_data, expected_readable",
        [
            (
                [
                    {"item_id": "mal-1", "marketplace": "vscode"},
                    {"item_id": "mal-2", "marketplace": "npm", "created_by": "user@example.com"},
                ],
                "2 blocklist items were removed successfully",
            ),
            (
                [{"item_id": "mal-1", "marketplace": "vscode"}],
                "mal-1",
            ),
        ],
        ids=["multiple_items", "single_item"],
    )
    def test_blocklist_item_remove_from_file(self, mock_client, mocker, tmp_path, items_data, expected_readable):
        """Test koi-blocklist-item-remove from a JSON file entry ID."""
        mocker.patch.object(mock_client, "remove_blocklist_items", return_value=None)

        json_file = tmp_path / "items.json"
        json_file.write_text(json.dumps(items_data))

        mocker.patch.object(demisto, "getFilePath", return_value={"path": str(json_file), "name": "items.json"})

        args = {"items_list_raw_json_entry_id": "entry-abc-123"}
        result = koi_blocklist_item_remove_command(mock_client, args)

        assert expected_readable in result.readable_output
        mock_client.remove_blocklist_items.assert_called_once_with(items_data)

    def test_blocklist_item_remove_file_takes_priority_over_single_item(self, mock_client, mocker, tmp_path):
        """Test that when both entry_id and item_id/marketplace are provided, entry_id takes priority."""
        mocker.patch.object(mock_client, "remove_blocklist_items", return_value=None)

        items_data = [{"item_id": "file-item", "marketplace": "npm"}]
        json_file = tmp_path / "items.json"
        json_file.write_text(json.dumps(items_data))

        mocker.patch.object(demisto, "getFilePath", return_value={"path": str(json_file), "name": "items.json"})

        args = {
            "items_list_raw_json_entry_id": "entry-abc-123",
            "item_id": "arg-item",
            "marketplace": "vscode",
        }
        result = koi_blocklist_item_remove_command(mock_client, args)

        mock_client.remove_blocklist_items.assert_called_once_with(items_data)
        assert "file-item" in result.readable_output


class TestClientRemoveBlocklistItems:
    """Tests for the Client.remove_blocklist_items method."""

    @pytest.mark.parametrize(
        "items",
        [
            [{"item_id": "mal-001", "marketplace": "vscode"}],
            [
                {"item_id": "mal-001", "marketplace": "vscode"},
                {"item_id": "mal-002", "marketplace": "npm"},
            ],
        ],
        ids=["single_item", "multiple_items"],
    )
    def test_remove_blocklist_items_request(self, mock_client, mocker, items):
        """Test remove_blocklist_items sends correct DELETE request."""
        mock_response = mocker.MagicMock()
        mock_response.status_code = 204
        mocker.patch.object(mock_client, "_http_request", return_value=mock_response)

        mock_client.remove_blocklist_items(items)

        call_kwargs = mock_client._http_request.call_args[1]
        assert call_kwargs["method"] == "DELETE"
        assert call_kwargs["url_suffix"] == API_BLOCKLIST
        assert call_kwargs["json_data"] == {"items": items}
        assert call_kwargs["resp_type"] == "response"
        assert call_kwargs["ok_codes"] == (204,)

    def test_remove_blocklist_items_api_error(self, mock_client, mocker):
        """Test that remove_blocklist_items propagates API errors."""
        mocker.patch.object(
            mock_client,
            "_http_request",
            side_effect=DemistoException("Error in API call [400] - Bad Request"),
        )

        with pytest.raises(DemistoException, match="Error in API call"):
            mock_client.remove_blocklist_items([{"item_id": "bad-item", "marketplace": "vscode"}])


# endregion
