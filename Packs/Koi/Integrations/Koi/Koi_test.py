import json
from datetime import datetime
from pathlib import Path

import pytest
import demistomock as demisto
from CommonServerPython import *  # noqa

from Koi import (
    ApiPaths,
    Client,
    Config,
    LogType,
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
    koi_allowlist_items_remove_command,
    koi_allowlist_items_add_command,
    koi_blocklist_get_command,
    koi_blocklist_items_remove_command,
    koi_blocklist_items_add_command,
    koi_policy_status_update_command,
    koi_inventory_list_command,
    koi_inventory_item_get_command,
    koi_inventory_search_command,
    koi_inventory_item_endpoints_list_command,
    parse_filter_from_args,
    resolve_items_from_args,
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
def policy_update_response() -> dict:
    """Fixture for a mock policy update API response."""
    return load_test_data("policy_update_response.json")


@pytest.fixture
def inventory_response() -> dict:
    """Fixture for a mock inventory API response."""
    return load_test_data("inventory_response.json")


@pytest.fixture
def inventory_item_response() -> dict:
    """Fixture for a mock inventory item API response."""
    return load_test_data("inventory_item_response.json")


@pytest.fixture
def inventory_item_endpoints_response() -> dict:
    """Fixture for a mock inventory item endpoints API response."""
    return load_test_data("inventory_item_endpoints_response.json")


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
        """Test main routes koi-allowlist-items-remove command correctly."""
        mocker.patch.object(demisto, "command", return_value="koi-allowlist-items-remove")
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
        COMMAND_MAP["koi-allowlist-items-remove"] = mock_allowlist_remove

        main()

        mock_return.assert_called_once_with("mock_allowlist_remove_result")

    def test_main_routes_allowlist_item_add(self, mocker):
        """Test main routes koi-allowlist-items-add command correctly."""
        mocker.patch.object(demisto, "command", return_value="koi-allowlist-items-add")
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
        COMMAND_MAP["koi-allowlist-items-add"] = mock_allowlist_add

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
        """Test main routes koi-blocklist-items-remove command correctly."""
        mocker.patch.object(demisto, "command", return_value="koi-blocklist-items-remove")
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
        COMMAND_MAP["koi-blocklist-items-remove"] = mock_blocklist_remove

        main()

        mock_return.assert_called_once_with("mock_blocklist_remove_result")

    def test_main_routes_blocklist_item_add(self, mocker):
        """Test main routes koi-blocklist-items-add command correctly."""
        mocker.patch.object(demisto, "command", return_value="koi-blocklist-items-add")
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
        mock_blocklist_add = mocker.MagicMock(return_value="mock_blocklist_add_result")
        COMMAND_MAP["koi-blocklist-items-add"] = mock_blocklist_add

        main()

        mock_return.assert_called_once_with("mock_blocklist_add_result")

    def test_main_routes_policy_status_update(self, mocker):
        """Test main routes koi-policy-status-update command correctly."""
        mocker.patch.object(demisto, "command", return_value="koi-policy-status-update")
        mocker.patch.object(demisto, "args", return_value={"policy_id": "1", "enabled": "true"})
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
        mock_policy_update = mocker.MagicMock(return_value="mock_policy_update_result")
        COMMAND_MAP["koi-policy-status-update"] = mock_policy_update

        main()

        mock_return.assert_called_once_with("mock_policy_update_result")

    def test_main_routes_inventory_list(self, mocker):
        """Test main routes koi-inventory-list command correctly."""
        mocker.patch.object(demisto, "command", return_value="koi-inventory-list")
        mocker.patch.object(demisto, "args", return_value={"page": "1"})
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
        mock_inventory_list = mocker.MagicMock(return_value="mock_inventory_result")
        COMMAND_MAP["koi-inventory-list"] = mock_inventory_list

        main()

        mock_return.assert_called_once_with("mock_inventory_result")

    def test_main_routes_inventory_item_get(self, mocker):
        """Test main routes koi-inventory-item-get command correctly."""
        mocker.patch.object(demisto, "command", return_value="koi-inventory-item-get")
        mocker.patch.object(demisto, "args", return_value={"item_id": "abc123", "marketplace": "chrome_web_store"})
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
        mock_inventory_item_get = mocker.MagicMock(return_value="mock_inventory_item_result")
        COMMAND_MAP["koi-inventory-item-get"] = mock_inventory_item_get

        main()

        mock_return.assert_called_once_with("mock_inventory_item_result")

    def test_main_routes_inventory_search(self, mocker):
        """Test main routes koi-inventory-search command correctly."""
        mocker.patch.object(demisto, "command", return_value="koi-inventory-search")
        mocker.patch.object(
            demisto,
            "args",
            return_value={"filter_json": '{"field": "risk_level", "operator": "eq", "value": "high"}'},
        )
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
        mock_inventory_search = mocker.MagicMock(return_value="mock_inventory_search_result")
        COMMAND_MAP["koi-inventory-search"] = mock_inventory_search

        main()

        mock_return.assert_called_once_with("mock_inventory_search_result")

    def test_main_routes_inventory_item_endpoints_list(self, mocker):
        """Test main routes koi-inventory-item-endpoints-list command correctly."""
        mocker.patch.object(demisto, "command", return_value="koi-inventory-item-endpoints-list")
        mocker.patch.object(
            demisto,
            "args",
            return_value={"item_id": "abc123", "marketplace": "chrome_web_store"},
        )
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
        mock_endpoints_list = mocker.MagicMock(return_value="mock_endpoints_result")
        COMMAND_MAP["koi-inventory-item-endpoints-list"] = mock_endpoints_list

        main()

        mock_return.assert_called_once_with("mock_endpoints_result")


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
        assert call_kwargs["url_suffix"] == ApiPaths.POLICIES
        assert call_kwargs["params"]["page"] == 2
        assert call_kwargs["params"]["page_size"] == 50
        assert "limit" not in call_kwargs["params"]
        assert result == policies_response

    def test_policy_list_page_size_exceeds_max_raises_error(self, mock_client, mocker):
        """Test that page_size exceeding MAX_PAGE_SIZE raises ValueError."""
        args = {"page": "1", "page_size": "501"}
        with pytest.raises(DemistoException, match="page_size .* exceeds the maximum allowed value"):
            koi_policy_list_command(mock_client, args)

    def test_policy_list_limit_exceeds_max_raises_error(self, mock_client, mocker):
        """Test that limit exceeding MAX_LIMIT raises ValueError."""
        args = {"limit": "1001"}
        with pytest.raises(DemistoException, match="limit .* exceeds the maximum allowed value"):
            koi_policy_list_command(mock_client, args)


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
        assert call_kwargs["url_suffix"] == ApiPaths.ALLOWLIST
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
    """Tests for the koi-allowlist-items-remove command."""

    def test_allowlist_item_remove_single_item(self, mock_client, mocker):
        """Test koi-allowlist-items-remove successfully removes a single item."""
        mocker.patch.object(mock_client, "remove_allowlist_items", return_value=None)

        args = {"item_id": "ext-123", "marketplace": "vscode"}
        result = koi_allowlist_items_remove_command(mock_client, args)

        assert "was removed successfully" in result.readable_output
        assert "ext-123" in result.readable_output
        assert result.outputs is None
        mock_client.remove_allowlist_items.assert_called_once_with([{"item_id": "ext-123", "marketplace": "vscode"}])

    @pytest.mark.parametrize(
        "items_data, expected_readable",
        [
            (
                [
                    {"item_id": "ext-1", "marketplace": "vscode"},
                    {"item_id": "ext-2", "marketplace": "npm", "created_by": "user@example.com"},
                ],
                "2 allowlist items were removed successfully",
            ),
            (
                [{"item_id": "ext-1", "marketplace": "vscode"}],
                "ext-1",
            ),
        ],
        ids=["multiple_items", "single_item"],
    )
    def test_allowlist_item_remove_from_file(self, mock_client, mocker, tmp_path, items_data, expected_readable):
        """Test koi-allowlist-items-remove from a JSON file entry ID."""
        mocker.patch.object(mock_client, "remove_allowlist_items", return_value=None)

        json_file = tmp_path / "items.json"
        json_file.write_text(json.dumps(items_data))

        mocker.patch.object(demisto, "getFilePath", return_value={"path": str(json_file), "name": "items.json"})

        args = {"items_list_raw_json_entry_id": "entry-abc-123"}
        result = koi_allowlist_items_remove_command(mock_client, args)

        assert expected_readable in result.readable_output
        mock_client.remove_allowlist_items.assert_called_once_with(items_data)


class TestClientRemoveAllowlistItems:
    """Tests for the Client.remove_allowlist_items method."""

    @pytest.mark.parametrize(
        "items",
        [
            [{"item_id": "ext-123", "marketplace": "vscode"}],
            [
                {"item_id": "ext-123", "marketplace": "vscode"},
                {"item_id": "ext-456", "marketplace": "npm"},
            ],
        ],
        ids=["single_item", "multiple_items"],
    )
    def test_remove_allowlist_items_request(self, mock_client, mocker, items):
        """Test remove_allowlist_items sends correct DELETE request."""
        mock_response = mocker.MagicMock()
        mock_response.status_code = 204
        mocker.patch.object(mock_client, "_http_request", return_value=mock_response)

        mock_client.remove_allowlist_items(items)

        call_kwargs = mock_client._http_request.call_args[1]
        assert call_kwargs["method"] == "DELETE"
        assert call_kwargs["url_suffix"] == ApiPaths.ALLOWLIST
        assert call_kwargs["json_data"] == {"items": items}
        assert call_kwargs["resp_type"] == "response"
        assert call_kwargs["ok_codes"] == (204,)

    def test_remove_allowlist_items_api_error(self, mock_client, mocker):
        """Test that remove_allowlist_items propagates API errors."""
        mocker.patch.object(
            mock_client,
            "_http_request",
            side_effect=DemistoException("Error in API call [404] - Not Found"),
        )

        with pytest.raises(DemistoException, match="Error in API call"):
            mock_client.remove_allowlist_items([{"item_id": "nonexistent", "marketplace": "vscode"}])


# endregion

# region Allowlist item add command tests


class TestKoiAllowlistItemAddCommand:
    """Tests for the koi-allowlist-items-add command."""

    def test_allowlist_item_add_single_item(self, mock_client, mocker):
        """Test koi-allowlist-items-add successfully adds a single item."""
        mocker.patch.object(mock_client, "add_allowlist_items", return_value=None)

        args = {"item_id": "ext-123", "marketplace": "vscode"}
        result = koi_allowlist_items_add_command(mock_client, args)

        assert "was added successfully" in result.readable_output
        assert "ext-123" in result.readable_output
        assert result.outputs is None
        mock_client.add_allowlist_items.assert_called_once_with([{"item_id": "ext-123", "marketplace": "vscode"}])

    def test_allowlist_item_add_from_file(self, mock_client, mocker, tmp_path):
        """Test koi-allowlist-items-add from a JSON file entry ID."""
        mocker.patch.object(mock_client, "add_allowlist_items", return_value=None)

        items_data = [
            {"item_id": "ext-1", "marketplace": "vscode"},
            {"item_id": "ext-2", "marketplace": "npm", "created_by": "user@example.com"},
        ]
        json_file = tmp_path / "items.json"
        json_file.write_text(json.dumps(items_data))

        mocker.patch.object(demisto, "getFilePath", return_value={"path": str(json_file), "name": "items.json"})

        args = {"items_list_raw_json_entry_id": "entry-abc-123"}
        result = koi_allowlist_items_add_command(mock_client, args)

        assert "2 allowlist items were added successfully" in result.readable_output
        mock_client.add_allowlist_items.assert_called_once_with(items_data)

    def test_allowlist_item_add_from_file_single_item(self, mock_client, mocker, tmp_path):
        """Test koi-allowlist-items-add from a JSON file with a single item uses singular message."""
        mocker.patch.object(mock_client, "add_allowlist_items", return_value=None)

        items_data = [{"item_id": "ext-1", "marketplace": "vscode"}]
        json_file = tmp_path / "items.json"
        json_file.write_text(json.dumps(items_data))

        mocker.patch.object(demisto, "getFilePath", return_value={"path": str(json_file), "name": "items.json"})

        args = {"items_list_raw_json_entry_id": "entry-abc-123"}
        result = koi_allowlist_items_add_command(mock_client, args)

        assert "ext-1" in result.readable_output
        assert "vscode" in result.readable_output
        assert "was added successfully" in result.readable_output


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
        assert call_kwargs["url_suffix"] == ApiPaths.ALLOWLIST
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
        assert call_kwargs["url_suffix"] == ApiPaths.BLOCKLIST
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

# region koi-blocklist-items-remove tests


class TestKoiBlocklistItemRemoveCommand:
    """Tests for the koi-blocklist-items-remove command."""

    def test_blocklist_item_remove_single_item(self, mock_client, mocker):
        """Test koi-blocklist-items-remove successfully removes a single item."""
        mocker.patch.object(mock_client, "remove_blocklist_items", return_value=None)

        args = {"item_id": "mal-001", "marketplace": "vscode"}
        result = koi_blocklist_items_remove_command(mock_client, args)

        assert "was removed successfully" in result.readable_output
        assert "mal-001" in result.readable_output
        assert result.outputs is None
        mock_client.remove_blocklist_items.assert_called_once_with([{"item_id": "mal-001", "marketplace": "vscode"}])

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
        """Test koi-blocklist-items-remove from a JSON file entry ID."""
        mocker.patch.object(mock_client, "remove_blocklist_items", return_value=None)

        json_file = tmp_path / "items.json"
        json_file.write_text(json.dumps(items_data))

        mocker.patch.object(demisto, "getFilePath", return_value={"path": str(json_file), "name": "items.json"})

        args = {"items_list_raw_json_entry_id": "entry-abc-123"}
        result = koi_blocklist_items_remove_command(mock_client, args)

        assert expected_readable in result.readable_output
        mock_client.remove_blocklist_items.assert_called_once_with(items_data)


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
        assert call_kwargs["url_suffix"] == ApiPaths.BLOCKLIST
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

# region koi-blocklist-items-add tests


class TestKoiBlocklistItemAddCommand:
    """Tests for the koi-blocklist-items-add command."""

    def test_blocklist_item_add_single_item(self, mock_client, mocker):
        """Test koi-blocklist-items-add successfully adds a single item."""
        mocker.patch.object(mock_client, "add_blocklist_items", return_value=None)

        args = {"item_id": "mal-001", "marketplace": "vscode"}
        result = koi_blocklist_items_add_command(mock_client, args)

        assert "was added successfully" in result.readable_output
        assert "mal-001" in result.readable_output
        assert result.outputs is None
        mock_client.add_blocklist_items.assert_called_once_with([{"item_id": "mal-001", "marketplace": "vscode"}])

    @pytest.mark.parametrize(
        "items_data, expected_readable",
        [
            (
                [
                    {"item_id": "mal-1", "marketplace": "vscode"},
                    {"item_id": "mal-2", "marketplace": "npm", "created_by": "user@example.com"},
                ],
                "2 blocklist items were added successfully",
            ),
            (
                [{"item_id": "mal-1", "marketplace": "vscode"}],
                "mal-1",
            ),
        ],
        ids=["multiple_items", "single_item"],
    )
    def test_blocklist_item_add_from_file(self, mock_client, mocker, tmp_path, items_data, expected_readable):
        """Test koi-blocklist-items-add from a JSON file entry ID."""
        mocker.patch.object(mock_client, "add_blocklist_items", return_value=None)

        json_file = tmp_path / "items.json"
        json_file.write_text(json.dumps(items_data))

        mocker.patch.object(demisto, "getFilePath", return_value={"path": str(json_file), "name": "items.json"})

        args = {"items_list_raw_json_entry_id": "entry-abc-123"}
        result = koi_blocklist_items_add_command(mock_client, args)

        assert expected_readable in result.readable_output
        mock_client.add_blocklist_items.assert_called_once_with(items_data)


class TestClientAddBlocklistItems:
    """Tests for the Client.add_blocklist_items method."""

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
    def test_add_blocklist_items_request(self, mock_client, mocker, items):
        """Test add_blocklist_items sends correct POST request."""
        mock_response = mocker.MagicMock()
        mock_response.status_code = 204
        mocker.patch.object(mock_client, "_http_request", return_value=mock_response)

        mock_client.add_blocklist_items(items)

        call_kwargs = mock_client._http_request.call_args[1]
        assert call_kwargs["method"] == "POST"
        assert call_kwargs["url_suffix"] == ApiPaths.BLOCKLIST
        assert call_kwargs["json_data"] == {"items": items}
        assert call_kwargs["resp_type"] == "response"
        assert call_kwargs["ok_codes"] == (204,)

    def test_add_blocklist_items_api_error(self, mock_client, mocker):
        """Test that add_blocklist_items propagates API errors."""
        mocker.patch.object(
            mock_client,
            "_http_request",
            side_effect=DemistoException("Error in API call [400] - Bad Request"),
        )

        with pytest.raises(DemistoException, match="Error in API call"):
            mock_client.add_blocklist_items([{"item_id": "bad-item", "marketplace": "vscode"}])


# endregion

# region resolve_items_from_args tests


class TestResolveItemsFromArgs:
    """Tests for the resolve_items_from_args helper function."""

    def test_single_item_required_only(self):
        """Test resolving a single item with required fields only."""
        args = {"item_id": "ext-123", "marketplace": "vscode"}
        result = resolve_items_from_args(args)

        assert result == [{"item_id": "ext-123", "marketplace": "vscode"}]

    def test_single_item_with_optional_params(self):
        """Test resolving a single item with optional created_by and notes."""
        args = {
            "item_id": "ext-123",
            "marketplace": "vscode",
            "created_by": "admin@example.com",
            "notes": "Test note",
        }
        result = resolve_items_from_args(args)

        assert result == [
            {
                "item_id": "ext-123",
                "marketplace": "vscode",
                "created_by": "admin@example.com",
                "notes": "Test note",
            }
        ]

    def test_invalid_marketplace(self):
        """Test that invalid marketplace raises DemistoException."""
        args = {"item_id": "ext-123", "marketplace": "invalid_store"}

        with pytest.raises(DemistoException, match="Invalid marketplace"):
            resolve_items_from_args(args)

    @pytest.mark.parametrize("marketplace", VALID_MARKETPLACES)
    def test_all_valid_marketplaces(self, marketplace):
        """Test that all valid marketplace values are accepted."""
        args = {"item_id": "test-item", "marketplace": marketplace}
        result = resolve_items_from_args(args)

        assert result == [{"item_id": "test-item", "marketplace": marketplace}]

    @pytest.mark.parametrize(
        "args",
        [
            {},
            {"item_id": "ext-123"},
            {"marketplace": "vscode"},
        ],
        ids=["no_args", "missing_marketplace", "missing_item_id"],
    )
    def test_missing_required_args(self, args):
        """Test that missing item_id/marketplace pair raises DemistoException."""
        with pytest.raises(DemistoException, match="Either 'item_id' and 'marketplace' must be provided"):
            resolve_items_from_args(args)

    def test_file_entry_id_takes_priority(self, mocker, tmp_path):
        """Test that file entry ID takes priority over single item args."""
        items_data = [{"item_id": "file-item", "marketplace": "npm"}]
        json_file = tmp_path / "items.json"
        json_file.write_text(json.dumps(items_data))

        mocker.patch.object(demisto, "getFilePath", return_value={"path": str(json_file), "name": "items.json"})

        args = {
            "items_list_raw_json_entry_id": "entry-abc-123",
            "item_id": "arg-item",
            "marketplace": "vscode",
        }
        result = resolve_items_from_args(args)

        assert result == items_data


# endregion

# region koi-policy-status-update tests


class TestKoiPolicyStatusUpdateCommand:
    """Tests for the koi-policy-status-update command."""

    @pytest.mark.parametrize(
        "enabled_arg, expected_enabled, expected_text",
        [
            ("true", True, "enabled"),
            ("false", False, "disabled"),
        ],
        ids=["enable", "disable"],
    )
    def test_policy_status_update(
        self, mock_client, policy_update_response, mocker, enabled_arg, expected_enabled, expected_text
    ):
        """Test koi-policy-status-update enables or disables a policy."""
        response = {**policy_update_response, "enabled": expected_enabled}
        mocker.patch.object(mock_client, "update_policy_status", return_value=response)

        args = {"policy_id": "1", "enabled": enabled_arg}
        result = koi_policy_status_update_command(mock_client, args)

        assert result.outputs_prefix == "Koi.Policy"
        assert result.outputs_key_field == "id"
        assert result.outputs["id"] == 1
        assert result.outputs["enabled"] == expected_enabled
        assert "Policy Updated" in result.readable_output
        mock_client.update_policy_status.assert_called_once_with(policy_id=1, enabled=expected_enabled)

    def test_policy_status_update_outputs_and_readable(self, mock_client, policy_update_response, mocker):
        """Test that all expected fields are present in outputs and readable output."""
        mocker.patch.object(mock_client, "update_policy_status", return_value=policy_update_response)

        args = {"policy_id": "1", "enabled": "true"}
        result = koi_policy_status_update_command(mock_client, args)

        # Verify all fields in outputs
        assert result.outputs["id"] == 1
        assert result.outputs["name"] == "My Policy"
        assert result.outputs["description"] == "This policy blocks high-risk extensions"
        assert result.outputs["action"] == "block"
        assert result.outputs["enabled"] is True
        assert result.outputs["group_ids"] == [1, 2, 3]
        assert result.outputs["creator_fullname"] == "John Doe"

        # Verify readable output contains key data
        assert "My Policy" in result.readable_output
        assert "block" in result.readable_output

    @pytest.mark.parametrize(
        "args",
        [
            {"policy_id": "abc", "enabled": "true"},
            {"policy_id": "1", "enabled": "not_a_bool"},
            {"enabled": "true"},
            {"policy_id": "1"},
            {},
        ],
        ids=["invalid_policy_id", "invalid_enabled", "missing_policy_id", "missing_enabled", "no_args"],
    )
    def test_policy_status_update_invalid_input(self, mock_client, args):
        """Test koi-policy-status-update raises error for invalid or missing input."""
        with pytest.raises((ValueError, KeyError, DemistoException)):
            koi_policy_status_update_command(mock_client, args)


class TestClientUpdatePolicyStatus:
    """Tests for the Client.update_policy_status method."""

    @pytest.mark.parametrize("enabled", [True, False], ids=["enable", "disable"])
    def test_update_policy_status_request(self, mock_client, policy_update_response, mocker, enabled):
        """Test update_policy_status sends correct PUT request."""
        mocker.patch.object(mock_client, "_http_request", return_value=policy_update_response)

        result = mock_client.update_policy_status(policy_id=42, enabled=enabled)

        call_kwargs = mock_client._http_request.call_args[1]
        assert call_kwargs["method"] == "PUT"
        assert call_kwargs["url_suffix"] == ApiPaths.policy(42)
        assert call_kwargs["json_data"] == {"enabled": enabled}
        assert result == policy_update_response

    def test_update_policy_status_api_error(self, mock_client, mocker):
        """Test that update_policy_status propagates API errors."""
        mocker.patch.object(
            mock_client,
            "_http_request",
            side_effect=DemistoException("Error in API call [404] - Not Found"),
        )

        with pytest.raises(DemistoException, match="Error in API call"):
            mock_client.update_policy_status(policy_id=999, enabled=True)


# endregion

# region koi-inventory-list tests


class TestKoiInventoryListCommand:
    """Tests for the koi-inventory-list command."""

    @pytest.mark.parametrize(
        "args, expected_page, expected_page_size",
        [
            ({"page": "1"}, 1, Config.DEFAULT_PAGE_SIZE),
            ({"page": "2", "page_size": "50"}, 2, 50),
            ({"page": "3", "page_size": "25", "limit": "200"}, 3, 25),
        ],
        ids=["default_page_size", "custom_page_size", "limit_ignored_when_page_provided"],
    )
    def test_inventory_list_single_page_mode(
        self, mock_client, inventory_response, mocker, args, expected_page, expected_page_size
    ):
        """Test koi-inventory-list in single-page mode with various argument combinations."""
        mocker.patch.object(mock_client, "get_inventory", return_value=inventory_response)

        result = koi_inventory_list_command(mock_client, args)

        assert result.outputs_prefix == "Koi.Inventory"
        assert result.outputs_key_field == "item_id"
        assert len(result.outputs) == 2
        mock_client.get_inventory.assert_called_once_with(page=expected_page, page_size=expected_page_size)

    def test_inventory_list_auto_paginate_default_limit(self, mock_client, inventory_response, mocker):
        """Test koi-inventory-list in auto-paginate mode with default limit (no args)."""
        mocker.patch.object(mock_client, "get_inventory", return_value=inventory_response)

        args: dict[str, str] = {}
        result = koi_inventory_list_command(mock_client, args)

        assert result.outputs_prefix == "Koi.Inventory"
        assert len(result.outputs) == 2

    @pytest.mark.parametrize(
        "limit_arg, api_item_count, expected_output_count",
        [
            ("500", Config.MAX_PAGE_SIZE, 500),
            ("500", 0, 0),
            ("500", 50, 50),
            ("10", Config.MAX_PAGE_SIZE, 10),
        ],
        ids=[
            "full_page_satisfies_limit",
            "empty_response",
            "partial_page_stops_pagination",
            "trims_to_limit",
        ],
    )
    def test_inventory_list_auto_paginate_behavior(self, mock_client, mocker, limit_arg, api_item_count, expected_output_count):
        """Test auto-paginate behavior with various limit and API response combinations."""
        response = {
            "items": [{"item_id": f"item-{i}"} for i in range(api_item_count)],
            "total_count": api_item_count,
        }
        mocker.patch.object(mock_client, "get_inventory", return_value=response)

        args = {"limit": limit_arg}
        result = koi_inventory_list_command(mock_client, args)

        assert len(result.outputs) == expected_output_count

    def test_inventory_list_empty_response(self, mock_client, mocker):
        """Test koi-inventory-list when no items are returned."""
        mocker.patch.object(mock_client, "get_inventory", return_value={"items": [], "total_count": 0})

        args: dict[str, str] = {}
        result = koi_inventory_list_command(mock_client, args)

        assert result.outputs == []
        assert "Inventory" in result.readable_output

    @pytest.mark.parametrize(
        "filter_args, expected_call_kwargs",
        [
            (
                {
                    "marketplace": "chrome_web_store",
                    "risk_level": "high",
                    "publisher_name": "Meta",
                    "platform": "chrome",
                    "view": "extensions",
                    "sort_by": "risk_level",
                    "sort_direction": "desc",
                },
                {
                    "marketplace": "chrome_web_store",
                    "risk_level": "high",
                    "publisher_name": "Meta",
                    "platform": "chrome",
                    "view": "extensions",
                    "sort_by": "risk_level",
                    "sort_direction": "desc",
                },
            ),
            (
                {
                    "brew_category_koi": "Command Line Tools & Utilities",
                    "browser_category_koi": "Developer Tools",
                    "chocolatey_category_koi": "Command Line Tools & Utilities",
                    "ide_category_koi": "Language Support & Tooling",
                    "software_category_koi": "Docs tools",
                },
                {
                    "brew_category_koi": "Command Line Tools & Utilities",
                    "browser_category_koi": "Developer Tools",
                    "chocolatey_category_koi": "Command Line Tools & Utilities",
                    "ide_category_koi": "Language Support & Tooling",
                    "software_category_koi": "Docs tools",
                },
            ),
            (
                {
                    "device_id": "550e8400-e29b-41d4-a716-446655440000",
                    "finding_id": "550e8400-e29b-41d4-a716-446655440001",
                    "item_id": "f53b1d43-eef4-4909-99ca-56b5fa3e108c",
                },
                {
                    "device_id": "550e8400-e29b-41d4-a716-446655440000",
                    "finding_id": "550e8400-e29b-41d4-a716-446655440001",
                    "item_id": "f53b1d43-eef4-4909-99ca-56b5fa3e108c",
                },
            ),
        ],
        ids=["marketplace_and_sorting_filters", "category_filters", "id_filters"],
    )
    def test_inventory_list_with_filters(self, mock_client, inventory_response, mocker, filter_args, expected_call_kwargs):
        """Test koi-inventory-list passes various filter arguments to the client."""
        mocker.patch.object(mock_client, "get_inventory", return_value=inventory_response)

        args = {"page": "1", **filter_args}
        result = koi_inventory_list_command(mock_client, args)

        assert result.outputs_prefix == "Koi.Inventory"
        mock_client.get_inventory.assert_called_once_with(
            page=1,
            page_size=Config.DEFAULT_PAGE_SIZE,
            **expected_call_kwargs,
        )

    def test_inventory_list_outputs_and_readable(self, mock_client, inventory_response, mocker):
        """Test that all expected fields are present in outputs and readable output contains data."""
        mocker.patch.object(mock_client, "get_inventory", return_value=inventory_response)

        args = {"page": "1"}
        result = koi_inventory_list_command(mock_client, args)

        # Verify readable output contains key data
        assert "React Developer Tools" in result.readable_output
        assert "Meta" in result.readable_output
        assert "chrome_web_store" in result.readable_output
        assert "marketplace" in result.readable_output
        assert "React debugging tools" in result.readable_output
        assert "2025-06-15T10:00:00Z" in result.readable_output
        assert "2023-01-15" in result.readable_output

        # Verify all fields in outputs
        item = result.outputs[0]
        assert item["item_id"] == "abc123"
        assert item["item_display_name"] == "React Developer Tools"
        assert item["marketplace"] == "chrome_web_store"
        assert item["platforms"] == ["chrome", "edge"]
        assert item["publisher_name"] == "Meta"
        assert item["risk"] == 5
        assert item["risk_level"] == "high"
        assert item["version"] == "1.0.0"
        assert item["status"] == "APPROVED"
        assert item["endpoint_count"] == 42
        assert item["installs_count"] == 1000000
        assert item["first_seen"] == "2024-01-01T10:00:00Z"
        assert item["last_seen"] == "2024-10-15T10:00:00Z"
        assert item["last_used"] == "2025-06-15T10:00:00Z"
        assert item["installation_method"] == "marketplace"
        assert item["is_first_party"] is False
        assert item["is_signed"] is True
        assert item["short_description"] == "React debugging tools"
        assert item["categories"] == ["Developer Tools"]
        assert item["findings"] == ["malware", "permissions"]
        assert item["released_at"] == "2023-01-15"
        assert item["governed_details"] == {"group-uuid-123": {"policy_id": "policy-uuid-456", "action": "allow"}}
        assert item["brew_category_koi"] == "Command Line Tools & Utilities"
        assert item["browser_category_koi"] == "Developer Tools"
        assert item["chocolatey_category_koi"] == "Command Line Tools & Utilities"
        assert item["ide_category_koi"] == "Language Support & Tooling"
        assert item["software_category_koi"] == "Docs tools"

    def test_inventory_list_auto_paginate_passes_filters(self, mock_client, mocker):
        """Test that auto-paginate mode passes filter arguments to each page request."""
        page1 = {"items": [{"item_id": "item-1"}], "total_count": 1}

        mocker.patch.object(mock_client, "get_inventory", return_value=page1)

        args = {"limit": "10", "marketplace": "vscode", "risk_level": "high"}
        koi_inventory_list_command(mock_client, args)

        call_kwargs = mock_client.get_inventory.call_args[1]
        assert call_kwargs["marketplace"] == "vscode"
        assert call_kwargs["risk_level"] == "high"


class TestClientGetInventory:
    """Tests for the Client.get_inventory method."""

    def test_get_inventory_params(self, mock_client, inventory_response, mocker):
        """Test that get_inventory passes correct params to the API."""
        mocker.patch.object(mock_client, "_http_request", return_value=inventory_response)

        result = mock_client.get_inventory(page=2, page_size=50, marketplace="vscode", risk_level="high")

        call_kwargs = mock_client._http_request.call_args[1]
        assert call_kwargs["method"] == "GET"
        assert call_kwargs["url_suffix"] == ApiPaths.INVENTORY
        assert call_kwargs["params"]["page"] == 2
        assert call_kwargs["params"]["page_size"] == 50
        assert call_kwargs["params"]["marketplace"] == "vscode"
        assert call_kwargs["params"]["risk_level"] == "high"
        assert result == inventory_response

    def test_inventory_list_page_size_exceeds_max_raises_error(self, mock_client, mocker):
        """Test that page_size exceeding MAX_PAGE_SIZE raises ValueError."""
        args = {"page": "1", "page_size": "501"}
        with pytest.raises(DemistoException, match="page_size .* exceeds the maximum allowed value"):
            koi_inventory_list_command(mock_client, args)

    def test_inventory_list_limit_exceeds_max_raises_error(self, mock_client, mocker):
        """Test that limit exceeding MAX_LIMIT raises ValueError."""
        args = {"limit": "1001"}
        with pytest.raises(DemistoException, match="limit .* exceeds the maximum allowed value"):
            koi_inventory_list_command(mock_client, args)

    def test_get_inventory_no_optional_params(self, mock_client, inventory_response, mocker):
        """Test that None optional params are excluded from the request (assign_params behavior)."""
        mocker.patch.object(mock_client, "_http_request", return_value=inventory_response)

        mock_client.get_inventory(page=1, page_size=100)

        call_kwargs = mock_client._http_request.call_args[1]
        params = call_kwargs["params"]
        assert "marketplace" not in params
        assert "risk_level" not in params
        assert "platform" not in params
        assert "publisher_name" not in params
        assert "view" not in params

    def test_get_inventory_all_filters(self, mock_client, inventory_response, mocker):
        """Test that all filter parameters are passed correctly."""
        mocker.patch.object(mock_client, "_http_request", return_value=inventory_response)

        mock_client.get_inventory(
            page=1,
            page_size=100,
            brew_category_koi="Command Line Tools & Utilities",
            browser_category_koi="Developer Tools",
            chocolatey_category_koi="Command Line Tools & Utilities",
            device_id="device-123",
            finding_id="finding-456",
            first_seen="2024-01-01T00:00:00Z",
            ide_category_koi="Language Support & Tooling",
            installation_method="marketplace",
            item_display_name="React",
            item_id="abc123",
            marketplace="chrome_web_store",
            platform="chrome",
            publisher_name="Meta",
            risk_level="high",
            software_category_koi="Docs tools",
            sort_by="first_seen",
            sort_direction="asc",
            view="extensions",
        )

        call_kwargs = mock_client._http_request.call_args[1]
        params = call_kwargs["params"]
        assert params["brew_category_koi"] == "Command Line Tools & Utilities"
        assert params["browser_category_koi"] == "Developer Tools"
        assert params["chocolatey_category_koi"] == "Command Line Tools & Utilities"
        assert params["device_id"] == "device-123"
        assert params["finding_id"] == "finding-456"
        assert params["first_seen"] == "2024-01-01T00:00:00Z"
        assert params["ide_category_koi"] == "Language Support & Tooling"
        assert params["installation_method"] == "marketplace"
        assert params["item_display_name"] == "React"
        assert params["item_id"] == "abc123"
        assert params["marketplace"] == "chrome_web_store"
        assert params["platform"] == "chrome"
        assert params["publisher_name"] == "Meta"
        assert params["risk_level"] == "high"
        assert params["software_category_koi"] == "Docs tools"
        assert params["sort_by"] == "first_seen"
        assert params["sort_direction"] == "asc"
        assert params["view"] == "extensions"


# endregion

# region koi-inventory-item-get tests


class TestKoiInventoryItemGetCommand:
    """Tests for the koi-inventory-item-get command."""

    @pytest.mark.parametrize(
        "args, expected_version",
        [
            ({"item_id": "abc123", "marketplace": "chrome_web_store", "version": "1.0.0"}, "1.0.0"),
            ({"item_id": "abc123", "marketplace": "chrome_web_store", "version": "2.0.0"}, "2.0.0"),
        ],
        ids=["version_1", "version_2"],
    )
    def test_inventory_item_get(self, mock_client, inventory_item_response, mocker, args, expected_version):
        """Test koi-inventory-item-get with different versions."""
        mocker.patch.object(mock_client, "get_inventory_item", return_value=inventory_item_response)

        result = koi_inventory_item_get_command(mock_client, args)

        assert result.outputs_prefix == "Koi.Inventory"
        assert result.outputs_key_field == "item_id"
        assert result.outputs["item_id"] == "abc123"
        assert result.outputs["item_display_name"] == "React Developer Tools"
        mock_client.get_inventory_item.assert_called_once_with(
            item_id="abc123",
            marketplace="chrome_web_store",
            version=expected_version,
        )

    def test_inventory_item_get_outputs_and_readable(self, mock_client, inventory_item_response, mocker):
        """Test that all expected fields are present in outputs and readable output."""
        mocker.patch.object(mock_client, "get_inventory_item", return_value=inventory_item_response)

        args = {"item_id": "abc123", "marketplace": "chrome_web_store", "version": "1.0.0"}
        result = koi_inventory_item_get_command(mock_client, args)

        # Verify readable output contains key data
        assert "React Developer Tools" in result.readable_output
        assert "Meta" in result.readable_output
        assert "Inventory Item" in result.readable_output

        # Verify all fields in outputs
        item = result.outputs
        assert item["item_id"] == "abc123"
        assert item["item_display_name"] == "React Developer Tools"
        assert item["marketplace"] == "chrome_web_store"
        assert item["version"] == "1.0.0"
        assert item["platforms"] == ["chrome", "edge"]
        assert item["publisher_name"] == "Meta"
        assert item["risk"] == 5
        assert item["risk_level"] == "high"
        assert item["status"] == "Allowed"
        assert item["endpoint_count"] == 42
        assert item["installs_count"] == 1000000
        assert item["installation_method"] == "marketplace"
        assert item["is_first_party"] is False
        assert item["is_signed"] is True
        assert item["first_seen"] == "2024-01-01T10:00:00Z"
        assert item["last_seen"] == "2024-10-15T10:00:00Z"
        assert item["last_used"] == "2025-06-15T10:00:00Z"
        assert item["released_at"] == "2023-01-15"
        assert item["short_description"] == "React debugging tools"
        assert item["categories"] == ["Developer Tools"]
        assert len(item["findings"]) == 1
        assert item["findings"][0]["finding_id"] == "malware_detected"
        assert item["findings"][0]["severity"] == "critical"
        assert "default" in item["governed_details"]
        assert item["brew_category_koi"] == "Command Line Tools & Utilities"
        assert item["browser_category_koi"] == "Developer Tools"
        assert item["chocolatey_category_koi"] == "Command Line Tools & Utilities"
        assert item["ide_category_koi"] == "Language Support & Tooling"
        assert item["software_category_koi"] == "Docs tools"

    @pytest.mark.parametrize(
        "args",
        [
            {"marketplace": "chrome_web_store"},
            {"item_id": "abc123"},
            {},
        ],
        ids=["missing_item_id", "missing_marketplace", "no_args"],
    )
    def test_inventory_item_get_missing_required_args(self, mock_client, args):
        """Test koi-inventory-item-get raises error for missing required arguments."""
        with pytest.raises(KeyError):
            koi_inventory_item_get_command(mock_client, args)


class TestClientGetInventoryItem:
    """Tests for the Client.get_inventory_item method."""

    def test_get_inventory_item_request(self, mock_client, inventory_item_response, mocker):
        """Test that get_inventory_item sends correct GET request with all required params."""
        mocker.patch.object(mock_client, "_http_request", return_value=inventory_item_response)

        result = mock_client.get_inventory_item(item_id="abc123", marketplace="chrome_web_store", version="2.0.0")

        call_kwargs = mock_client._http_request.call_args[1]
        assert call_kwargs["method"] == "GET"
        assert call_kwargs["url_suffix"] == ApiPaths.inventory_item("abc123")
        assert call_kwargs["params"]["marketplace"] == "chrome_web_store"
        assert call_kwargs["params"]["version"] == "2.0.0"
        assert result == inventory_item_response

    def test_get_inventory_item_api_error(self, mock_client, mocker):
        """Test that get_inventory_item propagates API errors."""
        mocker.patch.object(
            mock_client,
            "_http_request",
            side_effect=DemistoException("Error in API call [404] - Not Found"),
        )

        with pytest.raises(DemistoException, match="Error in API call"):
            mock_client.get_inventory_item(item_id="nonexistent", marketplace="chrome_web_store", version="1.0.0")


# endregion

# region koi-inventory-search tests


class TestParseFilterFromArgs:
    """Tests for the parse_filter_from_args helper function."""

    def test_parse_inline_filter_json(self):
        """Test parsing a valid inline JSON filter string."""
        args = {"filter_json": '{"field": "risk_level", "operator": "eq", "value": "high"}'}
        result = parse_filter_from_args(args)

        assert result == {"field": "risk_level", "operator": "eq", "value": "high"}

    def test_parse_filter_from_file(self, mocker, tmp_path):
        """Test parsing a filter from a JSON file entry ID."""
        filter_data = {"field": "marketplace", "operator": "eq", "value": "vscode"}
        json_file = tmp_path / "filter.json"
        json_file.write_text(json.dumps(filter_data))

        mocker.patch.object(demisto, "getFilePath", return_value={"path": str(json_file), "name": "filter.json"})

        args = {"filter_raw_json_entry_id": "entry-123"}
        result = parse_filter_from_args(args)

        assert result == filter_data

    def test_file_entry_takes_priority_over_inline(self, mocker, tmp_path):
        """Test that file entry ID takes priority over inline filter_json."""
        file_filter = {"source": "file"}
        json_file = tmp_path / "filter.json"
        json_file.write_text(json.dumps(file_filter))

        mocker.patch.object(demisto, "getFilePath", return_value={"path": str(json_file), "name": "filter.json"})

        args = {
            "filter_raw_json_entry_id": "entry-123",
            "filter_json": '{"source": "inline"}',
        }
        result = parse_filter_from_args(args)

        assert result == file_filter

    def test_no_filter_raises_error(self):
        """Test that missing both filter sources raises DemistoException."""
        with pytest.raises(DemistoException, match="Either 'filter_json' or 'filter_raw_json_entry_id'"):
            parse_filter_from_args({})

    @pytest.mark.parametrize(
        "args, file_content, error_match",
        [
            ({"filter_json": "not valid json {{{"}, None, "Failed to parse filter_json"),
            ({"filter_json": json.dumps(["not", "a", "dict"])}, None, "expected a dictionary"),
            ({"filter_raw_json_entry_id": "entry-123"}, "not valid json {{{", "Failed to parse JSON filter file"),
            ({"filter_raw_json_entry_id": "entry-123"}, json.dumps(["not", "a", "dict"]), "expected a dictionary"),
        ],
        ids=["invalid_inline_json", "inline_not_a_dict", "invalid_file_json", "file_not_a_dict"],
    )
    def test_invalid_filter_content(self, mocker, tmp_path, args, file_content, error_match):
        """Test that invalid filter content raises DemistoException."""
        if file_content is not None:
            json_file = tmp_path / "filter.json"
            json_file.write_text(file_content)
            mocker.patch.object(demisto, "getFilePath", return_value={"path": str(json_file), "name": "filter.json"})

        with pytest.raises(DemistoException, match=error_match):
            parse_filter_from_args(args)

    @pytest.mark.parametrize(
        "mock_kwargs, error_match",
        [
            ({"side_effect": Exception("Entry not found")}, "Could not find file"),
            ({"return_value": {}}, "not a valid file entry"),
        ],
        ids=["entry_not_found", "entry_not_a_file"],
    )
    def test_file_entry_resolution_errors(self, mocker, mock_kwargs, error_match):
        """Test that entry resolution errors raise DemistoException."""
        mocker.patch.object(demisto, "getFilePath", **mock_kwargs)

        with pytest.raises(DemistoException, match=error_match):
            parse_filter_from_args({"filter_raw_json_entry_id": "entry-123"})


class TestKoiInventorySearchCommand:
    """Tests for the koi-inventory-search command."""

    @pytest.mark.parametrize(
        "args, expected_filter, expected_sort_by, expected_sort_direction",
        [
            (
                {"page": "1", "filter_json": '{"field": "risk_level", "operator": "eq", "value": "high"}'},
                {"field": "risk_level", "operator": "eq", "value": "high"},
                None,
                None,
            ),
            (
                {
                    "page": "1",
                    "filter_json": '{"field": "marketplace", "operator": "eq", "value": "vscode"}',
                    "sort_by": "risk_level",
                    "sort_direction": "desc",
                },
                {"field": "marketplace", "operator": "eq", "value": "vscode"},
                "risk_level",
                "desc",
            ),
        ],
        ids=["basic_filter", "filter_with_sorting"],
    )
    def test_inventory_search_single_page(
        self,
        mock_client,
        inventory_response,
        mocker,
        args,
        expected_filter,
        expected_sort_by,
        expected_sort_direction,
    ):
        """Test koi-inventory-search in single-page mode with various argument combinations."""
        mocker.patch.object(mock_client, "search_inventory", return_value=inventory_response)

        result = koi_inventory_search_command(mock_client, args)

        assert result.outputs_prefix == "Koi.Inventory"
        assert result.outputs_key_field == "item_id"
        assert len(result.outputs) == 2
        mock_client.search_inventory.assert_called_once_with(
            page=1,
            page_size=Config.DEFAULT_PAGE_SIZE,
            filter_obj=expected_filter,
            sort_by=expected_sort_by,
            sort_direction=expected_sort_direction,
        )

    @pytest.mark.parametrize(
        "limit_arg, api_item_count, expected_output_count",
        [
            ("500", Config.MAX_PAGE_SIZE, 500),
            ("500", 0, 0),
            ("500", 50, 50),
            ("10", Config.MAX_PAGE_SIZE, 10),
        ],
        ids=[
            "full_page_satisfies_limit",
            "empty_response",
            "partial_page_stops_pagination",
            "trims_to_limit",
        ],
    )
    def test_inventory_search_auto_paginate_behavior(self, mock_client, mocker, limit_arg, api_item_count, expected_output_count):
        """Test auto-paginate behavior with various limit and API response combinations."""
        response = {
            "items": [{"item_id": f"item-{i}"} for i in range(api_item_count)],
            "total_count": api_item_count,
        }
        mocker.patch.object(mock_client, "search_inventory", return_value=response)

        args = {
            "limit": limit_arg,
            "filter_json": '{"field": "risk_level", "operator": "eq", "value": "high"}',
        }
        result = koi_inventory_search_command(mock_client, args)

        assert len(result.outputs) == expected_output_count

    def test_inventory_search_missing_filter_raises_error(self, mock_client):
        """Test that missing filter raises DemistoException."""
        with pytest.raises(DemistoException, match="Either 'filter_json' or 'filter_raw_json_entry_id'"):
            koi_inventory_search_command(mock_client, {"page": "1"})

    def test_inventory_search_from_file(self, mock_client, inventory_response, mocker, tmp_path):
        """Test koi-inventory-search with filter from file entry ID."""
        filter_data = {"field": "publisher_name", "operator": "contains", "value": "Meta"}
        json_file = tmp_path / "filter.json"
        json_file.write_text(json.dumps(filter_data))

        mocker.patch.object(demisto, "getFilePath", return_value={"path": str(json_file), "name": "filter.json"})
        mocker.patch.object(mock_client, "search_inventory", return_value=inventory_response)

        args = {"page": "1", "filter_raw_json_entry_id": "entry-123"}
        result = koi_inventory_search_command(mock_client, args)

        assert result.outputs_prefix == "Koi.Inventory"
        mock_client.search_inventory.assert_called_once_with(
            page=1,
            page_size=Config.DEFAULT_PAGE_SIZE,
            filter_obj=filter_data,
            sort_by=None,
            sort_direction=None,
        )

    def test_inventory_search_outputs_and_readable(self, mock_client, inventory_response, mocker):
        """Test that all expected fields are present in outputs and readable output."""
        mocker.patch.object(mock_client, "search_inventory", return_value=inventory_response)

        args = {
            "page": "1",
            "filter_json": '{"field": "risk_level", "operator": "eq", "value": "high"}',
        }
        result = koi_inventory_search_command(mock_client, args)

        # Verify readable output contains key data
        assert "Inventory Search" in result.readable_output
        assert "React Developer Tools" in result.readable_output
        assert "Meta" in result.readable_output

        # Verify outputs structure
        assert len(result.outputs) == 2
        item = result.outputs[0]
        assert item["item_id"] == "abc123"
        assert item["item_display_name"] == "React Developer Tools"
        assert item["marketplace"] == "chrome_web_store"
        assert item["version"] == "1.0.0"
        assert item["platforms"] == ["chrome", "edge"]
        assert item["publisher_name"] == "Meta"
        assert item["risk"] == 5
        assert item["risk_level"] == "high"
        assert item["status"] == "APPROVED"
        assert item["endpoint_count"] == 42
        assert item["installs_count"] == 1000000
        assert item["installation_method"] == "marketplace"
        assert item["is_first_party"] is False
        assert item["is_signed"] is True
        assert item["first_seen"] == "2024-01-01T10:00:00Z"
        assert item["last_seen"] == "2024-10-15T10:00:00Z"
        assert item["last_used"] == "2025-06-15T10:00:00Z"
        assert item["released_at"] == "2023-01-15"
        assert item["short_description"] == "React debugging tools"
        assert item["categories"] == ["Developer Tools"]
        assert item["findings"] == ["malware", "permissions"]
        assert "group-uuid-123" in item["governed_details"]
        assert item["governed_details"]["group-uuid-123"]["action"] == "allow"
        assert item["brew_category_koi"] == "Command Line Tools & Utilities"
        assert item["browser_category_koi"] == "Developer Tools"
        assert item["chocolatey_category_koi"] == "Command Line Tools & Utilities"
        assert item["ide_category_koi"] == "Language Support & Tooling"
        assert item["software_category_koi"] == "Docs tools"


class TestClientSearchInventory:
    """Tests for the Client.search_inventory method."""

    @pytest.mark.parametrize(
        "sort_by, sort_direction, expect_sort_in_body",
        [
            ("first_seen", "desc", True),
            (None, None, False),
        ],
        ids=["with_sorting", "without_sorting"],
    )
    def test_search_inventory_request(
        self, mock_client, inventory_response, mocker, sort_by, sort_direction, expect_sort_in_body
    ):
        """Test that search_inventory sends correct POST request with and without sorting."""
        mocker.patch.object(mock_client, "_http_request", return_value=inventory_response)

        filter_obj = {"field": "risk_level", "operator": "eq", "value": "high"}
        result = mock_client.search_inventory(
            page=1, page_size=100, filter_obj=filter_obj, sort_by=sort_by, sort_direction=sort_direction
        )

        call_kwargs = mock_client._http_request.call_args[1]
        assert call_kwargs["method"] == "POST"
        assert call_kwargs["url_suffix"] == ApiPaths.INVENTORY_SEARCH
        body = call_kwargs["json_data"]
        assert body["page"] == 1
        assert body["page_size"] == 100
        assert body["filter"] == filter_obj
        if expect_sort_in_body:
            assert body["sort_by"] == sort_by
            assert body["sort_direction"] == sort_direction
        else:
            assert "sort_by" not in body
            assert "sort_direction" not in body
        assert result == inventory_response

    def test_inventory_search_page_size_exceeds_max_raises_error(self, mock_client, mocker):
        """Test that page_size exceeding MAX_PAGE_SIZE raises ValueError."""
        args = {"page": "1", "page_size": "501", "filter_json": '{"field": "test"}'}
        with pytest.raises(DemistoException, match="page_size .* exceeds the maximum allowed value"):
            koi_inventory_search_command(mock_client, args)

    def test_inventory_search_limit_exceeds_max_raises_error(self, mock_client, mocker):
        """Test that limit exceeding MAX_LIMIT raises ValueError."""
        args = {"limit": "1001", "filter_json": '{"field": "test"}'}
        with pytest.raises(DemistoException, match="limit .* exceeds the maximum allowed value"):
            koi_inventory_search_command(mock_client, args)

    def test_search_inventory_api_error(self, mock_client, mocker):
        """Test that search_inventory propagates API errors."""
        mocker.patch.object(
            mock_client,
            "_http_request",
            side_effect=DemistoException("Error in API call [400] - Bad Request"),
        )

        with pytest.raises(DemistoException, match="Error in API call"):
            mock_client.search_inventory(page=1, page_size=100, filter_obj={"field": "test"})


# endregion

# region koi-inventory-item-endpoints-list tests


class TestKoiInventoryItemEndpointsListCommand:
    """Tests for the koi-inventory-item-endpoints-list command."""

    @pytest.mark.parametrize(
        "args, expected_version, expected_page, expected_page_size",
        [
            (
                {"item_id": "abc123", "marketplace": "chrome_web_store", "version": "1.0.0", "page": "1"},
                "1.0.0",
                1,
                Config.DEFAULT_PAGE_SIZE,
            ),
            (
                {"item_id": "abc123", "marketplace": "chrome_web_store", "version": "2.0.0", "page": "2", "page_size": "50"},
                "2.0.0",
                2,
                50,
            ),
            (
                {
                    "item_id": "abc123",
                    "marketplace": "chrome_web_store",
                    "version": "1.0.0",
                    "page": "3",
                    "page_size": "25",
                    "limit": "200",
                },
                "1.0.0",
                3,
                25,
            ),
        ],
        ids=["version_1_default_page_size", "explicit_version_and_page_size", "limit_ignored_when_page_provided"],
    )
    def test_endpoints_list_single_page(
        self,
        mock_client,
        inventory_item_endpoints_response,
        mocker,
        args,
        expected_version,
        expected_page,
        expected_page_size,
    ):
        """Test koi-inventory-item-endpoints-list in single-page mode with various argument combinations."""
        mocker.patch.object(mock_client, "get_inventory_item_endpoints", return_value=inventory_item_endpoints_response)

        result = koi_inventory_item_endpoints_list_command(mock_client, args)

        assert result.outputs_prefix == "Koi.Inventory.Endpoint"
        assert result.outputs_key_field == "id"
        assert len(result.outputs) == 2
        mock_client.get_inventory_item_endpoints.assert_called_once_with(
            item_id="abc123",
            marketplace="chrome_web_store",
            version=expected_version,
            page=expected_page,
            page_size=expected_page_size,
        )

    @pytest.mark.parametrize(
        "limit_arg, api_endpoint_count, expected_output_count",
        [
            ("500", Config.MAX_PAGE_SIZE, 500),
            ("500", 0, 0),
            ("500", 50, 50),
            ("10", Config.MAX_PAGE_SIZE, 10),
        ],
        ids=[
            "full_page_satisfies_limit",
            "empty_response",
            "partial_page_stops_pagination",
            "trims_to_limit",
        ],
    )
    def test_endpoints_list_auto_paginate_behavior(
        self, mock_client, mocker, limit_arg, api_endpoint_count, expected_output_count
    ):
        """Test auto-paginate behavior with various limit and API response combinations."""
        response = {
            "endpoints": [{"id": f"device-{i}"} for i in range(api_endpoint_count)],
            "total_count": api_endpoint_count,
        }
        mocker.patch.object(mock_client, "get_inventory_item_endpoints", return_value=response)

        args = {"item_id": "abc123", "marketplace": "chrome_web_store", "version": "1.0.0", "limit": limit_arg}
        result = koi_inventory_item_endpoints_list_command(mock_client, args)

        assert len(result.outputs) == expected_output_count

    def test_endpoints_list_outputs_and_readable(self, mock_client, inventory_item_endpoints_response, mocker):
        """Test that all expected fields are present in outputs and readable output."""
        mocker.patch.object(mock_client, "get_inventory_item_endpoints", return_value=inventory_item_endpoints_response)

        args = {"item_id": "abc123", "marketplace": "chrome_web_store", "version": "1.0.0", "page": "1"}
        result = koi_inventory_item_endpoints_list_command(mock_client, args)

        # Verify readable output
        assert "Inventory Item Endpoints" in result.readable_output
        assert "laptop-01" in result.readable_output
        assert "john.doe" in result.readable_output

        # Verify all fields in outputs
        assert len(result.outputs) == 2
        endpoint = result.outputs[0]
        assert endpoint["id"] == "device-123"
        assert endpoint["hostname"] == "laptop-01"
        assert endpoint["os"] == "windows"
        assert endpoint["platform"] == "chrome"
        assert endpoint["serial"] == "ABC123XYZ"
        assert endpoint["last_logged_on_user"] == "john.doe"
        assert endpoint["activation_status"] == "enabled"
        assert endpoint["path"] == "/Applications/Google Chrome.app/Contents/Extensions/abc123"
        assert endpoint["first_seen"] == "2024-01-01T10:00:00Z"
        assert endpoint["last_seen"] == "2024-10-15T10:00:00Z"

    @pytest.mark.parametrize(
        "args",
        [
            {"marketplace": "chrome_web_store"},
            {"item_id": "abc123"},
            {},
        ],
        ids=["missing_item_id", "missing_marketplace", "no_args"],
    )
    def test_endpoints_list_missing_required_args(self, mock_client, args):
        """Test that missing required arguments raises KeyError."""
        with pytest.raises(KeyError):
            koi_inventory_item_endpoints_list_command(mock_client, args)


class TestClientGetInventoryItemEndpoints:
    """Tests for the Client.get_inventory_item_endpoints method."""

    def test_get_inventory_item_endpoints_request(self, mock_client, inventory_item_endpoints_response, mocker):
        """Test that get_inventory_item_endpoints sends correct GET request."""
        mocker.patch.object(mock_client, "_http_request", return_value=inventory_item_endpoints_response)

        result = mock_client.get_inventory_item_endpoints(
            item_id="abc123", marketplace="chrome_web_store", version="1.0.0", page=1, page_size=100
        )

        call_kwargs = mock_client._http_request.call_args[1]
        assert call_kwargs["method"] == "GET"
        assert call_kwargs["url_suffix"] == ApiPaths.inventory_item_endpoints("abc123")
        assert call_kwargs["params"]["marketplace"] == "chrome_web_store"
        assert call_kwargs["params"]["version"] == "1.0.0"
        assert call_kwargs["params"]["page"] == 1
        assert call_kwargs["params"]["page_size"] == 100
        assert result == inventory_item_endpoints_response

    def test_inventory_item_endpoints_page_size_exceeds_max_raises_error(self, mock_client, mocker):
        """Test that page_size exceeding MAX_PAGE_SIZE raises ValueError."""
        args = {"item_id": "abc123", "marketplace": "chrome_web_store", "version": "1.0.0", "page": "1", "page_size": "501"}
        with pytest.raises(DemistoException, match="page_size .* exceeds the maximum allowed value"):
            koi_inventory_item_endpoints_list_command(mock_client, args)

    def test_inventory_item_endpoints_limit_exceeds_max_raises_error(self, mock_client, mocker):
        """Test that limit exceeding MAX_LIMIT raises ValueError."""
        args = {"item_id": "abc123", "marketplace": "chrome_web_store", "version": "1.0.0", "limit": "1001"}
        with pytest.raises(DemistoException, match="limit .* exceeds the maximum allowed value"):
            koi_inventory_item_endpoints_list_command(mock_client, args)

    def test_get_inventory_item_endpoints_api_error(self, mock_client, mocker):
        """Test that get_inventory_item_endpoints propagates API errors."""
        mocker.patch.object(
            mock_client,
            "_http_request",
            side_effect=DemistoException("Error in API call [404] - Not Found"),
        )

        with pytest.raises(DemistoException, match="Error in API call"):
            mock_client.get_inventory_item_endpoints(
                item_id="nonexistent", marketplace="chrome_web_store", version="1.0.0", page=1, page_size=100
            )


# endregion

# region Empty log_types guard tests


class TestEmptyLogTypesGuard:
    """Tests for the empty log_types guard in fetch_events_command."""

    def test_empty_event_types_to_fetch_does_not_crash(self, mock_client, mocker):
        """Test that an empty event_types_to_fetch param does not crash on ThreadPoolExecutor(max_workers=0)."""
        mocker.patch.object(
            demisto,
            "params",
            return_value={"max_fetch": "5000", "event_types_to_fetch": ""},
        )
        existing_last_run = {"last_fetch_alerts": "2024-01-01T00:00:00Z"}
        mocker.patch.object(demisto, "getLastRun", return_value=existing_last_run)
        mock_send = mocker.patch.object(mock_client, "send_events")
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")

        # Should return cleanly without raising
        fetch_events_command(mock_client)

        # No events sent
        mock_send.assert_not_called()
        # last_run preserved as-is
        mock_set_last_run.assert_called_once_with(existing_last_run)


# endregion

# region Client.send_events tests


class TestClientSendEvents:
    """Tests for the Client.send_events method."""

    def test_send_events_calls_send_events_to_xsiam(self, mock_client, mocker):
        """Test that send_events delegates to send_events_to_xsiam with correct vendor/product."""
        mock_send_to_xsiam = mocker.patch("Koi.send_events_to_xsiam")
        events = [{"id": "1", "_time": "2024-01-01T00:00:00Z"}, {"id": "2", "_time": "2024-01-01T00:00:01Z"}]

        mock_client.send_events(events)

        mock_send_to_xsiam.assert_called_once_with(events=events, vendor=Config.VENDOR, product=Config.PRODUCT)

    def test_send_events_with_empty_list(self, mock_client, mocker):
        """Test that send_events still calls send_events_to_xsiam when events list is empty."""
        mock_send_to_xsiam = mocker.patch("Koi.send_events_to_xsiam")

        mock_client.send_events([])

        mock_send_to_xsiam.assert_called_once_with(events=[], vendor=Config.VENDOR, product=Config.PRODUCT)


# endregion
