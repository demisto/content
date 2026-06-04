"""Unit tests for the O365 Message Trace integration."""

from datetime import datetime, timedelta, UTC
from unittest.mock import MagicMock

import pytest

import O365MessageTrace
from O365MessageTrace import (
    Client,
    Config,
    add_time_field,
    auth_test_command,
    deduplicate_events,
    fetch_events,
    fetch_events_sequential,
    format_datetime_for_filter,
    get_events_command,
    module_health_check,
    parse_datetime,
)


# ============================================================================
# Fixtures
# ============================================================================
@pytest.fixture
def mock_client() -> Client:
    """Return a Client whose ``ms_client`` is a MagicMock (no real HTTP calls)."""
    client = Client.__new__(Client)  # bypass __init__ to avoid building MicrosoftClient
    client.ms_client = MagicMock()
    return client


@pytest.fixture
def sample_events() -> list[dict]:
    return [
        {
            "id": "evt-1",
            "receivedDateTime": "2025-01-01T10:00:00Z",
            "senderAddress": "alice@contoso.com",
            "recipientAddress": "bob@contoso.com",
            "subject": "Hello",
            "status": "Delivered",
        },
        {
            "id": "evt-2",
            "receivedDateTime": "2025-01-01T10:01:00Z",
            "senderAddress": "carol@contoso.com",
            "recipientAddress": "dave@contoso.com",
            "subject": "Re: Hello",
            "status": "Pending",
        },
    ]


# ============================================================================
# Helper tests
# ============================================================================
class TestParseDatetime:
    def test_returns_default_when_value_is_none(self):
        default = datetime(2025, 1, 1, tzinfo=UTC)
        assert parse_datetime(None, default=default) == default

    def test_returns_now_when_no_value_and_no_default(self):
        before = datetime.now(UTC)
        result = parse_datetime(None)
        after = datetime.now(UTC)
        assert before <= result <= after

    def test_parses_iso_string(self):
        result = parse_datetime("2025-01-01T10:00:00Z")
        assert result == datetime(2025, 1, 1, 10, 0, 0, tzinfo=UTC)

    def test_result_is_always_timezone_aware(self):
        result = parse_datetime("2025-01-01T10:00:00")
        assert result.tzinfo is not None


class TestFormatDatetimeForFilter:
    def test_formats_in_graph_filter_format(self):
        dt = datetime(2025, 1, 1, 10, 30, 45, tzinfo=UTC)
        assert format_datetime_for_filter(dt) == "2025-01-01T10:30:45Z"


class TestDeduplicateEvents:
    def test_returns_all_events_when_seen_ids_empty(self, sample_events):
        result = deduplicate_events(sample_events, set())
        assert result == sample_events

    def test_filters_out_seen_events(self, sample_events):
        result = deduplicate_events(sample_events, {"evt-1"})
        assert len(result) == 1
        assert result[0]["id"] == "evt-2"

    def test_filters_all_when_all_seen(self, sample_events):
        result = deduplicate_events(sample_events, {"evt-1", "evt-2"})
        assert result == []

    def test_keeps_events_without_id(self):
        events = [{"id": "evt-1"}, {"receivedDateTime": "2025-01-01T00:00:00Z"}]
        result = deduplicate_events(events, {"evt-1"})
        assert len(result) == 1
        assert result[0] == {"receivedDateTime": "2025-01-01T00:00:00Z"}


class TestAddTimeField:
    def test_adds_time_field_from_received_date_time(self, sample_events):
        add_time_field(sample_events)
        assert sample_events[0]["_time"] == "2025-01-01T10:00:00Z"
        assert sample_events[1]["_time"] == "2025-01-01T10:01:00Z"

    def test_no_time_field_when_received_missing(self):
        events = [{"id": "evt-1"}]
        add_time_field(events)
        assert "_time" not in events[0]


# ============================================================================
# Client.get_message_traces_page tests
# ============================================================================
class TestGetMessageTracesPage:
    def test_uses_next_link_when_provided(self, mock_client):
        mock_client.ms_client.http_request.return_value = {"value": [], "@odata.nextLink": None}

        mock_client.get_message_traces_page(next_link="https://graph.microsoft.com/next-page")

        mock_client.ms_client.http_request.assert_called_once_with(
            method="GET",
            full_url="https://graph.microsoft.com/next-page",
            url_suffix="",
            ok_codes=[200],
        )

    def test_uses_filter_when_no_next_link(self, mock_client):
        mock_client.ms_client.http_request.return_value = {"value": []}

        mock_client.get_message_traces_page(
            start_date="2025-01-01T00:00:00Z",
            end_date="2025-01-01T01:00:00Z",
            page_size=500,
        )

        call_args = mock_client.ms_client.http_request.call_args
        assert call_args.kwargs["method"] == "GET"
        assert call_args.kwargs["url_suffix"] == Config.MESSAGE_TRACES_PATH
        assert call_args.kwargs["ok_codes"] == [200]
        params = call_args.kwargs["params"]
        assert params["$top"] == 500
        assert "receivedDateTime ge 2025-01-01T00:00:00Z" in params["$filter"]
        assert "receivedDateTime le 2025-01-01T01:00:00Z" in params["$filter"]


# ============================================================================
# fetch_events_sequential tests
# ============================================================================
class TestFetchEventsSequential:
    def test_returns_empty_when_window_is_inverted(self, mock_client):
        end = datetime(2025, 1, 1, tzinfo=UTC)
        start = end + timedelta(hours=1)
        assert fetch_events_sequential(mock_client, start, end, max_events=100) == []
        mock_client.ms_client.http_request.assert_not_called()

    def test_returns_empty_when_window_is_zero(self, mock_client):
        moment = datetime(2025, 1, 1, tzinfo=UTC)
        assert fetch_events_sequential(mock_client, moment, moment, max_events=100) == []

    def test_collects_single_page(self, mock_client, sample_events):
        mock_client.ms_client.http_request.return_value = {"value": sample_events}
        start = datetime(2025, 1, 1, tzinfo=UTC)
        end = start + timedelta(minutes=5)

        result = fetch_events_sequential(mock_client, start, end, max_events=100)

        assert result == sample_events
        assert mock_client.ms_client.http_request.call_count == 1

    def test_follows_next_link_across_pages(self, mock_client):
        page1 = {
            "value": [{"id": "evt-1", "receivedDateTime": "2025-01-01T10:00:00Z"}],
            "@odata.nextLink": "https://graph.microsoft.com/next",
        }
        page2 = {"value": [{"id": "evt-2", "receivedDateTime": "2025-01-01T10:01:00Z"}]}
        mock_client.ms_client.http_request.side_effect = [page1, page2]

        start = datetime(2025, 1, 1, tzinfo=UTC)
        end = start + timedelta(minutes=5)
        result = fetch_events_sequential(mock_client, start, end, max_events=100)

        assert len(result) == 2
        assert [e["id"] for e in result] == ["evt-1", "evt-2"]
        assert mock_client.ms_client.http_request.call_count == 2

    def test_stops_at_max_events(self, mock_client):
        page1 = {
            "value": [{"id": f"evt-{i}"} for i in range(5)],
            "@odata.nextLink": "https://graph.microsoft.com/next",
        }
        mock_client.ms_client.http_request.return_value = page1

        start = datetime(2025, 1, 1, tzinfo=UTC)
        end = start + timedelta(minutes=5)
        result = fetch_events_sequential(mock_client, start, end, max_events=3)

        assert len(result) == 3
        # Only one call should be made because limit reached after first page
        assert mock_client.ms_client.http_request.call_count == 1

    def test_breaks_on_exception(self, mock_client, mocker):
        mock_client.ms_client.http_request.side_effect = Exception("API failure")
        # demisto.error writes to stdout in the mock - patch to keep test output clean
        mocker.patch.object(O365MessageTrace.demisto, "error")
        start = datetime(2025, 1, 1, tzinfo=UTC)
        end = start + timedelta(minutes=5)

        result = fetch_events_sequential(mock_client, start, end, max_events=100)

        assert result == []

    def test_handles_missing_value_key(self, mock_client):
        mock_client.ms_client.http_request.return_value = {}
        start = datetime(2025, 1, 1, tzinfo=UTC)
        end = start + timedelta(minutes=5)

        result = fetch_events_sequential(mock_client, start, end, max_events=100)

        assert result == []


# ============================================================================
# module_health_check tests
# ============================================================================
class TestModuleHealthCheck:
    def test_returns_ok_on_success(self, mock_client):
        mock_client.ms_client.grant_type = "client_credentials"
        mock_client.ms_client.http_request.return_value = {"value": []}

        assert module_health_check(mock_client) == "ok"

    def test_raises_for_authorization_code_flow(self, mock_client):
        from O365MessageTrace import AUTHORIZATION_CODE, DemistoException

        mock_client.ms_client.grant_type = AUTHORIZATION_CODE

        with pytest.raises(DemistoException, match="Test module is not available"):
            module_health_check(mock_client)

    def test_returns_authorization_error_on_401(self, mock_client):
        mock_client.ms_client.grant_type = "client_credentials"
        mock_client.ms_client.http_request.side_effect = Exception("Got 401 Unauthorized")

        result = module_health_check(mock_client)
        assert "Authorization Error" in result

    def test_returns_authorization_error_on_403(self, mock_client):
        mock_client.ms_client.grant_type = "client_credentials"
        mock_client.ms_client.http_request.side_effect = Exception("403 Forbidden")

        result = module_health_check(mock_client)
        assert "Authorization Error" in result

    def test_reraises_unexpected_errors(self, mock_client):
        mock_client.ms_client.grant_type = "client_credentials"
        mock_client.ms_client.http_request.side_effect = Exception("network timeout")

        with pytest.raises(Exception, match="network timeout"):
            module_health_check(mock_client)


# ============================================================================
# auth_test_command tests
# ============================================================================
class TestAuthTestCommand:
    def test_returns_success_message(self, mock_client):
        mock_client.ms_client.http_request.return_value = {"value": []}

        result = auth_test_command(mock_client)

        assert result.readable_output == "Authentication was successful."

    def test_raises_demisto_exception_on_failure(self, mock_client):
        from O365MessageTrace import DemistoException

        mock_client.ms_client.http_request.side_effect = Exception("boom")

        with pytest.raises(DemistoException, match="Authentication was not successful"):
            auth_test_command(mock_client)


# ============================================================================
# get_events_command tests
# ============================================================================
class TestGetEventsCommand:
    def test_returns_command_results_without_pushing(self, mock_client, sample_events, mocker):
        mock_client.ms_client.http_request.return_value = {"value": sample_events}
        send_mock = mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")

        args = {
            "limit": "10",
            "start_time": "2025-01-01T00:00:00Z",
            "end_time": "2025-01-01T01:00:00Z",
            "should_push_events": "false",
        }
        result = get_events_command(mock_client, args)

        assert result.outputs_prefix == "O365MessageTrace.Event"
        assert result.outputs_key_field == "id"
        assert len(result.outputs) == 2
        # _time should have been added
        assert all("_time" in e for e in result.outputs)
        send_mock.assert_not_called()

    def test_pushes_events_when_requested(self, mock_client, sample_events, mocker):
        mock_client.ms_client.http_request.return_value = {"value": sample_events}
        send_mock = mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")

        args = {
            "limit": "10",
            "start_time": "2025-01-01T00:00:00Z",
            "end_time": "2025-01-01T01:00:00Z",
            "should_push_events": "true",
        }
        get_events_command(mock_client, args)

        send_mock.assert_called_once()
        call_kwargs = send_mock.call_args.kwargs
        assert call_kwargs["vendor"] == Config.VENDOR
        assert call_kwargs["product"] == Config.PRODUCT
        assert len(call_kwargs["events"]) == 2

    def test_does_not_push_when_no_events(self, mock_client, mocker):
        mock_client.ms_client.http_request.return_value = {"value": []}
        send_mock = mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")

        args = {"limit": "10", "should_push_events": "true"}
        get_events_command(mock_client, args)

        send_mock.assert_not_called()

    def test_uses_default_limit_and_window(self, mock_client, mocker):
        """When no args supplied, the command should still execute and produce CommandResults."""
        mock_client.ms_client.http_request.return_value = {"value": []}
        mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")

        result = get_events_command(mock_client, {})

        assert result.outputs == []


# ============================================================================
# fetch_events tests
# ============================================================================
class TestFetchEvents:
    def test_first_run_uses_default_lookback(self, mock_client, sample_events, mocker):
        mocker.patch.object(O365MessageTrace.demisto, "getLastRun", return_value={})
        set_last_run = mocker.patch.object(O365MessageTrace.demisto, "setLastRun")
        send_mock = mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.return_value = {"value": sample_events}

        fetch_events(mock_client, max_events=100)

        send_mock.assert_called_once()
        assert len(send_mock.call_args.kwargs["events"]) == 2
        set_last_run.assert_called_once()
        new_state = set_last_run.call_args.args[0]
        assert "last_fetch" in new_state
        assert "seen_ids" in new_state

    def test_subsequent_run_uses_last_fetch(self, mock_client, sample_events, mocker):
        last_run = {"last_fetch": "2025-01-01T09:00:00Z", "seen_ids": []}
        mocker.patch.object(O365MessageTrace.demisto, "getLastRun", return_value=last_run)
        mocker.patch.object(O365MessageTrace.demisto, "setLastRun")
        mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.return_value = {"value": sample_events}

        fetch_events(mock_client, max_events=100)

        # First http call params should contain the last_fetch start
        first_call_params = mock_client.ms_client.http_request.call_args_list[0].kwargs["params"]
        assert "2025-01-01T09:00:00Z" in first_call_params["$filter"]

    def test_deduplicates_against_seen_ids(self, mock_client, sample_events, mocker):
        last_run = {"last_fetch": "2025-01-01T09:00:00Z", "seen_ids": ["evt-1"]}
        mocker.patch.object(O365MessageTrace.demisto, "getLastRun", return_value=last_run)
        mocker.patch.object(O365MessageTrace.demisto, "setLastRun")
        send_mock = mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.return_value = {"value": sample_events}

        fetch_events(mock_client, max_events=100)

        # evt-1 should have been filtered out
        sent_events = send_mock.call_args.kwargs["events"]
        assert len(sent_events) == 1
        assert sent_events[0]["id"] == "evt-2"

    def test_no_events_does_not_call_send(self, mock_client, mocker):
        mocker.patch.object(O365MessageTrace.demisto, "getLastRun", return_value={})
        mocker.patch.object(O365MessageTrace.demisto, "setLastRun")
        send_mock = mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.return_value = {"value": []}

        fetch_events(mock_client, max_events=100)

        send_mock.assert_not_called()

    def test_updates_high_water_mark_to_latest_event(self, mock_client, sample_events, mocker):
        mocker.patch.object(O365MessageTrace.demisto, "getLastRun", return_value={})
        set_last_run = mocker.patch.object(O365MessageTrace.demisto, "setLastRun")
        mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.return_value = {"value": sample_events}

        fetch_events(mock_client, max_events=100)

        new_state = set_last_run.call_args.args[0]
        # Latest event is evt-2 at 2025-01-01T10:01:00Z
        assert new_state["last_fetch"] == "2025-01-01T10:01:00Z"
        assert "evt-2" in new_state["seen_ids"]

    def test_merges_seen_ids_when_high_water_mark_unchanged(self, mock_client, mocker):
        """If new events share the same timestamp as the previous high-water mark, seen_ids should be merged."""
        last_run = {"last_fetch": "2025-01-01T10:00:00Z", "seen_ids": ["evt-old"]}
        new_events = [
            {"id": "evt-new", "receivedDateTime": "2025-01-01T10:00:00Z"},
        ]
        mocker.patch.object(O365MessageTrace.demisto, "getLastRun", return_value=last_run)
        set_last_run = mocker.patch.object(O365MessageTrace.demisto, "setLastRun")
        mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.return_value = {"value": new_events}

        fetch_events(mock_client, max_events=100)

        new_state = set_last_run.call_args.args[0]
        assert new_state["last_fetch"] == "2025-01-01T10:00:00Z"
        assert set(new_state["seen_ids"]) == {"evt-old", "evt-new"}
