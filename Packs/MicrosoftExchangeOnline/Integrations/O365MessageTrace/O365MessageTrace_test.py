"""Unit tests for the O365 Message Trace integration."""

from datetime import datetime, timedelta, UTC
from unittest.mock import MagicMock

import pytest

import O365MessageTrace
from O365MessageTrace import (
    Client,
    Config,
    add_time_field,
    add_unique_id_field,
    auth_test_command,
    deduplicate_events,
    fetch_events,
    fetch_events_sequential,
    format_datetime_for_filter,
    get_events_command,
    parse_datetime,
)

# Reference the production ``test_module`` entrypoint via an alias that does
# NOT start with ``test_``, so pytest does not try to collect it as a test
# case (which would fail with "fixture 'client' not found").
run_test_module = O365MessageTrace.test_module


# ============================================================================
# Fixtures
# ============================================================================
@pytest.fixture
def mock_client() -> Client:
    """Return a Client whose underlying ``ms_client`` is a MagicMock (no real HTTP calls).

    Bypasses ``__init__`` to avoid building the real :class:`MicrosoftClient`
    machinery (token retrieval, integration context, etc.). The integration
    code reaches Microsoft Graph through ``client.ms_client.http_request`` and
    inspects ``client.ms_client.grant_type``, so the mock exposes those via a
    nested ``MagicMock``.
    """
    client = Client.__new__(Client)  # bypass __init__
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
    """``deduplicate_events`` keys off the derived ``_unique_id`` field that
    ``add_unique_id_field`` populates from ``<id>|<recipientAddress>``. Events
    that lack a ``_unique_id`` are always kept (we cannot dedupe what we cannot
    uniquely identify).
    """

    def test_returns_all_events_when_seen_ids_empty(self, sample_events):
        add_unique_id_field(sample_events)
        result = deduplicate_events(sample_events, set())
        assert result == sample_events

    def test_filters_out_seen_events(self, sample_events):
        add_unique_id_field(sample_events)
        result = deduplicate_events(sample_events, {"evt-1|bob@contoso.com"})
        assert len(result) == 1
        assert result[0]["id"] == "evt-2"

    def test_filters_all_when_all_seen(self, sample_events):
        add_unique_id_field(sample_events)
        result = deduplicate_events(
            sample_events,
            {"evt-1|bob@contoso.com", "evt-2|dave@contoso.com"},
        )
        assert result == []

    def test_keeps_events_without_unique_id(self):
        events = [
            {"_unique_id": "evt-1|bob@contoso.com"},
            {"receivedDateTime": "2025-01-01T00:00:00Z"},
        ]
        result = deduplicate_events(events, {"evt-1|bob@contoso.com"})
        assert len(result) == 1
        assert result[0] == {"receivedDateTime": "2025-01-01T00:00:00Z"}


class TestAddTimeField:
    def test_adds_time_field_from_received_date_time(self, sample_events):
        add_time_field(sample_events)
        assert sample_events[0]["_time"] == "2025-01-01T10:00:00Z"
        assert sample_events[1]["_time"] == "2025-01-01T10:01:00Z"

    def test_fallback_time_field_when_received_missing(self):
        """Event Collectors require ``_time`` on every event - a fallback must be added."""
        events = [{"id": "evt-1"}]
        add_time_field(events)
        assert "_time" in events[0]
        assert events[0]["_time"]  # non-empty

    def test_fallback_time_field_when_received_empty(self):
        events = [{"id": "evt-1", "receivedDateTime": ""}]
        add_time_field(events)
        assert events[0]["_time"]  # non-empty fallback value


class TestAddUniqueIdField:
    def test_adds_unique_id_from_id_and_recipient(self, sample_events):
        add_unique_id_field(sample_events)
        assert sample_events[0]["_unique_id"] == "evt-1|bob@contoso.com"
        assert sample_events[1]["_unique_id"] == "evt-2|dave@contoso.com"

    def test_does_not_mutate_original_id(self, sample_events):
        add_unique_id_field(sample_events)
        assert sample_events[0]["id"] == "evt-1"
        assert sample_events[1]["id"] == "evt-2"

    def test_skips_event_when_recipient_missing(self):
        events = [{"id": "evt-1"}]
        add_unique_id_field(events)
        assert "_unique_id" not in events[0]
        assert events[0]["id"] == "evt-1"

    def test_skips_event_when_id_missing(self):
        events = [{"recipientAddress": "bob@contoso.com"}]
        add_unique_id_field(events)
        assert "_unique_id" not in events[0]

    def test_skips_event_when_id_empty_string(self):
        events = [{"id": "", "recipientAddress": "bob@contoso.com"}]
        add_unique_id_field(events)
        assert "_unique_id" not in events[0]
        assert events[0]["id"] == ""

    def test_skips_event_when_recipient_empty_string(self):
        events = [{"id": "evt-1", "recipientAddress": ""}]
        add_unique_id_field(events)
        assert "_unique_id" not in events[0]
        assert events[0]["id"] == "evt-1"

    def test_skips_event_when_both_empty_strings(self):
        events = [{"id": "", "recipientAddress": ""}]
        add_unique_id_field(events)
        assert "_unique_id" not in events[0]
        assert events[0]["id"] == ""
        assert events[0]["recipientAddress"] == ""

    def test_handles_empty_event_list(self):
        events: list[dict] = []
        add_unique_id_field(events)
        assert events == []

    def test_processes_mixed_valid_and_invalid_events(self):
        events = [
            {"id": "evt-1", "recipientAddress": "bob@contoso.com"},
            {"id": "evt-2"},  # missing recipient
            {"recipientAddress": "dave@contoso.com"},  # missing id
            {"id": "evt-4", "recipientAddress": "alice@contoso.com"},
        ]
        add_unique_id_field(events)
        assert events[0]["_unique_id"] == "evt-1|bob@contoso.com"
        assert "_unique_id" not in events[1]
        assert "_unique_id" not in events[2]
        assert events[3]["_unique_id"] == "evt-4|alice@contoso.com"


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

    def test_fetches_all_pages_then_truncates_to_max_events(self, mock_client):
        """All pages are fetched while @odata.nextLink exists, even when the running
        count already exceeds max_events. The result is then truncated to max_events."""
        page1 = {
            "value": [
                {"id": "evt-3", "receivedDateTime": "2025-01-01T10:03:00Z"},
                {"id": "evt-2", "receivedDateTime": "2025-01-01T10:02:00Z"},
            ],
            "@odata.nextLink": "https://graph.microsoft.com/next",
        }
        page2 = {
            "value": [
                {"id": "evt-1", "receivedDateTime": "2025-01-01T10:01:00Z"},
                {"id": "evt-0", "receivedDateTime": "2025-01-01T10:00:00Z"},
            ],
        }
        mock_client.ms_client.http_request.side_effect = [page1, page2]

        start = datetime(2025, 1, 1, tzinfo=UTC)
        end = start + timedelta(minutes=5)
        result = fetch_events_sequential(mock_client, start, end, max_events=3)

        # Both pages must be fetched even though page1 already exceeded max_events.
        assert mock_client.ms_client.http_request.call_count == 2
        # After sorting ascending by receivedDateTime, the earliest 3 events are returned.
        assert len(result) == 3
        assert [e["id"] for e in result] == ["evt-0", "evt-1", "evt-2"]

    def test_returns_earliest_events_sorted_ascending(self, mock_client):
        """Events from all pages are sorted ascending by receivedDateTime so the
        earliest events come first, and max_events truncates from the start."""
        page1 = {
            "value": [{"id": "evt-late", "receivedDateTime": "2025-01-01T10:05:00Z"}],
            "@odata.nextLink": "https://graph.microsoft.com/next",
        }
        page2 = {
            "value": [{"id": "evt-early", "receivedDateTime": "2025-01-01T10:00:00Z"}],
        }
        mock_client.ms_client.http_request.side_effect = [page1, page2]

        start = datetime(2025, 1, 1, tzinfo=UTC)
        end = start + timedelta(minutes=10)
        result = fetch_events_sequential(mock_client, start, end, max_events=1)

        assert mock_client.ms_client.http_request.call_count == 2
        assert [e["id"] for e in result] == ["evt-early"]

    def test_reraises_when_first_page_fails(self, mock_client, mocker):
        """If the very first page fails we must propagate so lastRun is NOT advanced."""
        mock_client.ms_client.http_request.side_effect = Exception("API failure")
        mocker.patch.object(O365MessageTrace.demisto, "error")
        start = datetime(2025, 1, 1, tzinfo=UTC)
        end = start + timedelta(minutes=5)

        with pytest.raises(Exception, match="API failure"):
            fetch_events_sequential(mock_client, start, end, max_events=100)

    def test_returns_partial_when_later_page_fails(self, mock_client, mocker):
        """If a later page fails we keep the events collected so far."""
        page1 = {
            "value": [{"id": "evt-1", "receivedDateTime": "2025-01-01T10:00:00Z"}],
            "@odata.nextLink": "https://graph.microsoft.com/next",
        }
        mock_client.ms_client.http_request.side_effect = [page1, Exception("page 2 failure")]
        mocker.patch.object(O365MessageTrace.demisto, "error")
        start = datetime(2025, 1, 1, tzinfo=UTC)
        end = start + timedelta(minutes=5)

        result = fetch_events_sequential(mock_client, start, end, max_events=100)

        assert len(result) == 1
        assert result[0]["id"] == "evt-1"

    def test_handles_missing_value_key(self, mock_client):
        mock_client.ms_client.http_request.return_value = {}
        start = datetime(2025, 1, 1, tzinfo=UTC)
        end = start + timedelta(minutes=5)

        result = fetch_events_sequential(mock_client, start, end, max_events=100)

        assert result == []


# ============================================================================
# test_module tests
# ============================================================================
class TestModuleHealthCheck:
    def test_returns_ok_on_success(self, mock_client):
        mock_client.ms_client.grant_type = "client_credentials"
        mock_client.ms_client.http_request.return_value = {"value": []}

        assert run_test_module(mock_client) == "ok"

    def test_raises_for_authorization_code_flow(self, mock_client):
        from O365MessageTrace import AUTHORIZATION_CODE, DemistoException

        mock_client.ms_client.grant_type = AUTHORIZATION_CODE

        with pytest.raises(DemistoException, match="Test module is not available"):
            run_test_module(mock_client)

    def test_returns_authorization_error_on_401(self, mock_client, mocker):
        mock_client.ms_client.grant_type = "client_credentials"
        mock_client.ms_client.http_request.side_effect = Exception("Got 401 Unauthorized")
        mocker.patch.object(O365MessageTrace.demisto, "error")

        result = run_test_module(mock_client)
        assert "Authorization Error" in result

    def test_returns_authorization_error_on_403(self, mock_client, mocker):
        mock_client.ms_client.grant_type = "client_credentials"
        mock_client.ms_client.http_request.side_effect = Exception("403 Forbidden")
        mocker.patch.object(O365MessageTrace.demisto, "error")

        result = run_test_module(mock_client)
        assert "Authorization Error" in result

    def test_reraises_unexpected_errors(self, mock_client, mocker):
        mock_client.ms_client.grant_type = "client_credentials"
        mock_client.ms_client.http_request.side_effect = Exception("network timeout")
        mocker.patch.object(O365MessageTrace.demisto, "error")

        with pytest.raises(Exception, match="network timeout"):
            run_test_module(mock_client)


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
        outputs = result.outputs
        assert isinstance(outputs, list)
        assert len(outputs) == 2
        # _time should have been added
        assert all("_time" in e for e in outputs)
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

    def test_accepts_event_type_argument(self, mock_client, mocker):
        """The standard ``event_type`` argument must be accepted (and ignored)."""
        mock_client.ms_client.http_request.return_value = {"value": []}
        mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")

        result = get_events_command(mock_client, {"event_type": "message_trace"})

        assert result.outputs == []


# ============================================================================
# fetch_events tests
# ============================================================================
class TestFetchEvents:
    def test_first_run_uses_default_lookback(self, mock_client, sample_events, mocker):
        # Freeze ``now`` and shrink the first-fetch lookback to exactly one window
        # so the in-run loop walks a single window for this single-window assertion.
        now = datetime(2025, 1, 1, 10, 5, 0, tzinfo=UTC)

        class FrozenDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return now

        mocker.patch.object(O365MessageTrace, "datetime", FrozenDatetime)
        mocker.patch.object(O365MessageTrace.Config, "DEFAULT_FIRST_FETCH_MINUTES", Config.FETCH_WINDOW_MINUTES)
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
        # ``fetch_events`` deduplicates and tracks ``seen_ids`` using the derived
        # ``_unique_id`` field (``<id>|<recipientAddress>``). ``now`` is frozen one
        # window past ``last_fetch`` so a single window is walked for this assertion.
        now = datetime(2025, 1, 1, 9, 5, 0, tzinfo=UTC)

        class FrozenDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return now

        last_run = {"last_fetch": "2025-01-01T09:00:00Z", "seen_ids": ["evt-1|bob@contoso.com"]}
        mocker.patch.object(O365MessageTrace, "datetime", FrozenDatetime)
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
        # ``fetch_events`` stores the derived ``_unique_id`` (``<id>|<recipientAddress>``) in ``seen_ids``.
        assert "evt-2|dave@contoso.com" in new_state["seen_ids"]

    def test_merges_seen_ids_when_high_water_mark_unchanged(self, mock_client, mocker):
        """If new events share the same timestamp as the previous high-water mark, seen_ids should be merged."""
        last_run = {"last_fetch": "2025-01-01T10:00:00Z", "seen_ids": ["evt-old|bob@contoso.com"]}
        new_events = [
            {
                "id": "evt-new",
                "recipientAddress": "alice@contoso.com",
                "receivedDateTime": "2025-01-01T10:00:00Z",
            },
        ]
        mocker.patch.object(O365MessageTrace.demisto, "getLastRun", return_value=last_run)
        set_last_run = mocker.patch.object(O365MessageTrace.demisto, "setLastRun")
        mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.return_value = {"value": new_events}

        fetch_events(mock_client, max_events=100)

        new_state = set_last_run.call_args.args[0]
        assert new_state["last_fetch"] == "2025-01-01T10:00:00Z"
        assert set(new_state["seen_ids"]) == {"evt-old|bob@contoso.com", "evt-new|alice@contoso.com"}

    def test_first_page_failure_does_not_advance_last_run(self, mock_client, mocker):
        """If the very first page errors out, lastRun must NOT be advanced (data-loss protection)."""
        mocker.patch.object(O365MessageTrace.demisto, "getLastRun", return_value={})
        set_last_run = mocker.patch.object(O365MessageTrace.demisto, "setLastRun")
        mocker.patch.object(O365MessageTrace.demisto, "error")
        mock_client.ms_client.http_request.side_effect = Exception("API failure on first page")

        with pytest.raises(Exception, match="API failure"):
            fetch_events(mock_client, max_events=100)

        set_last_run.assert_not_called()

    def test_fetch_window_caps_end_at_window_minutes_when_behind(self, mock_client, mocker):
        """When far behind, a single run should only scan a FETCH_WINDOW_MINUTES slice.

        The window end must be ``last_fetch + FETCH_WINDOW_MINUTES`` (not ``now``),
        keeping each run small even with a large backlog.
        """
        last_run = {"last_fetch": "2025-01-01T09:00:00Z", "seen_ids": []}
        mocker.patch.object(O365MessageTrace.demisto, "getLastRun", return_value=last_run)
        mocker.patch.object(O365MessageTrace.demisto, "setLastRun")
        mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.return_value = {"value": []}

        fetch_events(mock_client, max_events=100)

        first_call_params = mock_client.ms_client.http_request.call_args_list[0].kwargs["params"]
        # Start at last_fetch, end exactly FETCH_WINDOW_MINUTES later.
        assert "2025-01-01T09:00:00Z" in first_call_params["$filter"]
        assert "2025-01-01T09:05:00Z" in first_call_params["$filter"]

    def test_empty_window_advances_last_fetch_to_window_end(self, mock_client, mocker):
        """An empty window must still move last_fetch forward to the window end.

        Otherwise we keep re-scanning the same empty slice and never make progress.
        ``now`` is frozen one window ahead of ``last_fetch`` so the in-run loop walks
        exactly one (empty) window and stops, leaving last_fetch at the window end.
        """
        now = datetime(2025, 1, 1, 9, 5, 0, tzinfo=UTC)

        class FrozenDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return now

        last_run = {"last_fetch": "2025-01-01T09:00:00Z", "seen_ids": ["evt-old|bob@contoso.com"]}
        mocker.patch.object(O365MessageTrace, "datetime", FrozenDatetime)
        mocker.patch.object(O365MessageTrace.demisto, "getLastRun", return_value=last_run)
        set_last_run = mocker.patch.object(O365MessageTrace.demisto, "setLastRun")
        mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.return_value = {"value": []}

        fetch_events(mock_client, max_events=100)

        new_state = set_last_run.call_args.args[0]
        assert new_state["last_fetch"] == "2025-01-01T09:05:00Z"
        # No events found, so seen_ids should be reset for the new high-water mark.
        assert new_state["seen_ids"] == []

    def test_window_end_capped_at_now_when_caught_up(self, mock_client, mocker):
        """When last_fetch + window would overshoot ``now``, the window must stop at ``now``."""
        now = datetime(2025, 1, 1, 9, 2, 0, tzinfo=UTC)

        class FrozenDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return now

        last_run = {"last_fetch": "2025-01-01T09:00:00Z", "seen_ids": []}
        mocker.patch.object(O365MessageTrace, "datetime", FrozenDatetime)
        mocker.patch.object(O365MessageTrace.demisto, "getLastRun", return_value=last_run)
        mocker.patch.object(O365MessageTrace.demisto, "setLastRun")
        mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.return_value = {"value": []}

        fetch_events(mock_client, max_events=100)

        first_call_params = mock_client.ms_client.http_request.call_args_list[0].kwargs["params"]
        # Window would be 09:05 but now is 09:02, so end is capped at now.
        assert "2025-01-01T09:02:00Z" in first_call_params["$filter"]
        assert "2025-01-01T09:05:00Z" not in first_call_params["$filter"]

    def test_seen_ids_keeps_all_ids_at_boundary_timestamp(self, mock_client, mocker):
        """All events sharing the high-water-mark timestamp must be retained in seen_ids.

        The Graph API timestamps have second-level granularity, so several events
        can share the exact same ``receivedDateTime``. If such events are split
        across two runs, the next run's ``$filter`` (``ge boundary``) re-fetches the
        ones already sent. They must still be recognized as duplicates, which
        requires ``seen_ids`` to hold the full set of IDs at the boundary timestamp
        - including events that were deduped out of this run's published events.
        """
        # Previous run already published evt-1 at the boundary timestamp (10:01:00).
        last_run = {"last_fetch": "2025-01-01T10:00:00Z", "seen_ids": ["evt-1|bob@contoso.com"]}
        fetched = [
            # evt-1 is a duplicate (already in seen_ids) sharing the boundary timestamp.
            {"id": "evt-1", "recipientAddress": "bob@contoso.com", "receivedDateTime": "2025-01-01T10:01:00Z"},
            # evt-2 is new but shares the same boundary timestamp.
            {"id": "evt-2", "recipientAddress": "dave@contoso.com", "receivedDateTime": "2025-01-01T10:01:00Z"},
        ]
        mocker.patch.object(O365MessageTrace.demisto, "getLastRun", return_value=last_run)
        set_last_run = mocker.patch.object(O365MessageTrace.demisto, "setLastRun")
        mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.return_value = {"value": fetched}

        fetch_events(mock_client, max_events=100)

        new_state = set_last_run.call_args.args[0]
        assert new_state["last_fetch"] == "2025-01-01T10:01:00Z"
        # Both the newly-sent event AND the already-seen duplicate at the boundary
        # timestamp must be present so the next run can dedup the re-fetched event.
        assert set(new_state["seen_ids"]) == {"evt-1|bob@contoso.com", "evt-2|dave@contoso.com"}


# ============================================================================
# fetch_events in-run window loop tests
# ============================================================================
class TestFetchEventsInRunLoop:
    """The in-run loop must walk consecutive windows oldest->newest within a
    single run instead of advancing only one ``FETCH_WINDOW_MINUTES`` slice per
    scheduler tick. After each window it decides:

    * ``max_events`` reached -> break (resume at the high-water mark next run),
    * caught up to ``now`` -> break,
    * otherwise advance ``start_dt`` to the next window and continue.

    ``last_run`` is persisted exactly once at the end of the run.
    """

    @staticmethod
    def _frozen_now(now: datetime):
        class FrozenDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return now

        return FrozenDatetime

    def test_walks_multiple_windows_until_caught_up_in_single_run(self, mock_client, mocker):
        """A backlog of several windows must be drained within one run, advancing
        ``last_fetch`` all the way to ``now`` (not just one window)."""
        # last_fetch=09:00, now=09:15 -> 3 windows: [09:00,09:05], [09:05,09:10], [09:10,09:15].
        now = datetime(2025, 1, 1, 9, 15, 0, tzinfo=UTC)
        last_run = {"last_fetch": "2025-01-01T09:00:00Z", "seen_ids": []}
        mocker.patch.object(O365MessageTrace, "datetime", self._frozen_now(now))
        mocker.patch.object(O365MessageTrace.demisto, "getLastRun", return_value=last_run)
        set_last_run = mocker.patch.object(O365MessageTrace.demisto, "setLastRun")
        mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.return_value = {"value": []}

        fetch_events(mock_client, max_events=100)

        # One first-page request per window (all empty).
        assert mock_client.ms_client.http_request.call_count == 3
        # last_run persisted exactly once at the end of the run.
        set_last_run.assert_called_once()
        assert set_last_run.call_args.args[0]["last_fetch"] == "2025-01-01T09:15:00Z"

    def test_first_call_starts_at_oldest_window(self, mock_client, mocker):
        """The loop must walk oldest->newest: the first request is the oldest window."""
        now = datetime(2025, 1, 1, 9, 15, 0, tzinfo=UTC)
        last_run = {"last_fetch": "2025-01-01T09:00:00Z", "seen_ids": []}
        mocker.patch.object(O365MessageTrace, "datetime", self._frozen_now(now))
        mocker.patch.object(O365MessageTrace.demisto, "getLastRun", return_value=last_run)
        mocker.patch.object(O365MessageTrace.demisto, "setLastRun")
        mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.return_value = {"value": []}

        fetch_events(mock_client, max_events=100)

        first_filter = mock_client.ms_client.http_request.call_args_list[0].kwargs["params"]["$filter"]
        assert "receivedDateTime ge 2025-01-01T09:00:00Z" in first_filter
        assert "receivedDateTime le 2025-01-01T09:05:00Z" in first_filter
        last_filter = mock_client.ms_client.http_request.call_args_list[-1].kwargs["params"]["$filter"]
        assert "receivedDateTime ge 2025-01-01T09:10:00Z" in last_filter
        assert "receivedDateTime le 2025-01-01T09:15:00Z" in last_filter

    def test_stops_advancing_when_max_events_reached(self, mock_client, mocker):
        """When a window fills up to ``max_events`` the loop breaks and resumes at the
        high-water mark next run - it must NOT advance to later windows in this run."""
        now = datetime(2025, 1, 1, 9, 15, 0, tzinfo=UTC)
        last_run = {"last_fetch": "2025-01-01T09:00:00Z", "seen_ids": []}
        # First window already returns >= max_events events.
        full_window = {
            "value": [
                {"id": "a", "recipientAddress": "bob@contoso.com", "receivedDateTime": "2025-01-01T09:01:00Z"},
                {"id": "b", "recipientAddress": "bob@contoso.com", "receivedDateTime": "2025-01-01T09:02:00Z"},
            ]
        }
        mocker.patch.object(O365MessageTrace, "datetime", self._frozen_now(now))
        mocker.patch.object(O365MessageTrace.demisto, "getLastRun", return_value=last_run)
        set_last_run = mocker.patch.object(O365MessageTrace.demisto, "setLastRun")
        mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.return_value = full_window

        fetch_events(mock_client, max_events=2)

        # Only the first window should have been requested - the loop broke on max_events.
        assert mock_client.ms_client.http_request.call_count == 1
        set_last_run.assert_called_once()
        # High-water mark set to the latest event timestamp so the next run resumes there.
        assert set_last_run.call_args.args[0]["last_fetch"] == "2025-01-01T09:02:00Z"

    def test_publishes_events_from_every_window_in_run(self, mock_client, mocker):
        """Events from each window walked in a single run must all be published."""
        now = datetime(2025, 1, 1, 9, 10, 0, tzinfo=UTC)
        last_run = {"last_fetch": "2025-01-01T09:00:00Z", "seen_ids": []}
        window1 = {"value": [{"id": "w1", "recipientAddress": "bob@contoso.com", "receivedDateTime": "2025-01-01T09:01:00Z"}]}
        window2 = {"value": [{"id": "w2", "recipientAddress": "bob@contoso.com", "receivedDateTime": "2025-01-01T09:06:00Z"}]}
        mocker.patch.object(O365MessageTrace, "datetime", self._frozen_now(now))
        mocker.patch.object(O365MessageTrace.demisto, "getLastRun", return_value=last_run)
        mocker.patch.object(O365MessageTrace.demisto, "setLastRun")
        send_mock = mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.side_effect = [window1, window2]

        fetch_events(mock_client, max_events=100)

        sent_ids = {e["id"] for call in send_mock.call_args_list for e in call.kwargs["events"]}
        assert sent_ids == {"w1", "w2"}

    def test_window_loop_cannot_spin_when_high_water_mark_stalls(self, mock_client, mocker):
        """Guard: if a non-empty window's high-water mark fails to advance past the
        window start, the loop must still advance to the next window (using the
        window end) instead of spinning forever on the same slice.

        Every event here sits exactly at the window start timestamp, so a naive
        ``last_fetch = latest_event_time`` would never move ``start_dt`` forward.
        """
        now = datetime(2025, 1, 1, 9, 10, 0, tzinfo=UTC)
        last_run = {"last_fetch": "2025-01-01T09:00:00Z", "seen_ids": []}
        # Both windows return an event stamped at the window's own start time.
        stalled_event = {
            "value": [{"id": "s", "recipientAddress": "bob@contoso.com", "receivedDateTime": "2025-01-01T09:00:00Z"}]
        }
        mocker.patch.object(O365MessageTrace, "datetime", self._frozen_now(now))
        mocker.patch.object(O365MessageTrace.demisto, "getLastRun", return_value=last_run)
        set_last_run = mocker.patch.object(O365MessageTrace.demisto, "setLastRun")
        mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.return_value = stalled_event

        fetch_events(mock_client, max_events=100)

        # The loop must terminate (caught up to now) rather than spin, and persist once.
        set_last_run.assert_called_once()
        # Two windows walked: [09:00,09:05] and [09:05,09:10]; the guard advanced via window end.
        assert mock_client.ms_client.http_request.call_count == 2

    def test_persists_last_run_once_per_run(self, mock_client, mocker):
        """``demisto.setLastRun`` must be called exactly once regardless of how many
        windows are walked in a single run."""
        now = datetime(2025, 1, 1, 9, 20, 0, tzinfo=UTC)  # 4 windows
        last_run = {"last_fetch": "2025-01-01T09:00:00Z", "seen_ids": []}
        mocker.patch.object(O365MessageTrace, "datetime", self._frozen_now(now))
        mocker.patch.object(O365MessageTrace.demisto, "getLastRun", return_value=last_run)
        set_last_run = mocker.patch.object(O365MessageTrace.demisto, "setLastRun")
        mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.return_value = {"value": []}

        fetch_events(mock_client, max_events=100)

        set_last_run.assert_called_once()
