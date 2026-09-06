"""Unit tests for the O365 Message Trace integration."""

from datetime import datetime, UTC
from unittest.mock import MagicMock

import pytest

import demistomock as demisto
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
    parse_integration_params,
)

# Reference the production ``test_module`` entrypoint via an alias that does
# NOT start with ``test_``, so pytest does not try to collect it as a test
# case (which would fail with "fixture 'client' not found").
run_test_module = O365MessageTrace.test_module


# ============================================================================
# Fixtures
# ============================================================================
@pytest.fixture(autouse=True)
def _silence_demisto_logging(mocker):
    """Silence ``demisto.debug``/``error``/``info`` so the repo conftest does not fail tests
    that exercise logging-heavy error/guard paths (it fails any test that writes to stdout)."""
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "error")
    mocker.patch.object(demisto, "info")


@pytest.fixture
def mock_client() -> Client:
    """Return a Client whose underlying ``ms_client`` is a MagicMock (no real HTTP calls)."""
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

    def test_parses_iso_string_to_utc(self):
        result = parse_datetime("2025-01-01T10:00:00Z")
        assert result == datetime(2025, 1, 1, 10, 0, 0, tzinfo=UTC)


class TestFormatDatetimeForFilter:
    def test_formats_datetime(self):
        dt = datetime(2025, 1, 1, 10, 0, 0, tzinfo=UTC)
        assert format_datetime_for_filter(dt) == "2025-01-01T10:00:00.000000Z"


class TestDeduplicateEvents:
    """``deduplicate_events`` keys off the ``_unique_id`` field."""

    def test_returns_all_events_when_seen_ids_empty(self, sample_events):
        add_unique_id_field(sample_events)
        assert deduplicate_events(sample_events, set()) == sample_events

    def test_filters_out_seen_events(self, sample_events):
        add_unique_id_field(sample_events)
        seen = {sample_events[0]["_unique_id"]}
        result = deduplicate_events(sample_events, seen)
        assert len(result) == 1
        assert result[0]["id"] == "evt-2"

    def test_filters_all_when_all_seen(self, sample_events):
        add_unique_id_field(sample_events)
        seen = {event["_unique_id"] for event in sample_events}
        assert deduplicate_events(sample_events, seen) == []

    def test_keeps_events_without_unique_id(self):
        events = [{"foo": "bar"}]
        assert deduplicate_events(events, {"x"}) == events


class TestAddTimeField:
    def test_adds_time_field_from_received_date_time(self, sample_events):
        add_time_field(sample_events)
        assert sample_events[0]["_time"] == "2025-01-01T10:00:00Z"

    def test_fallback_time_field_when_received_missing(self):
        events = [{"id": "x"}]
        add_time_field(events)
        assert events[0]["_time"]

    def test_fallback_time_field_when_received_empty(self):
        events = [{"id": "x", "receivedDateTime": ""}]
        add_time_field(events)
        assert events[0]["_time"]


class TestAddUniqueIdField:
    def test_adds_unique_id_from_id_and_recipient(self, sample_events):
        add_unique_id_field(sample_events)
        assert sample_events[0]["_unique_id"] == "evt-1|bob@contoso.com"
        assert sample_events[1]["_unique_id"] == "evt-2|dave@contoso.com"

    def test_does_not_mutate_original_id(self, sample_events):
        add_unique_id_field(sample_events)
        assert sample_events[0]["id"] == "evt-1"

    def test_skips_event_when_recipient_missing(self):
        events = [{"id": "evt-1"}]
        add_unique_id_field(events)
        assert "_unique_id" not in events[0]

    def test_skips_event_when_id_missing(self):
        events = [{"recipientAddress": "bob@contoso.com"}]
        add_unique_id_field(events)
        assert "_unique_id" not in events[0]

    def test_skips_event_when_id_empty_string(self):
        events = [{"id": "", "recipientAddress": "bob@contoso.com"}]
        add_unique_id_field(events)
        assert "_unique_id" not in events[0]

    def test_skips_event_when_recipient_empty_string(self):
        events = [{"id": "evt-1", "recipientAddress": ""}]
        add_unique_id_field(events)
        assert "_unique_id" not in events[0]

    def test_handles_empty_event_list(self):
        events: list[dict] = []
        add_unique_id_field(events)
        assert events == []

    def test_processes_mixed_valid_and_invalid_events(self):
        events = [
            {"id": "evt-1", "recipientAddress": "bob@contoso.com"},
            {"id": "evt-2"},
        ]
        add_unique_id_field(events)
        assert events[0]["_unique_id"] == "evt-1|bob@contoso.com"
        assert "_unique_id" not in events[1]


# ============================================================================
# get_message_traces_page tests
# ============================================================================
class TestGetMessageTracesPage:
    def test_uses_next_link_when_provided(self, mock_client):
        mock_client.ms_client.http_request.return_value = {"value": []}
        mock_client.get_message_traces_page(next_link="https://graph.microsoft.com/next")
        kwargs = mock_client.ms_client.http_request.call_args.kwargs
        assert kwargs["full_url"] == "https://graph.microsoft.com/next"

    def test_uses_filter_when_no_next_link(self, mock_client):
        mock_client.ms_client.http_request.return_value = {"value": []}
        mock_client.get_message_traces_page(
            start_date="2025-01-01T00:00:00Z",
            end_date="2025-01-01T01:00:00Z",
        )
        params = mock_client.ms_client.http_request.call_args.kwargs["params"]
        assert "receivedDateTime ge 2025-01-01T00:00:00Z" in params["$filter"]
        assert "receivedDateTime le 2025-01-01T01:00:00Z" in params["$filter"]

    def test_uses_default_page_size(self, mock_client):
        mock_client.ms_client.http_request.return_value = {"value": []}
        mock_client.get_message_traces_page(
            start_date="2025-01-01T00:00:00Z",
            end_date="2025-01-01T01:00:00Z",
        )
        params = mock_client.ms_client.http_request.call_args.kwargs["params"]
        assert params["$top"] == 5000


# ============================================================================
# parse_integration_params tests
# ============================================================================
class TestParseIntegrationParams:
    """``parse_integration_params`` normalizes the raw ``demisto.params()`` dict."""

    @pytest.fixture(autouse=True)
    def _patch_azure_helpers(self, mocker):
        fake_cloud = MagicMock()
        fake_cloud.endpoints.microsoft_graph_resource_id = "https://graph.microsoft.com"
        mocker.patch.object(O365MessageTrace, "get_azure_cloud", return_value=fake_cloud)
        self.managed_identity_mock = mocker.patch.object(
            O365MessageTrace, "get_azure_managed_identities_client_id", return_value=None
        )

    @staticmethod
    def _client_credentials_params(**overrides) -> dict:
        params = {
            "tenant_id": "tenant-123",
            "credentials_client_id": {"password": "client-abc"},
            "credentials": {"password": "secret-xyz"},
        }
        params.update(overrides)
        return params

    def test_returns_valid_config_for_client_credentials(self):
        result = parse_integration_params(self._client_credentials_params())
        assert result["tenant_id"] == "tenant-123"
        assert result["auth_id"] == "client-abc"
        assert result["enc_key"] == "secret-xyz"
        assert result["app_name"] == Config.APP_NAME
        assert result["auth_code"] is None
        assert result["redirect_uri"] is None
        assert result["managed_identities_client_id"] is None

    def test_falls_back_to_legacy_plain_client_secret(self):
        params = self._client_credentials_params()
        del params["credentials"]
        params["client_secret"] = "legacy-secret"
        result = parse_integration_params(params)
        assert result["enc_key"] == "legacy-secret"

    def test_authorization_code_happy_path(self):
        params = self._client_credentials_params(
            auth_code={"password": "the-auth-code"},
            redirect_uri="https://example.com/callback",
        )
        result = parse_integration_params(params)
        assert result["auth_code"] == "the-auth-code"
        assert result["redirect_uri"] == "https://example.com/callback"

    def test_managed_identities_skips_credential_validation(self):
        self.managed_identity_mock.return_value = "mi-client-id"
        result = parse_integration_params({"tenant_id": "tenant-123"})
        assert result["managed_identities_client_id"] == "mi-client-id"

    def test_certificate_thumbprint_and_private_key_parsed(self):
        params = self._client_credentials_params(
            creds_certificate={"identifier": "THUMB", "password": "PRIVATE_KEY"},
        )
        result = parse_integration_params(params)
        assert result["certificate_thumbprint"] == "THUMB"
        assert result["private_key"] is not None

    def test_private_key_is_none_when_not_provided(self):
        result = parse_integration_params(self._client_credentials_params())
        assert result["private_key"] is None

    def test_raises_when_client_credentials_missing_tenant(self):
        params = self._client_credentials_params()
        del params["tenant_id"]
        with pytest.raises(O365MessageTrace.DemistoException):
            parse_integration_params(params)

    def test_raises_when_client_credentials_missing_secret(self):
        params = self._client_credentials_params()
        del params["credentials"]
        with pytest.raises(O365MessageTrace.DemistoException):
            parse_integration_params(params)

    def test_raises_when_authorization_code_flow_missing_fields(self):
        params = {
            "tenant_id": "tenant-123",
            "credentials_client_id": {"password": "client-abc"},
            "auth_code": {"password": "the-auth-code"},
            "redirect_uri": "https://example.com/callback",
        }
        with pytest.raises(O365MessageTrace.DemistoException):
            parse_integration_params(params)

    def test_raises_when_no_credential_provided(self):
        params = {
            "tenant_id": "tenant-123",
            "credentials_client_id": {"password": "client-abc"},
        }
        with pytest.raises(O365MessageTrace.DemistoException):
            parse_integration_params(params)

    def test_default_max_events_when_not_supplied(self):
        result = parse_integration_params(self._client_credentials_params())
        assert result["max_events"] == Config.DEFAULT_MAX_EVENTS

    def test_custom_max_events_parsed_from_max_fetch(self):
        result = parse_integration_params(self._client_credentials_params(max_fetch="250"))
        assert result["max_events"] == 250

    def test_default_base_url_built_from_azure_cloud(self):
        result = parse_integration_params(self._client_credentials_params())
        assert result["base_url"] == "https://graph.microsoft.com/"

    def test_explicit_url_param_overrides_default_and_is_normalized(self):
        result = parse_integration_params(self._client_credentials_params(url="https://custom.graph"))
        assert result["base_url"] == "https://custom.graph/"

    def test_verify_and_proxy_flags_parsed(self):
        result = parse_integration_params(self._client_credentials_params(insecure=True, proxy=True))
        assert result["verify"] is False
        assert result["proxy"] is True


# ============================================================================
# fetch_events_sequential tests
# ============================================================================
class TestFetchEventsSequential:
    def test_returns_empty_when_window_is_inverted(self, mock_client):
        start = datetime(2025, 1, 1, 11, 0, 0, tzinfo=UTC)
        end = datetime(2025, 1, 1, 10, 0, 0, tzinfo=UTC)
        assert fetch_events_sequential(mock_client, start, end, max_events=100) == []

    def test_collects_single_page(self, mock_client, sample_events):
        mock_client.ms_client.http_request.return_value = {"value": sample_events}
        start = datetime(2025, 1, 1, 10, 0, 0, tzinfo=UTC)
        end = datetime(2025, 1, 1, 11, 0, 0, tzinfo=UTC)
        result = fetch_events_sequential(mock_client, start, end, max_events=100)
        assert len(result) == 2

    def test_follows_next_link_across_pages(self, mock_client):
        page1 = {
            "value": [{"id": "1", "receivedDateTime": "2025-01-01T10:00:00Z"}],
            "@odata.nextLink": "https://graph.microsoft.com/next",
        }
        page2 = {"value": [{"id": "2", "receivedDateTime": "2025-01-01T10:01:00Z"}]}
        mock_client.ms_client.http_request.side_effect = [page1, page2]
        start = datetime(2025, 1, 1, 10, 0, 0, tzinfo=UTC)
        end = datetime(2025, 1, 1, 11, 0, 0, tzinfo=UTC)
        result = fetch_events_sequential(mock_client, start, end, max_events=100)
        assert len(result) == 2

    def test_truncates_to_max_events(self, mock_client):
        events = [{"id": str(i), "receivedDateTime": f"2025-01-01T10:0{i}:00Z"} for i in range(5)]
        mock_client.ms_client.http_request.return_value = {"value": events}
        start = datetime(2025, 1, 1, 10, 0, 0, tzinfo=UTC)
        end = datetime(2025, 1, 1, 11, 0, 0, tzinfo=UTC)
        result = fetch_events_sequential(mock_client, start, end, max_events=3)
        assert len(result) == 3

    def test_returns_earliest_events_sorted_ascending(self, mock_client):
        events = [
            {"id": "late", "receivedDateTime": "2025-01-01T10:05:00Z"},
            {"id": "early", "receivedDateTime": "2025-01-01T10:01:00Z"},
        ]
        mock_client.ms_client.http_request.return_value = {"value": events}
        start = datetime(2025, 1, 1, 10, 0, 0, tzinfo=UTC)
        end = datetime(2025, 1, 1, 11, 0, 0, tzinfo=UTC)
        result = fetch_events_sequential(mock_client, start, end, max_events=100)
        assert result[0]["id"] == "early"
        assert result[1]["id"] == "late"

    def test_reraises_when_first_page_fails(self, mock_client):
        mock_client.ms_client.http_request.side_effect = Exception("boom")
        start = datetime(2025, 1, 1, 10, 0, 0, tzinfo=UTC)
        end = datetime(2025, 1, 1, 11, 0, 0, tzinfo=UTC)
        with pytest.raises(Exception, match="boom"):
            fetch_events_sequential(mock_client, start, end, max_events=100)

    def test_returns_partial_when_later_page_fails(self, mock_client):
        page1 = {
            "value": [{"id": "1", "receivedDateTime": "2025-01-01T10:00:00Z"}],
            "@odata.nextLink": "https://graph.microsoft.com/next",
        }
        mock_client.ms_client.http_request.side_effect = [page1, Exception("boom")]
        start = datetime(2025, 1, 1, 10, 0, 0, tzinfo=UTC)
        end = datetime(2025, 1, 1, 11, 0, 0, tzinfo=UTC)
        result = fetch_events_sequential(mock_client, start, end, max_events=100)
        assert len(result) == 1

    def test_handles_missing_value_key(self, mock_client):
        mock_client.ms_client.http_request.return_value = {}
        start = datetime(2025, 1, 1, 10, 0, 0, tzinfo=UTC)
        end = datetime(2025, 1, 1, 11, 0, 0, tzinfo=UTC)
        assert fetch_events_sequential(mock_client, start, end, max_events=100) == []

    def test_stops_on_non_advancing_next_link(self, mock_client):
        page = {
            "value": [{"id": "1", "receivedDateTime": "2025-01-01T10:00:00Z"}],
            "@odata.nextLink": "https://graph.microsoft.com/same",
        }
        mock_client.ms_client.http_request.return_value = page
        start = datetime(2025, 1, 1, 10, 0, 0, tzinfo=UTC)
        end = datetime(2025, 1, 1, 11, 0, 0, tzinfo=UTC)
        result = fetch_events_sequential(mock_client, start, end, max_events=100)
        # First page collected, then the repeated next_link trips the non-advancing guard.
        assert len(result) == 2

    def test_stops_on_empty_page_with_next_link(self, mock_client):
        page = {"value": [], "@odata.nextLink": "https://graph.microsoft.com/next"}
        mock_client.ms_client.http_request.return_value = page
        start = datetime(2025, 1, 1, 10, 0, 0, tzinfo=UTC)
        end = datetime(2025, 1, 1, 11, 0, 0, tzinfo=UTC)
        assert fetch_events_sequential(mock_client, start, end, max_events=100) == []


# ============================================================================
# Command tests
# ============================================================================
class TestModuleHealthCheck:
    def test_returns_ok_on_success(self, mock_client):
        mock_client.ms_client.grant_type = O365MessageTrace.CLIENT_CREDENTIALS
        mock_client.ms_client.http_request.return_value = {"value": []}
        assert run_test_module(mock_client) == "ok"

    def test_raises_for_authorization_code_flow(self, mock_client):
        mock_client.ms_client.grant_type = O365MessageTrace.AUTHORIZATION_CODE
        with pytest.raises(O365MessageTrace.DemistoException):
            run_test_module(mock_client)

    def test_returns_authorization_error_on_401(self, mock_client):
        mock_client.ms_client.grant_type = O365MessageTrace.CLIENT_CREDENTIALS
        mock_client.ms_client.http_request.side_effect = Exception("401 Unauthorized")
        result = run_test_module(mock_client)
        assert "Authorization Error" in result

    def test_returns_authorization_error_on_403(self, mock_client):
        mock_client.ms_client.grant_type = O365MessageTrace.CLIENT_CREDENTIALS
        mock_client.ms_client.http_request.side_effect = Exception("403 Forbidden")
        result = run_test_module(mock_client)
        assert "Authorization Error" in result

    def test_reraises_unexpected_errors(self, mock_client):
        mock_client.ms_client.grant_type = O365MessageTrace.CLIENT_CREDENTIALS
        mock_client.ms_client.http_request.side_effect = Exception("500 Server Error")
        with pytest.raises(Exception, match="500"):
            run_test_module(mock_client)


class TestAuthTestCommand:
    def test_returns_success_message(self, mock_client):
        mock_client.ms_client.http_request.return_value = {"value": []}
        result = auth_test_command(mock_client)
        assert "successful" in result.readable_output.lower()

    def test_raises_demisto_exception_on_failure(self, mock_client):
        mock_client.ms_client.http_request.side_effect = Exception("bad creds")
        with pytest.raises(O365MessageTrace.DemistoException):
            auth_test_command(mock_client)


class TestGetEventsCommand:
    def test_returns_command_results_without_pushing(self, mock_client, sample_events, mocker):
        mock_client.ms_client.http_request.return_value = {"value": sample_events}
        send = mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        result = get_events_command(mock_client, {"limit": "10"})
        assert result.outputs_prefix == "O365MessageTrace.Event"
        send.assert_not_called()

    def test_pushes_events_when_requested(self, mock_client, sample_events, mocker):
        mock_client.ms_client.http_request.return_value = {"value": sample_events}
        send = mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        get_events_command(mock_client, {"limit": "10", "should_push_events": "true"})
        send.assert_called_once()

    def test_does_not_push_when_no_events(self, mock_client, mocker):
        mock_client.ms_client.http_request.return_value = {"value": []}
        send = mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        get_events_command(mock_client, {"should_push_events": "true"})
        send.assert_not_called()


# ============================================================================
# fetch_events tests
# ============================================================================
class TestFetchEvents:
    @staticmethod
    def _frozen_now(now: datetime):
        class FrozenDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return now

        return FrozenDatetime

    def test_first_run_uses_default_first_fetch(self, mock_client, sample_events, mocker):
        now = datetime(2025, 1, 1, 10, 5, 0, tzinfo=UTC)
        mocker.patch.object(O365MessageTrace, "datetime", self._frozen_now(now))
        mocker.patch.object(demisto, "getLastRun", return_value={})
        set_last_run = mocker.patch.object(demisto, "setLastRun")
        mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.return_value = {"value": sample_events}

        fetch_events(mock_client, max_events=100)

        set_last_run.assert_called_once()

    def test_subsequent_run_uses_last_fetch(self, mock_client, sample_events, mocker):
        now = datetime(2025, 1, 1, 10, 3, 0, tzinfo=UTC)
        mocker.patch.object(O365MessageTrace, "datetime", self._frozen_now(now))
        mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch": "2025-01-01T10:00:00.000000Z", "seen_ids": []})
        mocker.patch.object(demisto, "setLastRun")
        mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.return_value = {"value": sample_events}

        fetch_events(mock_client, max_events=100)

        params = mock_client.ms_client.http_request.call_args.kwargs["params"]
        assert "2025-01-01T10:00:00" in params["$filter"]

    def test_deduplicates_against_seen_ids(self, mock_client, sample_events, mocker):
        now = datetime(2025, 1, 1, 10, 3, 0, tzinfo=UTC)
        mocker.patch.object(O365MessageTrace, "datetime", self._frozen_now(now))
        mocker.patch.object(
            demisto,
            "getLastRun",
            return_value={"last_fetch": "2025-01-01T10:00:00.000000Z", "seen_ids": ["evt-1|bob@contoso.com"]},
        )
        mocker.patch.object(demisto, "setLastRun")
        send = mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.return_value = {"value": sample_events}

        fetch_events(mock_client, max_events=100)

        sent = send.call_args.kwargs["events"]
        sent_ids = {event["id"] for event in sent}
        assert "evt-1" not in sent_ids
        assert "evt-2" in sent_ids

    def test_no_events_does_not_call_send(self, mock_client, mocker):
        now = datetime(2025, 1, 1, 10, 3, 0, tzinfo=UTC)
        mocker.patch.object(O365MessageTrace, "datetime", self._frozen_now(now))
        mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch": "2025-01-01T10:00:00.000000Z", "seen_ids": []})
        mocker.patch.object(demisto, "setLastRun")
        send = mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.return_value = {"value": []}

        fetch_events(mock_client, max_events=100)

        send.assert_not_called()

    def test_updates_high_water_mark_to_latest_event(self, mock_client, sample_events, mocker):
        now = datetime(2025, 1, 1, 10, 3, 0, tzinfo=UTC)
        mocker.patch.object(O365MessageTrace, "datetime", self._frozen_now(now))
        mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch": "2025-01-01T10:00:00.000000Z", "seen_ids": []})
        set_last_run = mocker.patch.object(demisto, "setLastRun")
        mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.return_value = {"value": sample_events}

        fetch_events(mock_client, max_events=100)

        new_last_run = set_last_run.call_args.args[0]
        assert new_last_run["last_fetch"] == "2025-01-01T10:01:00Z"

    def test_first_page_failure_does_not_advance_last_run(self, mock_client, mocker):
        now = datetime(2025, 1, 1, 10, 3, 0, tzinfo=UTC)
        mocker.patch.object(O365MessageTrace, "datetime", self._frozen_now(now))
        mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch": "2025-01-01T10:00:00.000000Z", "seen_ids": []})
        set_last_run = mocker.patch.object(demisto, "setLastRun")
        mock_client.ms_client.http_request.side_effect = Exception("boom")

        with pytest.raises(Exception, match="boom"):
            fetch_events(mock_client, max_events=100)

        set_last_run.assert_not_called()

    def test_empty_window_advances_last_fetch_to_window_end(self, mock_client, mocker):
        now = datetime(2025, 1, 1, 10, 3, 0, tzinfo=UTC)
        mocker.patch.object(O365MessageTrace, "datetime", self._frozen_now(now))
        mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch": "2025-01-01T10:00:00.000000Z", "seen_ids": []})
        set_last_run = mocker.patch.object(demisto, "setLastRun")
        mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.return_value = {"value": []}

        fetch_events(mock_client, max_events=100)

        new_last_run = set_last_run.call_args.args[0]
        # No events: cursor advances to the window end (now).
        assert new_last_run["last_fetch"] == "2025-01-01T10:03:00.000000Z"


class TestFetchEventsWindowWalk:
    """The in-run loop must walk consecutive windows oldest->newest within a single run."""

    @staticmethod
    def _frozen_now(now: datetime):
        class FrozenDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return now

        return FrozenDatetime

    def test_walks_multiple_windows_until_caught_up(self, mock_client, mocker):
        # last_fetch is ~12 min behind now => multiple 5-min windows.
        now = datetime(2025, 1, 1, 10, 12, 0, tzinfo=UTC)
        mocker.patch.object(O365MessageTrace, "datetime", self._frozen_now(now))
        mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch": "2025-01-01T10:00:00.000000Z", "seen_ids": []})
        mocker.patch.object(demisto, "setLastRun")
        mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.return_value = {"value": []}

        fetch_events(mock_client, max_events=100)

        # 10:00->10:05, 10:05->10:10, 10:10->10:12 = 3 window walks.
        assert mock_client.ms_client.http_request.call_count == 3

    def test_stops_advancing_when_max_events_reached(self, mock_client, mocker):
        now = datetime(2025, 1, 1, 10, 20, 0, tzinfo=UTC)
        mocker.patch.object(O365MessageTrace, "datetime", self._frozen_now(now))
        mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch": "2025-01-01T10:00:00.000000Z", "seen_ids": []})
        mocker.patch.object(demisto, "setLastRun")
        mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        # Each window returns 2 events; max_events=2 stops the walk after the first window.
        mock_client.ms_client.http_request.return_value = {
            "value": [
                {"id": "a", "receivedDateTime": "2025-01-01T10:01:00Z", "recipientAddress": "bob@contoso.com"},
                {"id": "b", "receivedDateTime": "2025-01-01T10:02:00Z", "recipientAddress": "bob@contoso.com"},
            ]
        }

        fetch_events(mock_client, max_events=2)

        assert mock_client.ms_client.http_request.call_count == 1

    def test_persists_last_run_once_per_run(self, mock_client, mocker):
        now = datetime(2025, 1, 1, 10, 12, 0, tzinfo=UTC)
        mocker.patch.object(O365MessageTrace, "datetime", self._frozen_now(now))
        mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch": "2025-01-01T10:00:00.000000Z", "seen_ids": []})
        set_last_run = mocker.patch.object(demisto, "setLastRun")
        mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.return_value = {"value": []}

        fetch_events(mock_client, max_events=100)

        assert set_last_run.call_count == 1


# ============================================================================
# O365MessageTraceClient.http_request tests
# ============================================================================
@pytest.fixture
def http_client(mocker):
    client = O365MessageTrace.O365MessageTraceClient.__new__(O365MessageTrace.O365MessageTraceClient)
    client.timeout = 60
    mocker.patch.object(client, "get_access_token", return_value="TOKEN")
    mocker.patch.object(client, "handle_error_with_metrics", return_value=None)
    return client


class TestHttpRequest:
    def test_injects_bearer_token_into_request_headers(self, http_client, mocker):
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"value": []}
        super_request = mocker.patch.object(O365MessageTrace.MicrosoftClient, "_http_request", return_value=response)
        mocker.patch.object(O365MessageTrace.MicrosoftClient, "create_api_metrics")

        http_client.http_request(method="GET", url_suffix="x")

        headers = super_request.call_args.kwargs["headers"]
        assert headers["Authorization"] == "Bearer TOKEN"

    def test_passes_429_and_503_in_status_list_to_retry(self, http_client, mocker):
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"value": []}
        super_request = mocker.patch.object(O365MessageTrace.MicrosoftClient, "_http_request", return_value=response)
        mocker.patch.object(O365MessageTrace.MicrosoftClient, "create_api_metrics")

        http_client.http_request(method="GET", url_suffix="x")

        assert super_request.call_args.kwargs["status_list_to_retry"] == [503, 429]

    def test_404_raises_not_found_error(self, http_client, mocker):
        response = MagicMock()
        response.status_code = 404
        response.json.return_value = {"error": "not found"}
        mocker.patch.object(O365MessageTrace.MicrosoftClient, "_http_request", return_value=response)
        mocker.patch.object(O365MessageTrace.MicrosoftClient, "create_api_metrics")

        with pytest.raises(O365MessageTrace.NotFoundError):
            http_client.http_request(method="GET", url_suffix="x")

    def test_calls_create_api_metrics_with_status_code(self, http_client, mocker):
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"value": []}
        mocker.patch.object(O365MessageTrace.MicrosoftClient, "_http_request", return_value=response)
        metrics = mocker.patch.object(O365MessageTrace.MicrosoftClient, "create_api_metrics")

        http_client.http_request(method="GET", url_suffix="x")

        metrics.assert_called_once_with(200)

    def test_non_json_body_raises_demisto_exception(self, http_client, mocker):
        response = MagicMock()
        response.status_code = 200
        response.json.side_effect = ValueError("bad json")
        response.content = b"not json"
        mocker.patch.object(O365MessageTrace.MicrosoftClient, "_http_request", return_value=response)
        mocker.patch.object(O365MessageTrace.MicrosoftClient, "create_api_metrics")

        with pytest.raises(O365MessageTrace.DemistoException):
            http_client.http_request(method="GET", url_suffix="x")
