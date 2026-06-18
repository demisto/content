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
    parse_integration_params,
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
# parse_integration_params tests
# ============================================================================
class TestParseIntegrationParams:
    """``parse_integration_params`` normalizes the raw ``demisto.params()`` dict
    into the keyword arguments needed to build a :class:`Client`, resolving the
    grant type and validating that the credentials required for that flow are
    present. ``get_azure_cloud`` and ``get_azure_managed_identities_client_id``
    reach into the Azure machinery, so they are patched on the module to keep the
    tests hermetic.
    """

    @pytest.fixture(autouse=True)
    def _patch_azure_helpers(self, mocker):
        """Patch the Azure helpers the function depends on.

        By default there is no managed-identity client id (so the credential
        validation branch runs) and a fake Azure cloud whose graph resource id
        is used to build the default ``base_url``.
        """
        fake_cloud = MagicMock()
        fake_cloud.endpoints.microsoft_graph_resource_id = "https://graph.microsoft.com"
        mocker.patch.object(O365MessageTrace, "get_azure_cloud", return_value=fake_cloud)
        self.managed_identity_mock = mocker.patch.object(
            O365MessageTrace, "get_azure_managed_identities_client_id", return_value=None
        )

    @staticmethod
    def _client_credentials_params(**overrides) -> dict:
        """A minimally-valid client-credentials param dict, with optional overrides."""
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
        """When no ``credentials`` creds-object is supplied, the legacy plain
        ``client_secret`` param must be honored."""
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
        """When a managed-identity client id is present, the credential-validation
        branch is skipped entirely (no exception even without secret/tenant)."""
        self.managed_identity_mock.return_value = "mi-client-id"

        result = parse_integration_params({})

        assert result["managed_identities_client_id"] == "mi-client-id"
        assert result["enc_key"] is None
        assert result["auth_id"] == ""

    def test_certificate_thumbprint_and_private_key_parsed(self, mocker):
        """Certificate auth: thumbprint + private key are extracted, and the private
        key has its spaces normalized via ``replace_spaces_in_credential``."""
        normalize = mocker.patch.object(O365MessageTrace, "replace_spaces_in_credential", return_value="normalized-key")
        params = self._client_credentials_params(
            creds_certificate={"identifier": "thumb-123", "password": "raw key with spaces"},
        )

        result = parse_integration_params(params)

        assert result["certificate_thumbprint"] == "thumb-123"
        assert result["private_key"] == "normalized-key"
        normalize.assert_called_once_with("raw key with spaces")

    def test_private_key_is_none_when_not_provided(self):
        result = parse_integration_params(self._client_credentials_params())

        assert result["certificate_thumbprint"] is None
        assert result["private_key"] is None

    def test_raises_when_client_credentials_missing_tenant(self):
        from O365MessageTrace import DemistoException

        params = self._client_credentials_params(tenant_id="")

        with pytest.raises(DemistoException, match="client credentials flow"):
            parse_integration_params(params)

    def test_raises_when_client_credentials_missing_secret(self):
        from O365MessageTrace import DemistoException

        params = self._client_credentials_params()
        del params["credentials"]

        with pytest.raises(DemistoException, match="client credentials flow"):
            parse_integration_params(params)

    def test_raises_when_authorization_code_flow_missing_fields(self):
        """Supplying redirect_uri without auth_code resolves to client-credentials,
        so to exercise the authorization-code validation we supply both auth_code
        and redirect_uri but omit the client id."""
        from O365MessageTrace import DemistoException

        params = {
            "tenant_id": "tenant-123",
            "credentials": {"password": "secret-xyz"},
            "auth_code": {"password": "the-auth-code"},
            "redirect_uri": "https://example.com/callback",
        }

        with pytest.raises(DemistoException, match="authorization code flow"):
            parse_integration_params(params)

    def test_raises_when_auth_code_flow_missing_redirect_uri(self):
        """An authorization-code attempt (auth_code supplied) without a redirect_uri
        must raise. Without redirect_uri the grant type falls back to client
        credentials, so the only credential offered is the auth code, which is not a
        valid client-credentials secret - validation must reject it."""
        from O365MessageTrace import DemistoException

        params = {
            "tenant_id": "tenant-123",
            "credentials_client_id": {"password": "client-abc"},
            "auth_code": {"password": "the-auth-code"},
            # redirect_uri intentionally omitted
        }

        with pytest.raises(DemistoException, match="client credentials flow"):
            parse_integration_params(params)

    def test_raises_when_no_credential_provided(self):
        """When no client secret, no certificate (thumbprint + private key) and no
        authorization code are supplied, validation must reject the configuration."""
        from O365MessageTrace import DemistoException

        params = {
            "tenant_id": "tenant-123",
            "credentials_client_id": {"password": "client-abc"},
            # no credentials/client_secret, no creds_certificate, no auth_code
        }

        with pytest.raises(DemistoException, match="client credentials flow"):
            parse_integration_params(params)

    def test_default_max_events_when_not_supplied(self):
        result = parse_integration_params(self._client_credentials_params())

        assert result["max_events"] == Config.DEFAULT_MAX_EVENTS

    def test_custom_max_events_parsed_from_max_fetch(self):
        result = parse_integration_params(self._client_credentials_params(max_fetch="250"))

        assert result["max_events"] == 250

    def test_default_base_url_built_from_azure_cloud(self):
        result = parse_integration_params(self._client_credentials_params())

        # Built from the patched graph resource id, normalized to a single trailing slash.
        assert result["base_url"] == "https://graph.microsoft.com/"

    def test_explicit_url_param_overrides_default_and_is_normalized(self):
        result = parse_integration_params(self._client_credentials_params(url="https://custom.example.com/graph/"))

        # Trailing slashes are stripped then a single one re-appended.
        assert result["base_url"] == "https://custom.example.com/graph/"

    def test_verify_and_proxy_flags_parsed(self):
        secure = parse_integration_params(self._client_credentials_params(insecure=False, proxy=False))
        insecure = parse_integration_params(self._client_credentials_params(insecure=True, proxy=True))

        assert secure["verify"] is True
        assert secure["proxy"] is False
        assert insecure["verify"] is False
        assert insecure["proxy"] is True


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

    def test_stops_on_non_advancing_next_link(self, mock_client, mocker):
        """A misbehaving server that keeps returning a non-empty page with the SAME
        ``@odata.nextLink`` every call must NOT loop forever. The loop detects the
        non-advancing cursor, logs an error, and breaks.
        """
        # Every call returns the same non-empty page with an identical nextLink.
        same_link = "https://graph.microsoft.com/stuck"
        page = {
            "value": [{"id": "evt-1", "receivedDateTime": "2025-01-01T10:00:00Z"}],
            "@odata.nextLink": same_link,
        }
        # Cap the number of responses so the test fails (StopIteration) instead of
        # hanging if the non-advancing guard were ever removed.
        mock_client.ms_client.http_request.side_effect = [page] * 50
        error_mock = mocker.patch.object(O365MessageTrace.demisto, "error")

        start = datetime(2025, 1, 1, tzinfo=UTC)
        end = start + timedelta(minutes=5)
        result = fetch_events_sequential(mock_client, start, end, max_events=100)

        # The cursor is detected as non-advancing on the second call, so the loop
        # breaks after exactly two requests instead of hanging.
        assert mock_client.ms_client.http_request.call_count == 2
        # Events collected before the break are still returned.
        assert [e["id"] for e in result] == ["evt-1", "evt-1"]
        # An error is logged explaining why the loop stopped.
        error_mock.assert_called_once()
        assert "did not advance" in error_mock.call_args.args[0]

    def test_stops_on_empty_page_with_next_link(self, mock_client):
        """An empty ``value`` must stop the loop on the empty-page break even when
        ``@odata.nextLink`` is still present (the empty-page check comes first)."""
        # Empty page but the server still advertises another page via nextLink.
        empty_page_with_link = {
            "value": [],
            "@odata.nextLink": "https://graph.microsoft.com/next",
        }
        # Cap responses so a regression that ignores the empty-page break surfaces
        # as StopIteration rather than an infinite hang.
        mock_client.ms_client.http_request.side_effect = [empty_page_with_link] * 50

        start = datetime(2025, 1, 1, tzinfo=UTC)
        end = start + timedelta(minutes=5)
        result = fetch_events_sequential(mock_client, start, end, max_events=100)

        # The loop stops on the empty page after a single request.
        assert mock_client.ms_client.http_request.call_count == 1
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

    def test_seen_ids_holds_sent_ids_at_boundary_timestamp(self, mock_client, mocker):
        """seen_ids holds the IDs of events sent to XSIAM at the high-water-mark timestamp.

        The Graph API timestamps have second-level granularity, so several events
        can share the exact same ``receivedDateTime``. ``seen_ids`` tracks the IDs of
        the events published to XSIAM at the boundary timestamp so the next run's
        ``$filter`` (``ge boundary``) does not re-send them. Events that were already
        deduped out this run are not re-published and therefore are not re-added.
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
        # Only the newly-published event at the boundary timestamp is tracked; the
        # already-seen duplicate (evt-1) was deduped out and not re-sent.
        assert set(new_state["seen_ids"]) == {"evt-2|dave@contoso.com"}


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

    def test_catch_up_stops_at_max_fetch_iterations(self, mock_client, mocker):
        """A backlog larger than ``MAX_FETCH_ITERATIONS`` windows must stop after the
        cap (a single-run safety bound) rather than walking all the way to ``now``.

        ``MAX_FETCH_ITERATIONS`` is patched to a small value so the cap is reached
        before the backlog (which spans more windows) is drained. The loop must make
        exactly ``MAX_FETCH_ITERATIONS`` requests and leave ``last_fetch`` at the
        capped window end - well short of ``now``.
        """
        # last_fetch=09:00, now=09:30 -> 6 windows of 5 min, but the cap is 3.
        now = datetime(2025, 1, 1, 9, 30, 0, tzinfo=UTC)
        last_run = {"last_fetch": "2025-01-01T09:00:00Z", "seen_ids": []}
        mocker.patch.object(O365MessageTrace, "datetime", self._frozen_now(now))
        mocker.patch.object(O365MessageTrace.Config, "MAX_FETCH_ITERATIONS", 3)
        mocker.patch.object(O365MessageTrace.demisto, "getLastRun", return_value=last_run)
        set_last_run = mocker.patch.object(O365MessageTrace.demisto, "setLastRun")
        mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.return_value = {"value": []}

        fetch_events(mock_client, max_events=100)

        # Exactly MAX_FETCH_ITERATIONS windows requested (one empty page each).
        assert mock_client.ms_client.http_request.call_count == 3
        # last_fetch advanced to the window end reached after the cap (09:20), well
        # short of ``now`` (09:30): the safety bound stops the catch-up early.
        new_state = set_last_run.call_args.args[0]
        assert new_state["last_fetch"] == "2025-01-01T09:20:00Z"
        assert new_state["last_fetch"] != "2025-01-01T09:30:00Z"

    def test_catch_up_truncates_total_to_max_events(self, mock_client, mocker):
        """Events accumulated across multiple windows must be truncated to
        ``max_events`` before publishing.

        Two windows each return two events (four total) but ``max_events`` is 3, so
        only three events may be published.
        """
        # last_fetch=09:00, now=09:10 -> 2 windows: [09:00,09:05], [09:05,09:10].
        now = datetime(2025, 1, 1, 9, 10, 0, tzinfo=UTC)
        last_run = {"last_fetch": "2025-01-01T09:00:00Z", "seen_ids": []}
        window1 = {
            "value": [
                {"id": "w1-a", "recipientAddress": "bob@contoso.com", "receivedDateTime": "2025-01-01T09:01:00Z"},
                {"id": "w1-b", "recipientAddress": "bob@contoso.com", "receivedDateTime": "2025-01-01T09:02:00Z"},
            ]
        }
        window2 = {
            "value": [
                {"id": "w2-a", "recipientAddress": "bob@contoso.com", "receivedDateTime": "2025-01-01T09:06:00Z"},
                {"id": "w2-b", "recipientAddress": "bob@contoso.com", "receivedDateTime": "2025-01-01T09:07:00Z"},
            ]
        }
        mocker.patch.object(O365MessageTrace, "datetime", self._frozen_now(now))
        mocker.patch.object(O365MessageTrace.demisto, "getLastRun", return_value=last_run)
        mocker.patch.object(O365MessageTrace.demisto, "setLastRun")
        send_mock = mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        mock_client.ms_client.http_request.side_effect = [window1, window2]

        fetch_events(mock_client, max_events=3)

        # Four events were collected across both windows but only three may be published.
        sent_events = [e for call in send_mock.call_args_list for e in call.kwargs["events"]]
        assert len(sent_events) == 3

    def test_429_on_second_window_keeps_first_window_events_and_advances_last_run(self, mock_client, mocker):
        """A 429 (rate-limit) error on the second window's API request must NOT lose
        the first window's events.

        Window 1 returns events successfully (they must be sent to XSIAM and
        ``last_run`` advanced to their high-water mark). Window 2's request raises a
        429-style exception which, with no events collected for that window, is
        re-raised by ``fetch_events_sequential`` and caught by the in-run loop's
        try/except: the error is logged and the loop breaks while still persisting
        and publishing what window 1 produced.
        """
        # last_fetch=09:00, now=09:10 -> 2 windows: [09:00,09:05], [09:05,09:10].
        now = datetime(2025, 1, 1, 9, 10, 0, tzinfo=UTC)
        last_run = {"last_fetch": "2025-01-01T09:00:00Z", "seen_ids": []}
        window1 = {
            "value": [
                {"id": "w1", "recipientAddress": "bob@contoso.com", "receivedDateTime": "2025-01-01T09:01:00Z"},
            ]
        }
        # Window 2's first (and only) request fails with a 429 rate-limit error.
        rate_limit_error = Exception("Error in API call [429] - Too Many Requests")
        mocker.patch.object(O365MessageTrace, "datetime", self._frozen_now(now))
        mocker.patch.object(O365MessageTrace.demisto, "getLastRun", return_value=last_run)
        set_last_run = mocker.patch.object(O365MessageTrace.demisto, "setLastRun")
        send_mock = mocker.patch.object(O365MessageTrace, "send_events_to_xsiam")
        error_mock = mocker.patch.object(O365MessageTrace.demisto, "error")
        # First call (window 1) succeeds, second call (window 2) raises 429.
        mock_client.ms_client.http_request.side_effect = [window1, rate_limit_error]

        fetch_events(mock_client, max_events=100)

        # Window 1's events must still be published to XSIAM.
        sent_events = [e for call in send_mock.call_args_list for e in call.kwargs["events"]]
        assert [e["id"] for e in sent_events] == ["w1"]

        # last_run must be persisted once and advanced to window 1's high-water mark.
        set_last_run.assert_called_once()
        new_state = set_last_run.call_args.args[0]
        assert new_state["last_fetch"] == "2025-01-01T09:01:00Z"
        assert new_state["seen_ids"] == ["w1|bob@contoso.com"]

        # The in-run loop's error for the failing window must be logged. The message
        # uses the datetime window bounds (09:05 -> 09:10) and the exception text.
        window_error_calls = [call.args[0] for call in error_mock.call_args_list if call.args and "[F" in call.args[0]]
        assert len(window_error_calls) == 1
        message = window_error_calls[0]
        assert "2025-01-01 09:05:00+00:00 -> 2025-01-01 09:10:00+00:00" in message
        assert "429" in message


# ============================================================================
# Rate-limit backoff tests
# ============================================================================
class TestRequestWithBackoff:
    """``Client._request_with_backoff`` retries a 429 with the fixed backoff
    schedule defined by ``Config.RATE_LIMIT_BACKOFFS`` and disables the shared
    module's own rate-limit reschedule via ``overwrite_rate_limit_retry=True``.
    """

    def test_returns_response_on_first_success_without_sleeping(self, mock_client, mocker):
        sleep_mock = mocker.patch.object(O365MessageTrace.time, "sleep")
        mock_client.ms_client.http_request.return_value = {"value": ["ok"]}

        result = mock_client._request_with_backoff(method="GET", url_suffix="x")

        assert result == {"value": ["ok"]}
        mock_client.ms_client.http_request.assert_called_once()
        sleep_mock.assert_not_called()

    def test_passes_overwrite_rate_limit_retry_and_ok_codes(self, mock_client, mocker):
        mocker.patch.object(O365MessageTrace.time, "sleep")
        mock_client.ms_client.http_request.return_value = {}

        mock_client._request_with_backoff(method="GET", full_url="full-url-placeholder", url_suffix="")

        call_kwargs = mock_client.ms_client.http_request.call_args.kwargs
        assert call_kwargs["overwrite_rate_limit_retry"] is True
        assert call_kwargs["ok_codes"] == [200]
        assert call_kwargs["method"] == "GET"
        assert call_kwargs["full_url"] == "full-url-placeholder"

    def test_retries_429_then_succeeds(self, mock_client, mocker):
        sleep_mock = mocker.patch.object(O365MessageTrace.time, "sleep")
        rate_limit_error = Exception("Error in API call [429] - Too Many Requests")
        mock_client.ms_client.http_request.side_effect = [rate_limit_error, {"value": ["ok"]}]

        result = mock_client._request_with_backoff(method="GET", url_suffix="x")

        assert result == {"value": ["ok"]}
        assert mock_client.ms_client.http_request.call_count == 2
        # First backoff value is used before the retry.
        sleep_mock.assert_called_once_with(Config.RATE_LIMIT_BACKOFFS[0])

    def test_exhausts_all_backoffs_then_raises(self, mock_client, mocker):
        sleep_mock = mocker.patch.object(O365MessageTrace.time, "sleep")
        rate_limit_error = Exception("Error in API call [429] - Too Many Requests")
        # Always 429: initial attempt + len(backoffs) retries all fail.
        mock_client.ms_client.http_request.side_effect = rate_limit_error

        with pytest.raises(Exception, match="429"):
            mock_client._request_with_backoff(method="GET", url_suffix="x")

        # initial attempt + one retry per backoff value.
        assert mock_client.ms_client.http_request.call_count == 1 + len(Config.RATE_LIMIT_BACKOFFS)
        assert [c.args[0] for c in sleep_mock.call_args_list] == list(Config.RATE_LIMIT_BACKOFFS)

    def test_non_429_error_propagates_immediately_without_retry(self, mock_client, mocker):
        sleep_mock = mocker.patch.object(O365MessageTrace.time, "sleep")
        other_error = Exception("Error in API call [500] - Internal Server Error")
        mock_client.ms_client.http_request.side_effect = other_error

        with pytest.raises(Exception, match="500"):
            mock_client._request_with_backoff(method="GET", url_suffix="x")

        mock_client.ms_client.http_request.assert_called_once()
        sleep_mock.assert_not_called()


class TestGetMessageTracesPageUsesBackoff:
    """``get_message_traces_page`` must route both the first-page and
    next-link requests through ``_request_with_backoff``.
    """

    def test_first_page_uses_backoff(self, mock_client, mocker):
        backoff_mock = mocker.patch.object(mock_client, "_request_with_backoff", return_value={"value": []})

        mock_client.get_message_traces_page(start_date="2025-01-01T00:00:00Z", end_date="2025-01-01T01:00:00Z")

        backoff_mock.assert_called_once()
        assert backoff_mock.call_args.kwargs["url_suffix"] == Config.MESSAGE_TRACES_PATH

    def test_next_link_uses_backoff(self, mock_client, mocker):
        backoff_mock = mocker.patch.object(mock_client, "_request_with_backoff", return_value={"value": []})

        mock_client.get_message_traces_page(next_link="next-link-placeholder")

        backoff_mock.assert_called_once()
        assert backoff_mock.call_args.kwargs["full_url"] == "next-link-placeholder"
