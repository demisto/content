import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa
from MicrosoftApiModule import *  # noqa: E402

import traceback
from datetime import datetime, timedelta, UTC
from typing import Any


# ============================================================================
# Constants
# ============================================================================
class Config:
    """Global static configuration."""

    VENDOR = "microsoft"
    PRODUCT = "o365_message_trace"

    APP_NAME = "o365-message-trace"
    GRAPH_SCOPE = "https://graph.microsoft.com/.default"

    MESSAGE_TRACES_PATH = "v1.0/admin/exchange/tracing/messageTraces"

    DATE_FORMAT_FILTER = "%Y-%m-%dT%H:%M:%SZ"
    DATE_FORMAT_EVENT = "%Y-%m-%dT%H:%M:%S.%fZ"

    DEFAULT_MAX_EVENTS = 50000
    DEFAULT_PAGE_SIZE = 1000  # API default/maximum per page
    DEFAULT_FIRST_FETCH_MINUTES = 1

    # Each fetch cycle only scans this many minutes starting from ``last_fetch``.
    # This keeps every run small and bounded even when the
    # integration is far behind, so a large backlog is drained oldest-first
    # across many runs instead of re-downloading days of events on every run.
    FETCH_WINDOW_MINUTES = 5


# ============================================================================
# Client
# ============================================================================
class Client:
    """Microsoft Graph client for O365 Message Trace events.

    Composes an instance of :class:`MicrosoftClient` (from ``MicrosoftApiModule``)
    so that the integration supports all standard Microsoft authentication
    methods: client credentials, certificate (thumbprint + private key),
    authorization-code and Azure Managed Identities.
    """

    def __init__(
        self,
        tenant_id: str,
        auth_id: str,
        enc_key: str | None,
        app_name: str,
        base_url: str,
        verify: bool,
        proxy: bool,
        certificate_thumbprint: str | None = None,
        private_key: str | None = None,
        auth_code: str | None = None,
        redirect_uri: str | None = None,
        managed_identities_client_id: str | None = None,
        azure_cloud: AzureCloud = AZURE_WORLDWIDE_CLOUD,
    ):
        grant_type = AUTHORIZATION_CODE if auth_code and redirect_uri else CLIENT_CREDENTIALS
        demisto.debug(f"[Auth] Using grant type: {grant_type}")
        client_args = {
            "tenant_id": tenant_id,
            "auth_id": auth_id,
            "enc_key": enc_key,
            "app_name": app_name,
            "base_url": base_url,
            "verify": verify,
            "proxy": proxy,
            "self_deployed": True,
            "certificate_thumbprint": certificate_thumbprint,
            "private_key": private_key,
            "auth_code": auth_code or "",
            "redirect_uri": redirect_uri,
            "grant_type": grant_type,
            "scope": Config.GRAPH_SCOPE,
            "resource": Resources.graph,
            "azure_cloud": azure_cloud,
            "azure_ad_endpoint": azure_cloud.endpoints.active_directory,
            "token_retrieval_url": urljoin(azure_cloud.endpoints.active_directory, f"/{tenant_id}/oauth2/v2.0/token"),
            "managed_identities_client_id": managed_identities_client_id,
            "managed_identities_resource_uri": Resources.graph,
            "command_prefix": Config.APP_NAME,
            "retry_on_rate_limit": True,
            "timeout": 60,
        }
        self.ms_client = MicrosoftClient(**client_args)

    # ------------------------------------------------------------------
    # API calls
    # ------------------------------------------------------------------
    def get_message_traces_page(
        self,
        start_date: str | None = None,
        end_date: str | None = None,
        next_link: str | None = None,
        page_size: int = Config.DEFAULT_PAGE_SIZE,
    ) -> dict[str, Any]:
        """Fetch a single page of message-trace records.

        When ``next_link`` is supplied it is used as-is (it already contains the
        required ``$skiptoken``); otherwise a fresh filtered request is issued
        using ``start_date`` and ``end_date``.
        """
        if next_link:
            demisto.debug(f"[API] Following @odata.nextLink: {next_link}")
            return self.ms_client.http_request(method="GET", full_url=next_link, url_suffix="", ok_codes=[200])

        params = {
            "$filter": f"receivedDateTime ge {start_date} and receivedDateTime le {end_date}",
            "$top": page_size,
        }
        demisto.debug(f"[API] First page request | params={params}")
        return self.ms_client.http_request(method="GET", url_suffix=Config.MESSAGE_TRACES_PATH, params=params, ok_codes=[200])


# ============================================================================
# Helpers
# ============================================================================
def parse_datetime(value: str | None, default: datetime | None = None) -> datetime:
    """Parse a date string and always return a tz-aware UTC datetime."""
    if not value:
        return default or datetime.now(UTC)
    parsed = arg_to_datetime(arg=value, is_utc=True)
    if not parsed:
        return default or datetime.now(UTC)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def format_datetime_for_filter(dt: datetime) -> str:
    """Format a datetime in the form expected by the Graph $filter clause."""
    return dt.strftime(Config.DATE_FORMAT_FILTER)


def deduplicate_events(events: list[dict], seen_ids: set[str]) -> list[dict]:
    """Filter out events whose IDs are already in ``seen_ids``."""
    if not seen_ids:
        return events

    new_events: list[dict] = []
    duplicates = 0
    for event in events:
        event_id = event.get("_unique_id")
        if event_id and event_id in seen_ids:
            duplicates += 1
            continue
        new_events.append(event)

    if duplicates:
        demisto.debug(f"[Dedup] Skipped {duplicates} duplicate events")
    return new_events


def add_time_field(events: list[dict]) -> None:
    """Add the XSIAM-required ``_time`` field to each event."""
    fallback_time = datetime.now(UTC).strftime(Config.DATE_FORMAT_FILTER)
    for event in events:
        received = event.get("receivedDateTime")
        event["_time"] = received if received else fallback_time


def add_unique_id_field(events: list[dict]) -> None:
    """Add a ``_unique_id`` field to each event in the form ``<id>|<recipientAddress>``.

    The new ``_unique_id`` field guarantees uniqueness across events that share
    the same underlying message id but were delivered to different recipients.
    """
    for event in events:
        event_id = event.get("id")
        recipient = event.get("recipientAddress")
        if event_id and recipient:
            event["_unique_id"] = f"{event_id}|{recipient}"


# ============================================================================
# Configuration parsing
# ============================================================================
def parse_integration_params(params: dict[str, Any]) -> dict[str, Any]:
    """Parse and validate integration configuration parameters.

    Extracts authentication settings, connection settings, and validates the
    resulting authentication credentials from the raw ``demisto.params()``
    dictionary. Supports client-credentials, certificate, authorization-code
    and Azure managed-identities flows.

    Args:
        params: Raw parameters from ``demisto.params()``.

    Returns:
        Validated configuration dictionary with the keys required to
        construct a :class:`Client` instance, plus ``max_events``.

    Raises:
        DemistoException: If required authentication credentials are missing
            or inconsistent for the resolved grant type.
    """
    # ----- Tenant / Auth ID / Secret (support both creds objects and legacy plain params) -----
    tenant_id = params.get("tenant_id", "")

    credentials_client_id = params.get("credentials_client_id") or {}
    client_id = credentials_client_id.get("password")

    credentials = params.get("credentials") or {}
    client_secret = credentials.get("password") or params.get("client_secret", "")

    # ----- Certificate auth -----
    creds_certificate = params.get("creds_certificate") or {}
    certificate_thumbprint = creds_certificate.get("identifier")
    private_key_raw = creds_certificate.get("password")
    private_key = replace_spaces_in_credential(private_key_raw) if private_key_raw else None

    # ----- Authorization-code flow -----
    auth_code_param = params.get("auth_code") or {}
    auth_code = auth_code_param.get("password")

    redirect_uri = params.get("redirect_uri")

    # ----- Managed Identities -----
    managed_identities_client_id = get_azure_managed_identities_client_id(params)

    # ----- Common settings -----
    azure_cloud = get_azure_cloud(params, "O365MessageTrace")
    base_url = (params.get("url") or urljoin(azure_cloud.endpoints.microsoft_graph_resource_id, "/")).rstrip("/") + "/"
    verify = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    max_events = arg_to_number(params.get("max_fetch")) or Config.DEFAULT_MAX_EVENTS

    # ----- Validation -----
    if not managed_identities_client_id:
        grant_type = AUTHORIZATION_CODE if auth_code and redirect_uri else CLIENT_CREDENTIALS
        if grant_type == AUTHORIZATION_CODE:
            if not tenant_id or not client_id or not client_secret or not auth_code or not redirect_uri:
                raise DemistoException(
                    "Tenant ID, Client ID, Client Secret, Authorization code and Application redirect URI "
                    "are required for the authorization code flow."
                )
        elif grant_type == CLIENT_CREDENTIALS and (not tenant_id or not client_id or not client_secret):
            raise DemistoException("Tenant ID, Client ID and Client Secret are required for the client credentials flow.")
        if not client_secret and not (certificate_thumbprint and private_key) and not auth_code:
            raise DemistoException(
                "An authentication credential must be provided: Client Secret, "
                "Certificate Thumbprint + Private Key, or Authorization Code."
            )

    return {
        "tenant_id": tenant_id,
        "auth_id": client_id or "",
        "enc_key": client_secret or None,
        "app_name": Config.APP_NAME,
        "base_url": base_url,
        "verify": verify,
        "proxy": proxy,
        "certificate_thumbprint": certificate_thumbprint,
        "private_key": private_key,
        "auth_code": auth_code,
        "redirect_uri": redirect_uri,
        "managed_identities_client_id": managed_identities_client_id,
        "azure_cloud": azure_cloud,
        "max_events": max_events,
    }


# ============================================================================
# Core fetch logic
# ============================================================================
def fetch_events_sequential(
    client: Client,
    start: datetime,
    end: datetime,
    max_events: int,
) -> list[dict]:
    """Fetch all message-trace pages for the [start, end] window sequentially.

    Iterates through ALL available pages using ``@odata.nextLink`` until no more
    pages remain, even when the running total already exceeds ``max_events``.
    The API returns the latest events first, so all events must be collected
    before they can be sorted ascending by ``receivedDateTime`` and truncated to
    the earliest ``max_events`` events.

    If the first page fails the exception is re-raised so the calling
    ``fetch_events`` cycle aborts and ``lastRun`` is not advanced (preventing
    data loss). If a later page fails we keep the events collected so far and
    log the failure - the next fetch cycle will resume from the high-water mark.
    """
    if end <= start:
        demisto.debug(f"[Fetch] Empty time range ({start.isoformat()} -> {end.isoformat()}). Skipping.")
        return []

    start_str = format_datetime_for_filter(start)
    end_str = format_datetime_for_filter(end)
    demisto.debug(f"[Fetch] Fetching window {start_str} -> {end_str} | max={max_events}")

    collected: list[dict] = []
    next_link: str | None = None
    page_events: list[dict] = [{}]  # Sentinel non-empty value to enter the loop.

    while page_events:
        try:
            response = client.get_message_traces_page(
                start_date=start_str,
                end_date=end_str,
                next_link=next_link,
                page_size=Config.DEFAULT_PAGE_SIZE,
            )
        except Exception as e:
            demisto.error(f"[Fetch] Failed to fetch page for window {start_str} -> {end_str}: {e}\n{traceback.format_exc()}")
            # No events collected yet - propagate so lastRun is NOT updated
            # and we retry the same window on the next fetch cycle.
            if not collected:
                raise
            # We already have some events from previous pages - stop here and
            # let the caller persist what we have.
            break

        page_events = response.get("value", []) or []
        collected.extend(page_events)

        demisto.debug(
            f"[Fetch] Window {start_str} -> {end_str}: page returned {len(page_events)} events "
            f"(running total: {len(collected)})"
        )

        # The API returns the latest events first, so we must follow every
        # ``@odata.nextLink`` (even past ``max_events``) to be able to keep the
        # earliest events after sorting below.
        next_link = response.get("@odata.nextLink")
        if not next_link:
            demisto.debug(f"[Fetch] Window {start_str} -> {end_str}: no more pages.")
            break

    # Sort all collected events ascending by receivedDateTime (parsed as datetime) so the
    # earliest event is first.
    collected.sort(
        key=lambda event: safe_strptime(event["receivedDateTime"], Config.DATE_FORMAT_EVENT)
        if event.get("receivedDateTime")
        else datetime.min
    )

    if len(collected) > max_events:
        demisto.debug(f"[Fetch] Collected {len(collected)} events, truncating to max_events ({max_events}).")
        collected = collected[:max_events]

    return collected


# ============================================================================
# Commands
# ============================================================================
def test_module(client: Client) -> str:
    """Validate credentials and Graph connectivity by fetching a tiny window.

    Raises:
        DemistoException: If using the authorization code flow, since test-module cannot access the
            integration context required by that flow. The ``o365-message-trace-auth-test`` command
            should be used instead.
    """
    demisto.debug("[Test] Starting test-module")
    if client.ms_client.grant_type == AUTHORIZATION_CODE:
        raise DemistoException(
            "Test module is not available for the authorization code flow. "
            "Use the o365-message-trace-auth-test command instead."
        )

    try:
        end = datetime.now(UTC)
        start = end - timedelta(minutes=5)
        fetch_events_sequential(client, start, end, max_events=1)
        return "ok"
    except Exception as e:
        error_message = str(e)
        if "401" in error_message or "403" in error_message:
            return f"Authorization Error: verify Tenant ID, Client ID and authentication credentials. Details: {error_message}"
        raise


def auth_test_command(client: Client) -> CommandResults:
    """Tests connectivity to Microsoft.

    Used to validate the authentication flow (especially the authorization-code
    flow) after the integration has been configured, since the standard
    test-module cannot access the integration context.
    """
    demisto.debug("[Auth Test] Starting o365-message-trace-auth-test")
    try:
        end = datetime.now(UTC)
        start = end - timedelta(minutes=5)
        client.get_message_traces_page(
            start_date=format_datetime_for_filter(start),
            end_date=format_datetime_for_filter(end),
            page_size=1,
        )
    except Exception as e:
        raise DemistoException(f"Authentication was not successful. Verify the configuration parameters. Error: {e}") from e
    return CommandResults(readable_output="Authentication was successful.")


def get_events_command(client: Client, args: dict) -> CommandResults:
    """Manual command to retrieve events (and optionally push them to XSIAM)."""
    limit = arg_to_number(args.get("limit")) or 50
    start_time = args.get("start_time")
    end_time = args.get("end_time")
    should_push_events = argToBoolean(args.get("should_push_events", False))

    end_dt = parse_datetime(end_time, default=datetime.now(UTC))
    start_dt = parse_datetime(start_time, default=end_dt - timedelta(minutes=Config.DEFAULT_FIRST_FETCH_MINUTES))

    events = fetch_events_sequential(client, start_dt, end_dt, max_events=limit)
    add_unique_id_field(events)
    add_time_field(events)

    if should_push_events and events:
        send_events_to_xsiam(events=events, vendor=Config.VENDOR, product=Config.PRODUCT)

    readable = tableToMarkdown(
        "O365 Message Trace Events",
        events,
        removeNull=True,
        headerTransform=pascalToSpace,
        headers=["id", "receivedDateTime", "senderAddress", "recipientAddress", "subject", "status"],
    )
    return CommandResults(
        readable_output=readable,
        outputs_prefix="O365MessageTrace.Event",
        outputs_key_field="id",
        outputs=events,
    )


def fetch_events(client: Client, max_events: int) -> None:
    """Scheduled fetch command - reads state, fetches, deduplicates, persists state."""
    last_run = demisto.getLastRun() or {}
    demisto.debug(f"[Fetch] last_run={last_run}")

    last_fetch_str: str | None = last_run.get("last_fetch")
    seen_ids: list[str] = last_run.get("seen_ids", []) or []

    now = datetime.now(UTC)
    if last_fetch_str:
        start_dt = parse_datetime(last_fetch_str)
    else:
        start_dt = now - timedelta(minutes=Config.DEFAULT_FIRST_FETCH_MINUTES)
        demisto.debug(f"[Fetch] First run - looking back {Config.DEFAULT_FIRST_FETCH_MINUTES} minutes from now")

    window_end_dt = min(start_dt + timedelta(minutes=Config.FETCH_WINDOW_MINUTES), now)
    demisto.debug(f"[Fetch] Window {start_dt.isoformat()} -> {window_end_dt.isoformat()} (now={now.isoformat()})")

    # Fetch all events in the window sequentially
    events = fetch_events_sequential(client, start_dt, window_end_dt, max_events=max_events)
    add_unique_id_field(events)
    add_time_field(events)
    demisto.debug(f"[Fetch] Fetched {len(events)} raw events before dedup")

    # Deduplicate against previous run's high-water-mark IDs
    new_events = deduplicate_events(events, set(seen_ids))
    demisto.debug(f"[Fetch] {len(new_events)} new events after dedup")

    if new_events:
        send_events_to_xsiam(events=new_events, vendor=Config.VENDOR, product=Config.PRODUCT)
        demisto.debug(f"[Fetch] Sent {len(new_events)} events to XSIAM")

    # New high-water mark. With no events, advance to the window end and reset seen_ids.
    new_last_fetch = format_datetime_for_filter(window_end_dt)
    new_seen_ids: list[str] = []

    # Use ALL fetched events (not just published ones): timestamps are second-granular, so
    # seen_ids must keep every ID at the boundary - including deduped-out ones - or the next
    # run (re-fetching at ``>= boundary``) would re-send already-sent events as duplicates.
    timed_events = [event for event in events if event.get("_time")]

    if timed_events:
        latest_time: str = max(event["_time"] for event in timed_events)
        new_last_fetch = latest_time
        ids_at_latest = [eid for event in timed_events if event.get("_time") == latest_time and (eid := event.get("_unique_id"))]
        # If the high-water mark hasn't moved, merge with the existing seen_ids
        if latest_time == last_fetch_str:
            new_seen_ids = list(set(seen_ids) | set(ids_at_latest))
        else:
            new_seen_ids = ids_at_latest

    new_last_run = {
        "last_fetch": new_last_fetch,
        "seen_ids": new_seen_ids,
    }
    demisto.setLastRun(new_last_run)
    demisto.debug(f"[Fetch] Updated last_run={new_last_run}")


# ============================================================================
# Main
# ============================================================================
def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    demisto.debug(f"[Main] Command={command}")

    config = parse_integration_params(params)
    max_events = config.pop("max_events")

    try:
        client = Client(**config)  # pylint: disable=E1123

        if command == "test-module":
            return_results(test_module(client))
        elif command == "o365-message-trace-auth-test":
            return_results(auth_test_command(client))
        elif command == "o365-message-trace-auth-reset":
            return_results(reset_auth())
        elif command == "o365-message-trace-get-events":
            return_results(get_events_command(client, args))
        elif command == "fetch-events":
            fetch_events(client, max_events=max_events)
        elif command == "o365-message-trace-generate-login-url":
            return_results(generate_login_url(client.ms_client))

        else:
            raise NotImplementedError(f"Command '{command}' is not implemented.")
    except Exception as e:
        error_msg = f"Failed to execute {command}. Error: {e!s}"
        demisto.error(f"{error_msg}\n{traceback.format_exc()}")
        return_error(error_msg)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
