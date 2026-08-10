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

    # Bump on every hotfix so the running build can be confirmed from the `[Version]` debug log.
    VERSION_TAG = "o365-message-trace/2.0.1-fetch-lookback"

    VENDOR = "microsoft"
    PRODUCT = "o365_message_trace"

    APP_NAME = "o365-message-trace"
    GRAPH_SCOPE = "https://graph.microsoft.com/.default"

    MESSAGE_TRACES_PATH = "v1.0/admin/exchange/tracing/messageTraces"

    DATE_FORMAT_FILTER = "%Y-%m-%dT%H:%M:%S.%fZ"
    DATE_FORMAT_EVENT = "%Y-%m-%dT%H:%M:%S.%fZ"

    DEFAULT_MAX_EVENTS = 50000
    DEFAULT_PAGE_SIZE = 1000  # API default/maximum per page
    DEFAULT_FIRST_FETCH_MINUTES = 1

    # Each fetch cycle only scans this many minutes starting from ``last_fetch``.
    # This keeps every run small and bounded even when the
    # integration is far behind, so a large backlog is drained oldest-first
    # across many runs instead of re-downloading days of events on every run.
    FETCH_WINDOW_MINUTES = 5

    # Trailing look-back overlap (minutes): each cycle re-scans from ``last_fetch - LOOKBACK``.
    # Records are mutable (status evolves) but keep their original ``receivedDateTime``, so late
    # status updates must be re-scanned to be captured. Status-aware ``_unique_id`` dedup prevents
    # real duplicates from being re-sent. Observed status-settling lag is ~8 min max; 15 min adds
    # headroom for the tail. Configurable via the integration parameter if needed.
    DEFAULT_LOOKBACK_MINUTES = 15

    # Fixed backoff schedule (in seconds) applied between retries when the Graph
    # API responds with HTTP 429 (Too Many Requests).
    RATE_LIMIT_BACKOFFS = (30, 60, 90)


# ============================================================================
# Microsoft client
# ============================================================================
class O365MessageTraceClient(MicrosoftClient):
    """Thin subclass of :class:`MicrosoftClient` for the O365 Message Trace integration.

    It overrides :meth:`MicrosoftClient.http_request` while keeping the exact same
    logic as the parent implementation. All other behavior (authentication flows,
    token retrieval, metrics and error parsing) is inherited unchanged.
    """

    def http_request(
        self,
        *args,
        resp_type="json",
        headers=None,
        return_empty_response=False,
        scope: str | None = None,
        resource: str = "",
        **kwargs,
    ):
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.

        Args:
            resp_type: Type of response to return. will be ignored if `return_empty_response` is True.
            headers: Headers to add to the request.
            return_empty_response: Return the response itself if the return_code is 206.
            scope: A scope to request. Currently, will work only with self-deployed app.
            resource (str): The resource identifier for which the generated token will have access to.
        Returns:
            Response from api according to resp_type. The default is `json` (dict or list).
        """

        token = self.get_access_token(resource=resource, scope=scope)
        default_headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "application/json"}

        if headers:
            default_headers |= headers

        if self.timeout:
            kwargs["timeout"] = self.timeout

        kwargs["error_handler"] = self.handle_error_with_metrics

        response = super()._http_request(  # type: ignore[misc]
            *args,
            resp_type="response",
            headers=default_headers,
            status_list_to_retry=[503, 429],
            backoff_factor=30,
            retries=3,
            ok_codes=(200, 201, 202, 204, 206, 404),
            **kwargs,
        )

        MicrosoftClient.create_api_metrics(response.status_code)
        # 206 indicates Partial Content, reason will be in the warning header.
        # In that case, logs with the warning header will be written.
        if response.status_code == 206:
            demisto.debug(str(response.headers))
        is_response_empty_and_successful = response.status_code == 204
        if is_response_empty_and_successful and return_empty_response:
            return response

        # Handle 404 errors instead of raising them as exceptions:
        if response.status_code == 404:
            try:
                error_message = response.json()
            except Exception:
                error_message = "Not Found - 404 Response"
            raise NotFoundError(error_message)

        try:
            if resp_type == "json":
                return response.json()
            if resp_type == "text":
                return response.text
            if resp_type == "content":
                return response.content
            if resp_type == "xml":
                try:
                    import defusedxml.ElementTree as defused_ET

                    defused_ET.fromstring(response.text)
                except ImportError:
                    demisto.debug("defused_ET is not supported, using ET instead.")
                    ET.fromstring(response.text)
            return response
        except ValueError as exception:
            raise DemistoException(f"Failed to parse json object from response: {response.content}", exception)


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
        self.ms_client = O365MessageTraceClient(**client_args)

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
            return self.ms_client.http_request(method="GET", full_url=next_link, url_suffix="")

        params = {
            "$filter": f"receivedDateTime ge {start_date} and receivedDateTime le {end_date}",
            "$top": page_size,
        }
        demisto.debug(f"[API] First page request | params={params}")
        return self.ms_client.http_request(method="GET", url_suffix=Config.MESSAGE_TRACES_PATH, params=params)


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
    """Filter out events whose internal ``_dedup_key`` is already in ``seen_ids``."""
    if not seen_ids:
        return events

    new_events: list[dict] = []
    duplicates = 0
    for event in events:
        dedup_key = event.get("_dedup_key")
        if dedup_key and dedup_key in seen_ids:
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
    """Add the dataset ``_unique_id`` field (``<id>|<recipientAddress>``) and an internal
    ``_dedup_key`` (``<id>|<recipientAddress>|<status>``).

    ``_unique_id`` is the documented dataset field and stays 2-part for schema stability.
    ``_dedup_key`` additionally includes ``status`` and is used ONLY for fetch dedup/seen_ids
    (never sent to XSIAM): a message-trace record is re-emitted as its status evolves
    (e.g. delivered -> recalled), so keying dedup on status lets each transition through while
    still suppressing true duplicates of the same (id, recipient, status) across overlapping
    fetch windows.
    """
    for event in events:
        event_id = event.get("id")
        recipient = event.get("recipientAddress")
        status = event.get("status") or ""
        if event_id and recipient:
            event["_unique_id"] = f"{event_id}|{recipient}"
            event["_dedup_key"] = f"{event_id}|{recipient}|{status}"


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
    lookback_minutes = arg_to_number(params.get("lookback_minutes")) or Config.DEFAULT_LOOKBACK_MINUTES

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
        "lookback_minutes": lookback_minutes,
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
    previous_link: str | None = None  # Track to detect a non-advancing cursor.
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
            f"[Fetch] Window {start_str} -> {end_str}: page returned {len(page_events)} events (running total: {len(collected)})"
        )
        # Defensive stop #1: empty page means there is nothing more to read.
        if not page_events:
            demisto.debug(f"[Fetch] Window {start_str} -> {end_str}: empty page, stopping.")
            break
        next_link = response.get("@odata.nextLink")
        # Normal stop: no more pages.
        if not next_link:
            demisto.debug(f"[Fetch] Window {start_str} -> {end_str}: no more pages.")
            break
        # Defensive stop #2: the cursor did not advance (non-advancing/self-referential
        # @odata.nextLink). Without this, a misbehaving server could loop forever.
        if next_link == previous_link:
            demisto.error(
                f"[Fetch] Window {start_str} -> {end_str}: @odata.nextLink did not advance "
                f"({next_link}). Stopping to avoid an infinite loop."
            )
            break
        previous_link = next_link

    # Sort all collected events ascending by receivedDateTime (parsed as datetime) so the
    # earliest event is first.
    collected.sort(
        key=lambda event: safe_strptime(event["receivedDateTime"], Config.DATE_FORMAT_EVENT)
        if event.get("receivedDateTime")
        else datetime.min
    )

    if len(collected) > max_events:
        # Truncate to max_events, but never cut through a group sharing the same
        # receivedDateTime second - otherwise the high-water mark would advance past a
        # second whose events were only partially fetched, permanently skipping the rest.
        cut = max_events
        boundary_time = collected[max_events - 1].get("receivedDateTime")
        while cut < len(collected) and collected[cut].get("receivedDateTime") == boundary_time:
            cut += 1
        demisto.debug(
            f"[Fetch] Collected {len(collected)} events, truncating to {cut} "
            f"(max_events={max_events}, extended to keep whole boundary second {boundary_time})."
        )
        collected = collected[:cut]

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
            "Test module is not available for the authorization code flow. Use the o365-message-trace-auth-test command instead."
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
    # ``_dedup_key`` is an internal fetch-only field; never expose it via this manual command.
    for event in events:
        event.pop("_dedup_key", None)

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


def fetch_events(client: Client, max_events: int, lookback_minutes: int | None = None) -> None:
    """Scheduled fetch command - reads state, fetches, deduplicates, persists state."""
    if lookback_minutes is None:
        lookback_minutes = Config.DEFAULT_LOOKBACK_MINUTES
    last_run = demisto.getLastRun() or {}
    demisto.debug(f"[Fetch] last_run={last_run} | max_events={max_events} | lookback_minutes={lookback_minutes}")

    last_fetch_str: str | None = last_run.get("last_fetch")
    seen_ids: list[str] = last_run.get("seen_ids", []) or []

    now = datetime.now(UTC)
    if last_fetch_str:
        # Trailing look-back overlap: re-scan back from last_fetch so late status updates
        # (which keep their original receivedDateTime) are re-surfaced. Status-aware dedup
        # below prevents already-sent (id, recipient, status) tuples from being re-sent.
        # When the look-back exceeds one window, the run naturally takes the window-walk branch
        # below, keeping every API call bounded to FETCH_WINDOW_MINUTES.
        start_dt = parse_datetime(last_fetch_str) - timedelta(minutes=lookback_minutes)
        demisto.debug(
            f"[Fetch] Resuming from last_fetch={last_fetch_str} with {lookback_minutes}m look-back "
            f"-> effective start={start_dt.isoformat()}"
        )
    else:
        start_dt = now - timedelta(minutes=Config.DEFAULT_FIRST_FETCH_MINUTES)
        demisto.debug(f"[Fetch] First run - looking back {Config.DEFAULT_FIRST_FETCH_MINUTES} minutes from now")

    if now < start_dt + timedelta(minutes=Config.FETCH_WINDOW_MINUTES):
        window_end_dt = now
        demisto.debug(f"[Fetch] Window {start_dt.isoformat()} -> {window_end_dt.isoformat()} (now={now.isoformat()})")
        events = fetch_events_sequential(client, start_dt, window_end_dt, max_events=max_events)

    else:
        window_end_dt = min(start_dt + timedelta(minutes=Config.FETCH_WINDOW_MINUTES), now)
        all_events: list[dict] = []

        # Walk fixed-size windows until we either catch up to ``now``, collect enough
        # events, or hit the safety cap on how many times ``fetch_events_sequential``
        # may be called in a single run.
        while start_dt < now and len(all_events) < max_events:
            window_end_dt = min(start_dt + timedelta(minutes=Config.FETCH_WINDOW_MINUTES), now)
            try:
                events = fetch_events_sequential(client, start_dt, window_end_dt, max_events=max_events)
            except Exception as e:
                demisto.error(f"[Fetch] Error fetching events for window {start_dt} -> {window_end_dt}: {e}")
                break
            all_events.extend(events)
            # Guard: the window cursor MUST advance, or stop (mirrors the pagination guard).
            if window_end_dt <= start_dt:
                demisto.error(f"[Fetch] Window did not advance ({start_dt} -> {window_end_dt}); stopping.")
                break
            start_dt = window_end_dt
            window_end_dt = min(start_dt + timedelta(minutes=Config.FETCH_WINDOW_MINUTES), now)

        events = all_events
        if len(events) > max_events:
            events = events[:max_events]

    add_unique_id_field(events)
    add_time_field(events)
    demisto.debug(f"[Fetch] Fetched {len(events)} raw events before dedup")

    # Deduplicate against previous run's high-water-mark IDs
    new_events = deduplicate_events(events, set(seen_ids))
    demisto.debug(f"[Fetch] {len(new_events)} new events after dedup (skipped {len(events) - len(new_events)})")

    if new_events:
        # Strip the internal dedup key so it never lands in the dataset.
        for event in new_events:
            event.pop("_dedup_key", None)
        send_events_to_xsiam(events=new_events, vendor=Config.VENDOR, product=Config.PRODUCT)
        demisto.debug(f"[Fetch] Sent {len(new_events)} events to XSIAM")

    # New high-water mark. With no events, advance to the window end.
    new_last_fetch = format_datetime_for_filter(window_end_dt)

    timed_events = [event for event in events if event.get("_time") and event.get("_dedup_key")]
    if timed_events:
        new_last_fetch = max(event["_time"] for event in timed_events)

    # Persist EVERY _dedup_key whose _time falls inside the trailing look-back window that the
    # NEXT run will re-scan (``[new_last_fetch - lookback, new_last_fetch]``). The next run
    # re-queries that entire overlap, so every key in it - not just the boundary second - must be
    # in seen_ids, otherwise every event in the overlap would be re-sent as a duplicate on each
    # run. Keys older than the overlap are dropped, keeping the state bounded to the window.
    # Compare parsed datetimes, not raw strings: ``_time`` (raw API value) and a formatted
    # cutoff may differ in fractional-second precision, so a string ``>=`` would silently drop
    # every key and re-send the whole overlap each run.
    overlap_cutoff_dt = parse_datetime(new_last_fetch) - timedelta(minutes=lookback_minutes)
    seen_set = {event["_dedup_key"] for event in timed_events if parse_datetime(event["_time"]) >= overlap_cutoff_dt}

    # If the high-water mark did NOT advance, this run did not re-fetch anything newer than the
    # previous boundary, so previously-seen ids must be retained (they would otherwise be re-sent
    # next run). When it DID advance, this run already re-fetched the whole overlap, so its own
    # set is a superset and no merge is needed. Compare as datetimes, not strings: an upgraded
    # instance may still hold ``last_fetch`` in an older format, so a string ``==`` could wrongly
    # skip the merge even when the instant is unchanged.
    if last_fetch_str and parse_datetime(new_last_fetch) == parse_datetime(last_fetch_str):
        seen_set |= set(seen_ids)

    new_seen_ids = sorted(seen_set)
    demisto.debug(
        f"[Fetch] overlap_cutoff={overlap_cutoff_dt.isoformat()} | " f"{len(new_seen_ids)} seen_ids carried forward for next run"
    )

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
    demisto.debug(f"[Version] Running {Config.VERSION_TAG}")
    demisto.debug(f"[Main] Command={command}")

    config = parse_integration_params(params)
    max_events = config.pop("max_events")
    lookback_minutes = config.pop("lookback_minutes")

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
            fetch_events(client, max_events=max_events, lookback_minutes=lookback_minutes)
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
