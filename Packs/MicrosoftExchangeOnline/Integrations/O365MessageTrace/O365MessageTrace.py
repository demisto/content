import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa
from ContentClientApiModule import *  # noqa: F401,F403

import time
import urllib3
import httpx
from datetime import datetime, timedelta, UTC
from typing import Any

urllib3.disable_warnings()

# ============================================================================
# Constants
# ============================================================================
class Config:
    """Global static configuration."""

    VENDOR = "microsoft"
    PRODUCT = "o365_message_trace"

    DEFAULT_BASE_URL = "https://graph.microsoft.com"
    GRAPH_SCOPE = "https://graph.microsoft.com/.default"
    LOGIN_URL = "https://login.microsoftonline.com"
    MANAGED_IDENTITIES_TOKEN_URL = "http://169.254.169.254/metadata/identity/oauth2/token"
    MANAGED_IDENTITIES_API_VERSION = "2018-02-01"

    MESSAGE_TRACES_PATH = "/v1.0/admin/exchange/tracing/messageTraces"

    DATE_FORMAT_FILTER = "%Y-%m-%dT%H:%M:%SZ"

    DEFAULT_MAX_EVENTS = 50000
    DEFAULT_PAGE_SIZE = 1000  # API default/maximum per page
    DEFAULT_FIRST_FETCH_MINUTES = 10
    TOKEN_CONTEXT_NAMESPACE = "o365_message_trace"


# ============================================================================
# Auth handler for Azure Managed Identity (extends ContentClientApiModule)
# ============================================================================
class AzureManagedIdentityAuthHandler(AuthHandler):  # type: ignore[misc] # AuthHandler comes from ContentClientApiModule
    """Auth handler that fetches a token from the Azure Instance Metadata Service.

    Used when running inside an Azure VM/Function/AKS with a managed identity
    assigned. Tokens are cached and refreshed 60 seconds before expiry, mirroring
    the behavior of :class:`OAuth2ClientCredentialsHandler` from
    ``ContentClientApiModule``.
    """

    def __init__(self, resource: str = Config.DEFAULT_BASE_URL, client_id: str | None = None):
        super().__init__()
        self.resource = resource
        self.client_id = client_id  # optional - for user-assigned managed identities
        self.name = "azure_managed_identity"
        self._access_token: str | None = None
        self._expires_at: float = 0

    async def on_request(self, client: "ContentClient", request: httpx.Request) -> None:  # type: ignore[name-defined]
        if self._should_refresh():
            await self._refresh_token(client)
        if self._access_token:
            request.headers["Authorization"] = f"Bearer {self._access_token}"

    async def on_auth_failure(self, client: "ContentClient", response: httpx.Response) -> bool:  # type: ignore[name-defined]
        await self._refresh_token(client)
        return True

    def _should_refresh(self) -> bool:
        return not self._access_token or time.monotonic() >= self._expires_at - 60

    async def _refresh_token(self, client: "ContentClient") -> None:  # type: ignore[name-defined]
        params: dict[str, str] = {
            "api-version": Config.MANAGED_IDENTITIES_API_VERSION,
            "resource": self.resource,
        }
        if self.client_id:
            params["client_id"] = self.client_id

        async with httpx.AsyncClient(verify=client._verify, timeout=httpx.Timeout(30.0)) as imds_client:
            try:
                response = await imds_client.get(
                    Config.MANAGED_IDENTITIES_TOKEN_URL,
                    params=params,
                    headers={"Metadata": "True"},
                )
                response.raise_for_status()
                token_data = response.json()
            except Exception as e:
                raise ContentClientAuthenticationError(f"Managed Identity token fetch failed: {e}") from e

        access_token = token_data.get("access_token")
        if not access_token:
            raise ContentClientAuthenticationError(f"No access_token in IMDS response: {token_data}")

        self._access_token = access_token
        self._expires_at = time.monotonic() + int(token_data.get("expires_in", 3600))
        demisto.debug(f"[Auth/IMDS] Token refreshed, valid for {token_data.get('expires_in')}s")


# ============================================================================
# Client
# ============================================================================
class Client(ContentClient):  # type: ignore[misc] # ContentClient comes from ContentClientApiModule
    """Microsoft Graph client for O365 Message Trace events.

    Extends :class:`ContentClient` from ``ContentClientApiModule`` and selects
    between OAuth2 client-credentials and Azure Managed Identity auth based on
    integration parameters.
    """

    def __init__(
        self,
        base_url: str,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        use_managed_identity: bool,
        verify: bool,
        proxy: bool,
    ):
        auth_handler: AuthHandler  # type: ignore[name-defined]
        if use_managed_identity:
            demisto.debug("[Auth] Using Azure Managed Identity")
            auth_handler = AzureManagedIdentityAuthHandler(
                resource=base_url,
                client_id=client_id or None,
            )
        else:
            if not (tenant_id and client_id and client_secret):
                raise DemistoException("Tenant ID, Client ID and Client Secret are required when not using Azure Managed Identity.")
            demisto.debug("[Auth] Using OAuth2 client credentials")
            token_url = f"{Config.LOGIN_URL}/{tenant_id}/oauth2/v2.0/token"
            auth_handler = OAuth2ClientCredentialsHandler(
                token_url=token_url,
                client_id=client_id,
                client_secret=client_secret,
                scope=Config.GRAPH_SCOPE,
                context_store=ContentClientContextStore(namespace=Config.TOKEN_CONTEXT_NAMESPACE),
            )

        retry_policy = RetryPolicy(  # type: ignore[call-arg]
            max_attempts=4,
            retryable_status_codes=(429, 500, 502, 503, 504),
        )

        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            auth_handler=auth_handler,
            retry_policy=retry_policy,
            client_name="O365MessageTrace",
            timeout=60,
        )

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
            return self._http_request(method="GET", full_url=next_link)

        params = {
            "$filter": f"receivedDateTime ge {start_date} and receivedDateTime le {end_date}",
            "$top": page_size,
        }
        demisto.debug(f"[API] First page request | params={params}")
        return self._http_request(method="GET", url_suffix=Config.MESSAGE_TRACES_PATH, params=params)


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
        event_id = event.get('id')
        if event_id and event_id in seen_ids:
            duplicates += 1
            continue
        new_events.append(event)

    if duplicates:
        demisto.debug(f"[Dedup] Skipped {duplicates} duplicate events")
    return new_events


def add_time_field(events: list[dict]) -> None:
    """Add the XSIAM-required ``_time`` field to each event."""
    for event in events:
        received = event.get("receivedDateTime")
        if received:
            event["_time"] = received


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

    Iterates through all available pages using ``@odata.nextLink`` until either
    ``max_events`` is reached or no more pages remain.
    """
    if end <= start:
        demisto.debug(f"[Fetch] Empty time range ({start.isoformat()} -> {end.isoformat()}). Skipping.")
        return []

    start_str = format_datetime_for_filter(start)
    end_str = format_datetime_for_filter(end)
    demisto.debug(f"[Fetch] Fetching window {start_str} -> {end_str} | max={max_events}")

    collected: list[dict] = []
    next_link: str | None = None

    while True:
        try:
            response = client.get_message_traces_page(
                start_date=start_str,
                end_date=end_str,
                next_link=next_link,
                page_size=Config.DEFAULT_PAGE_SIZE,
            )
        except Exception as e:
            demisto.error(f"[Fetch] Failed to fetch page for window {start_str} -> {end_str}: {e}")
            break

        page_events = response.get("value", []) or []
        collected.extend(page_events)
        demisto.debug(
            f"[Fetch] Window {start_str} -> {end_str}: page returned {len(page_events)} events "
            f"(running total: {len(collected)})"
        )

        if len(collected) >= max_events:
            demisto.debug(f"[Fetch] Reached max_events ({max_events}). Stopping.")
            collected = collected[:max_events]
            break

        next_link = response.get("@odata.nextLink")
        if not next_link:
            demisto.debug(f"[Fetch] Window {start_str} -> {end_str}: no more pages.")
            break

    return collected


# ============================================================================
# Commands
# ============================================================================
def test_module(client: Client) -> str:
    """Validate credentials and Graph connectivity by fetching a tiny window."""
    demisto.debug("[Test] Starting test-module")
    try:
        end = datetime.now(UTC)
        start = end - timedelta(minutes=5)
        client.get_message_traces_page(
            start_date=format_datetime_for_filter(start),
            end_date=format_datetime_for_filter(end),
            page_size=1,
        )
        return "ok"
    except Exception as e:
        error_message = str(e)
        if "401" in error_message or "403" in error_message:
            return f"Authorization Error: verify Tenant ID, Client ID and Client Secret. Details: {error_message}"
        raise


def get_events_command(client: Client, args: dict) -> CommandResults:
    """Manual command to retrieve events (and optionally push them to XSIAM)."""
    limit = arg_to_number(args.get("limit")) or 50
    start_time = args.get("start_time")
    end_time = args.get("end_time")
    should_push_events = argToBoolean(args.get("should_push_events", False))

    end_dt = parse_datetime(end_time, default=datetime.now(UTC))
    start_dt = parse_datetime(start_time, default=end_dt - timedelta(minutes=Config.DEFAULT_FIRST_FETCH_MINUTES))

    events = fetch_events_sequential(client, start_dt, end_dt, max_events=limit)
    add_time_field(events)

    if should_push_events and events:
        send_events_to_xsiam(events=events, vendor=Config.VENDOR, product=Config.PRODUCT)

    readable = tableToMarkdown(
        "O365 Message Trace Events",
        events,
        removeNull=True,
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

    end_dt = datetime.now(UTC)
    if last_fetch_str:
        start_dt = parse_datetime(last_fetch_str)
    else:
        start_dt = end_dt - timedelta(minutes=Config.DEFAULT_FIRST_FETCH_MINUTES)
        demisto.debug(f"[Fetch] First run - looking back {Config.DEFAULT_FIRST_FETCH_MINUTES} minutes from now")

    # Fetch all events in the window sequentially
    events = fetch_events_sequential(client, start_dt, end_dt, max_events=max_events)
    demisto.debug(f"[Fetch] Fetched {len(events)} raw events before dedup")

    # Deduplicate against previous run's high-water-mark IDs
    new_events = deduplicate_events(events, set(seen_ids))
    demisto.debug(f"[Fetch] {len(new_events)} new events after dedup")



    if new_events:
        add_time_field(new_events)
        send_events_to_xsiam(events=new_events, vendor=Config.VENDOR, product=Config.PRODUCT)
        demisto.debug(f"[Fetch] Sent {len(new_events)} events to XSIAM")

    # Compute the new high-water mark: latest receivedDateTime + IDs at that timestamp
    new_last_fetch = last_fetch_str or format_datetime_for_filter(end_dt)
    new_seen_ids: list[str] = seen_ids

    if new_events:
        # Reverse events so the latest event is the last one
        new_events.reverse()
        latest_time: str | None = new_events[-1].get("_time")

        if latest_time:
            new_last_fetch = latest_time
            ids_at_latest = [
                eid for event in new_events
                if event.get("_time") == latest_time and (eid := event.get('id'))
            ]
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
def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    demisto.debug(f"[Main] Command={command}")

    base_url = (params.get("url") or Config.DEFAULT_BASE_URL).rstrip("/")
    tenant_id = params.get("tenant_id", "")

    credentials_client_id = params.get("credentials_client_id") or {}
    if isinstance(credentials_client_id, dict):
        client_id = credentials_client_id.get("password") or params.get("client_id", "")
    else:
        client_id = params.get("client_id", "")

    credentials = params.get("credentials") or {}
    if isinstance(credentials, dict):
        client_secret = credentials.get("password") or params.get("client_secret", "")
    else:
        client_secret = params.get("client_secret", "")

    use_managed_identity = argToBoolean(params.get("use_managed_identity", False))
    verify = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    max_events = arg_to_number(params.get("max_fetch")) or Config.DEFAULT_MAX_EVENTS






    try:
        client = Client(
            base_url=base_url,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            use_managed_identity=use_managed_identity,
            verify=verify,
            proxy=proxy,
        )

        if command == "test-module":
            return_results(test_module(client))
        elif command == "o365-message-trace-get-events":
            return_results(get_events_command(client, args))
        elif command == "fetch-events":
            fetch_events(client, max_events=max_events)
        else:
            raise NotImplementedError(f"Command '{command}' is not implemented.")
    except Exception as e:
        return_error(f"Failed to execute '{command}' command. Error: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
