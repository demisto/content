"""Akamai Prolexic Event Collector for Cortex XSIAM.

Fetches DDoS-related events from the Akamai Prolexic Analytics API and forwards
them to Cortex XSIAM as a single ``akamai_prolexic_raw`` dataset
(vendor=``akamai``, product=``prolexic``).

Two event sources are supported:

* **Critical Events** — ``GET /prolexic-analytics/v2/critical-events/contract/{contract}``
* **Events**          — ``GET /prolexic-analytics/v2/events/contract/{contract}?extended=true``

Authentication is Akamai EdgeGrid HMAC-SHA-256, performed by the
``akamai-edgegrid`` library and attached to every HTTP request via the
``requests`` ``auth`` mechanism.
"""

import traceback
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

import demistomock as demisto  # noqa: F401
import urllib3
from akamai.edgegrid import EdgeGridAuth
from CommonServerPython import *  # noqa: F401

urllib3.disable_warnings()

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

VENDOR = "akamai"
PRODUCT = "prolexic"

CRITICAL_EVENTS = "Critical Events"
EVENTS = "Events"

# Per-source configuration — exact endpoints/timestamp fields come from the
# Akamai Prolexic Analytics design document (CIAC-16080).
SOURCE_CONFIG: dict[str, dict[str, str]] = {
    CRITICAL_EVENTS: {
        "endpoint_template": "/prolexic-analytics/v2/critical-events/contract/{contract}",
        "time_field": "firstOccur",
        "last_run_key": "critical_events",
    },
    EVENTS: {
        "endpoint_template": "/prolexic-analytics/v2/events/contract/{contract}",
        "time_field": "eventStartTime",
        "last_run_key": "events",
    },
}

# Default to "now" so the first fetch does not back-fill historical events
# (matches the XSIAM Event-Collector convention used by OnePassword and others).
DEFAULT_FIRST_FETCH = "now"
DEFAULT_MAX_EVENTS_PER_FETCH = 1000
MAX_EVENTS_PER_FETCH_CEILING = 10000
ISO_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #


class Client(BaseClient):
    """Thin wrapper around ``BaseClient`` that issues EdgeGrid-signed requests
    to the Akamai Prolexic Analytics API.

    ``BaseClient`` is intentionally used (instead of ``ContentClient``) because
    the Akamai EdgeGrid library ships a ``requests.auth.AuthBase`` implementation
    that signs each call synchronously via ``self._session.auth`` — this is
    natively supported by ``BaseClient`` but is not directly compatible with
    the ``httpx``-based ``ContentClient``. This mirrors the pattern used by
    the existing ``Akamai_SIEM`` pack.
    """

    def __init__(
        self,
        base_url: str,
        verify: bool,
        proxy: bool,
        client_token: str,
        client_secret: str,
        access_token: str,
        account_switch_key: str | None = None,
    ) -> None:
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        # ``EdgeGridAuth`` is a ``requests.auth.AuthBase`` implementation that
        # signs the request with HMAC-SHA-256 immediately before it is sent.
        self._session.auth = EdgeGridAuth(
            client_token=client_token,
            client_secret=client_secret,
            access_token=access_token,
        )
        self._account_switch_key = account_switch_key or None

    def _build_params(self, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        """Always merge in ``accountSwitchKey`` when configured."""
        params: dict[str, Any] = dict(extra or {})
        if self._account_switch_key:
            params["accountSwitchKey"] = self._account_switch_key
        return params

    def get_critical_events(self, contract_id: str) -> dict[str, Any]:
        """Calls ``GET /v2/critical-events/contract/{contract}``."""
        url_suffix = SOURCE_CONFIG[CRITICAL_EVENTS]["endpoint_template"].format(contract=contract_id)
        return self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params=self._build_params(),
            headers={"Accept": "application/json"},
        )

    def get_events(self, contract_id: str) -> dict[str, Any]:
        """Calls ``GET /v2/events/contract/{contract}?extended=true``."""
        url_suffix = SOURCE_CONFIG[EVENTS]["endpoint_template"].format(contract=contract_id)
        return self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params=self._build_params({"extended": "true"}),
            headers={"Accept": "application/json"},
        )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def parse_first_fetch(first_fetch: str) -> str:
    """Convert the human-friendly ``first_fetch`` parameter into an ISO string.

    Falls back to :data:`DEFAULT_FIRST_FETCH` if the value is empty/invalid.
    """
    parsed: datetime | None = arg_to_datetime(first_fetch or DEFAULT_FIRST_FETCH, required=False)
    if parsed is None:
        parsed = arg_to_datetime(DEFAULT_FIRST_FETCH, required=True)  # type: ignore[assignment]
    assert parsed is not None  # for mypy
    return parsed.astimezone(UTC).strftime(ISO_FORMAT)


def normalize_event_timestamp(value: Any) -> str | None:
    """Normalise a raw timestamp value (string, int, float) to ISO-8601 UTC.

    Returns ``None`` if the value cannot be parsed.
    """
    if value is None or value == "":
        return None
    try:
        parsed = arg_to_datetime(value, required=False)
    except (ValueError, TypeError):
        return None
    if parsed is None:
        return None
    return parsed.astimezone(UTC).strftime(ISO_FORMAT)


def make_event_id(event_type: str, raw: dict[str, Any], time_field: str) -> str:
    """Build a stable dedup key.

    The Prolexic API does not return a single canonical ``id`` field, so we
    use the documented timestamp field together with any provided ``id``-like
    field to form a composite key. This is robust against re-emission of the
    same record across overlapping fetch windows.
    """
    candidate_id_fields = ("id", "eventId", "incidentId", "alertId", "uuid")
    raw_id = next((str(raw[k]) for k in candidate_id_fields if raw.get(k) is not None), "")
    raw_time = str(raw.get(time_field, ""))
    return f"{event_type}:{raw_id}:{raw_time}"


def annotate_critical_event(event: dict[str, Any]) -> None:
    """Add the ``_ENTRY_STATUS`` field per the design doc.

    * ``_ENTRY_STATUS = "new"``     when ``recentOccur == firstOccur``
    * ``_ENTRY_STATUS = "updated"`` when ``recentOccur >  firstOccur``
    """
    first_occur = event.get("firstOccur")
    recent_occur = event.get("recentOccur")
    if first_occur is None:
        return
    if recent_occur is None or recent_occur == first_occur:
        event["_ENTRY_STATUS"] = "new"
    else:
        event["_ENTRY_STATUS"] = "updated"


def extract_event_list(response: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract the list of event dicts from a Prolexic API response.

    The Akamai Prolexic Analytics API typically returns a wrapper dict whose
    payload key varies (``events``, ``criticalEvents``, ``data``, ``items``).
    We probe each candidate and fall back to a top-level list if present.
    """
    if isinstance(response, list):
        return [e for e in response if isinstance(e, dict)]
    if not isinstance(response, dict):
        return []
    for key in ("events", "criticalEvents", "data", "items", "results"):
        value = response.get(key)
        if isinstance(value, list):
            return [e for e in value if isinstance(e, dict)]
    return []


def filter_and_dedup(
    raw_events: list[dict[str, Any]],
    event_type: str,
    last_fetch_iso: str,
    fetched_ids: set[str],
    max_events: int,
) -> tuple[list[dict[str, Any]], str, set[str]]:
    """Filter out previously-seen events and cap by ``max_events``.

    Returns the selected events, the new high-water-mark timestamp, and the
    set of dedup ids that share that high-water-mark (to be persisted in
    ``last_run`` so the next fetch can skip them even if the API re-emits them
    at exactly the same timestamp).

    Note: The returned id-set is computed defensively. When the high-water
    mark does NOT advance (i.e. ``new_high_water == last_fetch_iso``) we
    UNION with the input ``fetched_ids`` so that previously-seen ids at the
    same boundary timestamp survive into the next ``last_run``. Replacing
    them would risk re-ingestion if the API re-emitted the same event.
    """
    time_field = SOURCE_CONFIG[event_type]["time_field"]
    selected: list[dict[str, Any]] = []
    last_fetch_dt = arg_to_datetime(last_fetch_iso)
    new_high_water = last_fetch_iso
    new_high_water_dt = last_fetch_dt
    skipped_invalid_ts = 0
    skipped_old = 0
    skipped_seen = 0

    # Sort ascending by timestamp so we walk the time window forward.
    def _sort_key(ev: dict[str, Any]) -> str:
        return str(ev.get(time_field) or "")

    for raw in sorted(raw_events, key=_sort_key):
        normalized_ts = normalize_event_timestamp(raw.get(time_field))
        if normalized_ts is None:
            skipped_invalid_ts += 1
            continue
        event_dt = arg_to_datetime(normalized_ts)
        if last_fetch_dt is not None and event_dt is not None and event_dt < last_fetch_dt:
            skipped_old += 1
            continue

        dedup_id = make_event_id(event_type, raw, time_field)
        if dedup_id in fetched_ids:
            skipped_seen += 1
            continue

        enriched: dict[str, Any] = dict(raw)
        enriched["_time"] = normalized_ts
        enriched["event_type"] = event_type
        enriched["SOURCE_LOG_TYPE"] = event_type.upper().replace(" ", "_")
        if event_type == CRITICAL_EVENTS:
            annotate_critical_event(enriched)

        selected.append(enriched)
        fetched_ids.add(dedup_id)

        if event_dt is not None and (new_high_water_dt is None or event_dt > new_high_water_dt):
            new_high_water_dt = event_dt
            new_high_water = normalized_ts

        if len(selected) >= max_events:
            break

    if skipped_invalid_ts or skipped_old or skipped_seen:
        demisto.debug(
            f"{event_type}: skipped {skipped_invalid_ts} invalid-timestamp, "
            f"{skipped_old} pre-cursor and {skipped_seen} previously-seen events."
        )
    if len(selected) >= max_events:
        demisto.debug(f"Reached max_events={max_events} for {event_type}; truncating.")

    # Compute retained ids for next run.
    new_run_ids = {make_event_id(event_type, ev, time_field) for ev in selected if ev.get("_time") == new_high_water}
    if new_high_water == last_fetch_iso:
        # Cursor did not advance — keep prior boundary ids so they cannot
        # be re-ingested next run.
        retained_ids = fetched_ids | new_run_ids
    else:
        retained_ids = new_run_ids
    return selected, new_high_water, retained_ids


# --------------------------------------------------------------------------- #
# Source dispatch
# --------------------------------------------------------------------------- #


def fetch_source_events(
    client: Client,
    event_type: str,
    contract_id: str,
    source_last_run: dict[str, Any],
    max_events: int,
    first_fetch_iso: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fetch + dedup events for a single source. Returns ``(events, next_run)``."""
    last_fetch_iso = source_last_run.get("last_fetch_ts") or first_fetch_iso
    fetched_ids = set(source_last_run.get("fetched_ids") or [])

    if event_type == CRITICAL_EVENTS:
        response = client.get_critical_events(contract_id)
    elif event_type == EVENTS:
        response = client.get_events(contract_id)
    else:
        raise DemistoException(f"Unsupported event type: {event_type}")

    raw_events = extract_event_list(response)
    demisto.debug(f"Fetched {len(raw_events)} raw {event_type} from Prolexic API.")

    events, new_high_water, retained_ids = filter_and_dedup(
        raw_events=raw_events,
        event_type=event_type,
        last_fetch_iso=last_fetch_iso,
        fetched_ids=fetched_ids,
        max_events=max_events,
    )
    next_run = {"last_fetch_ts": new_high_water, "fetched_ids": sorted(retained_ids)}
    return events, next_run


def push_events(events: list[dict[str, Any]]) -> None:
    """Push events to XSIAM with the documented vendor/product."""
    if not events:
        demisto.debug("No events to push to XSIAM.")
        return
    demisto.debug(f"Pushing {len(events)} events to XSIAM as {VENDOR}/{PRODUCT}.")
    send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #


def run_test_module(client: Client, contract_id: str, event_types: Iterable[str]) -> str:
    """Run a lightweight call against each configured source to confirm
    credentials and contract id.

    Named ``run_test_module`` (not ``test_module``) so that pytest does not
    collect it as a test case.
    """
    selected_types = list(event_types) or [CRITICAL_EVENTS, EVENTS]
    for event_type in selected_types:
        if event_type not in SOURCE_CONFIG:
            return f"Unknown event type configured: {event_type}"
        try:
            if event_type == CRITICAL_EVENTS:
                client.get_critical_events(contract_id)
            else:
                client.get_events(contract_id)
        except DemistoException as exc:
            # Use duck-typing on ``exc.res`` so that any object exposing
            # ``status_code`` (real ``requests.Response`` or stub) works.
            status = getattr(getattr(exc, "res", None), "status_code", None)
            if status in (401, 403):
                return (
                    "Authorization Error: verify the EdgeGrid Client Token, Client Secret, "
                    "Access Token and that the API client has access to the configured Contract ID."
                )
            if status == 404:
                return "Endpoint not found: verify the Server URL and Contract ID."
            raise
    return "ok"


def get_events_command(
    client: Client,
    args: dict[str, Any],
    contract_id: str,
    configured_types: list[str],
    first_fetch_iso: str,
) -> tuple[list[dict[str, Any]], CommandResults]:
    """Manual fetch (``akamai-prolexic-get-events``) used for development."""
    limit = arg_to_number(args.get("limit")) or 50
    requested_types = argToList(args.get("event_type")) or configured_types or [CRITICAL_EVENTS, EVENTS]

    # ``start_time`` lets the caller override the lower-bound timestamp used
    # for client-side filtering. If omitted we fall back to ``first_fetch``.
    start_time_arg = args.get("start_time")
    if start_time_arg:
        start_iso = parse_first_fetch(str(start_time_arg))
    else:
        start_iso = first_fetch_iso

    all_events: list[dict[str, Any]] = []
    for event_type in requested_types:
        events, _ = fetch_source_events(
            client=client,
            event_type=event_type,
            contract_id=contract_id,
            source_last_run={"last_fetch_ts": start_iso, "fetched_ids": []},
            max_events=limit,
            first_fetch_iso=start_iso,
        )
        all_events.extend(events)

    human_readable = tableToMarkdown(
        name=f"{VENDOR.title()} {PRODUCT.title()} Events",
        t=all_events,
        removeNull=True,
    )
    return all_events, CommandResults(readable_output=human_readable)


def fetch_events(
    client: Client,
    contract_id: str,
    event_types: list[str],
    max_events_per_fetch: int,
    first_fetch_iso: str,
    last_run: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Top-level fetch. Returns ``(events, next_run)``."""
    next_run: dict[str, Any] = dict(last_run or {})
    all_events: list[dict[str, Any]] = []
    for event_type in event_types:
        source_key = SOURCE_CONFIG[event_type]["last_run_key"]
        source_last_run = (last_run or {}).get(source_key, {})
        events, source_next_run = fetch_source_events(
            client=client,
            event_type=event_type,
            contract_id=contract_id,
            source_last_run=source_last_run,
            max_events=max_events_per_fetch,
            first_fetch_iso=first_fetch_iso,
        )
        all_events.extend(events)
        next_run[source_key] = source_next_run
    return all_events, next_run


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def _parse_max_events_per_fetch(raw: Any) -> int:
    """Parse and validate the ``max_events_per_fetch`` parameter.

    Distinguishes between "not supplied" (use default) and "explicitly 0/negative"
    (reject). Using ``arg_to_number(...) or DEFAULT`` would silently rewrite
    ``0`` to ``DEFAULT``, masking misconfiguration.
    """
    if raw in (None, ""):
        return DEFAULT_MAX_EVENTS_PER_FETCH
    parsed = arg_to_number(raw)
    if parsed is None:
        raise DemistoException(f"Maximum events per fetch must be an integer; got {raw!r}.")
    if parsed <= 0 or parsed > MAX_EVENTS_PER_FETCH_CEILING:
        raise DemistoException(f"Maximum events per fetch must be between 1 and {MAX_EVENTS_PER_FETCH_CEILING}; got {parsed}.")
    return parsed


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url: str = (params.get("url") or "").rstrip("/")
    contract_id: str = (params.get("contract_id") or "").strip()
    client_token: str = (params.get("client_token_creds") or {}).get("password", "") or params.get("client_token", "")
    client_secret: str = (params.get("client_secret_creds") or {}).get("password", "") or params.get("client_secret", "")
    access_token: str = (params.get("access_token_creds") or {}).get("password", "") or params.get("access_token", "")
    account_switch_key: str = (params.get("account_switch_key") or "").strip() or ""

    event_types: list[str] = argToList(params.get("event_types_to_fetch")) or [CRITICAL_EVENTS, EVENTS]
    for event_type in event_types:
        if event_type not in SOURCE_CONFIG:
            return_error(f"Unsupported event type configured: {event_type}")

    if not base_url:
        return_error("Server URL is required.")
    if not contract_id:
        return_error("Contract ID is required.")
    if not (client_token and client_secret and access_token):
        return_error("Client Token, Client Secret and Access Token are all required.")

    first_fetch_iso = parse_first_fetch(params.get("first_fetch") or DEFAULT_FIRST_FETCH)
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    demisto.debug(f"Command being called is {command!r}")
    try:
        max_events_per_fetch = _parse_max_events_per_fetch(params.get("max_events_per_fetch"))

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            client_token=client_token,
            client_secret=client_secret,
            access_token=access_token,
            account_switch_key=account_switch_key,
        )

        if command == "test-module":
            return_results(run_test_module(client, contract_id, event_types))
            return

        if command == "akamai-prolexic-get-events":
            should_push = argToBoolean(args.get("should_push_events", "false"))
            events, results = get_events_command(
                client=client,
                args=args,
                contract_id=contract_id,
                configured_types=event_types,
                first_fetch_iso=first_fetch_iso,
            )
            return_results(results)
            if should_push:
                push_events(events)
            return

        if command == "fetch-events":
            last_run = demisto.getLastRun() or {}
            events, next_run = fetch_events(
                client=client,
                contract_id=contract_id,
                event_types=event_types,
                max_events_per_fetch=max_events_per_fetch,
                first_fetch_iso=first_fetch_iso,
                last_run=last_run,
            )
            push_events(events)
            demisto.setLastRun(next_run)
            return

        raise NotImplementedError(f"Command {command!r} is not implemented.")

    except Exception as exc:  # noqa: BLE001
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command!r} command. Error: {exc!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
