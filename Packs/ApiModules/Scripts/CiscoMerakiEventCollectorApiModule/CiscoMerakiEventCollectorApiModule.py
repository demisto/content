import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CiscoMerakiApiModule import *  # noqa: E402

""" Imports """
import hashlib
import http
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

""" Constants """

VENDOR = "cisco"
PRODUCT = "meraki"
COLLECTOR_COMMAND_PREFIX = "cisco-meraki"
DEFAULT_MAX_EVENTS_PER_TYPE = 10000
FIRST_FETCH_LOOKBACK = timedelta(hours=1)
NETWORK_CACHE_TTL = timedelta(hours=24)
BOUNDARY_TOLERANCE = timedelta(seconds=1)
MERAKI_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
NETWORK_EVENTS_PRODUCT_TYPES = {"appliance", "camera", "cellularGateway", "switch", "systemsManager", "wireless"}

CONFIGURATION_CHANGES = "configuration_changes"
NETWORK_EVENTS = "network_events"
API_REQUESTS = "api_requests"
APPLIANCE_SECURITY_EVENTS = "appliance_security_events"


@dataclass(frozen=True)
class WindowedEventType:
    """An organization-level event type fetched by a [t0, t1] time window and Link-header pagination."""

    name: str
    display: str
    url_template: str
    time_field: str
    max_page_size: int
    max_lookback: timedelta
    extra_params: tuple[tuple[str, str], ...] = ()


# Registry of the organization-level, time-windowed event types. Add an entry to support a new type.
WINDOWED_EVENT_TYPES: dict[str, WindowedEventType] = {
    CONFIGURATION_CHANGES: WindowedEventType(
        name=CONFIGURATION_CHANGES,
        display="Configuration changes",
        url_template="organizations/{organization_id}/configurationChanges",
        time_field="ts",
        # The API accepts perPage up to 100,000, so a per-type limit up to that size is fetched in a single request.
        max_page_size=100000,
        max_lookback=timedelta(days=365),
    ),
    API_REQUESTS: WindowedEventType(
        name=API_REQUESTS,
        display="API requests",
        url_template="organizations/{organization_id}/apiRequests",
        time_field="ts",
        max_page_size=1000,
        max_lookback=timedelta(days=31),
    ),
    APPLIANCE_SECURITY_EVENTS: WindowedEventType(
        name=APPLIANCE_SECURITY_EVENTS,
        display="Appliance security events",
        url_template="organizations/{organization_id}/appliance/security/events",
        time_field="ts",
        max_page_size=1000,
        max_lookback=timedelta(days=365),
        extra_params=(("sortOrder", "ascending"),),
    ),
}
NETWORK_EVENTS_DISPLAY = "Network events"
NETWORK_EVENTS_TIME_FIELD = "occurredAt"
NETWORK_EVENTS_MAX_PAGE_SIZE = 1000

# Display names (the `event_types` param / argument values) mapped to internal names.
EVENT_TYPE_DISPLAY_TO_NAME = {
    **{event_type.display: name for name, event_type in WINDOWED_EVENT_TYPES.items()},
    NETWORK_EVENTS_DISPLAY: NETWORK_EVENTS,
}
EVENT_TYPE_TIME_FIELDS = {
    **{name: event_type.time_field for name, event_type in WINDOWED_EVENT_TYPES.items()},
    NETWORK_EVENTS: NETWORK_EVENTS_TIME_FIELD,
}


""" Helpers """


def utc_now() -> datetime:
    return datetime.now(UTC)


def format_meraki_time(value: datetime) -> str:
    return value.astimezone(UTC).strftime(MERAKI_TIME_FORMAT)


def parse_meraki_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def event_hash(event: dict[str, Any]) -> str:
    """Meraki events carry no unique ID, so duplicates at window boundaries are detected by hashing the full event."""
    return hashlib.sha256(json.dumps(event, sort_keys=True, default=str).encode()).hexdigest()


def boundary_hashes(events: list[dict[str, Any]], time_field: str, boundary: datetime) -> list[str]:
    """Hashes of the events whose timestamp is within the boundary tolerance of the next window start."""
    hashes = []
    for event in events:
        event_time = parse_meraki_time(event.get(time_field))
        if event_time and event_time >= boundary - BOUNDARY_TOLERANCE:
            hashes.append(event_hash(event))
    return hashes


def next_link(links: dict[str, Any]) -> str | None:
    return dict_safe_get(links, ["next", "url"])


def parse_event_types(raw_event_types: Any) -> list[str]:
    """Map the display names of the event types param/argument to internal names (all types when empty)."""
    selected = argToList(raw_event_types) or list(EVENT_TYPE_DISPLAY_TO_NAME)
    unknown = [value for value in selected if value not in EVENT_TYPE_DISPLAY_TO_NAME]
    if unknown:
        raise DemistoException(
            f"Unknown event types: {', '.join(unknown)}. Valid values: {', '.join(EVENT_TYPE_DISPLAY_TO_NAME)}."
        )
    return [EVENT_TYPE_DISPLAY_TO_NAME[value] for value in selected]


def enrich_events(events: list[dict[str, Any]], event_type: str) -> list[dict[str, Any]]:
    """Add the `_time` and `_source_log_type` fields used by XSIAM to every event."""
    time_field = EVENT_TYPE_TIME_FIELDS[event_type]
    for event in events:
        event["_time"] = event.get(time_field)
        event["_source_log_type"] = event_type
    return events


""" Client """


class CiscoMerakiEventCollectorClient(MerakiBaseClient):
    """Meraki Dashboard API client for the event collector."""

    def __init__(self, organization_id: str, **kwargs) -> None:
        super().__init__(scopes=CISCO_MERAKI_COLLECTOR_OAUTH_SCOPES, **kwargs)
        self.organization_id = organization_id

    def get_organization(self) -> dict[str, Any]:
        return self._http_request(method="GET", url_suffix=f"organizations/{self.organization_id}")

    def list_networks(self) -> list[dict[str, Any]]:
        page, links = self.get_page(url_suffix=f"organizations/{self.organization_id}/networks", params={"perPage": 100000})
        networks: list[dict[str, Any]] = list(page or [])
        while next_url := next_link(links):
            page, links = self.call_link(next_url)
            networks.extend(page or [])
        return networks


""" Fetchers """


def fetch_windowed_events(
    client: CiscoMerakiEventCollectorClient,
    event_type: WindowedEventType,
    state: dict[str, Any],
    max_events: int,
    now: datetime,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fetch one organization-level event type for the current cycle.

    A cycle either resumes a saved `next_url` inside its saved window, or opens a new window
    [last t1 (or now - 1 hour), now] clamped to the type's maximum lookback.

    Returns:
        tuple: The new events and the next state for this type.
    """
    log_prefix = f"[Fetch][{event_type.name}]"
    previous_hashes = set(state.get("boundary_hashes") or [])
    next_url = state.get("next_url")
    if next_url:
        window_start, window_end = state["window_start"], state["window_end"]
        demisto.debug(f"{log_prefix} Resuming the saved window {window_start} - {window_end}.")
        page, links = client.call_link(next_url)
    else:
        earliest = now - event_type.max_lookback
        start = parse_meraki_time(state.get("last_window_end")) or (now - FIRST_FETCH_LOOKBACK)
        window_start, window_end = format_meraki_time(max(start, earliest)), format_meraki_time(now)
        params = {
            "t0": window_start,
            "t1": window_end,
            "perPage": max(3, min(event_type.max_page_size, max_events)),
            **dict(event_type.extra_params),
        }
        demisto.debug(f"{log_prefix} Opening the window {window_start} - {window_end} (perPage {params['perPage']}).")
        page, links = client.get_page(
            url_suffix=event_type.url_template.format(organization_id=client.organization_id), params=params
        )

    events: list[dict[str, Any]] = []
    duplicates = 0
    pages = 1
    while True:
        for event in page or []:
            if event_hash(event) in previous_hashes:
                duplicates += 1
            else:
                events.append(event)
        next_url = next_link(links)
        if not next_url or len(events) >= max_events:
            break
        page, links = client.call_link(next_url)
        pages += 1

    if next_url:
        demisto.debug(f"{log_prefix} Reached the limit of {max_events}; saving the next page link to resume next cycle.")
        new_state = {
            "next_url": next_url,
            "window_start": window_start,
            "window_end": window_end,
            "boundary_hashes": list(previous_hashes),
            "last_window_end": state.get("last_window_end"),
        }
    else:
        window_end_time = parse_meraki_time(window_end) or now
        new_state = {
            "last_window_end": window_end,
            "boundary_hashes": boundary_hashes(events, event_type.time_field, window_end_time),
        }
    demisto.debug(f"{log_prefix} Fetched {len(events)} events from {pages} page(s), dropped {duplicates} duplicates.")
    return events, new_state


def get_network_targets(
    client: CiscoMerakiEventCollectorClient, network_ids: list[str], state: dict[str, Any], now: datetime
) -> tuple[list[tuple[str, str]], dict[str, Any]]:
    """Return the (network ID, product type) pairs to fetch, using a network list cached for 24 hours.

    Returns:
        tuple: The targets and the updated network cache.
    """
    cache = state.get("network_cache") or {}
    cached_at = parse_meraki_time(cache.get("updated_at"))
    if not cached_at or now - cached_at > NETWORK_CACHE_TTL:
        demisto.debug("[Network Cache] The cache is missing or expired; refreshing the network list.")
        networks = [
            {"id": network["id"], "productTypes": network.get("productTypes") or []} for network in client.list_networks()
        ]
        cache = {"updated_at": format_meraki_time(now), "networks": networks}
        demisto.debug(f"[Network Cache] Cached {len(networks)} networks.")
    else:
        demisto.debug(f"[Network Cache] Using {len(cache.get('networks') or [])} cached networks from {cache.get('updated_at')}.")

    networks = cache.get("networks") or []
    if network_ids:
        known_ids = {network["id"] for network in networks}
        unknown_ids = [network_id for network_id in network_ids if network_id not in known_ids]
        if unknown_ids:
            demisto.info(f"Ignoring network IDs not found in organization {client.organization_id}: {', '.join(unknown_ids)}")
        networks = [network for network in networks if network["id"] in network_ids]

    targets = [
        (network["id"], product_type)
        for network in networks
        for product_type in network["productTypes"]
        if product_type in NETWORK_EVENTS_PRODUCT_TYPES
    ]
    return targets, cache


def fetch_network_events(
    client: CiscoMerakiEventCollectorClient,
    network_ids: list[str],
    state: dict[str, Any],
    max_events: int,
    now: datetime,
    errors: list[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fetch network events, keeping one cursor per (network, product type).

    The type's budget is shared across networks; the starting network rotates every cycle so that
    no network is starved. A failing (network, product type) keeps its cursor and does not stop the others.

    Args:
        errors (list[str] | None): Collects one message per failing (network, product type).

    Returns:
        tuple: The new events and the next state for this type.
    """
    targets, network_cache = get_network_targets(client, network_ids, state, now)
    cursors: dict[str, Any] = dict(state.get("cursors") or {})
    rotation = state.get("rotation", 0) % len(targets) if targets else 0
    events: list[dict[str, Any]] = []

    for network_id, product_type in targets[rotation:] + targets[:rotation]:
        remaining = max_events - len(events)
        if remaining <= 0:
            break
        key = f"{network_id}:{product_type}"
        try:
            network_events, cursors[key] = fetch_single_network_events(
                client, network_id, product_type, cursors.get(key) or {}, remaining, now
            )
        except Exception as exc:  # noqa: BLE001 - one failing network must not stop the others
            message = f"network {network_id} ({product_type}): {exc}"
            demisto.error(f"[Fetch][{NETWORK_EVENTS}] Failed to fetch {message}")
            if errors is not None:
                errors.append(message)
            continue
        events.extend(network_events)

    active_keys = {f"{network_id}:{product_type}" for network_id, product_type in targets}
    new_state = {
        "network_cache": network_cache,
        "cursors": {key: value for key, value in cursors.items() if key in active_keys},
        "rotation": rotation + 1,
    }
    demisto.debug(f"[Fetch][{NETWORK_EVENTS}] Fetched {len(events)} events from {len(targets)} network/product targets.")
    return events, new_state


def fetch_single_network_events(
    client: CiscoMerakiEventCollectorClient,
    network_id: str,
    product_type: str,
    cursor: dict[str, Any],
    max_events: int,
    now: datetime,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    previous_hashes = set(cursor.get("boundary_hashes") or [])
    starting_after = cursor.get("starting_after") or format_meraki_time(now - FIRST_FETCH_LOOKBACK)
    params = {
        "productType": product_type,
        "startingAfter": starting_after,
        "perPage": max(3, min(NETWORK_EVENTS_MAX_PAGE_SIZE, max_events)),
    }
    events: list[dict[str, Any]] = []
    page, links = client.get_page(url_suffix=f"networks/{network_id}/events", params=params)
    while True:
        page_events = (page or {}).get("events") or []
        events.extend(event for event in page_events if event_hash(event) not in previous_hashes)
        next_url = next_link(links)
        if not next_url or not page_events or len(events) >= max_events:
            break
        page, links = client.call_link(next_url)

    demisto.debug(
        f"[Fetch][{NETWORK_EVENTS}] Network {network_id} ({product_type}): {len(events)} events after {starting_after}."
    )
    if not events:
        return [], cursor

    event_times = [t for t in (parse_meraki_time(event.get(NETWORK_EVENTS_TIME_FIELD)) for event in events) if t]
    latest = max(event_times, default=None) or parse_meraki_time(starting_after) or now
    new_cursor = {
        "starting_after": format_meraki_time(latest),
        "boundary_hashes": boundary_hashes(events, NETWORK_EVENTS_TIME_FIELD, latest),
    }
    return events, new_cursor


def fetch_one_event_type(
    client: CiscoMerakiEventCollectorClient,
    event_type: str,
    network_ids: list[str],
    type_state: dict[str, Any],
    max_events: int,
    now: datetime,
    errors: list[str],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if event_type == NETWORK_EVENTS:
        return fetch_network_events(client, network_ids, type_state, max_events, now, errors)
    return fetch_windowed_events(client, WINDOWED_EVENT_TYPES[event_type], type_state, max_events, now)


def fetch_events_by_type(
    client: CiscoMerakiEventCollectorClient,
    event_types: list[str],
    network_ids: list[str],
    last_run: dict[str, Any],
    max_events_per_type: int,
    now: datetime | None = None,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any], list[str]]:
    """Fetch every selected event type with its own, independent budget and state.

    A failing event type keeps its previous state and does not stop the other types.

    Returns:
        tuple: The enriched events per type, the next last run and the error messages (empty when all succeeded).
    """
    now = now or utc_now()
    events_by_type: dict[str, list[dict[str, Any]]] = {}
    next_run = dict(last_run)
    errors: list[str] = []

    for event_type in event_types:
        try:
            events, next_run[event_type] = fetch_one_event_type(
                client, event_type, network_ids, last_run.get(event_type) or {}, max_events_per_type, now, errors
            )
        except Exception as exc:  # noqa: BLE001 - one failing event type must not stop the others
            demisto.error(f"[Fetch][{event_type}] Failed; keeping the previous state for this type: {exc}")
            errors.append(f"{event_type}: {exc}")
            events = []
        events_by_type[event_type] = enrich_events(events, event_type)
    return events_by_type, next_run, errors


""" Commands """


def collector_test_module(client: CiscoMerakiEventCollectorClient) -> str:
    if client.auth_mode == MerakiAuthMode.OAUTH:
        return (
            f"OAuth 2.0 authentication is configured. Use the `!{COLLECTOR_COMMAND_PREFIX}-generate-login-url` and "
            f"`!{COLLECTOR_COMMAND_PREFIX}-auth-test` commands to authorize and test the connection."
        )
    try:
        client.get_organization()
    except DemistoException as exc:
        if exc.res is not None and exc.res.status_code == http.HTTPStatus.UNAUTHORIZED:
            return "Authorization Error: invalid credentials."
        if exc.res is not None and exc.res.status_code == http.HTTPStatus.NOT_FOUND:
            return f"Organization '{client.organization_id}' was not found, or the Server URL is invalid."
        raise
    demisto.debug(f"[Test Module] Organization {client.organization_id} is reachable.")
    return "ok"


def get_events_command(
    client: CiscoMerakiEventCollectorClient, args: dict[str, Any], network_ids: list[str]
) -> list[CommandResults | str]:
    """Fetch events on demand, without changing the fetch state. For development and debugging only."""
    event_types = parse_event_types(args.get("event_types"))
    limit = arg_to_number(args.get("limit")) or 10
    start_time = arg_to_datetime(args.get("start_time") or "1 hour", required=True)
    now = utc_now()
    seed = format_meraki_time(start_time)  # type: ignore[arg-type]
    seeded_last_run = {
        **{name: {"last_window_end": seed} for name in WINDOWED_EVENT_TYPES},
        NETWORK_EVENTS: {},
    }
    events_by_type, _, errors = fetch_events_by_type(client, event_types, network_ids, seeded_last_run, limit, now)

    results: list[CommandResults | str] = []
    for event_type, events in events_by_type.items():
        events = events[:limit]
        if argToBoolean(args.get("should_push_events", False)):
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
        results.append(
            CommandResults(
                readable_output=tableToMarkdown(f"Cisco Meraki {event_type} events", events, removeNull=True),
                raw_response=events,
            )
        )
    if errors:
        results.append(CommandResults(readable_output=format_fetch_errors(errors), entry_type=EntryType.ERROR))
    return results


def format_fetch_errors(errors: list[str]) -> str:
    return "Some Cisco Meraki event types failed and will be retried next cycle:\n" + "\n".join(f"- {e}" for e in errors)


def fetch_events_command(
    client: CiscoMerakiEventCollectorClient, event_types: list[str], network_ids: list[str], max_events_per_type: int
) -> None:
    """Fetch, send and save state for every type that succeeded, then raise if any type or network failed.

    Raises:
        DemistoException: After the successful events were sent and the state saved, when any type or network failed.
    """
    last_run = demisto.getLastRun() or {}
    events_by_type, next_run, errors = fetch_events_by_type(client, event_types, network_ids, last_run, max_events_per_type)
    events = [event for type_events in events_by_type.values() for event in type_events]
    demisto.debug(
        f"[Fetch] Sending {len(events)} events to XSIAM: { {name: len(value) for name, value in events_by_type.items()} }"
    )
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
    demisto.setLastRun(next_run)
    demisto.debug(f"[Fetch] Saved the last run for {len(next_run)} event types.")
    if errors:
        raise DemistoException(format_fetch_errors(errors))


""" Entry point """


def run_cisco_meraki_event_collector() -> None:
    """Entry point shared by the Cisco Meraki Event Collector integrations."""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    demisto.debug(f"[Main] Command being called is {command}")

    try:
        organization_id = params.get("organization_id")
        if not organization_id:
            raise DemistoException("The Organization ID parameter is required.")
        network_ids = argToList(params.get("network_ids"))
        client = CiscoMerakiEventCollectorClient(
            organization_id=organization_id,
            base_url=resolve_meraki_base_url(params),
            api_key=dict_safe_get(params, ["api_key", "password"]) or None,
            client_id=dict_safe_get(params, ["credentials", "identifier"]) or None,
            client_secret=dict_safe_get(params, ["credentials", "password"]) or None,
            redirect_uri=params.get("redirect_uri") or None,
            auth_code=dict_safe_get(params, ["auth_code", "password"]) or None,
            verify=not argToBoolean(params.get("insecure") or False),
            proxy=argToBoolean(params.get("proxy") or False),
        )

        if command == "test-module":
            return_results(collector_test_module(client))
        elif command == "fetch-events":
            fetch_events_command(
                client,
                parse_event_types(params.get("event_types")),
                network_ids,
                arg_to_number(params.get("max_events_per_type")) or DEFAULT_MAX_EVENTS_PER_TYPE,
            )
        elif command == f"{COLLECTOR_COMMAND_PREFIX}-get-events":
            return_results(get_events_command(client, args, network_ids))
        elif command == f"{COLLECTOR_COMMAND_PREFIX}-generate-login-url":
            return_results(oauth_generate_login_url_command(client, COLLECTOR_COMMAND_PREFIX))
        elif command == f"{COLLECTOR_COMMAND_PREFIX}-auth-test":
            return_results(oauth_auth_test_command(client))
        elif command == f"{COLLECTOR_COMMAND_PREFIX}-auth-reset":
            return_results(oauth_auth_reset_command(client, COLLECTOR_COMMAND_PREFIX))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e}")
