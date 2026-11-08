import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401

from ContentClientApiModule import *  # noqa: F401

import traceback
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, quote_plus

# ############################################################################
# Endpoints, auth scheme and field names below were confirmed against KELA's
# official OpenAPI 3.1 spec for the Identity Guard "bots-client-api" (v1),
# and the search-incidents/search-bot-markets calls were smoke-tested against
# the live API. This integration intentionally covers only the three "search"
# endpoints that return incident-like data:
#   - /search-incidents          (general Identity Guard incidents)
#   - /search-bot-markets        (bots/webmails for sale on marketplaces)
#   - /search-cookie-incidents   (compromised session cookies)
# ############################################################################

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"
SEVERITY_LABEL_TO_INT = {"low": 0, "medium": 1, "high": 2, "critical": 3}

XSOAR_SEVERITY_BY_KELA_SEVERITY = {
    0: 1,  # low -> Low
    1: 2,  # medium -> Medium
    2: 3,  # high -> High
    3: 4,  # critical -> Critical
}

# Bot-market alerts don't carry a severity field at all (per the OpenAPI spec's BotAlert
# schema), so fetched bot-market incidents are always created at this fixed severity.
DEFAULT_BOT_MARKET_XSOAR_SEVERITY = 2  # Medium


def normalize_severity(value: Any) -> int:
    """The /search-incidents API returns severity as a string label on responses but
    expects an int (0-3) as a filter. Handle both defensively."""
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    label = str(value).strip().lower()
    if label in SEVERITY_LABEL_TO_INT:
        return SEVERITY_LABEL_TO_INT[label]
    try:
        return int(label)
    except ValueError:
        return 0


def cookie_severity_to_xsoar(value: Any) -> int:
    """Cookie incidents use a 2-level severity enum: critical / non-critical."""
    if str(value).strip().lower() == "critical":
        return 4  # Critical
    return 2  # Medium


class Client(ContentClient):
    """REST client for the KELA Identity Guard API (bots-client-api v1), BaseClient-compatible.
    Authentication is a query-string parameter (`apiToken`), injected by APIKeyAuthHandler.
    """

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool):
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            auth_handler=APIKeyAuthHandler(key=api_key, query_param="apiToken"),
            client_name="KELAIdentityGuardClient",
        )
        add_sensitive_log_strs(api_key)

    def search_incidents(self, workspace_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._http_request(
            method="POST",
            url_suffix="/search-incidents",
            json_data={"workspaceId": workspace_id, "payload": payload},
        )

    def search_bot_markets(self, workspace_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._http_request(
            method="POST",
            url_suffix="/search-bot-markets",
            json_data={"workspaceId": workspace_id, "payload": payload},
        )

    def search_cookie_incidents(self, workspace_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._http_request(
            method="POST",
            url_suffix="/search-cookie-incidents",
            json_data={"workspaceId": workspace_id, "payload": payload},
        )


# ############################################################################
# Helpers
# ############################################################################


def mask_secret(text: str, secret: str | None) -> str:
    """Remove the API key (raw and URL-encoded) from a text so it never reaches the UI or logs."""
    if not secret:
        return text
    for variant in {secret, quote(secret, safe=""), quote_plus(secret)}:
        text = text.replace(variant, "<API_KEY>")
    return text


def parse_date_utc(value: Any, arg_name: str) -> datetime:
    """Parse an absolute or relative date ("2024-01-15T12:34:56Z", "3 days") as a timezone-aware UTC datetime."""
    parsed = arg_to_datetime(
        value, arg_name=arg_name, required=True, settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True}
    )
    if parsed is None:  # unreachable with required=True, narrows the type for mypy
        raise ValueError(f'Missing "{arg_name}"')
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def api_date_to_utc(value: str) -> datetime:
    """Parse a createdDate returned by the KELA API (ISO 8601) as a timezone-aware UTC datetime."""
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return parse_date_utc(value, "createdDate")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def csv_arg(args: dict[str, Any], key: str) -> list[str] | None:
    value = args.get(key)
    if not value:
        return None
    return argToList(value)


def bool_arg(args: dict[str, Any], key: str) -> bool | None:
    value = args.get(key)
    if value is None or value == "":
        return None
    return argToBoolean(value)


def date_range_filter(args: dict[str, Any], prefix: str) -> dict[str, str] | None:
    """Build a {startDate, endDate} filter object from `<prefix>_start` / `<prefix>_end` args."""
    start = args.get(f"{prefix}_start")
    end = args.get(f"{prefix}_end")
    if not start and not end:
        return None
    date_filter: dict[str, str] = {}
    if start:
        date_filter["startDate"] = parse_date_utc(start, f"{prefix}_start").strftime(DATE_FORMAT)
    if end:
        date_filter["endDate"] = parse_date_utc(end, f"{prefix}_end").strftime(DATE_FORMAT)
    return date_filter


def pagination_and_sort(args: dict[str, Any], sort_fields: list[str], default_sort: str = "updatedDate") -> dict[str, Any]:
    payload: dict[str, Any] = {
        "pagination": {
            "offset": arg_to_number(args.get("offset")) or 0,
            "size": arg_to_number(args.get("limit")) or 50,
        }
    }
    if sort_fields:
        payload["sort"] = {
            "sortBy": args.get("sort_by") or default_sort,
            "order": args.get("order") or "desc",
        }
    return payload


def resolve_workspace_id(args: dict[str, Any], params: dict[str, Any]) -> str:
    workspace_id = args.get("workspace_id") or params.get("workspace_id")
    if not workspace_id:
        raise ValueError("workspace_id was not provided and no Default Workspace ID is configured on the instance.")
    return workspace_id


def strip_none(d: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in d.items() if v not in (None, "", [], {})}


# ############################################################################
# Commands
# ############################################################################


def test_module(client: Client, params: dict[str, Any]) -> str:
    workspace_id = params.get("workspace_id")
    if not workspace_id:
        raise ValueError("Set a Default Workspace ID on the instance to run the connection test.")
    client.search_incidents(workspace_id, {"pagination": {"offset": 0, "size": 1}})
    return "ok"


def search_incidents_command(client: Client, args: dict[str, Any], params: dict[str, Any]) -> CommandResults:
    workspace_id = resolve_workspace_id(args, params)

    severity = args.get("severity")
    filters = strip_none(
        {
            "searchTerm": args.get("search_term"),
            "severity": SEVERITY_LABEL_TO_INT.get(severity) if severity else None,
            "status": args.get("status"),  # RESOLVED / UNRESOLVED
            "sourceTypes": csv_arg(args, "source_types"),
            "sourceCategory": csv_arg(args, "source_category"),
            "archived": csv_arg(args, "archived"),
            "deleted": bool_arg(args, "deleted"),
            "dateFilters": strip_none(
                {
                    "createdDate": date_range_filter(args, "created_date"),
                    "updatedDate": date_range_filter(args, "updated_date"),
                    "sourceDate": date_range_filter(args, "source_date"),
                }
            ),
        }
    )
    payload = {"filters": filters, **pagination_and_sort(args, sort_fields=["createdDate", "updatedDate", "sourceDate"])}

    response = client.search_incidents(workspace_id, payload)
    incidents = response.get("results", [])

    readable = tableToMarkdown(
        f"KELA Identity Guard incidents (workspace {workspace_id}) - {response.get('total', len(incidents))} total",
        incidents,
        headers=["incidentId", "severity", "status", "sourceType", "accountUserName", "accountServiceHostname", "createdDate"],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix="KELA.IdentityGuard.Incident",
        outputs_key_field="incidentId",
        outputs=incidents,
        readable_output=readable,
        raw_response=response,
    )


def search_bot_markets_command(client: Client, args: dict[str, Any], params: dict[str, Any]) -> CommandResults:
    workspace_id = resolve_workspace_id(args, params)

    filters = strip_none(
        {
            "searchTerm": args.get("search_term"),
            "statuses": csv_arg(args, "statuses"),
            "availabilityIssues": csv_arg(args, "availability_issues"),
            "incidentStatus": csv_arg(args, "incident_status"),
            "services": csv_arg(args, "services"),
            "isArchived": bool_arg(args, "is_archived"),
            "isDeleted": bool_arg(args, "is_deleted"),
            "dateFilters": strip_none(
                {
                    "createdDate": date_range_filter(args, "created_date"),
                    "updatedDate": date_range_filter(args, "updated_date"),
                    "postedDate": date_range_filter(args, "posted_date"),
                }
            ),
        }
    )
    payload = {"filters": filters, **pagination_and_sort(args, sort_fields=["createdDate", "updatedDate", "postedDate"])}

    response = client.search_bot_markets(workspace_id, payload)
    items = response.get("results", [])

    readable = tableToMarkdown(
        f"KELA Identity Guard bot-market alerts (workspace {workspace_id})",
        items,
        headers=["alertId", "marketName", "requestStatus", "availabilityStatus", "price", "postedDate"],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix="KELA.IdentityGuard.BotMarket",
        outputs_key_field="alertId",
        outputs=items,
        readable_output=readable,
        raw_response=response,
    )


def search_cookie_incidents_command(client: Client, args: dict[str, Any], params: dict[str, Any]) -> CommandResults:
    workspace_id = resolve_workspace_id(args, params)

    filters = strip_none(
        {
            "searchTerm": args.get("search_term"),
            # The API expects these two in upper case (CRITICAL/NON_CRITICAL,
            # RESOLVED/UNRESOLVED) for this endpoint specifically - confirmed live
            # against the API, which rejects the lower-case values with a 400.
            "severity": args.get("severity", "").upper() or None,
            "status": args.get("status", "").upper() or None,
            "cookieCategory": csv_arg(args, "cookie_category"),
            "serviceHostname": csv_arg(args, "service_hostname"),
            "geographies": csv_arg(args, "geographies"),
            "incidentHash": args.get("incident_hash"),
            "sessionHash": args.get("session_hash"),
            "linkedUsernames": bool_arg(args, "linked_usernames"),
            "archived": bool_arg(args, "archived"),
            "dateFilters": strip_none(
                {
                    "createdDate": date_range_filter(args, "created_date"),
                    "sourceDate": date_range_filter(args, "source_date"),
                    "updatedDate": date_range_filter(args, "updated_date"),
                }
            ),
        }
    )
    payload = {"filters": filters, **pagination_and_sort(args, sort_fields=["createdDate", "sourceDate", "updatedDate"])}

    response = client.search_cookie_incidents(workspace_id, payload)
    items = response.get("results", [])

    readable = tableToMarkdown(
        f"KELA Identity Guard cookie incidents (workspace {workspace_id})",
        items,
        headers=["incidentId", "severity", "status", "cookieCategory", "cookieName", "botCountry"],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix="KELA.IdentityGuard.CookieIncident",
        outputs_key_field="incidentId",
        outputs=items,
        readable_output=readable,
        raw_response=response,
    )


# ############################################################################
# Fetch incidents - merges all three enabled sources into one XSOAR feed
# ############################################################################


# Upper bound on how many "already seen" IDs are remembered per source (see
# _fetch_source). They are only the IDs that share the newest createdDate, so in
# practice the list holds a handful of entries; the cap is just a safety net so the
# last-run object can never grow without limit.
MAX_SEEN_IDS = 1000


def _fetch_source(
    search_fn: Any,
    workspace_id: str,
    filters: dict[str, Any],
    last_run: dict[str, Any],
    state_key: str,
    default_start: str,
    max_fetch: int,
    name_prefix: str,
    id_field: str,
    get_severity: Any,
    min_severity: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fetch one source, drop records already ingested, and return the new XSOAR
    incidents plus this source's updated last-run state.

    Why this is more than a plain "createdDate > last_fetch" filter: the KELA API treats
    ``dateFilters.createdDate.startDate`` as INCLUSIVE (verified live: querying with
    startDate equal to a record's exact createdDate returns that record). Using the
    newest createdDate seen as the next startDate therefore returns that same record
    again on every cycle. XSOAR does not dedupe fetched incidents, so each cycle would
    create a duplicate. To prevent it we keep, next to the watermark, the IDs of the
    records that sit exactly AT the watermark (``last_ids_<source>``) and skip them next
    time.

    Last-run state per source:
        last_fetch_<source>: createdDate watermark (the API's own ISO string, sent back as-is
                             as the next startDate so no precision is lost)
        last_ids_<source>:   IDs of records whose createdDate == the watermark

    Dates are compared as timezone-aware UTC datetimes, never as strings, so a different
    precision or offset in the API's createdDate cannot break the ordering or the dedup.
    """
    ts_key = f"last_fetch_{state_key}"
    ids_key = f"last_ids_{state_key}"

    last_fetch = last_run.get(ts_key) or default_start
    last_fetch_dt = api_date_to_utc(last_fetch)
    seen_ids = set(last_run.get(ids_key) or [])

    payload = {
        "filters": {**filters, "dateFilters": {"createdDate": {"startDate": last_fetch}}},
        "sort": {"sortBy": "createdDate", "order": "asc"},
        # Ask for max_fetch NEW records on top of the ones we will skip, so a boundary
        # group can never fill the whole page and stall the watermark.
        "pagination": {"offset": 0, "size": min(max_fetch + len(seen_ids), 1000)},
    }
    response = search_fn(workspace_id, payload)
    raw_items = response.get("results", [])

    incidents: list[dict[str, Any]] = []
    watermark, watermark_dt = last_fetch, last_fetch_dt
    ids_at_watermark = set(seen_ids)
    new_count = 0

    for raw in raw_items:
        record_id = raw.get(id_field)
        created_date = raw.get("createdDate") or last_fetch
        created_dt = api_date_to_utc(created_date)

        if created_dt == last_fetch_dt and record_id in seen_ids:
            continue  # the inclusive-boundary record we already ingested
        if new_count >= max_fetch:
            break
        new_count += 1

        # Advance the watermark for EVERY record processed (even ones filtered out by
        # min_severity), otherwise a trailing low-severity record would be re-read forever.
        if created_dt > watermark_dt:
            watermark, watermark_dt = created_date, created_dt
            ids_at_watermark = set()
        if created_dt == watermark_dt and record_id is not None:
            ids_at_watermark.add(record_id)

        severity = get_severity(raw)
        if severity < min_severity:
            continue
        incidents.append(
            {
                "name": f"{name_prefix} {record_id}",
                "occurred": created_date,
                "severity": severity,
                "rawJSON": json.dumps(raw),
            }
        )

    # If the watermark did not move (nothing new), keep the IDs we already knew.
    if watermark_dt == last_fetch_dt:
        ids_at_watermark = seen_ids | ids_at_watermark
    return incidents, {
        ts_key: watermark,
        ids_key: sorted(ids_at_watermark)[:MAX_SEEN_IDS],
    }


def fetch_incidents(client: Client, params: dict[str, Any]) -> None:
    workspace_id = params.get("workspace_id")
    if not workspace_id:
        raise ValueError("Fetch incidents requires a Default Workspace ID to be configured on the instance.")

    demisto.debug("[Fetch] Starting fetch...")
    max_fetch = min(arg_to_number(params.get("max_fetch")) or 50, 200)
    min_severity_label = (params.get("min_severity") or "0 - low").split(" - ")[-1]
    min_severity_kela = SEVERITY_LABEL_TO_INT.get(min_severity_label, 0)
    # min_severity is compared against each source's get_severity() return value below, which is
    # always in XSOAR's 1-4 scale (not KELA's own 0-3 scale) - translate it here so the comparison
    # and the incident's stored severity are always on the same scale.
    min_severity = XSOAR_SEVERITY_BY_KELA_SEVERITY.get(min_severity_kela, 1)
    fetch_bot_markets = params.get("fetch_bot_markets", True)
    fetch_cookie_incidents = params.get("fetch_cookie_incidents", True)

    last_run = demisto.getLastRun() or {}
    first_fetch = params.get("first_fetch") or "3 days"
    default_start = parse_date_utc(first_fetch, "first_fetch").strftime(DATE_FORMAT)

    all_incidents: list[dict[str, Any]] = []
    # Start from the previous state so a disabled source keeps its watermark.
    new_last_run: dict[str, Any] = dict(last_run)

    # Source 1: general Identity Guard incidents.
    incidents, state = _fetch_source(
        client.search_incidents,
        workspace_id,
        {"status": "UNRESOLVED"},
        last_run,
        "incidents",
        default_start,
        max_fetch,
        "KELA Identity Guard incident",
        "incidentId",
        # Translate KELA's own 0-3 severity scale to XSOAR's 1-4 scale, so the incident is created
        # with the correct XSOAR severity (previously stored the raw 0-3 value directly).
        lambda raw: XSOAR_SEVERITY_BY_KELA_SEVERITY.get(normalize_severity(raw.get("severity")), 1),
        min_severity,
    )
    all_incidents.extend(incidents)
    new_last_run.update(state)

    # Source 2: bot-market alerts (bots/webmails for sale). No severity field exists on
    # this source, so min_severity is not applied and every fetched alert uses a fixed
    # default XSOAR severity.
    if fetch_bot_markets:
        incidents, state = _fetch_source(
            client.search_bot_markets,
            workspace_id,
            {"incidentStatus": ["unresolved"]},
            last_run,
            "bot_markets",
            default_start,
            max_fetch,
            "KELA Bot Market alert",
            "alertId",
            lambda raw: DEFAULT_BOT_MARKET_XSOAR_SEVERITY,
            0,  # severity threshold doesn't apply to this source
        )
        all_incidents.extend(incidents)
        new_last_run.update(state)

    # Source 3: compromised session-cookie incidents.
    if fetch_cookie_incidents:
        incidents, state = _fetch_source(
            client.search_cookie_incidents,
            workspace_id,
            # Confirmed live: this endpoint rejects a lower-case "unresolved" with a
            # 400 Bad Request - it needs the upper-case value, unlike the other two
            # sources' status filters.
            {"status": "UNRESOLVED"},
            last_run,
            "cookie_incidents",
            default_start,
            max_fetch,
            "KELA Cookie incident",
            "incidentId",
            lambda raw: cookie_severity_to_xsoar(raw.get("severity")),
            min_severity,
        )
        all_incidents.extend(incidents)
        new_last_run.update(state)

    demisto.incidents(all_incidents)
    demisto.setLastRun(new_last_run)
    demisto.info(f"[Fetch] Completed fetch, created {len(all_incidents)} incident(s).")


# ############################################################################
# Main
# ############################################################################


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get("url", "").rstrip("/")
    api_key = params.get("credentials", {}).get("password", "")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(base_url=base_url, api_key=api_key, verify=verify, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client, params))
        elif command == "fetch-incidents":
            fetch_incidents(client, params)
        elif command == "kela-identityguard-search-incidents":
            return_results(search_incidents_command(client, args, params))
        elif command == "kela-identityguard-search-bot-markets":
            return_results(search_bot_markets_command(client, args, params))
        elif command == "kela-identityguard-search-cookie-incidents":
            return_results(search_cookie_incidents_command(client, args, params))
        else:
            raise NotImplementedError(f"Command '{command}' is not implemented.")

    except Exception as e:
        # The traceback can include the request URL, which carries the API key as a query parameter.
        demisto.error(mask_secret(traceback.format_exc(), api_key))
        return_error(f"Failed to execute {command} command.\nError:\n{mask_secret(str(e), api_key)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
