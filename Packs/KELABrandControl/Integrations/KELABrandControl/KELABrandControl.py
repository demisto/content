import json
import traceback
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, quote_plus

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from ContentClientApiModule import *  # noqa: F401
from BaseContentApiModule import *  # noqa: F401

""" KELA Brand Control integration for Cortex XSOAR.

Evidence legend used in comments:
    [SPEC]      -> taken from the OpenAPI file only (kela-api-BrandControl.yaml).
    [OWNER]     -> confirmed by the module owner (answers given while building this pack).
    [LIVE]      -> verified against the live API. NOTHING in this file is marked [LIVE] yet:
                   see TECHNICAL_DOC.md, section "Live verification checklist".
"""

# region Constants
CONTEXT_PREFIX = "KELA.BrandControl"
DEFAULT_BASE_URL = "https://api.ke-la.com/brand-control/v1"

DEFAULT_LIMIT = 50  # [SPEC] pagination.limit default
API_MAX_LIMIT = 1000  # [SPEC] "Values above 1000 are disregarded"
DEFAULT_FIRST_FETCH = "3 days"
DEFAULT_MAX_FETCH = 50
MAX_FETCH_LIMIT = 200
# Cap for the stored list of IDs that share the watermark timestamp.
# MAX_FETCH_LIMIT + SEEN_IDS_CAP must stay <= API_MAX_LIMIT so the page size can always be honored.
SEEN_IDS_CAP = 500
# [SPEC] rate limit: 1 request per second, enforced by ContentClient's built-in rate limiter.
# 429 responses are retried by ContentClient's _http_request.
RATE_LIMIT_PER_SECOND = 1.0
RETRIES_ON_429 = 3

# [SPEC] enums, lowercase with underscores. [OWNER] confirmed lowercase.
INCIDENT_TYPES = [
    "phishing_website",
    "look_alike_domain",
    "phishing_email",
    "fake_social_media_profile",
    "fake_shop",
    "malicious_application",
    "brand_infringement",
]
INCIDENT_STATUSES = [
    "new",
    "in_review",
    "resolved",
    "requested_takedown",
    "false_positive",
    "irrelevant",
    "whitelisted",
]
SEVERITIES = ["low", "medium", "high", "critical"]
TIME_RANGE_FIELDS = ["incident_date", "incident_update_date"]
SORT_FIELDS = ["incidentDate", "severity", "status", "lastUpdated"]
SORT_ORDERS = ["asc", "desc"]

# [OWNER] severity is always returned as one of the four strings.
SEVERITY_TO_XSOAR = {
    "low": IncidentSeverity.LOW,
    "medium": IncidentSeverity.MEDIUM,
    "high": IncidentSeverity.HIGH,
    "critical": IncidentSeverity.CRITICAL,
}
# endregion


# region Helpers
def mask_secret(text: str, secret: str | None) -> str:
    """Remove the API token (raw and URL-encoded) from a text so it can never reach the UI or logs."""
    if not secret:
        return text
    for variant in {secret, quote(secret, safe=""), quote_plus(secret)}:
        text = text.replace(variant, "<API_TOKEN>")
    return text


def parse_workspace_ids(raw: Any) -> list[str]:
    """Split a comma separated workspace ID string into a clean, de-duplicated, ordered list."""
    if not raw:
        raise DemistoException("Workspace ID is required. Provide one or more workspace IDs separated by commas.")
    ids: list[str] = []
    for item in argToList(raw):
        item = str(item).strip()
        if item and item not in ids:
            ids.append(item)
    if not ids:
        raise DemistoException("Workspace ID is required. Provide one or more workspace IDs separated by commas.")
    return ids


def to_epoch_ms(value: Any, arg_name: str) -> int | None:
    """Convert a user supplied date into Unix epoch MILLISECONDS ([OWNER]: the API needs 13 digit values).

    Accepts: 13 digit epoch ms, 10 digit epoch seconds (converted), ISO dates and relative dates ("3 days").
    """
    if value is None or str(value).strip() == "":
        return None
    text = str(value).strip()
    if text.isdigit():
        if len(text) == 13:
            return int(text)
        if len(text) == 10:
            return int(text) * 1000
        raise DemistoException(f"Invalid '{arg_name}': numeric dates must be a 13 digit epoch in milliseconds.")
    parsed = arg_to_datetime(text, arg_name, is_utc=True, required=False)
    if parsed is None:
        raise DemistoException(f"Invalid '{arg_name}': could not parse '{text}'.")
    return int(parsed.timestamp() * 1000)


def ms_to_iso(ms: int) -> str:
    """Epoch milliseconds -> ISO 8601 UTC string (millisecond precision)."""
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def validate_choices(values: list[str], allowed: list[str], arg_name: str) -> list[str]:
    invalid = [v for v in values if v not in allowed]
    if invalid:
        raise DemistoException(f"Invalid value(s) for '{arg_name}': {invalid}. Allowed values: {allowed}.")
    return values


def build_filters(
    *,
    start_ms: int | None = None,
    end_ms: int | None = None,
    time_field: str = "incident_date",
    search_term: str | None = None,
    types: list[str] | None = None,
    statuses: list[str] | None = None,
    severities: list[str] | None = None,
    is_deleted: bool = False,
    is_archived: bool = False,
    new_updates_only: bool = False,
) -> dict[str, Any]:
    """Build the `filters` object of POST /incidents. Only documented keys are used [SPEC]."""
    filters: dict[str, Any] = {"isDeleted": is_deleted, "isArchived": is_archived}
    if start_ms is not None or end_ms is not None:
        time_range: dict[str, Any] = {"fieldName": time_field}
        if start_ms is not None:
            time_range["startDate"] = start_ms
        if end_ms is not None:
            time_range["endDate"] = end_ms
        filters["timeRange"] = time_range
    if search_term:
        filters["searchTerm"] = search_term
    if types:
        filters["types"] = types
    if statuses:
        filters["statuses"] = statuses
    if severities:
        filters["severities"] = severities
    if new_updates_only:
        filters["newUpdatesOnly"] = True
    return filters


def get_pagination(args: dict[str, Any]) -> tuple[int, int]:
    """XSOAR pagination conventions -> (limit, offset) for the API.

    page + page_size take precedence over limit. `page` starts at 1.
    """
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))
    if page is not None or page_size is not None:
        page = page if page is not None else 1
        page_size = page_size if page_size is not None else DEFAULT_LIMIT
        if page < 1 or page_size < 1:
            raise DemistoException("'page' and 'page_size' must be positive integers.")
        limit, offset = page_size, (page - 1) * page_size
    else:
        limit, offset = (limit if limit is not None else DEFAULT_LIMIT), 0
    if limit < 1:
        raise DemistoException("The number of results per request must be a positive integer.")
    return limit, offset


# endregion


# region Client
class Client(ContentClient):
    """All HTTP traffic goes through ContentClient._http_request (BaseClient-compatible).

    The apiToken is injected into every request's query string by APIKeyAuthHandler, and the
    1 request/second rate limit [SPEC] is enforced by ContentClient's built-in rate limiter.
    """

    def __init__(self, base_url: str, api_token: str, verify: bool, proxy: bool):
        super().__init__(
            base_url=base_url.rstrip("/"),
            verify=verify,
            proxy=proxy,
            auth_handler=APIKeyAuthHandler(key=api_token, query_param="apiToken"),
            rate_limiter=RateLimitPolicy(rate_per_second=RATE_LIMIT_PER_SECOND, burst=1),
            client_name="KELABrandControlClient",
        )
        add_sensitive_log_strs(api_token)

    @staticmethod
    def _error_handler(res) -> None:
        """Turn API errors into readable messages. Never includes the request URL (it contains the token)."""
        try:
            message = res.json().get("message")  # [SPEC] ErrorResponse {message}
        except (ValueError, AttributeError):
            message = None
        message = message or (res.text or "")[:200]
        if res.status_code == 401:
            raise DemistoException("Authorization Error: make sure the API Token is correct and not expired.")
        if res.status_code == 429:
            raise DemistoException("Rate limit exceeded (1 request per second). Wait before running more requests.")
        raise DemistoException(f"Error in API call [{res.status_code}] - {message}")

    def incidents_list(
        self,
        workspace_id: str,
        filters: dict[str, Any] | None = None,
        sort: dict[str, str] | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> dict[str, Any]:
        """POST /incidents (operationId getincidents). workspaceId goes in the query string [SPEC]."""
        body: dict[str, Any] = {
            "filters": filters or {},
            "pagination": {"limit": limit, "offset": offset},
        }
        if sort:
            body["sort"] = sort
        return self._http_request(
            method="POST",
            url_suffix="/incidents",
            params={"workspaceId": workspace_id},
            json_data=body,
            retries=RETRIES_ON_429,
            status_list_to_retry=[429],
            backoff_factor=1,
            error_handler=self._error_handler,
        )


# endregion


# region Commands
def test_module(client: Client, workspace_ids: list[str], params: dict[str, Any]) -> str:
    """Validate credentials + every configured workspace, and the fetch settings when fetch is enabled."""
    if argToBoolean(params.get("isFetch", False)):
        to_epoch_ms(params.get("first_fetch") or DEFAULT_FIRST_FETCH, "first_fetch")
        parse_max_fetch(params.get("max_fetch"))
        validate_choices(argToList(params.get("fetch_severities")), SEVERITIES, "fetch_severities")
    for workspace_id in workspace_ids:
        try:
            client.incidents_list(workspace_id, filters=build_filters(), limit=1)
        except DemistoException as e:
            if "Authorization" in str(e):
                return "Authorization Error: make sure the API Token is correct and the workspace is shared with your group."
            raise
    return "ok"


def resolve_workspace(arg_value: Any, configured: list[str]) -> str:
    if arg_value:
        return str(arg_value).strip()
    if len(configured) == 1:
        return configured[0]
    raise DemistoException(
        "Multiple workspaces are configured on this instance: provide the 'workspace_id' argument to choose one."
    )


def incident_list_command(client: Client, args: dict[str, Any], configured_workspaces: list[str]) -> CommandResults:
    """kela-brandcontrol-incident-list -> POST /incidents."""
    workspace_id = resolve_workspace(args.get("workspace_id"), configured_workspaces)
    types = validate_choices(argToList(args.get("types")), INCIDENT_TYPES, "types")
    statuses = validate_choices(argToList(args.get("statuses")), INCIDENT_STATUSES, "statuses")
    severities = validate_choices(argToList(args.get("severities")), SEVERITIES, "severities")
    time_field = args.get("time_range_field") or "incident_date"
    validate_choices([time_field], TIME_RANGE_FIELDS, "time_range_field")

    filters = build_filters(
        start_ms=to_epoch_ms(args.get("start_date"), "start_date"),
        end_ms=to_epoch_ms(args.get("end_date"), "end_date"),
        time_field=time_field,
        search_term=args.get("search_term"),
        types=types,
        statuses=statuses,
        severities=severities,
        is_deleted=argToBoolean(args.get("is_deleted", "false")),
        is_archived=argToBoolean(args.get("is_archived", "false")),
        new_updates_only=argToBoolean(args.get("new_updates_only", "false")),
    )
    sort = None
    if args.get("sort_by"):
        validate_choices([args["sort_by"]], SORT_FIELDS, "sort_by")
        sort = {"sortBy": args["sort_by"]}
        if args.get("sort_order"):
            validate_choices([args["sort_order"]], SORT_ORDERS, "sort_order")
            sort["order"] = args["sort_order"]
    limit, offset = get_pagination(args)

    response = client.incidents_list(workspace_id, filters=filters, sort=sort, limit=limit, offset=offset)
    incidents = response.get("incidents") or []

    rows = [
        {
            "Incident ID": inc.get("incidentId"),
            "Incident Date": ms_to_iso(inc["incidentDate"]) if isinstance(inc.get("incidentDate"), int) else None,
            "Type": inc.get("type"),
            "Severity": inc.get("severity"),
            "Status": inc.get("status"),
            "Title": inc.get("title"),
            "Impersonated Asset": (inc.get("analysis") or {}).get("impersonatedAsset"),
            "Detected URLs": (inc.get("detectedEntity") or {}).get("urls"),
        }
        for inc in incidents
    ]
    title = (
        f"KELA Brand Control incidents (showing {len(incidents)} of {response.get('filteredCount', len(incidents))} "
        f"matching, {response.get('count', 'n/a')} total in the workspace)"
    )
    return CommandResults(
        outputs_prefix=f"{CONTEXT_PREFIX}.Incident",
        outputs_key_field="incidentId",
        outputs=incidents,
        readable_output=tableToMarkdown(title, rows, removeNull=True),
        raw_response=response,
    )


# endregion


# region Fetch incidents
def parse_max_fetch(value: Any) -> int:
    max_fetch = arg_to_number(value) if value not in (None, "") else DEFAULT_MAX_FETCH
    if max_fetch is None or max_fetch < 1 or max_fetch > MAX_FETCH_LIMIT:
        raise DemistoException(f"'max_fetch' must be between 1 and {MAX_FETCH_LIMIT}.")
    return max_fetch


def incident_to_xsoar(incident: dict[str, Any]) -> dict[str, Any]:
    """Map a Brand Control incident to an XSOAR incident. occurred = incidentDate [SPEC]."""
    title = incident.get("title") or incident.get("type") or "Incident"
    return {
        "name": f"KELA Brand Control - {title} [{incident['incidentId']}]",
        "occurred": ms_to_iso(incident["incidentDate"]),
        "severity": SEVERITY_TO_XSOAR.get(str(incident.get("severity", "")).lower(), 0),
        "details": incident.get("description") or "",
        "rawJSON": json.dumps(incident),
    }


def get_workspace_state(last_run: dict[str, Any], workspace_id: str, first_fetch_ms: int) -> dict[str, Any]:
    """Return {'watermark': int, 'seen_ids': list|None} for a workspace.

    seen_ids=None means "legacy last run without ID list" (upgrade path).
    Legacy shapes handled: {'workspaces': {ws: {'watermark': n}}} and the flat {'last_fetch': n}.
    """
    state = (last_run.get("workspaces") or {}).get(workspace_id)
    if state and state.get("watermark") is not None:
        return {"watermark": int(state["watermark"]), "seen_ids": state.get("seen_ids")}
    if last_run.get("last_fetch") is not None:
        return {"watermark": int(last_run["last_fetch"]), "seen_ids": None}
    return {"watermark": first_fetch_ms, "seen_ids": []}


def fetch_workspace(
    client: Client,
    workspace_id: str,
    state: dict[str, Any],
    max_fetch: int,
    severities: list[str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Fetch one workspace with a watermark + same-timestamp ID de-duplication.

    Why: startDate may be INCLUSIVE (the record sitting exactly on the watermark comes back every cycle) and
    XSOAR never de-duplicates fetched incidents. We therefore store, next to the watermark, the IDs of the
    records whose date == watermark and skip them next cycle. The page is sized max_fetch + len(seen_ids) so a
    group of same-timestamp records can never stall the watermark.
    """
    watermark = state["watermark"]
    legacy = state["seen_ids"] is None
    seen_ids: list[str] = [] if legacy else list(state["seen_ids"])
    seen_set = set(seen_ids)

    # Legacy last run: unknown how many records share the watermark -> pad with the ID cap.
    page_size = min(max_fetch + (SEEN_IDS_CAP if legacy else len(seen_ids)), API_MAX_LIMIT)
    filters = build_filters(start_ms=watermark, time_field="incident_date", is_deleted=False, is_archived=False)
    response = client.incidents_list(
        workspace_id,
        filters=filters,
        sort={"sortBy": "incidentDate", "order": "asc"},
        limit=page_size,
        offset=0,
    )
    records = [r for r in (response.get("incidents") or []) if r.get("incidentId") and isinstance(r.get("incidentDate"), int)]
    skipped_invalid = len(response.get("incidents") or []) - len(records)
    if skipped_invalid:
        demisto.debug(f"KELA BrandControl: ignored {skipped_invalid} record(s) without incidentId/incidentDate.")
    records.sort(key=lambda r: r["incidentDate"])  # defensive: the API is asked for asc but we do not rely on it

    new_watermark = watermark
    ids_at_watermark: list[str] = list(seen_ids)
    incidents: list[dict[str, Any]] = []
    processed = 0
    wanted = {s.lower() for s in severities}

    for record in records:
        date_ms, incident_id = record["incidentDate"], record["incidentId"]
        if date_ms < watermark:
            continue  # defensive: should not be returned
        if date_ms == watermark and (legacy or incident_id in seen_set):
            # Already ingested in an earlier cycle (or assumed so for a legacy last run).
            if incident_id not in ids_at_watermark:
                ids_at_watermark.append(incident_id)
            continue
        if processed >= max_fetch:
            break
        processed += 1
        # The watermark advances for EVERY processed record, even those filtered out by severity.
        if date_ms > new_watermark:
            new_watermark = date_ms
            ids_at_watermark = [incident_id]
        elif incident_id not in ids_at_watermark:
            ids_at_watermark.append(incident_id)
        if wanted and str(record.get("severity", "")).lower() not in wanted:
            continue
        incidents.append(incident_to_xsoar(record))

    if len(ids_at_watermark) > SEEN_IDS_CAP:
        demisto.debug(f"KELA BrandControl: seen_ids capped at {SEEN_IDS_CAP} for workspace {workspace_id}.")
        ids_at_watermark = ids_at_watermark[-SEEN_IDS_CAP:]
    return {"watermark": new_watermark, "seen_ids": ids_at_watermark}, incidents


def fetch_incidents(
    client: Client,
    workspace_ids: list[str],
    last_run: dict[str, Any],
    first_fetch_ms: int,
    max_fetch: int,
    severities: list[str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Fetch every configured workspace with an independent state.

    State of workspaces no longer configured is preserved, so re-enabling one resumes where it stopped.
    If any workspace fails the whole cycle raises: nothing is created and the last run is not saved, so the
    next cycle retries cleanly with no duplicates.
    """
    demisto.debug(f"KELA BrandControl: fetch started for workspaces {workspace_ids}.")
    previous = last_run.get("workspaces") or {}
    next_workspaces: dict[str, Any] = {ws: st for ws, st in previous.items() if ws not in workspace_ids}
    all_incidents: list[dict[str, Any]] = []
    for workspace_id in workspace_ids:
        state = get_workspace_state(last_run, workspace_id, first_fetch_ms)
        next_state, incidents = fetch_workspace(client, workspace_id, state, max_fetch, severities)
        next_workspaces[workspace_id] = next_state
        all_incidents.extend(incidents)
    demisto.info(f"KELA BrandControl: fetch completed, {len(all_incidents)} incident(s) created.")
    return {"workspaces": next_workspaces}, all_incidents


# endregion


# region Main
def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    api_token = (params.get("credentials") or {}).get("password") or ""
    demisto.debug(f"Command being called is {command}")
    try:
        if not api_token:
            raise DemistoException("API Token is required.")
        workspace_ids = parse_workspace_ids(params.get("workspace_ids"))
        client = Client(
            base_url=params.get("url") or DEFAULT_BASE_URL,
            api_token=api_token,
            verify=not argToBoolean(params.get("insecure", False)),
            proxy=argToBoolean(params.get("proxy", False)),
        )
        if command == "test-module":
            return_results(test_module(client, workspace_ids, params))
        elif command == "fetch-incidents":
            next_run, incidents = fetch_incidents(
                client,
                workspace_ids,
                demisto.getLastRun(),
                to_epoch_ms(params.get("first_fetch") or DEFAULT_FIRST_FETCH, "first_fetch"),  # type: ignore[arg-type]
                parse_max_fetch(params.get("max_fetch")),
                validate_choices(argToList(params.get("fetch_severities")), SEVERITIES, "fetch_severities"),
            )
            demisto.incidents(incidents)
            demisto.setLastRun(next_run)
        elif command == "kela-brandcontrol-incident-list":
            return_results(incident_list_command(client, args, workspace_ids))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as e:
        demisto.error(mask_secret(traceback.format_exc(), api_token))
        return_error(f"Failed to execute {command} command.\nError:\n{mask_secret(str(e), api_token)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
# endregion
