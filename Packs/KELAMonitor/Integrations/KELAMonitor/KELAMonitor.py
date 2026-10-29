import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import html
import re
from datetime import UTC, datetime
from urllib.parse import quote, quote_plus

""" KELA Monitor integration for Cortex.

Reads incidents of a KELA Monitor through the KELA Monitor API (https://platform.ke-la.com/api/monitor).
The API token is sent in the `apiToken` HTTP header, which the KELA Monitor API accepts as an alternative to the
`apiToken` query parameter, so it is not part of the request URL. It is also registered for log masking and removed
from the error messages this integration reports.
"""

# region Constants
VENDOR = "KELA"
PRODUCT = "Monitor"
CONTEXT_PREFIX = "KELA.Monitor"
DEFAULT_BASE_URL = "https://platform.ke-la.com/api/monitor"
API_TOKEN_HEADER = "apiToken"

# Values of the incident_type query parameter that this integration fetches.
# "reports" (Intelligence Report) and "dld_source_codes" (Data-Loss Detection) are not fetched yet.
INCIDENT_TYPES = [
    "hacking_discussions",
    "instant_messaging",
    "leaked_credentials",
    "network_vulnerabilities",
    "credit_cards",
    "botnets",
]
# Monitor severities: 1 = Low, 2 = Medium, 3 = High, 4 = Critical. The API sends and accepts the integer.
SEVERITY_LABELS = {"low": 1, "medium": 2, "high": 3, "critical": 4}
CORTEX_SEVERITY_BY_KELA = {
    1: IncidentSeverity.LOW,
    2: IncidentSeverity.MEDIUM,
    3: IncidentSeverity.HIGH,
    4: IncidentSeverity.CRITICAL,
}

DEFAULT_LIST_LIMIT = 20
MAX_LIST_LIMIT = 1000
PAGE_LIMIT = MAX_LIST_LIMIT  # batch size used by fetch
DEFAULT_MAX_FETCH = 50
MAX_FETCH_LIMIT = 200
SEEN_IDS_CAP = 500  # cap of the stored IDs that share the watermark second
WINDOW_MAX_SECONDS = 24 * 3600  # fetch looks at most this far ahead of the watermark per request
WINDOW_MIN_SECONDS = 1
MAX_CALLS_PER_STREAM = 20  # API calls (list + scroll pages) per incident type per fetch cycle
LATE_MARGIN_SECONDS = 300  # a window is considered "closed" only if it ended this long ago
HTTP_RETRIES = 3  # retries on HTTP 429 (the API allows 1 request per second)
HTTP_BACKOFF_FACTOR = 1
MASK = "********"
# Keys whose values are masked at any depth of a record when "Mask sensitive data" is selected.
SENSITIVE_KEYS = {"password", "passwd", "pass", "pwd", "cookie", "cookies", "token", "session", "secret", "cvv"}
# Epoch fields converted to ISO 8601 UTC in command outputs.
EPOCH_SECONDS_KEYS = ("incident_date", "publish_date", "posted_date", "relevant_date")
EPOCH_MILLISECONDS_RANGE_KEY = "posted_date_range"
# endregion


# region Helpers
def mask_secret(text: str, secret: str | None) -> str:
    """Remove the API token (raw and URL-encoded) from a text so it can never reach the UI or logs."""
    if not secret:
        return text
    for variant in {secret, quote(secret, safe=""), quote_plus(secret)}:
        text = text.replace(variant, "<API_TOKEN>")
    return text


def parse_monitor_id(value: Any) -> int:
    """The Monitor ID is an integer."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        raise DemistoException("Monitor ID is required and must be a number (see the monitorId parameter in the Monitor URL).")


def parse_incident_types(raw: Any) -> list[str]:
    """At least one incident type is mandatory for fetch."""
    types = [str(t).strip() for t in argToList(raw) if str(t).strip()]
    if not types:
        raise DemistoException(f"Select at least one incident type to fetch. Allowed values: {INCIDENT_TYPES}.")
    invalid = [t for t in types if t not in INCIDENT_TYPES]
    if invalid:
        raise DemistoException(f"Invalid incident type(s): {invalid}. Allowed values: {INCIDENT_TYPES}.")
    return list(dict.fromkeys(types))


def parse_severities(raw: Any) -> list[int]:
    """Accepts low/medium/high/critical or 1-4 and returns the integers the API expects."""
    result: list[int] = []
    for item in argToList(raw):
        text = str(item).strip().lower()
        if not text:
            continue
        if text in SEVERITY_LABELS:
            value = SEVERITY_LABELS[text]
        elif text in {"1", "2", "3", "4"}:
            value = int(text)
        else:
            raise DemistoException(f"Invalid severity '{item}'. Use low, medium, high, critical (or 1-4).")
        if value not in result:
            result.append(value)
    return result


def to_epoch_seconds(value: Any, arg_name: str) -> int | None:
    """Convert a date into Unix epoch SECONDS (from_date / to_date are seconds).

    Accepts 10 digit epoch seconds, 13 digit epoch milliseconds (converted), ISO dates and relative dates ("3 days").
    A date without a timezone is read as UTC, whatever the engine's local timezone is.
    """
    if value is None or str(value).strip() == "":
        return None
    text = str(value).strip()
    if text.isdigit():
        if len(text) == 10:
            return int(text)
        if len(text) == 13:
            return int(text) // 1000
        raise DemistoException(f"Invalid '{arg_name}': numeric dates must be a 10 digit epoch in seconds.")
    parsed = arg_to_datetime(text, arg_name, is_utc=True, required=False)
    if parsed is None:
        raise DemistoException(f"Invalid '{arg_name}': could not parse '{text}'.")
    if parsed.tzinfo is None:
        # arg_to_datetime returns a naive datetime that already holds UTC wall time; .timestamp() would read it as local.
        parsed = parsed.replace(tzinfo=UTC)
    return int(parsed.timestamp())


def to_cortex_severity(value: Any) -> float:
    """Map the KELA severity (1-4, "1"-"4" or low..critical) to IncidentSeverity; anything else becomes LOW."""
    text = str(value).strip().lower() if value is not None else ""
    level = SEVERITY_LABELS.get(text) or (int(text) if text in {"1", "2", "3", "4"} else None)
    return CORTEX_SEVERITY_BY_KELA.get(level, IncidentSeverity.LOW) if level else IncidentSeverity.LOW


def epoch_to_iso(seconds: int) -> str:
    return datetime.fromtimestamp(seconds, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def clean_text(value: Any) -> str:
    """Matched patterns come wrapped in <span> tags and may contain HTML entities."""
    if not value:
        return ""
    return html.unescape(re.sub(r"<[^>]+>", "", str(value))).strip()


def mask_card_number(number: Any) -> str:
    digits = str(number)
    if len(digits) <= 10:
        return "*" * len(digits)
    return digits[:6] + "*" * (len(digits) - 10) + digits[-4:]


def _mask_sensitive_keys(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: (MASK if str(k).lower() in SENSITIVE_KEYS and v not in (None, "") else _mask_sensitive_keys(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_mask_sensitive_keys(item) for item in value]
    return value


def mask_record(record: dict[str, Any]) -> dict[str, Any]:
    """Mask sensitive data: secrets under SENSITIVE_KEYS (any depth) and credit card numbers (BIN + last 4 kept)."""
    masked = _mask_sensitive_keys(record)
    if masked.get("type") == "credit_cards" and masked.get("number"):
        masked["number"] = mask_card_number(masked["number"])
    return masked


def format_dates_for_context(record: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of the record with its epoch dates as ISO 8601 UTC strings (command outputs only)."""
    formatted = dict(record)
    for key in EPOCH_SECONDS_KEYS:
        if isinstance(formatted.get(key), int):
            formatted[key] = epoch_to_iso(formatted[key])
    date_range = formatted.get(EPOCH_MILLISECONDS_RANGE_KEY)
    if isinstance(date_range, dict):
        formatted[EPOCH_MILLISECONDS_RANGE_KEY] = {
            k: epoch_to_iso(v // 1000) if isinstance(v, int) else v for k, v in date_range.items()
        }
    return formatted


def mask_identity(value: Any) -> str:
    """Keep the first character and the domain of an email or user name: jane@example.com -> j***@example.com."""
    text = str(value or "")
    if not text:
        return text
    local, at, domain = text.partition("@")
    return f"{local[:1]}***{at}{domain}"


def _type_specific_name(record: dict[str, Any], incident_type: str, mask: bool) -> str:
    if incident_type == "hacking_discussions":
        return record.get("title") or "Hacking discussion"
    if incident_type == "instant_messaging":
        return f"{record.get('chat_name') or record.get('source_name') or 'Chat'}: {clean_text(record.get('snippet'))[:60]}"
    if incident_type == "leaked_credentials":
        email = mask_identity(record.get("email")) if mask else record.get("email")
        return email or record.get("domain") or "Leaked credentials"
    if incident_type == "network_vulnerabilities":
        host = f"{record.get('ip')}:{record.get('port')}" if record.get("port") else record.get("ip")
        return f"{host or 'Host'} {record.get('description') or ''}".strip()
    if incident_type == "credit_cards":
        number = str(record.get("number") or "")
        return (
            f"Credit card {number[:6]}...{number[-4:]}" if len(number) > 10 else f"Credit card {record.get('bin') or ''}".strip()
        )
    if incident_type == "botnets":
        username = mask_identity(record.get("username")) if mask else record.get("username")
        return f"{username or 'Bot'} @ {record.get('resource') or record.get('service') or record.get('source') or ''}"
    return record.get("title") or clean_text(record.get("text"))[:80] or incident_type


def build_incident_name(record: dict[str, Any], mask: bool = False) -> str:
    """Stable, human readable name that never includes passwords or full card numbers.

    With mask=True the leaked email and the compromised user name are shown as j***@example.com.
    """
    incident_type = record.get("type") or "incident"
    core = _type_specific_name(record, incident_type, mask)
    return f"KELA Monitor - {incident_type}: {str(core).strip()[:110]} [{record['id']}]"


def build_incident_details(record: dict[str, Any]) -> str:
    """Incident text; for instant messaging the full message is preferred over the snippet."""
    if record.get("type") == "instant_messaging" and record.get("full_text"):
        return clean_text(record.get("full_text"))
    details = clean_text(record.get("text")) or clean_text(record.get("snippet")) or record.get("description") or ""
    return details or record.get("sub_type_description") or ""


def build_kela_meta(record: dict[str, Any], monitor_id: int) -> dict[str, Any]:
    """Values the incoming mapper cannot derive from the raw record. Sensitive values are always masked here."""
    masked = mask_record(record)
    posted = record.get("posted_date") or record.get("publish_date")
    meta: dict[str, Any] = {
        "monitorId": str(monitor_id),
        "postedDateIso": epoch_to_iso(posted) if isinstance(posted, int) else None,
        "passwordMasked": masked.get("password") if record.get("type") == "leaked_credentials" else None,
        "cardNumberMasked": masked.get("number") if record.get("type") == "credit_cards" else None,
        "availableDataJson": json.dumps(masked["available_data"]) if masked.get("available_data") else None,
    }
    return {key: value for key, value in meta.items() if value not in (None, "")}


def incident_to_xsoar(record: dict[str, Any], mask: bool, monitor_id: int | None = None) -> dict[str, Any]:
    """Map a Monitor incident to a Cortex incident. occurred = incident_date, severity from the KELA 1-4 scale.

    The name, details and rawJSON come from the stored (masked when masking is on) record. The incident type is set by
    the classifier from the raw `type`; the incident fields are set by the incoming mapper.
    """
    stored = mask_record(record) if mask else dict(record)
    if monitor_id is not None:
        stored["kelaMeta"] = build_kela_meta(record, monitor_id)
    return {
        "name": build_incident_name(stored, mask),
        "occurred": epoch_to_iso(record["incident_date"]),
        "severity": to_cortex_severity(record.get("severity")),
        "details": build_incident_details(stored),
        "dbotMirrorId": str(record["id"]),
        "rawJSON": json.dumps(stored),
    }


def is_handled(record: dict[str, Any]) -> bool:
    """handled is false, or the name of the person who handled the incident in KELA."""
    flags = record.get("user_actions") or record.get("actions") or {}
    return bool(flags.get("handled"))


def is_hidden_or_deleted(record: dict[str, Any]) -> bool:
    """Incidents hidden or deleted by a user in KELA's platform are skipped by fetch."""
    flags = record.get("user_actions") or record.get("actions") or {}
    return bool(flags.get("hide") or flags.get("delete"))


# endregion


# region Client
class ForbiddenError(DemistoException):
    """HTTP 403: the token is valid but has no access to this Monitor or to this incident type."""


class Client(BaseClient):
    """All HTTP traffic goes through BaseClient._http_request. The token travels in the apiToken header only."""

    def __init__(self, base_url: str, api_token: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url.rstrip("/"), verify=verify, proxy=proxy, headers={API_TOKEN_HEADER: api_token})
        add_sensitive_log_strs(api_token)

    @staticmethod
    def _error_handler(res: requests.Response) -> None:
        """Error shapes differ per status: 400 is HTML, 401 is {message}, 500 is {error_msg}."""
        message = None
        try:
            body = res.json()
            if isinstance(body, dict):
                message = body.get("message") or body.get("error_msg")
        except ValueError:
            message = None
        if res.status_code == 401:
            raise DemistoException("Authorization Error: make sure the API Token is correct and not expired.")
        if res.status_code == 403:
            raise ForbiddenError(
                f"Forbidden [403] - {message or 'not authorized'}: "
                "the API Token has no access to this Monitor or to this incident type."
            )
        if res.status_code == 400:
            raise DemistoException("Bad Request: check the Monitor ID, the incident type and the filters.")
        if res.status_code == 404:
            raise DemistoException("Not Found: check the Monitor ID (a scroll ID also expires 2 minutes after it was issued).")
        if res.status_code == 429:
            raise DemistoException("Rate limit exceeded (1 request per second). Wait before running more requests.")
        raise DemistoException(f"Error in API call [{res.status_code}] - {message or 'no details returned'}")

    def _get(self, url_suffix: str, params: dict[str, Any]) -> dict[str, Any]:
        response = self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params=params,
            retries=HTTP_RETRIES,
            status_list_to_retry=[429],
            backoff_factor=HTTP_BACKOFF_FACTOR,
            error_handler=self._error_handler,
        )
        return (response or {}).get("data") or {}

    def incidents_list(
        self,
        monitor_id: int,
        incident_type: str,
        text: str | None = None,
        limit: int = DEFAULT_LIST_LIMIT,
        from_date: int | None = None,
        to_date: int | None = None,
        severities: list[int] | None = None,
        first_appearance: bool = False,
    ) -> dict[str, Any]:
        """GET /monitor_id/{monitor_id}/incidents (Incidents List by Incident Type)."""
        params: dict[str, Any] = {"incident_type": incident_type, "limit": limit}
        if text:
            params["text"] = text
        if from_date is not None:
            params["from_date"] = from_date
        if to_date is not None:
            params["to_date"] = to_date
        if severities:
            params["severities"] = ",".join(str(s) for s in severities)
        if first_appearance:
            params["first_appearance"] = "true"
        return self._get(f"/monitor_id/{monitor_id}/incidents", params)

    def incidents_scroll(self, monitor_id: int, scroll_id: str) -> dict[str, Any]:
        """GET /monitor_id/{monitor_id}/incidents/scroll/{scroll_id} (Scroll Incidents List by Incident Type)."""
        return self._get(f"/monitor_id/{monitor_id}/incidents/scroll/{quote(scroll_id, safe='')}", {})


# endregion


# region Commands
def validate_server_url(url: str) -> str:
    """The token travels in a header, so only https is accepted."""
    if not url.strip().lower().startswith("https://"):
        raise DemistoException("Server URL must start with https://.")
    return url.strip()


def validate_fetch_params(params: dict[str, Any]) -> None:
    parse_incident_types(params.get("incident_types"))
    to_epoch_seconds(params.get("first_fetch") or "3 days", "first_fetch")
    parse_max_fetch(params.get("max_fetch"))
    parse_severities(params.get("fetch_severities"))


def probe_incident_types(client: Client, monitor_id: int, probe_types: list[str]) -> list[str] | None:
    """Probe each type with limit=1. Returns the forbidden types, or None when the token is rejected."""
    forbidden: list[str] = []
    try:
        for probe_type in probe_types:
            try:
                client.incidents_list(monitor_id, probe_type, limit=1)
            except ForbiddenError:
                forbidden.append(probe_type)
    except DemistoException as e:
        if "Authorization" in str(e):
            return None
        raise
    return forbidden


def test_module(client: Client, monitor_id: int, incident_types: list[str], params: dict[str, Any]) -> str:
    """Validate credentials and monitor access, plus the fetch settings when fetch is enabled."""
    if params.get("isFetch"):
        validate_fetch_params(params)
    probe_types = incident_types or ["hacking_discussions"]
    forbidden = probe_incident_types(client, monitor_id, probe_types)
    if forbidden is None:
        return "Authorization Error: make sure the API Token is correct and has access to this monitor."
    if forbidden and len(forbidden) == len(probe_types):
        raise DemistoException(
            "Forbidden [403] for every selected incident type: the API Token has no access to this Monitor. "
            "Check the Monitor ID and the token."
        )
    if forbidden:
        return (
            f"Partial access: the API Token has no access to {', '.join(forbidden)}. Fetch skips them and keeps working with the "
            "other incident types. Unselect them to remove this message."
        )
    return "ok"


def _incident_rows(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "ID": inc.get("id"),
            "Type": inc.get("type"),
            "Sub Type": inc.get("sub_type_description"),
            "Severity": inc.get("severity"),
            "Incident Date": inc.get("incident_date"),
            "Title": inc.get("title"),
            "Source": inc.get("source") or inc.get("source_name"),
            "Tags": inc.get("tags"),
        }
        for inc in incidents
    ]


def _scroll_result(scroll_id: str, monitor_id: int, incident_type: str | None) -> CommandResults:
    return CommandResults(
        outputs_prefix=f"{CONTEXT_PREFIX}.Scroll",
        outputs_key_field="scrollId",
        outputs={"scrollId": scroll_id, "monitorId": monitor_id, "incidentType": incident_type},
        readable_output=(
            "More incidents may be available. "
            f"Run `kela-monitor-incident-scroll scroll_id={scroll_id}` to get the next batch. "
            "The scroll ID is valid for 2 minutes."
        ),
    )


def _list_results(
    data: dict[str, Any], monitor_id: int, incident_type: str | None, mask: bool, title: str
) -> list[CommandResults]:
    raw_incidents = [mask_record(i) if mask else i for i in (data.get("incidents") or [])]
    incidents = [format_dates_for_context(i) for i in raw_incidents]
    scroll_id = data.get("scrollId")
    results = [
        CommandResults(
            outputs_prefix=f"{CONTEXT_PREFIX}.Incident",
            outputs_key_field="id",
            outputs=incidents,
            readable_output=tableToMarkdown(f"{title} ({len(incidents)} returned)", _incident_rows(incidents), removeNull=True),
            raw_response=data if not mask else {"incidents": raw_incidents, "scrollId": scroll_id},
        )
    ]
    if scroll_id and incidents:
        results.append(_scroll_result(scroll_id, monitor_id, incident_type))
    return results


def parse_list_limit(value: Any) -> int:
    limit = arg_to_number(value)
    limit = DEFAULT_LIST_LIMIT if limit is None else limit
    if not 1 <= limit <= MAX_LIST_LIMIT:
        raise DemistoException(f"'limit' must be between 1 and {MAX_LIST_LIMIT}.")
    return limit


def incident_list_command(client: Client, args: dict[str, Any], default_monitor_id: int, mask: bool) -> list[CommandResults]:
    """kela-monitor-incident-list -> GET /monitor_id/{id}/incidents."""
    incident_type = args.get("incident_type")
    if incident_type not in INCIDENT_TYPES:
        raise DemistoException(f"'incident_type' is required. Allowed values: {INCIDENT_TYPES}.")
    monitor_id = parse_monitor_id(args.get("monitor_id") or default_monitor_id)
    data = client.incidents_list(
        monitor_id,
        incident_type,
        text=args.get("text"),
        limit=parse_list_limit(args.get("limit")),
        from_date=to_epoch_seconds(args.get("from_date"), "from_date"),
        to_date=to_epoch_seconds(args.get("to_date"), "to_date"),
        severities=parse_severities(args.get("severities")),
        first_appearance=argToBoolean(args.get("first_appearance", "false")),
    )
    return _list_results(data, monitor_id, incident_type, mask, f"KELA Monitor incidents ({incident_type})")


def incident_scroll_command(client: Client, args: dict[str, Any], default_monitor_id: int, mask: bool) -> list[CommandResults]:
    """kela-monitor-incident-scroll -> GET /monitor_id/{id}/incidents/scroll/{scroll_id}."""
    scroll_id = args.get("scroll_id")
    if not scroll_id:
        raise DemistoException("'scroll_id' is required (returned by kela-monitor-incident-list).")
    monitor_id = parse_monitor_id(args.get("monitor_id") or default_monitor_id)
    data = client.incidents_scroll(monitor_id, str(scroll_id))
    results = _list_results(data, monitor_id, None, mask, "KELA Monitor incidents (scroll)")
    if not data.get("incidents"):
        results[0].readable_output = "No more incidents available for this scroll."
    return results


# endregion


# region Fetch incidents
def parse_max_fetch(value: Any) -> int:
    max_fetch = arg_to_number(value) if value not in (None, "") else DEFAULT_MAX_FETCH
    if max_fetch is None or max_fetch < 1 or max_fetch > MAX_FETCH_LIMIT:
        raise DemistoException(f"'max_fetch' must be between 1 and {MAX_FETCH_LIMIT}.")
    return max_fetch


def get_stream_state(last_run: dict[str, Any], key: str, first_fetch_s: int) -> dict[str, Any]:
    """State of one (monitor, incident type) stream.

    watermark: epoch seconds of the latest processed incident_date.
    seen_ids: IDs processed at the watermark second.
    after_id: when set, every ID at the watermark second that sorts at or before it was already processed (used once a
              same-second group grows past SEEN_IDS_CAP, so the stored list stays bounded).
    window: current request window in seconds.
    """
    state = (last_run.get("streams") or {}).get(key)
    if state and state.get("watermark") is not None:
        return {
            "watermark": int(state["watermark"]),
            "seen_ids": state.get("seen_ids") or [],
            "after_id": state.get("after_id"),
            "window": int(state.get("window") or WINDOW_MAX_SECONDS),
        }
    return {"watermark": first_fetch_s, "seen_ids": [], "after_id": None, "window": WINDOW_MAX_SECONDS}


def collect_window(
    client: Client,
    monitor_id: int,
    incident_type: str,
    from_s: int,
    to_s: int,
    severities: list[int],
    budget: int,
) -> tuple[list[dict[str, Any]], bool, int]:
    """Read EVERY incident of a time window: first request + scroll pages until `incidents` comes back empty.

    The API returns the newest incidents first, so a partial read would hold only the newest part of the window. If the
    call budget runs out the window is reported as truncated and the caller must not use it.
    """
    records: dict[str, dict[str, Any]] = {}
    data = client.incidents_list(
        monitor_id, incident_type, limit=PAGE_LIMIT, from_date=from_s, to_date=to_s, severities=severities or None
    )
    calls = 1
    while True:
        batch = data.get("incidents") or []
        for item in batch:
            if item.get("id"):
                records[item["id"]] = item
        scroll_id = data.get("scrollId")
        if not batch or not scroll_id:
            return list(records.values()), False, calls
        if calls >= budget:
            return list(records.values()), True, calls
        data = client.incidents_scroll(monitor_id, scroll_id)
        calls += 1


def _valid_sorted_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    valid = [r for r in records if r.get("id") and isinstance(r.get("incident_date"), int)]
    if len(valid) != len(records):
        demisto.debug(f"[Fetch] KELA Monitor: ignored {len(records) - len(valid)} record(s) without id/incident_date.")
    valid.sort(key=lambda r: (r["incident_date"], r["id"]))  # never rely on the API order
    return valid


def _already_processed(record: dict[str, Any], watermark: int, seen: set[str], after_id: str | None) -> bool:
    date_s, incident_id = record["incident_date"], record["id"]
    if date_s < watermark:
        return True  # processed in an earlier cycle (we re-request from watermark - 1)
    if date_s > watermark:
        return False
    return incident_id in seen or (after_id is not None and incident_id <= after_id)


def process_window(
    records: list[dict[str, Any]],
    state: dict[str, Any],
    max_fetch: int,
    mask: bool,
    monitor_id: int | None = None,
    skip_handled: bool = False,
) -> tuple[dict[str, Any], list[dict[str, Any]], bool]:
    """Apply watermark + same-second ID de-duplication to a fully read window.

    The API works in whole seconds, so many incidents share the watermark second, and we always re-request from just
    before the watermark. Cortex does not de-duplicate fetched incidents, so the IDs that share the watermark second
    are stored (or summarised by `after_id`) and skipped next cycle.
    Returns (new_state, cortex_incidents, cut_by_max_fetch); new_state holds watermark, seen_ids and after_id.
    """
    watermark, after_id = state["watermark"], state.get("after_id")
    seen = set(state["seen_ids"])
    ids_at_watermark = list(state["seen_ids"])
    incidents: list[dict[str, Any]] = []
    processed, cut = 0, False
    for record in _valid_sorted_records(records):
        date_s, incident_id = record["incident_date"], record["id"]
        if _already_processed(record, state["watermark"], seen, after_id):
            continue
        if processed >= max_fetch:
            cut = True
            break
        processed += 1
        # The watermark advances for EVERY processed record, even those that are skipped below.
        if date_s > watermark:
            watermark, ids_at_watermark, after_id = date_s, [incident_id], None
        elif incident_id not in ids_at_watermark:
            ids_at_watermark.append(incident_id)
        if is_hidden_or_deleted(record) or (skip_handled and is_handled(record)):
            continue
        incidents.append(incident_to_xsoar(record, mask, monitor_id))
    return {"watermark": watermark, "seen_ids": ids_at_watermark, "after_id": after_id}, incidents, cut


def compact_seen_ids(seen_ids: list[str], after_id: str | None) -> tuple[list[str], str | None]:
    """Keep the stored ID list bounded without forgetting any processed ID of the watermark second.

    Inside one second the records are processed in ID order, so once the list passes SEEN_IDS_CAP it is replaced by
    the highest processed ID (`after_id`); later cycles skip every ID at that second up to it and keep draining the rest.
    """
    if len(seen_ids) <= SEEN_IDS_CAP:
        return seen_ids, after_id
    demisto.debug(f"[Dedup] KELA Monitor: {len(seen_ids)} IDs at the watermark second, compacted to an ID cursor.")
    return [], max([*seen_ids, *([after_id] if after_id else [])])


def fetch_stream(
    client: Client,
    monitor_id: int,
    incident_type: str,
    state: dict[str, Any],
    max_fetch: int,
    severities: list[int],
    mask: bool,
    now_s: int,
    skip_handled: bool = False,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Fetch one (monitor, incident type) stream, walking time windows from the watermark towards now.

    Windows in the past are crossed in the same cycle until max_fetch incidents were collected or the call budget
    (MAX_CALLS_PER_STREAM) is spent. If a window holds more incidents than the call budget can read, the window is
    halved for the next cycle.
    """
    window = state["window"]
    current = {"watermark": state["watermark"], "seen_ids": list(state["seen_ids"]), "after_id": state.get("after_id")}
    incidents: list[dict[str, Any]] = []
    calls_left = MAX_CALLS_PER_STREAM
    first_window = True

    while calls_left > 0:
        from_s = max(current["watermark"] - 1, 0)  # 1s overlap in case from_date is exclusive; dedup absorbs the repeat
        to_s = min(now_s, current["watermark"] + window)
        records, truncated, used = collect_window(client, monitor_id, incident_type, from_s, to_s, severities, calls_left)
        calls_left -= used
        if truncated:
            if first_window and window > WINDOW_MIN_SECONDS:
                window = max(window // 2, WINDOW_MIN_SECONDS)
                demisto.debug(f"[Pagination Loop] KELA Monitor: window too large for {incident_type}, halved to {window}s.")
                break
            if not first_window:
                break  # keep what earlier (empty) windows achieved and retry with a fresh budget next cycle
            demisto.debug(f"[Pagination Loop] KELA Monitor: minimal window still truncated for {incident_type}.")
        first_window = False

        current, emitted, cut = process_window(records, current, max_fetch - len(incidents), mask, monitor_id, skip_handled)
        incidents.extend(emitted)
        closed_window = to_s < now_s - LATE_MARGIN_SECONDS
        if not cut and closed_window and to_s > current["watermark"]:
            # nothing newer can still appear inside a window that closed long ago
            current = {"watermark": to_s, "seen_ids": [], "after_id": None}
        window = min(window * 2, WINDOW_MAX_SECONDS)
        if cut or len(incidents) >= max_fetch or not closed_window:
            break

    seen_ids, after_id = compact_seen_ids(current["seen_ids"], current["after_id"])
    return {"watermark": current["watermark"], "seen_ids": seen_ids, "after_id": after_id, "window": window}, incidents


def fetch_incidents(
    client: Client,
    monitor_id: int,
    incident_types: list[str],
    last_run: dict[str, Any],
    first_fetch_s: int,
    max_fetch: int,
    severities: list[int],
    mask: bool,
    now_s: int,
    skip_handled: bool = False,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Fetch every selected incident type with an independent state.

    The state of types that are no longer selected is preserved. A type answering 403 (no access) is skipped and the
    others continue; if every type answers 403 the cycle raises. Any other failure raises for the whole cycle: nothing is
    created and the last run is not saved, so the next cycle retries cleanly with no duplicates.
    """
    demisto.debug(f"[Fetch] KELA Monitor: fetch started for monitor {monitor_id}, incident types {incident_types}.")
    wanted_keys = {f"{monitor_id}:{t}" for t in incident_types}
    previous = last_run.get("streams") or {}
    next_streams: dict[str, Any] = {k: v for k, v in previous.items() if k not in wanted_keys}
    all_incidents: list[dict[str, Any]] = []
    forbidden: list[str] = []
    for incident_type in incident_types:
        key = f"{monitor_id}:{incident_type}"
        state = get_stream_state(last_run, key, first_fetch_s)
        try:
            next_state, incidents = fetch_stream(
                client, monitor_id, incident_type, state, max_fetch, severities, mask, now_s, skip_handled
            )
        except ForbiddenError:
            # No access to this type: skip it, keep its state untouched (none if it never ran) and retry next cycle.
            forbidden.append(incident_type)
            if key in previous:
                next_streams[key] = previous[key]
            continue
        next_streams[key] = next_state
        all_incidents.extend(incidents)
    if forbidden and len(forbidden) == len(incident_types):
        raise DemistoException(
            "Forbidden [403] for every selected incident type: the API Token has no access to this Monitor. "
            "Check the Monitor ID and the token."
        )
    if forbidden:
        demisto.info(f"[Fetch] KELA Monitor: no access (403) to {forbidden}; skipped. The other incident types were fetched.")
    demisto.info(f"[Fetch] KELA Monitor: fetch completed, {len(all_incidents)} incident(s) created.")
    return {"streams": next_streams}, all_incidents


# endregion


# region Main
def run_fetch(client: Client, params: dict[str, Any], monitor_id: int, mask: bool) -> None:
    first_fetch_s = to_epoch_seconds(params.get("first_fetch") or "3 days", "first_fetch")
    next_run, incidents = fetch_incidents(
        client,
        monitor_id,
        parse_incident_types(params.get("incident_types")),
        demisto.getLastRun(),
        first_fetch_s or int(time.time()),
        parse_max_fetch(params.get("max_fetch")),
        parse_severities(params.get("fetch_severities")),
        mask,
        int(time.time()),
        argToBoolean(params.get("skip_handled", False)),
    )
    demisto.incidents(incidents)
    demisto.setLastRun(next_run)


def return_sanitized_error(command: str, error: Exception, api_token: str) -> None:
    """Report an error without the API token, also when the server runs in debug mode.

    In debug mode return_error appends the traceback of the exception being handled. A sanitized exception is raised
    `from None` and handled here, so that traceback holds neither the original exception nor its message.
    """
    demisto.error(mask_secret(traceback.format_exc(), api_token))
    message = f"Failed to execute {command} command.\nError:\n{mask_secret(str(error), api_token)}"
    try:
        raise DemistoException(message) from None
    except DemistoException as sanitized:
        return_error(message, error=sanitized)


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    api_token = (params.get("credentials") or {}).get("password") or ""
    demisto.debug(f"Command being called is {command}")
    try:
        if not api_token:
            raise DemistoException("API Token is required.")
        monitor_id = parse_monitor_id(params.get("monitor_id"))
        mask = argToBoolean(params.get("mask_sensitive_data", True))
        client = Client(
            base_url=validate_server_url(params.get("url") or DEFAULT_BASE_URL),
            api_token=api_token,
            verify=not params.get("insecure", False),
            proxy=params.get("proxy", False),
        )
        if command == "test-module":
            return_results(test_module(client, monitor_id, argToList(params.get("incident_types")), params))
        elif command == "fetch-incidents":
            run_fetch(client, params, monitor_id, mask)
        elif command == "kela-monitor-incident-list":
            return_results(incident_list_command(client, args, monitor_id, mask))
        elif command == "kela-monitor-incident-scroll":
            return_results(incident_scroll_command(client, args, monitor_id, mask))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as e:
        return_sanitized_error(command, e, api_token)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
# endregion
