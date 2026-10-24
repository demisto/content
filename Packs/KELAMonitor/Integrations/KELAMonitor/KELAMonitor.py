import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import html
import re
from datetime import datetime, UTC
from urllib.parse import quote, quote_plus

""" KELA Monitor integration for Cortex.

Evidence legend used in comments:
    [SPEC]      -> taken from the OpenAPI file only (kela-api-Monitor.yaml).
    [POSTMAN]   -> observed in the saved example responses of the "API Monitor" Postman collection.
    [OWNER]     -> decided/confirmed by the module owner while building this pack.
    [LIVE]      -> verified against the live API. NOTHING in this file is marked [LIVE] yet:
                   see TECHNICAL_DOC.md, section "Live verification checklist".
"""

# region Constants
VENDOR = "KELA"
PRODUCT = "Monitor"
CONTEXT_PREFIX = "KELA.Monitor"
DEFAULT_BASE_URL = "https://platform.ke-la.com/api/monitor"  # [SPEC] servers[0]

# [SPEC] enum of incident_type (query param of Incidents List by Incident Type)
INCIDENT_TYPES = [
    "hacking_discussions",
    "instant_messaging",
    "leaked_credentials",
    "network_vulnerabilities",
    "credit_cards",
    "botnets",
]
# [SPEC] severities: 1 = Low, 2 = Medium, 3 = High, 4 = Critical. The API sends/accepts the integer.
SEVERITY_LABELS = {"low": 1, "medium": 2, "high": 3, "critical": 4}

DEFAULT_LIST_LIMIT = 20  # [SPEC] "Defaults to 20"
MAX_LIST_LIMIT = 1000  # maximum "limit" accepted by the API (confirmed by the module owner)
PAGE_LIMIT = MAX_LIST_LIMIT  # batch size used by fetch
DEFAULT_MAX_FETCH = 50
MAX_FETCH_LIMIT = 200
SEEN_IDS_CAP = 500  # cap of the stored IDs that share the watermark second
WINDOW_MAX_SECONDS = 24 * 3600  # fetch looks at most this far ahead of the watermark per request
WINDOW_MIN_SECONDS = 1
MAX_CALLS_PER_STREAM = 20  # API calls (list + scroll pages) per incident type per fetch cycle
LATE_MARGIN_SECONDS = 300  # a window is considered "closed" only if it ended this long ago
RATE_LIMIT_SECONDS = 1.0  # [SPEC] 1 request per second
MASK = "********"
PASSWORD_KEYS = {"password", "passwd", "pass", "pwd"}
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
    """[SPEC] monitor_id is an integer."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        raise DemistoException("Monitor ID is required and must be a number (see the monitorId parameter in the Monitor URL).")


def parse_incident_types(raw: Any) -> list[str]:
    """[OWNER] At least one incident type is mandatory."""
    types = [str(t).strip() for t in argToList(raw) if str(t).strip()]
    if not types:
        raise DemistoException(f"Select at least one incident type. Allowed values: {INCIDENT_TYPES}.")
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
    """Convert a date into Unix epoch SECONDS ([SPEC]: from_date / to_date are seconds).

    Accepts 10 digit epoch seconds, 13 digit epoch milliseconds (converted), ISO dates and relative dates ("3 days").
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
    return int(parsed.timestamp())


def epoch_to_iso(seconds: int) -> str:
    return datetime.fromtimestamp(seconds, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def clean_text(value: Any) -> str:
    """[SPEC] Matched patterns come wrapped in <span> tags and may contain HTML entities."""
    if not value:
        return ""
    return html.unescape(re.sub(r"<[^>]+>", "", str(value))).strip()


def mask_card_number(number: Any) -> str:
    digits = str(number)
    if len(digits) <= 10:
        return "*" * len(digits)
    return digits[:6] + "*" * (len(digits) - 10) + digits[-4:]


def _mask_passwords(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: (MASK if str(k).lower() in PASSWORD_KEYS and v not in (None, "") else _mask_passwords(v)) for k, v in value.items()
        }
    if isinstance(value, list):
        return [_mask_passwords(item) for item in value]
    return value


def mask_record(record: dict[str, Any]) -> dict[str, Any]:
    """[OWNER] Sensitive data is masked by default: passwords (any depth) and credit card numbers (BIN + last 4 kept)."""
    masked = _mask_passwords(record)
    if masked.get("type") == "credit_cards" and masked.get("number"):
        masked["number"] = mask_card_number(masked["number"])
    return masked


def build_incident_name(record: dict[str, Any]) -> str:
    """Stable, human readable name that never includes passwords or full card numbers."""
    incident_type = record.get("type") or "incident"
    if incident_type == "hacking_discussions":
        core = record.get("title") or "Hacking discussion"
    elif incident_type == "instant_messaging":
        core = f"{record.get('chat_name') or record.get('source_name') or 'Chat'}: {clean_text(record.get('snippet'))[:60]}"
    elif incident_type == "leaked_credentials":
        core = record.get("email") or record.get("domain") or "Leaked credentials"
    elif incident_type == "network_vulnerabilities":
        host = f"{record.get('ip')}:{record.get('port')}" if record.get("port") else record.get("ip")
        core = f"{host or 'Host'} {record.get('description') or ''}".strip()
    elif incident_type == "credit_cards":
        number = str(record.get("number") or "")
        core = (
            f"Credit card {number[:6]}...{number[-4:]}" if len(number) > 10 else f"Credit card {record.get('bin') or ''}".strip()
        )
    elif incident_type == "botnets":
        core = (
            f"{record.get('username') or 'Bot'} @ {record.get('resource') or record.get('service') or record.get('source') or ''}"
        )
    else:
        core = record.get("title") or clean_text(record.get("text"))[:80] or incident_type
    return f"KELA Monitor - {incident_type}: {str(core).strip()[:110]} [{record['id']}]"


def incident_to_xsoar(record: dict[str, Any], mask: bool) -> dict[str, Any]:
    """Map a Monitor incident to an XSOAR incident. occurred = incident_date, severity is already 1-4 [SPEC]."""
    name = build_incident_name(record)  # built from the ORIGINAL record, then the raw JSON is masked
    stored = mask_record(record) if mask else record
    details = clean_text(record.get("text")) or clean_text(record.get("snippet")) or record.get("description") or ""
    if not details:
        details = record.get("sub_type_description") or ""
    severity = record.get("severity")
    return {
        "name": name,
        "occurred": epoch_to_iso(record["incident_date"]),
        "severity": severity if severity in (1, 2, 3, 4) else 0,
        "details": details,
        "rawJSON": json.dumps(stored),
    }


def is_hidden_or_deleted(record: dict[str, Any]) -> bool:
    """[OWNER] Incidents hidden or deleted by a user in KELA's platform are skipped by fetch."""
    flags = record.get("user_actions") or record.get("actions") or {}
    return bool(flags.get("hide") or flags.get("delete"))


# endregion


# region Client
class ForbiddenError(DemistoException):
    """HTTP 403: the token is valid but has no access to this Monitor or to this incident type."""


class Client(BaseClient):
    """All HTTP traffic goes through BaseClient._http_request."""

    def __init__(self, base_url: str, api_token: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url.rstrip("/"), verify=verify, proxy=proxy)
        self._api_token = api_token
        self._last_request_ts = 0.0
        add_sensitive_log_strs(api_token)

    def _throttle(self) -> None:
        """[SPEC] 1 request / second."""
        elapsed = time.monotonic() - self._last_request_ts
        if elapsed < RATE_LIMIT_SECONDS:
            time.sleep(RATE_LIMIT_SECONDS - elapsed)
        self._last_request_ts = time.monotonic()

    @staticmethod
    def _error_handler(res) -> None:
        """Real error shapes differ from the spec [POSTMAN]: 400 is HTML, 401 is {message}, 500 is {error_msg}.

        Never includes the request URL (it contains the token).
        """
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
        self._throttle()
        response = self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params={**params, "apiToken": self._api_token},
            retries=3,
            status_list_to_retry=[429],
            backoff_factor=1,
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
        """GET /monitor_id/{monitor_id}/incidents (operationId incidentsbytype)."""
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
        """GET /monitor_id/{monitor_id}/incidents/scroll/{scroll_id} (operationId scrollincidents)."""
        return self._get(f"/monitor_id/{monitor_id}/incidents/scroll/{quote(scroll_id, safe='')}", {})


# endregion


# region Commands
def test_module(client: Client, monitor_id: int, incident_types: list[str], params: dict[str, Any]) -> str:
    """Validate credentials and monitor access, plus the fetch settings when fetch is enabled."""
    if params.get("isFetch"):
        parse_incident_types(params.get("incident_types"))
        to_epoch_seconds(params.get("first_fetch") or "3 days", "first_fetch")
        parse_max_fetch(params.get("max_fetch"))
        parse_severities(params.get("fetch_severities"))
    probe_types = incident_types or ["hacking_discussions"]
    forbidden: list[str] = []
    try:
        for probe_type in probe_types:
            try:
                client.incidents_list(monitor_id, probe_type, limit=1)
            except ForbiddenError:
                forbidden.append(probe_type)
    except DemistoException as e:
        if "Authorization" in str(e):
            return "Authorization Error: make sure the API Token is correct and has access to this monitor."
        raise
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
            "Incident Date": epoch_to_iso(inc["incident_date"]) if isinstance(inc.get("incident_date"), int) else None,
            "Title": inc.get("title"),
            "Source": inc.get("source") or inc.get("source_name"),
            "Tags": inc.get("tags"),
        }
        for inc in incidents
    ]


def _list_results(
    data: dict[str, Any], monitor_id: int, incident_type: str | None, mask: bool, title: str
) -> list[CommandResults]:
    incidents = [mask_record(i) if mask else i for i in (data.get("incidents") or [])]
    scroll_id = data.get("scrollId")
    results = [
        CommandResults(
            outputs_prefix=f"{CONTEXT_PREFIX}.Incident",
            outputs_key_field="id",
            outputs=incidents,
            readable_output=tableToMarkdown(f"{title} ({len(incidents)} returned)", _incident_rows(incidents), removeNull=True),
            raw_response=data if not mask else {"incidents": incidents, "scrollId": scroll_id},
        )
    ]
    if scroll_id and incidents:
        results.append(
            CommandResults(
                outputs_prefix=f"{CONTEXT_PREFIX}.Scroll",
                outputs_key_field="scrollId",
                outputs={"scrollId": scroll_id, "monitorId": monitor_id, "incidentType": incident_type},
                readable_output=(
                    f"More incidents may be available. "
                    f"Run `kela-monitor-incident-scroll scroll_id={scroll_id}` to get the next batch. "
                    "The scroll ID is valid for 2 minutes."
                ),
            )
        )
    return results


def incident_list_command(client: Client, args: dict[str, Any], default_monitor_id: int, mask: bool) -> list[CommandResults]:
    """kela-monitor-incident-list -> GET /monitor_id/{id}/incidents."""
    incident_type = args.get("incident_type")
    if incident_type not in INCIDENT_TYPES:
        raise DemistoException(f"'incident_type' is required. Allowed values: {INCIDENT_TYPES}.")
    monitor_id = parse_monitor_id(args.get("monitor_id") or default_monitor_id)
    limit = arg_to_number(args.get("limit"))
    limit = DEFAULT_LIST_LIMIT if limit is None else limit
    if not 1 <= limit <= MAX_LIST_LIMIT:
        raise DemistoException(f"'limit' must be between 1 and {MAX_LIST_LIMIT}.")
    data = client.incidents_list(
        monitor_id,
        incident_type,
        text=args.get("text"),
        limit=limit,
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
    """State of one (monitor, incident type) stream: watermark (epoch seconds), seen IDs and current window.

    seen_ids=None means "last run without ID list" (upgrade path).
    """
    state = (last_run.get("streams") or {}).get(key)
    if state and state.get("watermark") is not None:
        return {
            "watermark": int(state["watermark"]),
            "seen_ids": state.get("seen_ids"),
            "window": int(state.get("window") or WINDOW_MAX_SECONDS),
        }
    return {"watermark": first_fetch_s, "seen_ids": [], "window": WINDOW_MAX_SECONDS}


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

    The API returns the newest incidents first [POSTMAN], so a partial read would hold only the newest part of the
    window. If the call budget runs out the window is reported as truncated and the caller must not use it.
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


def process_window(
    records: list[dict[str, Any]],
    watermark: int,
    seen_ids: list[str],
    legacy: bool,
    max_fetch: int,
    mask: bool,
) -> tuple[int, list[str], list[dict[str, Any]], bool]:
    """Apply watermark + same-second ID de-duplication to a fully read window.

    Why: the API works in whole seconds, so many incidents share the watermark second, and we always re-request from
    just before the watermark (from_date inclusiveness is unverified). XSOAR never de-duplicates fetched incidents, so
    the IDs that share the watermark second are stored and skipped next cycle.
    Returns (new_watermark, ids_at_watermark, xsoar_incidents, cut_by_max_fetch).
    """
    seen_set = set(seen_ids)
    new_watermark = watermark
    ids_at_watermark = list(seen_ids)
    incidents: list[dict[str, Any]] = []
    processed = 0
    cut = False
    valid = [r for r in records if r.get("id") and isinstance(r.get("incident_date"), int)]
    if len(valid) != len(records):
        demisto.debug(f"[Fetch] KELA Monitor: ignored {len(records) - len(valid)} record(s) without id/incident_date.")
    valid.sort(key=lambda r: (r["incident_date"], r["id"]))  # never rely on the API order

    for record in valid:
        date_s, incident_id = record["incident_date"], record["id"]
        if date_s < watermark:
            continue  # already processed in an earlier cycle (we re-request from watermark - 1)
        if date_s == watermark and (legacy or incident_id in seen_set):
            if incident_id not in ids_at_watermark:
                ids_at_watermark.append(incident_id)
            continue
        if processed >= max_fetch:
            cut = True
            break
        processed += 1
        # The watermark advances for EVERY processed record, even those that are skipped below.
        if date_s > new_watermark:
            new_watermark = date_s
            ids_at_watermark = [incident_id]
        elif incident_id not in ids_at_watermark:
            ids_at_watermark.append(incident_id)
        if is_hidden_or_deleted(record):
            continue
        incidents.append(incident_to_xsoar(record, mask))
    return new_watermark, ids_at_watermark, incidents, cut


def fetch_stream(
    client: Client,
    monitor_id: int,
    incident_type: str,
    state: dict[str, Any],
    max_fetch: int,
    severities: list[int],
    mask: bool,
    now_s: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Fetch one (monitor, incident type) stream, walking time windows from the watermark towards now.

    Windows in the past are crossed in the same cycle until max_fetch incidents were collected or the call budget
    (MAX_CALLS_PER_STREAM) is spent.
    If a window holds more incidents than the call budget can read, the window is halved for the next cycle.
    """
    watermark = state["watermark"]
    window = state["window"]
    legacy = state["seen_ids"] is None
    seen_ids: list[str] = [] if legacy else list(state["seen_ids"])
    incidents: list[dict[str, Any]] = []
    calls_left = MAX_CALLS_PER_STREAM
    first_window = True

    while calls_left > 0:
        from_s = max(watermark - 1, 0)  # 1s overlap in case from_date is exclusive; dedup absorbs the repeat
        to_s = min(now_s, watermark + window)
        records, truncated, used = collect_window(client, monitor_id, incident_type, from_s, to_s, severities, calls_left)
        calls_left -= used
        if truncated:
            if first_window and window > WINDOW_MIN_SECONDS:
                window = max(window // 2, WINDOW_MIN_SECONDS)
                demisto.debug(f"[Fetch] KELA Monitor: window too large for {incident_type}, halved to {window}s.")
                break
            if not first_window:
                break  # keep what earlier (empty) windows achieved and retry with a fresh budget next cycle
            demisto.debug(f"[Fetch] KELA Monitor: minimal window still truncated for {incident_type}; processing what was read.")
        first_window = False

        new_watermark, ids_at_watermark, emitted, cut = process_window(
            records, watermark, seen_ids, legacy, max_fetch - len(incidents), mask
        )
        watermark, seen_ids, legacy = new_watermark, ids_at_watermark, False
        incidents.extend(emitted)
        closed_window = to_s < now_s - LATE_MARGIN_SECONDS
        if not cut and closed_window and to_s > watermark:
            watermark, seen_ids = to_s, []  # nothing newer can still appear inside a window that closed long ago
        window = min(window * 2, WINDOW_MAX_SECONDS)
        if cut or len(incidents) >= max_fetch or not closed_window:
            break

    if len(seen_ids) > SEEN_IDS_CAP:
        demisto.debug(f"[Fetch] KELA Monitor: seen_ids capped at {SEEN_IDS_CAP} for {incident_type}.")
        seen_ids = seen_ids[-SEEN_IDS_CAP:]
    return {"watermark": watermark, "seen_ids": seen_ids, "window": window}, incidents


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
            next_state, incidents = fetch_stream(client, monitor_id, incident_type, state, max_fetch, severities, mask, now_s)
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
        incident_types = argToList(params.get("incident_types"))
        mask = argToBoolean(params.get("mask_sensitive_data", True))
        client = Client(
            base_url=params.get("url") or DEFAULT_BASE_URL,
            api_token=api_token,
            verify=not params.get("insecure", False),
            proxy=params.get("proxy", False),
        )
        if command == "test-module":
            return_results(test_module(client, monitor_id, incident_types, params))
        elif command == "fetch-incidents":
            next_run, incidents = fetch_incidents(
                client,
                monitor_id,
                parse_incident_types(params.get("incident_types")),
                demisto.getLastRun(),
                to_epoch_seconds(params.get("first_fetch") or "3 days", "first_fetch"),  # type: ignore[arg-type]
                parse_max_fetch(params.get("max_fetch")),
                parse_severities(params.get("fetch_severities")),
                mask,
                int(time.time()),
            )
            demisto.incidents(incidents)
            demisto.setLastRun(next_run)
        elif command == "kela-monitor-incident-list":
            return_results(incident_list_command(client, args, monitor_id, mask))
        elif command == "kela-monitor-incident-scroll":
            return_results(incident_scroll_command(client, args, monitor_id, mask))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as e:
        demisto.error(mask_secret(traceback.format_exc(), api_token))
        return_error(f"Failed to execute {command} command.\nError:\n{mask_secret(str(e), api_token)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
# endregion
