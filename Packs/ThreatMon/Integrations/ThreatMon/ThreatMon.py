import os
import re
import time
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Any

import demistomock as demisto
from CommonServerPython import *  # noqa: F401

""" CONSTANTS """

INTEGRATION_VERSION = "2.0.0"
USER_AGENT = f"threatmon-xsoar/{INTEGRATION_VERSION}"
DEFAULT_BASE_URL = "https://external.threatmonit.io/api/threatmon/external"
INCIDENT_TYPE = "ThreatMon Alert"
INCIDENT_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
PAGE_SIZE = 10  # Fixed by the ThreatMon API.
CVE_PAGE_SIZE = 100

DEFAULT_FIRST_FETCH = "3 days"
DEFAULT_MAX_FETCH = 50
MAX_FETCH_LIMIT = 200
DEFAULT_LOOKBACK_MINUTES = 30
FETCH_PAGE_BUDGET = 50  # Pages read per fetch run (500 alarms) before the run stops and resumes next time.
MIRROR_PAGE_BUDGET = 30  # Pages read per mirroring cycle.
FETCH_RUN_SECONDS = 4 * 60  # Stay well within the fetch timeout.
CREATED_RETENTION_DAYS = 400
MIRROR_CACHE_HOURS = 24
ECHO_GUARD_SECONDS = 120

RATE_LIMIT_CALLS = 10  # ThreatMon allows 10 requests per 10 seconds.
RATE_LIMIT_WINDOW = 10.0
RETRY_STATUSES = {429, 500, 502, 503, 504}
MAX_RETRIES = 4
REQUEST_TIMEOUT = 60.0
ECHO_SKEW_SECONDS = 30  # Allowed clock difference between Cortex and ThreatMon for the echo guard.
ECHO_GUARD_SECONDS = 600  # Longer than the change index lag (1-6 minutes). After it, the alarm is mirrored again.
MIRROR_SAVE_ATTEMPTS = 5

STATUSES = ["Open", "In Progress", "Resolved", "Ignore"]
CLOSED_STATUSES = {"resolved", "ignore"}
SEVERITY_NAMES = ["Information", "Low", "Medium", "High", "Critical"]
SEVERITY_RANK = {"information": 0, "info": 0, "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
XSOAR_SEVERITY = {
    0: IncidentSeverity.INFO,
    1: IncidentSeverity.LOW,
    2: IncidentSeverity.MEDIUM,
    3: IncidentSeverity.HIGH,
    4: IncidentSeverity.CRITICAL,
}
MIRROR_DIRECTION_MAPPING = {"None": None, "Incoming": "In", "Outgoing": "Out", "Incoming And Outgoing": "Both"}
# Cortex close reasons that mean the alarm was not a real threat. Every other close reason maps to Resolved.
IGNORE_CLOSE_REASONS = {"false positive", "duplicate"}

SECRET_KEY_RE = re.compile(r"pass(word|wd)?|pwd|secret|token|cookie|session|api_?key", re.IGNORECASE)
FRACTION_RE = re.compile(r"\.(\d+)")
MIRRORED_FIELDS = ["status", "severity", "title", "lastUpdateDate"]

ACTION_RESULTS = {
    200: ("Submitted", True, "The request was submitted to ThreatMon."),
    400: ("Not Eligible", False, "This finding is not eligible for the request."),
    403: (
        "Not Allowed",
        False,
        "The request quota is exceeded, or the request type is not included in the ThreatMon subscription.",
    ),
    404: ("Not Found", False, "The finding was not found in ThreatMon."),
    409: ("Already Requested", True, "A request for this finding was already submitted."),
}

""" HELPERS """


def normalize_base_url(url: str | None) -> str:
    """Returns the External API base URL without a trailing slash or a /v1 suffix."""
    url = (url or DEFAULT_BASE_URL).strip().rstrip("/")
    if url.endswith("/v1"):
        url = url[: -len("/v1")]
    return url


def parse_api_date(value: Any) -> datetime | None:
    """Parses a ThreatMon date. The API returns 1 to 6 fraction digits and sometimes omits the time zone."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    text = FRACTION_RE.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), text, count=1)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def format_api_date(value: datetime) -> str:
    """Formats a date the way the lastUpdateStartDate parameter expects it."""
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def now_utc() -> datetime:
    return datetime.now(UTC)


def severity_rank(value: Any) -> int:
    return SEVERITY_RANK.get(str(value or "").strip().lower(), 0)


def status_key(value: Any) -> str:
    """Compares statuses letters-only and case-insensitively, so 'InProgress' equals 'In Progress'."""
    return re.sub(r"[^a-z]", "", str(value or "").lower())


def canonical_status(value: Any) -> str | None:
    key = status_key(value)
    for status in STATUSES:
        if status_key(status) == key:
            return status
    return None


def to_int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def mask_value(value: Any) -> Any:
    if not isinstance(value, str) or not value:
        return value
    return value[:2] + "******"


def mask_secrets(data: Any) -> Any:
    """Masks the values of secret-looking keys (passwords, tokens, cookies) in alarm items and details."""
    if isinstance(data, list):
        return [mask_secrets(item) for item in data]
    if isinstance(data, dict):
        if "key" in data and "value" in data and SECRET_KEY_RE.search(str(data.get("key"))):
            return {**data, "value": mask_value(data.get("value"))}
        return {
            key: mask_value(value)
            if SECRET_KEY_RE.search(str(key)) and not isinstance(value, dict | list)
            else mask_secrets(value)
            for key, value in data.items()
        }
    return data


def normalize_list(value: Any) -> list:
    """Returns a list for the items or details field, which some feeds return as a JSON string or a single object."""
    if value is None or value == "":
        return []
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return [value]
    if isinstance(value, dict):
        return [value]
    return value if isinstance(value, list) else [value]


def get_findings(alarm: dict[str, Any]) -> list[dict[str, Any]]:
    """Returns the findings of an alarm: one dict per finding, with its findingId when ThreatMon publishes one."""
    findings = [row for row in normalize_list(alarm.get("details")) if isinstance(row, dict)]
    if findings:
        return findings
    groups = []
    for group in normalize_list(alarm.get("items")):
        pairs = group if isinstance(group, list) else [group]
        row = {str(p.get("key")): p.get("value") for p in pairs if isinstance(p, dict) and "key" in p}
        if row:
            groups.append(row)
    return groups


def findings_markdown(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return ""
    headers: list[str] = ["findingId"] if any("findingId" in f for f in findings) else []
    for finding in findings:
        headers.extend(key for key in finding if key not in headers)
    return tableToMarkdown("Findings", findings, headers=headers, removeNull=True)


def alarm_summary(alarm: dict[str, Any]) -> dict[str, Any]:
    """Returns the context output of an alarm."""
    findings = get_findings(alarm)
    return {
        "AlarmCode": to_int(alarm.get("alarmCode")),
        "Title": alarm.get("title"),
        "AlarmType": alarm.get("alarmType"),
        "Category": alarm.get("category"),
        "SubCategory": alarm.get("subCategory"),
        "Severity": alarm.get("severity"),
        "Status": alarm.get("status"),
        "Source": alarm.get("source"),
        "AlarmDate": alarm.get("alarmDate"),
        "LastUpdateDate": alarm.get("lastUpdateDate"),
        "Description": alarm.get("description"),
        "Mitigation": alarm.get("mitigation"),
        "Findings": findings,
        "FindingIDs": [f["findingId"] for f in findings if f.get("findingId") is not None],
    }


def alarm_position(alarm: dict[str, Any]) -> tuple[datetime, int] | None:
    """Returns the (lastUpdateDate, alarmCode) keyset position of an alarm, or None if it has no position."""
    code = to_int(alarm.get("alarmCode"))
    updated = parse_api_date(alarm.get("lastUpdateDate"))
    if code is None or updated is None:
        return None
    return updated, code


def position_to_state(position: tuple[datetime, int]) -> dict[str, Any]:
    return {"updated": format_api_date(position[0]), "code": position[1]}


def position_from_state(state: dict[str, Any] | None) -> tuple[datetime, int] | None:
    if not isinstance(state, dict):
        return None
    updated = parse_api_date(state.get("updated"))
    code = to_int(state.get("code"))
    if updated is None or code is None:
        return None
    return updated, code


def day_number(moment: datetime) -> int:
    return int(moment.timestamp() // 86400)


class RateLimiter:
    """A sliding-window limiter, so one command never exceeds the ThreatMon rate limit."""

    def __init__(self, calls: int = RATE_LIMIT_CALLS, window: float = RATE_LIMIT_WINDOW):
        self.calls = calls
        self.window = window
        self.history: deque[float] = deque()

    def wait(self) -> None:
        current = time.monotonic()
        while self.history and current - self.history[0] >= self.window:
            self.history.popleft()
        if len(self.history) >= self.calls:
            time.sleep(max(0.0, self.window - (current - self.history[0])))  # pylint: disable=E9003
            self.history.popleft()
        self.history.append(time.monotonic())


""" CLIENT """


class Client(BaseClient):
    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool, customer_name: str | None = None):
        super().__init__(
            base_url=normalize_base_url(base_url),
            verify=verify,
            proxy=proxy,
            headers={"X-COMPANY-API-KEY": api_key, "accept": "application/json", "User-Agent": USER_AGENT},
        )
        self.customer_name = (customer_name or "").strip() or None
        self.limiter = RateLimiter()
        self.deadline: float | None = None  # When set, retries and timeouts stay within this time.

    def request(
        self,
        method: str,
        url_suffix: str,
        params: dict[str, Any] | None = None,
        json_data: Any = None,
        with_customer: bool = True,
        retry: bool = True,
        files: Any = None,
        auth_retry: bool = True,
    ) -> requests.Response:
        """Sends a request and returns the response.

        Only idempotent methods are retried. Takedown and data removal requests (POST) are never retried,
        so a request that may already have reached ThreatMon is not submitted twice.
        """
        params = {k: v for k, v in (params or {}).items() if v not in (None, "")}
        if with_customer and self.customer_name:
            params["customerName"] = self.customer_name
        attempts = MAX_RETRIES + 1 if retry else 1
        auth_retried = False
        delay = 2
        attempt = 0

        def can_retry(wait: float) -> bool:
            # A fetch run must end before Cortex stops it, so no retry starts after the run deadline.
            return attempt < attempts and (not self.deadline or time.time() + wait < self.deadline)

        while True:
            attempt += 1
            self.limiter.wait()
            timeout = REQUEST_TIMEOUT
            if self.deadline:
                timeout = max(5.0, min(REQUEST_TIMEOUT, self.deadline - time.time()))
            try:
                response = self._http_request(
                    method,
                    url_suffix=url_suffix,
                    params=params,
                    json_data=json_data,
                    files=files,
                    resp_type="response",
                    ok_codes=tuple(range(200, 600)),
                    timeout=timeout,
                )
            except DemistoException as error:
                if is_connection_error(error) and can_retry(delay):
                    demisto.debug(f"ThreatMon request failed ({error}), retrying in {delay} s.")
                    time.sleep(delay)  # pylint: disable=E9003
                    delay *= 2
                    continue
                raise
            permanent = response.status_code == 500 and "not whitelisted" in (response.text or "").lower()
            if response.status_code in RETRY_STATUSES and not permanent and can_retry(delay):
                demisto.debug(f"ThreatMon returned {response.status_code}, retrying in {delay} s.")
                time.sleep(delay)  # pylint: disable=E9003
                delay *= 2
                continue
            if (
                response.status_code == 403
                and retry
                and auth_retry
                and not auth_retried
                and not response.text.strip()
                and can_retry(5)
            ):
                # ThreatMon occasionally rejects a valid key once. Retry a single time before reporting it.
                auth_retried = True
                time.sleep(5)  # pylint: disable=E9003
                continue
            return response

    def get_json(
        self, url_suffix: str, params: dict[str, Any] | None = None, with_customer: bool = True, retry: bool = True
    ) -> Any:
        response = self.request("GET", url_suffix, params=params, with_customer=with_customer, retry=retry)
        if response.status_code != 200:
            raise_api_error(response, self.customer_name)
        return parse_json(response)

    def get_alarms(
        self,
        page: int = 0,
        updated_after: str | None = None,
        after_alarm_code: int | None = None,
        severities: list[str] | None = None,
        category: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> dict[str, Any]:
        params = {
            "lastUpdateStartDate": updated_after,
            "afterAlarmCode": after_alarm_code,
            "severities": ",".join(severities) if severities else None,
            "category": category,
            "startDate": start_date,
            "endDate": end_date,
        }
        return self.get_json(f"/v1/vulnerabilities/{page}", params=params) or {}

    def get_changed_alarms(self, position: tuple[datetime, int], severities: list[str] | None = None) -> list[dict]:
        """Returns the next page of alarms changed after the (lastUpdateDate, alarmCode) position."""
        response = self.get_alarms(
            updated_after=format_api_date(position[0]), after_alarm_code=position[1], severities=severities
        )
        return [alarm for alarm in response.get("data") or [] if isinstance(alarm, dict)]

    def update_status(
        self,
        alarm_ids: list[int],
        status: str,
        remarks: str | None = None,
        assigned_email: str | None = None,
        info_emails: list[str] | None = None,
    ) -> None:
        body: dict[str, Any] = {"alarmIds": alarm_ids, "status": status}
        if remarks:
            body["remarks"] = remarks[:2000]
        if assigned_email:
            body["assignedEmail"] = assigned_email
        if info_emails:
            body["infoEmailList"] = info_emails
        response = self.request("PATCH", "/v1/incident/status", json_data=body)
        if response.status_code != 200:
            raise_api_error(response, self.customer_name)

    def submit_action(self, url_suffix: str, finding_id: int, finding: str) -> requests.Response:
        return self.request("POST", url_suffix, json_data={"findingId": finding_id, "finding": finding}, retry=False)

    def get_stats(self, kind: str, from_date: str | None = None, to_date: str | None = None) -> dict[str, Any]:
        return self.get_json(f"/v1/alarm/{kind}", params={"fromDate": from_date, "toDate": to_date}) or {}

    def get_cve_detail(self, cve_id: str, include: str | None = None) -> dict[str, Any] | None:
        """Returns a Vulnerability Knowledge CVE, or None when ThreatMon does not know it."""
        response = self.request("GET", f"/v1/cve/detail/{cve_id}", params={"include": include})
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise_api_error(response, self.customer_name)
        detail = parse_json(response)
        return detail if isinstance(detail, dict) else None

    def get_screenshot(self, blob_name: str) -> bytes | None:
        """Returns the image of a finding's screenshot, or None when ThreatMon does not have it."""
        # Some screenshots return HTTP 403 for a valid key. They are reported as not available, without a retry.
        response = self.request("GET", "/v1/screenshot", params={"blobName": blob_name}, auth_retry=False)
        if response.status_code in (403, 404):
            return None
        if response.status_code != 200:
            raise_api_error(response, self.customer_name)
        return response.content

    def get_cve_list(self, page: int = 0, cvss: str | None = None) -> dict[str, Any]:
        return self.get_json(f"/v1/cve/{page}", params={"cvss": cvss}, with_customer=False) or {}

    def get_subscribed_cve_list(self, page: int = 0, cvss: str | None = None, customer_name: str | None = None) -> dict:
        params = {"cvss": cvss, "customerName": customer_name}
        return self.get_json(f"/v1/cve/subscribed/{page}", params=params, with_customer=not customer_name) or {}


def parse_json(response: requests.Response) -> Any:
    if not (response.text or "").strip():
        return None
    try:
        return response.json()
    except ValueError as error:
        raise DemistoException(f"ThreatMon returned an invalid JSON response: {response.text[:200]}") from error


def is_connection_error(error: DemistoException) -> bool:
    text = str(error).lower()
    return any(word in text for word in ("connection", "timeout", "timed out", "max retries", "proxy"))


def raise_api_error(response: requests.Response, customer_name: str | None = None) -> None:
    """Raises an error that names the cause and what the customer can do about it."""
    code = response.status_code
    body = (response.text or "").strip()
    if code == 403 and "<html" in body.lower():
        message = (
            "ThreatMon rejected the request because this server's public IP address is not whitelisted. "
            "Send the public IP address of the Cortex engine or server to support@threatmonit.io."
        )
    elif code == 403 and "1010" in body:
        message = (
            "The request was blocked by the ThreatMon firewall (error code 1010). If a proxy is used, make sure it "
            "does not change the request headers, or contact support@threatmonit.io."
        )
    elif code in (401, 403):
        message = (
            "ThreatMon rejected the API key. Check the External API Key in ThreatMon under Settings > Integrations > Settings."
        )
        if customer_name:
            message += f" Also check that '{customer_name}' is the exact name of a sub company of this account."
    elif code == 429:
        message = "The ThreatMon rate limit was exceeded. Try again in a minute."
    elif "not whitelisted" in body.lower():
        message = (
            "ThreatMon did not allow this request for the API key (API key is not whitelisted). MSSP customer "
            "management works only with the External API Key of the MSSP administrator account. For other features, "
            "ask support@threatmonit.io to enable the feature for the key."
        )
    else:
        message = f"ThreatMon API error {code}"
        if body:
            message += f": {body[:300]}"
    raise DemistoException(message, res=response)


""" FETCH """


def get_lookback_minutes(params: dict[str, Any]) -> int:
    """Returns the Look-back Window (minutes) parameter. Fetch and mirroring use the same value, including 0."""
    lookback = arg_to_number(params.get("lookback_minutes"))
    lookback = DEFAULT_LOOKBACK_MINUTES if lookback is None else lookback
    if not 0 <= lookback <= 1440:
        raise DemistoException("Look-back Window (minutes) must be between 0 and 1440.")
    return lookback


def get_fetch_statuses(params: dict[str, Any]) -> list[str]:
    """Returns the Alarm Statuses to Fetch parameter. An unknown status is an error, so the fetch never stops silently."""
    values = [v for v in argToList(params.get("fetch_statuses")) if str(v).strip()]
    unknown = [v for v in values if canonical_status(v) is None]
    if unknown:
        raise DemistoException(
            f"Alarm Statuses to Fetch contains unknown values: {', '.join(unknown)}. Use {', '.join(STATUSES)}."
        )
    return [canonical_status(v) for v in values] or ["Open", "In Progress"]  # type: ignore[misc]


def get_fetch_settings(params: dict[str, Any]) -> dict[str, Any]:
    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH
    if not 1 <= max_fetch <= MAX_FETCH_LIMIT:
        raise DemistoException(f"Maximum number of incidents per fetch must be between 1 and {MAX_FETCH_LIMIT}.")
    lookback = get_lookback_minutes(params)
    first_fetch = arg_to_datetime(params.get("first_fetch") or DEFAULT_FIRST_FETCH, arg_name="First Fetch Time")
    if first_fetch is None:
        raise DemistoException("Invalid First Fetch Time parameter.")
    min_rank = severity_rank(params.get("min_severity") or "Information")
    statuses = get_fetch_statuses(params)
    return {
        "max_fetch": max_fetch,
        "lookback": timedelta(minutes=lookback),
        "first_fetch": first_fetch.astimezone(UTC) if first_fetch.tzinfo else first_fetch.replace(tzinfo=UTC),
        "min_rank": min_rank,
        "severities": SEVERITY_NAMES[min_rank:] if min_rank else None,
        "statuses": {status_key(s) for s in statuses if s},
        "categories": {c.strip().lower() for c in argToList(params.get("categories")) if c.strip()},
        "floor": to_int(params.get("lastIncidentId")) or 0,
        "mask": argToBoolean(params.get("mask_secrets", True)),
        "mirror_direction": MIRROR_DIRECTION_MAPPING.get(params.get("mirror_direction") or "None"),
        "screenshots": argToBoolean(params.get("attach_screenshots", True)),
    }


def initial_fetch_state(last_run: dict[str, Any], settings: dict[str, Any], current: datetime) -> dict[str, Any]:
    """Builds the fetch state on the first run, or migrates the state of version 1.x."""
    floor = settings["floor"]
    if "last_incident_id" in last_run:
        # Version 1.x read alarms by code only. Every alarm up to the highest code it saw was already handled,
        # so it becomes the floor. Newer alarms are read from the first fetch time, so alarms that 1.x had not
        # reached yet (a backlog, or a fetch that failed before the upgrade) are not lost.
        floor = max(floor, to_int(last_run.get("last_incident_id")) or 0, to_int(last_run.get("max_seen_id")) or 0)
    start = min(settings["first_fetch"], current)
    return {"version": 2, "cursor": position_to_state((start, 0)), "resume": None, "floor": floor, "created": {}}


def load_created(value: Any) -> dict[str, int]:
    """Returns {alarm code: day last seen} from the compact {day: [codes]} form kept in the fetch state."""
    created: dict[str, int] = {}
    if isinstance(value, dict):
        for day, codes in value.items():
            if isinstance(codes, list):
                for code in codes:
                    created[str(code)] = max(created.get(str(code), 0), to_int(day) or 0)
            elif to_int(codes) is not None:  # A plain {code: day} map.
                created[str(day)] = to_int(codes) or 0
    return created


def dump_created(created: dict[str, int], today: int) -> dict[str, list[int]]:
    buckets: dict[str, list[int]] = {}
    for code, day in created.items():
        if today - day <= CREATED_RETENTION_DAYS and to_int(code) is not None:
            buckets.setdefault(str(day), []).append(to_int(code) or 0)
    return {day: sorted(codes) for day, codes in sorted(buckets.items())}


def should_create(alarm: dict[str, Any], code: int, state: dict[str, Any], settings: dict[str, Any]) -> bool:
    if code <= state["floor"] or str(code) in state["created"]:
        return False
    if status_key(alarm.get("status")) not in settings["statuses"]:
        return False
    if severity_rank(alarm.get("severity")) < settings["min_rank"]:
        return False
    return not (settings["categories"] and str(alarm.get("category") or "").strip().lower() not in settings["categories"])


def build_incident(alarm: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
    raw = mask_secrets(alarm) if settings["mask"] else dict(alarm)
    code = to_int(alarm.get("alarmCode"))
    findings = get_findings(raw)
    raw["alarmCode"] = code
    raw["status"] = canonical_status(alarm.get("status")) or alarm.get("status")
    raw["findings"] = findings_markdown(findings)
    raw["findingIds"] = [str(f["findingId"]) for f in findings if f.get("findingId") is not None]
    raw["mirror_id"] = str(code)
    raw["mirror_direction"] = settings["mirror_direction"]
    raw["mirror_instance"] = demisto.integrationInstance()
    occurred = parse_api_date(alarm.get("alarmDate")) or parse_api_date(alarm.get("lastUpdateDate")) or now_utc()
    return {
        "name": f"ThreatMon #{code}: {alarm.get('title') or 'Alarm'}",
        "occurred": occurred.strftime(INCIDENT_DATE_FORMAT),
        "details": alarm.get("description") or "",
        "severity": XSOAR_SEVERITY[severity_rank(alarm.get("severity"))],
        "mirror_direction": settings["mirror_direction"],
        "mirror_instance": demisto.integrationInstance(),
        "rawJSON": json.dumps(raw),
        "labels": [{"type": "Status", "value": str(alarm.get("status") or "")}],
    }


def fetch_incidents(
    client: Client, params: dict[str, Any], last_run: dict[str, Any], deadline: float | None = None
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fetches new alarms with the (lastUpdateDate, alarmCode) change cursor.

    The change cursor also returns alarms that were approved late with an older alarm code, which a cursor by
    code alone misses. Each run re-reads a look-back window, because ThreatMon indexes changes with a delay of a
    few minutes; alarms that were already created are skipped. When a run stops early (incident limit, page
    budget or time), the next run resumes from the exact position, without the look-back.
    """
    settings = get_fetch_settings(params)
    current = now_utc()
    state = dict(last_run) if last_run.get("version") == 2 else initial_fetch_state(last_run, settings, current)
    state["created"] = load_created(state.get("created"))
    deadline = deadline or time.time() + FETCH_RUN_SECONDS
    client.deadline = deadline

    cursor = position_from_state(state.get("cursor")) or (current - settings["lookback"], 0)
    resume = position_from_state(state.get("resume"))
    position = resume or (cursor[0] - settings["lookback"], 0)
    today = day_number(current)
    incidents: list[dict[str, Any]] = []
    pages = 0
    stopped_early = False

    while True:
        if pages >= FETCH_PAGE_BUDGET or time.time() >= deadline:
            stopped_early = True
            break
        alarms = client.get_changed_alarms(position, severities=settings["severities"])
        pages += 1
        moved = False
        for alarm in alarms:
            alarm_pos = alarm_position(alarm)
            if alarm_pos is None or alarm_pos <= position:
                continue
            if settings["screenshots"] and incidents and time.time() >= deadline:
                stopped_early = True  # The next run continues with this alarm and its screenshots.
                break
            position = alarm_pos
            moved = True
            cursor = max(cursor, alarm_pos)
            code = alarm_pos[1]
            if str(code) in state["created"]:
                state["created"][str(code)] = today
            elif should_create(alarm, code, state, settings):
                incident = build_incident(alarm, settings)
                if settings["screenshots"]:
                    attachments = screenshot_attachments(client, alarm, deadline)
                    if attachments:
                        incident["attachment"] = attachments
                incidents.append(incident)
                state["created"][str(code)] = today
                if len(incidents) >= settings["max_fetch"]:
                    stopped_early = True
                    break
        if stopped_early or len(alarms) < PAGE_SIZE or not moved:
            break

    state["cursor"] = position_to_state(cursor)
    state["resume"] = position_to_state(position) if stopped_early else None
    state["created"] = dump_created(state["created"], today)
    demisto.debug(f"ThreatMon fetch: {len(incidents)} incidents, {pages} pages, resume={state['resume']}")
    return incidents, state


""" MIRRORING """


def normalize_mirror_state(context: Any) -> dict[str, Any]:
    state = context.get("mirror") if isinstance(context, dict) else None
    state = dict(state) if isinstance(state, dict) else {}
    for key in ("alarms", "delivered", "set"):
        state[key] = dict(state.get(key) or {})
    return state


def load_mirror_state() -> dict[str, Any]:
    context, _ = get_integration_context_with_version()
    return normalize_mirror_state(context)


def update_mirror_state(apply: Any) -> dict[str, Any]:
    """Applies this command's changes to the latest mirroring state and saves it.

    Mirroring commands run in separate processes. Each one re-reads the latest state and applies only its own
    changes, so a save never brings back older values written by another command. A version conflict is retried.
    """
    for attempt in range(1, MIRROR_SAVE_ATTEMPTS + 1):
        context, version = get_integration_context_with_version()
        context = dict(context) if isinstance(context, dict) else {}
        state = normalize_mirror_state(context)
        apply(state)
        context["mirror"] = state
        try:
            set_integration_context(context, version=version)
            return state
        except ValueError as error:
            if attempt == MIRROR_SAVE_ATTEMPTS:
                raise DemistoException(f"Could not save the ThreatMon mirroring state: {error}") from error
            time.sleep(0.05 * attempt)  # pylint: disable=E9003
    return {}  # pragma: no cover


def newer_alarm(cached: dict[str, Any] | None, alarm: dict[str, Any]) -> bool:
    if not cached:
        return True
    old = parse_api_date(cached.get("lastUpdateDate"))
    new = parse_api_date(alarm.get("lastUpdateDate"))
    return old is None or (new is not None and new >= old)


def prune_mirror_state(state: dict[str, Any], current: datetime, keep_since: datetime | None = None) -> None:
    cache_limit = current - timedelta(hours=MIRROR_CACHE_HOURS)
    if keep_since:
        cache_limit = min(cache_limit, keep_since)  # Keep every change that Cortex has not asked for yet.
    state["alarms"] = {
        code: alarm
        for code, alarm in state["alarms"].items()
        if (parse_api_date(alarm.get("lastUpdateDate")) or current) >= cache_limit
    }
    echo_limit = current.timestamp() - 3600
    state["set"] = {code: entry for code, entry in state["set"].items() if entry.get("at", 0) >= echo_limit}
    today = day_number(current)
    state["delivered"] = {
        code: entry for code, entry in state["delivered"].items() if today - entry.get("day", today) <= CREATED_RETENTION_DAYS
    }


def get_modified_remote_data_command(
    client: Client, args: dict[str, Any], params: dict[str, Any]
) -> GetModifiedRemoteDataResponse:
    """Reads the alarms that changed since the last mirroring cycle and caches them for get-remote-data.

    ThreatMon has no endpoint that returns a single alarm, so this command reads the change feed once per cycle
    and get-remote-data answers from the cache.
    """
    remote_args = GetModifiedRemoteDataArgs(args)
    current = now_utc()
    lookback = timedelta(minutes=get_lookback_minutes(params))
    last_update = arg_to_datetime(remote_args.last_update) or current - lookback
    last_update = last_update.astimezone(UTC) if last_update.tzinfo else last_update.replace(tzinfo=UTC)

    state = load_mirror_state()
    resume = position_from_state(state.get("resume"))
    cursor = position_from_state(state.get("cursor"))
    start = min(cursor[0], last_update) if cursor else last_update
    position = resume or (start - lookback, 0)
    # The cursor only moves forward: without any change it stays at the last update time.
    newest = cursor or (last_update, 0)
    seen: dict[str, dict[str, Any]] = {}
    pages = 0
    stopped_early = False
    while True:
        if pages >= MIRROR_PAGE_BUDGET:
            stopped_early = True
            break
        alarms = client.get_changed_alarms(position)
        pages += 1
        moved = False
        for alarm in alarms:
            alarm_pos = alarm_position(alarm)
            if alarm_pos is None or alarm_pos <= position:
                continue
            position = alarm_pos
            moved = True
            newest = max(newest, alarm_pos)
            entry = {key: alarm.get(key) for key in MIRRORED_FIELDS}
            entry["status"] = canonical_status(entry.get("status")) or entry.get("status")
            if newer_alarm(seen.get(str(alarm_pos[1])), entry):
                seen[str(alarm_pos[1])] = entry
        if len(alarms) < PAGE_SIZE or not moved:
            break

    changed: set[str] = set()
    released: set[str] = set()

    def apply(latest: dict[str, Any]) -> None:
        changed.clear()
        released.clear()
        # When the echo guard of an own change ends, report the alarm again, so a change that a ThreatMon user
        # made right after the integration's change is mirrored even if it is outside the modified window.
        for code, entry in list(latest["set"].items()):
            if current.timestamp() >= entry.get("at", 0) + ECHO_GUARD_SECONDS:
                if code in latest["alarms"]:
                    released.add(code)
                del latest["set"][code]
        for code, entry in seen.items():
            cached = latest["alarms"].get(code)
            # An older version of the alarm from the lagging change index never replaces a newer one.
            if newer_alarm(cached, entry):
                if not cached or cached.get("lastUpdateDate") != entry.get("lastUpdateDate"):
                    changed.add(code)
                latest["alarms"][code] = entry
        latest_cursor = position_from_state(latest.get("cursor"))
        latest["cursor"] = position_to_state(max(newest, latest_cursor) if latest_cursor else newest)
        latest["resume"] = position_to_state(position) if stopped_early else None
        prune_mirror_state(latest, current, keep_since=last_update - lookback)

    state = update_mirror_state(apply)
    since = last_update - lookback
    modified = sorted(
        changed
        | released
        | {code for code, alarm in state["alarms"].items() if (parse_api_date(alarm.get("lastUpdateDate")) or current) >= since},
        key=lambda code: to_int(code) or 0,
    )
    demisto.debug(f"ThreatMon mirroring: {len(modified)} modified alarms, {pages} pages.")
    return GetModifiedRemoteDataResponse(modified)


def get_remote_data_command(args: dict[str, Any], params: dict[str, Any]) -> GetRemoteDataResponse:
    """Returns the latest status of a mirrored alarm, and closes or reopens the incident when configured."""
    remote_args = GetRemoteDataArgs(args)
    code = str(remote_args.remote_incident_id)
    state = load_mirror_state()
    alarm = state["alarms"].get(code)
    if not alarm:
        return GetRemoteDataResponse({}, [])

    status = canonical_status(alarm.get("status")) or str(alarm.get("status") or "")
    updated = parse_api_date(alarm.get("lastUpdateDate"))
    own_change = state["set"].get(code)
    if (
        own_change
        and updated
        and status_key(status) != status_key(own_change.get("status"))
        and updated.timestamp() <= own_change.get("at", 0) + ECHO_SKEW_SECONDS
        and now_utc().timestamp() < own_change.get("at", 0) + ECHO_GUARD_SECONDS
    ):
        # The lagging change index still returns the alarm from before this integration changed its status.
        return GetRemoteDataResponse({}, [])

    mirrored = {"alarmCode": to_int(code), **alarm, "status": status, "id": code}
    entries: list[dict[str, Any]] = []
    previous = state["delivered"].get(code, {}).get("status")
    if previous != status:
        set_by_us = bool(own_change) and status_key(own_change.get("status")) == status_key(status)
        if previous and not set_by_us:
            entries.append(
                {
                    "Type": EntryType.NOTE,
                    "Contents": f"The ThreatMon status of alarm {code} changed from {previous} to {status}.",
                    "ContentsFormat": EntryFormat.MARKDOWN,
                    "Note": True,
                }
            )
        if argToBoolean(params.get("close_incident", False)) and not set_by_us:
            if status_key(status) in CLOSED_STATUSES:
                entries.append(
                    {
                        "Type": EntryType.NOTE,
                        "Contents": {
                            "dbotIncidentClose": True,
                            "closeReason": "Resolved" if status_key(status) == "resolved" else "Other",
                            "closeNotes": f"The alarm was set to {status} in ThreatMon.",
                        },
                        "ContentsFormat": EntryFormat.JSON,
                    }
                )
            elif previous and status_key(previous) in CLOSED_STATUSES:
                entries.append(
                    {"Type": EntryType.NOTE, "Contents": {"dbotIncidentReopen": True}, "ContentsFormat": EntryFormat.JSON}
                )
        delivered = {"status": status, "day": day_number(now_utc())}
        update_mirror_state(lambda latest: latest["delivered"].__setitem__(code, delivered))
    return GetRemoteDataResponse(mirrored, entries)


def update_remote_system_command(client: Client, args: dict[str, Any], params: dict[str, Any]) -> str:
    """Sets the ThreatMon status of an alarm when the mirrored Cortex incident changes or is closed."""
    parsed = UpdateRemoteSystemArgs(args)
    code = parsed.remote_incident_id
    alarm_id = to_int(code)
    if not parsed.incident_changed or alarm_id is None:
        return code
    delta = parsed.delta or {}
    data = parsed.data or {}
    known = load_mirror_state()["delivered"].get(str(alarm_id), {}).get("status")
    target = canonical_status(delta.get("status"))
    remarks = None
    if parsed.inc_status == IncidentStatus.DONE and argToBoolean(params.get("close_out", False)):
        if status_key(known) in CLOSED_STATUSES:
            # The alarm is already Resolved or Ignore in ThreatMon, for example because the incident was closed by
            # incoming mirroring. Do not overwrite the status the ThreatMon analyst chose.
            return code
        reason = str(data.get("closeReason") or delta.get("closeReason") or "")
        target = "Ignore" if reason.strip().lower() in IGNORE_CLOSE_REASONS else "Resolved"
        notes = data.get("closeNotes") or delta.get("closeNotes") or ""
        remarks = f"Closed in Cortex. Reason: {reason or 'not set'}. {notes}".strip()
    if not target:
        return code
    if status_key(known) == status_key(target):
        return code  # ThreatMon already has this status, for example because it came in through incoming mirroring.
    try:
        client.update_status([alarm_id], target, remarks or f"Set to {target} in Cortex.")
    except Exception as error:
        demisto.error(f"ThreatMon outgoing mirroring failed for alarm {code}: {error}")
        raise
    changed_at = now_utc()

    def apply(latest: dict[str, Any]) -> None:
        latest["set"][str(alarm_id)] = {"status": target, "at": changed_at.timestamp()}
        latest["delivered"][str(alarm_id)] = {"status": target, "day": day_number(changed_at)}

    update_mirror_state(apply)
    return code


def get_mapping_fields_command() -> GetMappingFieldsResponse:
    scheme = SchemeTypeMapping(type_name=INCIDENT_TYPE)
    scheme.add_field("status", "The ThreatMon status of the alarm: Open, In Progress, Resolved or Ignore.")
    response = GetMappingFieldsResponse()
    response.add_scheme_type(scheme)
    return response


""" COMMANDS """


def test_module(client: Client, params: dict[str, Any]) -> str:
    client.get_stats("status")
    if argToBoolean(params.get("isFetch", False)):
        get_fetch_settings(params)
    return "ok"


def list_alarms_command(client: Client, args: dict[str, Any]) -> CommandResults:
    limit = arg_to_number(args.get("limit")) or PAGE_SIZE
    if not 1 <= limit <= 100:
        raise DemistoException("The limit argument must be between 1 and 100.")
    page = arg_to_number(args.get("page")) or 0
    severities = [s for s in argToList(args.get("severity")) if s]
    updated_after = arg_to_datetime(args.get("updated_after"))
    start = arg_to_datetime(args.get("start_date"))
    end = arg_to_datetime(args.get("end_date"))
    statuses = {status_key(s) for s in argToList(args.get("status"))}

    # The requested page holds the alarms at offset page * limit. ThreatMon pages always hold 10 alarms, so read
    # the ThreatMon pages that cover that range and cut it out. The status filter applies to this range only.
    offset = page * limit
    api_page, skip = divmod(offset, PAGE_SIZE)
    rows: list[dict[str, Any]] = []
    total = 0
    while len(rows) < skip + limit:
        response = client.get_alarms(
            page=api_page,
            updated_after=format_api_date(updated_after) if updated_after else None,
            severities=severities or None,
            category=args.get("category"),
            start_date=format_api_date(start) if start else None,
            end_date=format_api_date(end) if end else None,
        )
        total = response.get("totalRecords") or 0
        data = response.get("data") or []
        rows.extend(data)
        api_page += 1
        if len(data) < PAGE_SIZE:
            break
    alarms = [a for a in rows[skip : skip + limit] if not statuses or status_key(a.get("status")) in statuses]
    outputs = [alarm_summary(mask_secrets(alarm)) for alarm in alarms]
    readable = tableToMarkdown(
        f"ThreatMon Alarms (Total Records: {total})",
        outputs,
        headers=["AlarmCode", "Title", "Severity", "Status", "Category", "AlarmDate", "LastUpdateDate", "FindingIDs"],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix="ThreatMon.Alarm",
        outputs_key_field="AlarmCode",
        outputs=outputs,
        readable_output=readable,
        raw_response=[mask_secrets(alarm) for alarm in alarms],
    )


def update_alarm_status_command(client: Client, args: dict[str, Any]) -> CommandResults:
    alarm_ids = [to_int(a) for a in argToList(args.get("alarm_ids"))]
    if not alarm_ids or any(a is None for a in alarm_ids):
        raise DemistoException("The alarm_ids argument must be a comma-separated list of alarm codes.")
    status = canonical_status(args.get("status"))
    if not status:
        raise DemistoException(f"The status argument must be one of: {', '.join(STATUSES)}.")
    client.update_status(
        [a for a in alarm_ids if a is not None],
        status,
        args.get("remarks"),
        assigned_email=args.get("assigned_email"),
        info_emails=argToList(args.get("info_email_list")),
    )
    return CommandResults(
        outputs_prefix="ThreatMon.Alarm",
        outputs_key_field="AlarmCode",
        outputs=[{"AlarmCode": a, "Status": status} for a in alarm_ids],
        readable_output=f"The status of ThreatMon alarm(s) {', '.join(str(a) for a in alarm_ids)} was set to {status}.",
    )


def legacy_update_status_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """The deprecated threatmon_update_incident_status command, kept for existing playbooks."""
    code = args.get("alarmId")
    status = args.get("status")
    alarm_id = to_int(code)
    if alarm_id is None:
        raise DemistoException(f"alarmId must be a valid integer, got: {code}")
    response = client.request("PATCH", "/v1/incident/status", json_data={"status": status, "alarmIds": [alarm_id]})
    if response.status_code != 200:
        raise DemistoException(
            f"Failed to change status for incident {code}. API returned {response.status_code}: {response.text}"
        )
    return CommandResults(readable_output=f"Incident {code} status changed to {status}.")


def parse_action_args(args: dict[str, Any]) -> tuple[int, str]:
    finding_id_raw = args.get("finding_id", args.get("findingId"))
    finding = args.get("finding")
    if not finding_id_raw:
        raise ValueError("findingId argument is required.")
    if not finding:
        raise ValueError("finding argument is required.")
    finding_id = to_int(finding_id_raw)
    if finding_id is None:
        raise ValueError(f"findingId must be a valid integer, got: {finding_id_raw}")
    return finding_id, str(finding)


def action_command(client: Client, args: dict[str, Any], action: str) -> CommandResults:
    """Submits a takedown or data removal request once. ThreatMon's refusals are results, not errors."""
    finding_id, finding = parse_action_args(args)
    url_suffix, prefix, name = ACTIONS[action]
    response = client.submit_action(url_suffix, finding_id, finding)
    if response.status_code not in ACTION_RESULTS:
        raise_api_error(response, client.customer_name)
    result, submitted, message = ACTION_RESULTS[response.status_code]
    if response.status_code == 403 and "<html" in (response.text or "").lower():
        raise_api_error(response, client.customer_name)
    output = {"FindingID": finding_id, "Finding": finding, "Result": result, "Submitted": submitted, "Message": message}
    return CommandResults(
        outputs_prefix=prefix,
        outputs_key_field="FindingID",
        outputs=output,
        readable_output=f"### ThreatMon {name}\n**{result}**: {message} (findingId {finding_id})",
        raw_response=output,
    )


def legacy_action_command(client: Client, args: dict[str, Any], action: str) -> CommandResults:
    """The deprecated takedown and data removal commands, which raise an error when ThreatMon refuses a request."""
    finding_id, finding = parse_action_args(args)
    url_suffix, _, name = ACTIONS[action]
    response = client.submit_action(url_suffix, finding_id, finding)
    code = response.status_code
    if code == 200:
        return CommandResults(readable_output=f"{name} request submitted successfully.")
    messages = {
        404: f"Finding not found: findingId={finding_id}",
        409: f"A {name.lower()} request already exists for findingId={finding_id}",
        403: f"{name} quota exceeded or insufficient rights. Please contact ThreatMon.",
        400: f"This finding is not eligible for a {name.lower()} request.",
    }
    raise DemistoException(messages.get(code, f"API Error: {code} - {response.text}"))


ACTIONS = {
    "takedown": ("/v1/takedown", "ThreatMon.Takedown", "Takedown"),
    "data_removal": ("/v1/blackMarket/dataRemoval", "ThreatMon.DataRemoval", "Data removal"),
}


def alarm_stats_command(client: Client, args: dict[str, Any]) -> CommandResults:
    from_date = arg_to_datetime(args.get("from_date"))
    to_date = arg_to_datetime(args.get("to_date"))
    dates = {
        "from_date": format_api_date(from_date) if from_date else None,
        "to_date": format_api_date(to_date) if to_date else None,
    }
    outputs: dict[str, Any] = {}
    for kind, key in (("status", "Status"), ("severity", "Severity"), ("total", "Category")):
        counts = client.get_stats(kind, **dates)
        outputs[key] = {name: to_int(count) or 0 for name, count in counts.items()}
    readable = "\n".join(
        tableToMarkdown(
            f"ThreatMon Alarms by {key}", [{"Name": n, "Count": c} for n, c in values.items()], headers=["Name", "Count"]
        )
        for key, values in outputs.items()
    )
    return CommandResults(outputs_prefix="ThreatMon.AlarmStats", outputs=outputs, readable_output=readable)


def format_cve_vendors(vendors: dict[str, list[str]]) -> str:
    """Formats a vendor-to-products map into a human-readable string for the markdown table."""
    if not vendors:
        return ""
    return "; ".join(f"{vendor}: {', '.join(products)}" for vendor, products in vendors.items())


CVE_HEADERS = [
    "cve",
    "summary",
    "cvssV2",
    "severityV2",
    "cvssV3",
    "severityV3",
    "cvssV3_1",
    "severityV3_1",
    "cvssV4",
    "severityV4",
    "vendors",
    "exploit",
    "knownRansomwareCampaignUse",
    "zeroday",
    "createdAt",
    "updatedAt",
]


def build_cve_command_results(response: dict[str, Any], readable_title: str) -> CommandResults:
    """Builds CommandResults for a page of CVE records returned by the ThreatMon CVE endpoints."""
    records = response.get("data") or []
    total_records = response.get("totalRecords", 0)
    rows = [{**record, "vendors": format_cve_vendors(record.get("vendors") or {})} for record in records]
    readable_output = tableToMarkdown(
        f"{readable_title} (Total Records: {total_records})",
        rows,
        headers=CVE_HEADERS,
        headerTransform=string_to_table_header,
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix="ThreatMon.CVE",
        outputs_key_field="cve",
        outputs=records,
        readable_output=readable_output,
        raw_response=response,
    )


def list_cves_command(client: Client, args: dict[str, Any]) -> CommandResults:
    page = arg_to_number(args.get("page")) or 0
    response = client.get_cve_list(page=page, cvss=args.get("cvss"))
    return build_cve_command_results(response, "ThreatMon CVE List")


def list_subscribed_cves_command(client: Client, args: dict[str, Any]) -> CommandResults:
    page = arg_to_number(args.get("page")) or 0
    response = client.get_subscribed_cve_list(page=page, cvss=args.get("cvss"), customer_name=args.get("customer_name"))
    return build_cve_command_results(response, "ThreatMon Subscribed CVE List")


""" INTELLIGENCE, ASSETS, SANDBOX AND MSSP COMMANDS """

ASSET_TYPES = {
    "IP": "ip",
    "Cloud IP": "cloudIp",
    "Domain": "domains",
    "Subdomain": "subdomains",
    "Cloud Subdomain": "cloudSubdomain",
    "WHOIS": "whois",
    "Website": "website",
    "SSL Certificate": "ssl",
    "Technology": "technology",
    "DNS Record": "v2/dnsRecord",
    "Bucket": "bucket",
    "Bucket File": "bucketFile",
}
SANDBOX_DBOT_SCORES = {
    "malicious": Common.DBotScore.BAD,
    "suspicious": Common.DBotScore.SUSPICIOUS,
    "clean": Common.DBotScore.GOOD,
}
CVE_SEARCH_MAX = 1000
CVE_TABLE_HEADERS = [
    "cve",
    "severity",
    "cvssV3_1",
    "cvssV4",
    "tmvs",
    "brvs",
    "epss",
    "exploit",
    "hasPoc",
    "publishedAt",
    "summary",
]
SCREENSHOTS_PER_INCIDENT = 3
SANDBOX_CLOCK_SKEW_SECONDS = 300
SANDBOX_DONE_STATUSES = {2}  # Observed live: 5 queued, 1 running, 2 done. A failed analysis is not documented.
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


HEADER_NAMES = {
    "cve": "CVE",
    "cvssV3_1": "CVSS 3.1",
    "cvssV4": "CVSS 4.0",
    "tmvs": "TMVS",
    "brvs": "BRVS",
    "epss": "EPSS",
    "hasPoc": "Public PoC",
    "publishedAt": "Published",
    "ip": "IP",
    "ipList": "IP List",
    "ipsAndCnames": "IPs and CNAMEs",
    "reverseDnss": "Reverse DNS",
    "reverseDns": "Reverse DNS",
    "asnSystemOrganization": "ASN Organization",
    "websiteUrl": "Website URL",
    "isLogin": "Login Page",
    "vuln": "Vulnerable",
    "sslProtocolNames": "SSL Protocols",
    "url": "URL",
    "step_num": "Step",
    "eta": "ETA",
    "platformLabel": "Platform",
}


def nice_header(key: str) -> str:
    """Turns an API field name into a readable table header, for example countryName into Country Name."""
    if key in HEADER_NAMES:
        return HEADER_NAMES[key]
    words = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", key.replace("_", " ")).split()
    return " ".join(w if w.isupper() else w.capitalize() for w in words)


def get_reliability(params: dict[str, Any]) -> str:
    reliability = params.get("integrationReliability") or DBotScoreReliability.B
    if not DBotScoreReliability.is_valid_type(reliability):
        raise DemistoException("Please provide a valid value for the Source Reliability parameter.")
    return reliability


def cve_score(record: dict[str, Any]) -> tuple[float | None, str | None]:
    """Returns the score and version of the newest CVSS version of a CVE."""
    for key, version in (("cvssV4", "4.0"), ("cvssV3_1", "3.1"), ("cvssV3", "3.0"), ("cvssV2", "2.0")):
        if record.get(key) is not None:
            return record[key], version
    return None, None


def cve_detail_markdown(detail: dict[str, Any]) -> str:
    kev = detail.get("kev") or {}
    assets = detail.get("affectedAssets") or {}
    summary = {
        "CVE": detail.get("cve"),
        "Severity": detail.get("severity"),
        "CVSS": cve_score(detail)[0],
        "TMVS": detail.get("tmvs"),
        "BRVS": detail.get("brvs"),
        "EPSS": detail.get("epss"),
        "Exploit": detail.get("exploit"),
        "Public PoC": detail.get("hasPoc"),
        "Ransomware Use": detail.get("knownRansomwareCampaignUse"),
        "CISA KEV": kev.get("dateAdded"),
        "Trending": detail.get("trending"),
        "Affected Assets": assets.get("totalCount"),
        "Published": detail.get("publishedAt"),
    }
    readable = tableToMarkdown(f"ThreatMon CVE {detail.get('cve')}", summary, removeNull=True, headerTransform=nice_header)
    readable += f"\n{detail.get('summary') or ''}\n"
    if kev.get("requiredAction"):
        readable += f"\n**CISA required action:** {kev['requiredAction']}\n"
    pocs = detail.get("pocs") or []
    if pocs:
        readable += tableToMarkdown(
            "Proofs of Concept", pocs, headers=["url", "source", "verdict", "stars"], removeNull=True, headerTransform=nice_header
        )
    return readable


def valid_cve_id(value: Any) -> str:
    cve_id = str(value or "").strip().upper()
    if not CVE_ID_RE.match(cve_id):
        raise DemistoException(f"{value} is not a valid CVE ID. Use the form CVE-2024-3400.")
    return cve_id


def cve_reputation_command(client: Client, args: dict[str, Any], reliability: str) -> list[CommandResults]:
    """The standard cve command: enriches CVEs with ThreatMon Vulnerability Knowledge."""
    results = []
    for value in argToList(args.get("cve") or args.get("cve_id")):
        if not str(value).strip():
            continue
        cve_id = valid_cve_id(value)
        dbot = Common.DBotScore(
            indicator=cve_id,
            indicator_type=DBotScoreType.CVE,
            integration_name="ThreatMon",
            score=Common.DBotScore.NONE,
            reliability=reliability,
        )
        detail = client.get_cve_detail(cve_id)
        if detail is None:
            results.append(
                CommandResults(
                    readable_output=f"ThreatMon has no information about {cve_id}.",
                    indicator=Common.CVE(id=cve_id, cvss=None, published=None, modified=None, description=None, dbot_score=dbot),
                )
            )
            continue
        score, version = cve_score(detail)
        indicator = Common.CVE(
            dbot_score=dbot,
            id=cve_id,
            cvss=score,
            published=detail.get("publishedAt"),
            modified=detail.get("updatedAt"),
            description=detail.get("summary"),
            cvss_version=version,
            cvss_score=score,
        )
        results.append(
            CommandResults(
                outputs_prefix="ThreatMon.CVE",
                outputs_key_field="cve",
                outputs=detail,
                readable_output=cve_detail_markdown(detail),
                indicator=indicator,
                raw_response=detail,
            )
        )
    return results


def cve_report_markdown(report: Any) -> str:
    """Renders the AI enrichment report of a CVE as an analyst brief."""
    if isinstance(report, str):
        return f"\n### AI Report\n{report}\n"
    if not isinstance(report, dict):
        return ""
    header = report.get("header") or {}
    brief = report.get("analyst_brief") or {}
    text = f"\n### AI Report: {header.get('title') or header.get('cve_id') or ''}\n"
    if brief.get("priority"):
        text += f"**Priority:** {brief['priority']}. {brief.get('priority_rationale') or ''}\n\n"
    for line in (report.get("overview") or {}).get("executive_summary") or []:
        text += f"- {line}\n"
    steps = (report.get("response") or {}).get("ir_playbook") or []
    if steps:
        text += tableToMarkdown(
            "Response Steps", steps, headers=["step_num", "title", "description", "eta"], headerTransform=nice_header
        )
    detection = (report.get("detection") or {}).get("detection_opportunities") or []
    if detection:
        text += "\n**Detection opportunities:**\n" + "".join(f"- {line}\n" for line in detection)
    return text


def cve_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    if not str(args.get("cve_id") or "").strip():
        raise DemistoException("The cve_id argument is required.")
    cve_id = valid_cve_id(args.get("cve_id"))
    include = ",".join(argToList(args.get("include")))
    detail = client.get_cve_detail(cve_id, include=include or None)
    if detail is None:
        return CommandResults(readable_output=f"ThreatMon has no information about {cve_id}.")
    readable = cve_detail_markdown(detail) + cve_report_markdown(detail.get("report"))
    timeline = detail.get("timeline")
    if isinstance(timeline, list) and timeline:
        readable += tableToMarkdown(
            "Timeline (latest 10 events)",
            timeline[:10],
            headers=["date", "type", "platformLabel", "description", "url"],
            headerTransform=nice_header,
            removeNull=True,
        )
    return CommandResults(
        outputs_prefix="ThreatMon.CVE", outputs_key_field="cve", outputs=detail, readable_output=readable, raw_response=detail
    )


def read_cursor_parts(fetch: Any, limit: int, cursor: Any) -> tuple[list[dict[str, Any]], Any]:
    """Reads whole parts of a cursor-based list until at least limit records are read or the list ends.

    ThreatMon returns fixed parts of 100 records, and its cursor points after a whole part. The records of every
    part read are returned, so the returned cursor never skips records.
    """
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    while len(records) < limit:
        response = fetch(cursor) or {}
        data = response.get("data") or [] if isinstance(response, dict) else []
        records.extend(row for row in data if isinstance(row, dict))
        cursor = response.get("nextCursor") if isinstance(response, dict) else None
        if cursor in (None, "") or not data or str(cursor) in seen:
            cursor = None if not data or str(cursor) in seen else cursor
            break
        seen.add(str(cursor))
    return records, cursor


def search_limit(args: dict[str, Any]) -> int:
    limit = arg_to_number(args.get("limit")) or 50
    if not 1 <= limit <= CVE_SEARCH_MAX:
        raise DemistoException(f"The limit argument must be between 1 and {CVE_SEARCH_MAX}.")
    return limit


def short_summary(records: list[dict[str, Any]], length: int = 160) -> list[dict[str, Any]]:
    """Shortens the CVE summaries for the War Room table. The context keeps the full text."""
    rows = []
    for record in records:
        summary = str(record.get("summary") or "")
        rows.append({**record, "summary": summary if len(summary) <= length else summary[: length - 3].rstrip() + "..."})
    return rows


def cve_search_command(client: Client, args: dict[str, Any]) -> CommandResults:
    start = arg_to_datetime(args.get("start_date"), arg_name="start_date", required=True)
    end = arg_to_datetime(args.get("end_date"), arg_name="end_date")
    params: dict[str, Any] = {
        "startDate": format_api_date(start) if start else None,
        "endDate": format_api_date(end) if end else None,
        "dateField": args.get("date_field"),
        "cvss": args.get("cvss"),
        "search": args.get("search"),
        "vendor": args.get("vendor"),
        "product": args.get("product"),
    }
    for arg, param in (
        ("exploit", "exploit"),
        ("has_poc", "poc"),
        ("trending", "trending"),
        ("known_ransomware_use", "knownRansomwareCampaignUse"),
        ("confirmed_affected", "confirmedAffected"),
        ("potentially_affected", "potentiallyAffected"),
    ):
        if args.get(arg) not in (None, ""):
            params[param] = str(argToBoolean(args[arg])).lower()
    records, next_cursor = read_cursor_parts(
        lambda cursor: client.get_json("/v1/cve/vulnerabilities", params={**params, "cursor": cursor}),
        search_limit(args),
        args.get("cursor"),
    )
    readable = tableToMarkdown(
        f"ThreatMon CVEs ({len(records)})",
        short_summary(records),
        headers=CVE_TABLE_HEADERS,
        headerTransform=nice_header,
        removeNull=True,
    )
    if next_cursor:
        readable += f"\nMore CVEs are available. Run the command again with cursor={next_cursor}."
    return CommandResults(
        outputs={
            "ThreatMon.CVE(val.cve && val.cve == obj.cve)": records,
            "ThreatMon.CVESearch": {"NextCursor": next_cursor},
        },
        readable_output=readable,
        raw_response=records,
    )


def cve_subscription_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    records, next_cursor = read_cursor_parts(
        lambda cursor: client.get_json("/v1/cve/subscriptions", params={"cursor": cursor, "email": args.get("recipient_email")}),
        search_limit(args),
        args.get("cursor"),
    )
    readable = tableToMarkdown(
        f"ThreatMon CVE Subscriptions ({len(records)})",
        [
            {
                **r,
                "recipients": ", ".join(
                    str(x.get("email") or "") if isinstance(x, dict) else str(x) for x in r.get("recipients") or []
                ),
            }
            for r in records
        ],
        headers=["vendor", "product", "internal", "external", "subscribedAt", "recipients"],
        headerTransform=nice_header,
        removeNull=True,
    )
    return CommandResults(
        outputs={
            "ThreatMon.CVESubscription(val.productId && val.productId == obj.productId)": records,
            "ThreatMon.CVESubscriptionList": {"NextCursor": next_cursor},
        },
        readable_output=readable,
        raw_response=records,
    )


def subscribed_cve_search_command(client: Client, args: dict[str, Any]) -> CommandResults:
    start = arg_to_datetime(args.get("start_date"), arg_name="start_date", required=True)
    end = arg_to_datetime(args.get("end_date"), arg_name="end_date")
    params = {
        "startDate": format_api_date(start) if start else None,
        "endDate": format_api_date(end) if end else None,
        "cvss": args.get("cvss"),
        "email": args.get("recipient_email"),
    }
    records, next_cursor = read_cursor_parts(
        lambda cursor: client.get_json("/v1/cve/subscriptions/vulnerabilities", params={**params, "cursor": cursor}),
        search_limit(args),
        args.get("cursor"),
    )
    readable = tableToMarkdown(
        f"ThreatMon CVEs of Subscribed Products ({len(records)})",
        short_summary(records),
        headers=CVE_TABLE_HEADERS,
        headerTransform=nice_header,
        removeNull=True,
    )
    if next_cursor:
        readable += f"\nMore CVEs are available. Run the command again with cursor={next_cursor}."
    return CommandResults(
        outputs={
            "ThreatMon.CVE(val.cve && val.cve == obj.cve)": records,
            "ThreatMon.SubscribedCVESearch": {"NextCursor": next_cursor},
        },
        readable_output=readable,
        raw_response=records,
    )


def asset_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    asset_type = args.get("asset_type") or "Domain"
    kind = ASSET_TYPES.get(asset_type)
    if not kind:
        raise DemistoException(f"The asset_type argument must be one of: {', '.join(ASSET_TYPES)}.")
    limit = arg_to_number(args.get("limit")) or 50
    if not 1 <= limit <= 100:
        raise DemistoException("The limit argument must be between 1 and 100.")
    page = arg_to_number(args.get("page")) or 0
    api_page, skip = divmod(page * limit, PAGE_SIZE)
    rows: list[dict[str, Any]] = []
    total = 0
    while len(rows) < skip + limit:
        response = client.get_json(f"/df/{kind}/{api_page}") or {}
        total = response.get("totalRecords") or 0
        data = response.get("data") or []
        rows.extend(data)
        api_page += 1
        if len(data) < PAGE_SIZE:
            break
    assets = [{"AssetType": asset_type, **row} for row in rows[skip : skip + limit]]
    return CommandResults(
        outputs_prefix="ThreatMon.Asset",
        outputs=assets,
        readable_output=tableToMarkdown(
            f"ThreatMon {asset_type} Assets (Total Records: {total})",
            [{k: v for k, v in a.items() if k != "AssetType"} for a in assets],
            headerTransform=nice_header,
            removeNull=True,
        ),
        raw_response=rows,
    )


def ciso_dashboard_command(client: Client, args: dict[str, Any]) -> CommandResults:
    dashboard = client.get_json("/v1/ciso/dashboard") or {}
    score = dashboard.get("score") or {}
    modules = [
        {"Module": name, "Score": score.get(f"{prefix}Score"), "Grade": score.get(f"{prefix}Grade")}
        for name, prefix, flag in (
            ("Attack Surface", "as", "attackSurface"),
            ("Dark Web", "dw", "darkWeb"),
            ("Brand", "brand", "brand"),
            ("Threat Intelligence", "ti", "threatIntel"),
            ("Supply Chain", "sc", "supplyChain"),
            ("GRC", "grc", "grc"),
        )
        if score.get(flag)
    ]
    readable = tableToMarkdown(
        f"ThreatMon CISO Dashboard: Risk Score {score.get('score')} ({score.get('grade')})",
        dashboard.get("statistics") or {},
        headerTransform=nice_header,
        removeNull=True,
    )
    readable += tableToMarkdown(
        "Module Scores", modules, headers=["Module", "Score", "Grade"], removeNull=True, headerTransform=nice_header
    )
    readable += tableToMarkdown(
        "Top Alerts", dashboard.get("topAlerts") or [], headers=["title", "total"], headerTransform=nice_header
    )
    if argToBoolean(args.get("include_report", True)) and score.get("report"):
        readable += f"\n{score['report']}\n"
    return CommandResults(
        outputs_prefix="ThreatMon.CISODashboard", outputs=dashboard, readable_output=readable, raw_response=dashboard
    )


def screenshot_name(blob_name: str) -> str:
    name = re.split(r"[/=]", blob_name.rstrip("/"))[-1] or "screenshot.png"
    return name if "." in name else f"{name}.png"


def screenshot_get_command(client: Client, args: dict[str, Any]) -> dict[str, Any] | CommandResults:
    blob_name = str(args.get("blob_name") or "").strip()
    if not blob_name:
        raise DemistoException("The blob_name argument is required.")
    content = client.get_screenshot(blob_name)
    if content is None:
        return CommandResults(readable_output=f"The screenshot {blob_name} is not available from ThreatMon.")
    return fileResult(screenshot_name(blob_name), content, file_type=EntryType.IMAGE)


def get_screenshot_values(alarm: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for finding in get_findings(alarm):
        for key, value in finding.items():
            if str(key).strip().lower() == "screenshot" and isinstance(value, str) and value and value not in values:
                values.append(value)
    for group in normalize_list(alarm.get("items")):
        for pair in group if isinstance(group, list) else [group]:
            if isinstance(pair, dict) and str(pair.get("key")).strip().lower() == "screenshot":
                value = pair.get("value")
                if isinstance(value, str) and value and value not in values:
                    values.append(value)
    return values


def screenshot_attachments(client: Client, alarm: dict[str, Any], deadline: float) -> list[dict[str, str]]:
    """Downloads the screenshots of an alarm and returns them as incident attachments. Errors never stop the fetch."""
    attachments = []
    for blob_name in get_screenshot_values(alarm)[:SCREENSHOTS_PER_INCIDENT]:
        if time.time() >= deadline:
            break
        try:
            content = client.get_screenshot(blob_name)
        except Exception as error:
            demisto.debug(f"ThreatMon screenshot {blob_name} was not attached: {error}")
            continue
        if content:
            name = screenshot_name(blob_name)
            file = fileResult(name, content, file_type=EntryType.IMAGE)
            attachments.append({"path": file["FileID"], "name": name, "showMediaFile": True})
    return attachments


def sandbox_data(response: Any) -> Any:
    if isinstance(response, dict) and "data" in response and "code" in response:
        return response.get("data")
    return response


def sandbox_submission_output(submission: dict[str, Any]) -> dict[str, Any]:
    return {
        "ID": to_int(submission.get("id")),
        "SID": str(submission.get("sid") or ""),
        "FileName": submission.get("originalFileName"),
        "FileSize": submission.get("fileSize"),
        "Status": submission.get("status"),
        "TotalJobs": submission.get("totalJobs"),
        "OverallRating": submission.get("overallRating"),
        "CreatedAt": submission.get("createdAt"),
        "UpdatedAt": submission.get("updatedAt"),
    }


def sandbox_results(client: Client, sid: str, reliability: str, page: int = 0, size: int = 50) -> list[CommandResults]:
    submission = sandbox_data(client.get_json(f"/v1/sandbox/submission/{sid}/status", with_customer=False, retry=False)) or {}
    page_data = (
        sandbox_data(
            client.get_json(
                f"/v1/sandbox/submission/{sid}/results",
                params={"page": page, "size": size},
                with_customer=False,
                retry=False,
            )
        )
        or {}
    )
    submission = submission if isinstance(submission, dict) else {}
    page_data = page_data if isinstance(page_data, dict) else {}
    rows = page_data.get("content") or [] if isinstance(page_data, dict) else []
    output = sandbox_submission_output(submission)
    output["Results"] = [
        {
            "FileName": row.get("fileName"),
            "FileType": row.get("fileType"),
            "SHA256": row.get("sha256"),
            "SHA1": row.get("sha1"),
            "Rating": row.get("rating"),
            "Score": row.get("score"),
            "MalwareName": row.get("malwareName"),
            "RatingSource": row.get("ratingSource"),
            "CreatedAt": row.get("createdAt"),
            "BehaviorData": row.get("behaviorData"),
        }
        for row in rows
    ]
    indicator_results = []
    for row in rows:
        if not row.get("sha256"):
            continue
        dbot = Common.DBotScore(
            indicator=row["sha256"],
            indicator_type=DBotScoreType.FILE,
            integration_name="ThreatMon",
            score=SANDBOX_DBOT_SCORES.get(str(row.get("rating") or "").lower(), Common.DBotScore.NONE),
            reliability=reliability,
            malicious_description=row.get("malwareName") if str(row.get("rating")).lower() == "malicious" else None,
        )
        indicator_results.append(
            CommandResults(
                readable_output=f"ThreatMon sandbox verdict for {row.get('fileName') or row['sha256']}: {row.get('rating')}",
                indicator=Common.File(dbot_score=dbot, sha256=row["sha256"], sha1=row.get("sha1"), name=row.get("fileName")),
            )
        )
    readable = tableToMarkdown(
        f"ThreatMon Sandbox Submission {output['SID']}: {output.get('OverallRating') or 'In progress'}",
        {k: v for k, v in output.items() if k != "Results"},
        removeNull=True,
        headerTransform=nice_header,
    )
    readable += tableToMarkdown(
        "Analyzed Files",
        output["Results"],
        headers=["FileName", "FileType", "Rating", "MalwareName", "RatingSource", "SHA256"],
        removeNull=True,
        headerTransform=nice_header,
    )
    summary = CommandResults(
        outputs_prefix="ThreatMon.Sandbox",
        outputs_key_field="ID",
        outputs=output,
        readable_output=readable,
        raw_response={"submission": submission, "results": page_data},
    )
    return [summary, *indicator_results]


def sandbox_finished(submission: dict[str, Any]) -> bool:
    return bool(submission.get("overallRating")) or to_int(submission.get("status")) in SANDBOX_DONE_STATUSES


def list_recent_submissions(client: Client) -> list[dict[str, Any]]:
    data = sandbox_data(client.get_json("/v1/sandbox/submissions", params={"page": 0, "size": 50}, with_customer=False))
    return data.get("content") or [] if isinstance(data, dict) else []


def resolve_submission(client: Client, args: dict[str, Any]) -> dict[str, Any] | None:
    """Finds the submission of this command in the submission list.

    ThreatMon lists a new submission first with a temporary ID that the status endpoint rejects (HTTP 500), and
    replaces it with the final submission ID when the analysis starts. Only the row id stays the same, so the
    submission is found by its file name and time once, and then followed by its row id.
    """
    rows = list_recent_submissions(client)
    row_id = to_int(args.get("submission_id"))
    if row_id is not None:
        row = next((row for row in rows if to_int(row.get("id")) == row_id), None)
        if row is None and str(args.get("sid") or "").isdigit():
            # The submission is no longer among the newest ones. Read it by its final submission ID.
            row = sandbox_data(client.get_json(f"/v1/sandbox/submission/{args['sid']}/status", with_customer=False)) or None
        return row if isinstance(row, dict) else None
    temporary_sid = args.get("temporary_sid")
    if temporary_sid:
        row = next((row for row in rows if str(row.get("sid")) == str(temporary_sid)), None)
        if row:
            return row
    submitted_at = float(args.get("submitted_at") or 0)
    file_size = to_int(args.get("file_size"))
    for row in rows:  # Newest first.
        if file_size is not None and to_int(row.get("fileSize")) not in (None, file_size):
            continue
        created = parse_api_date(row.get("createdAt"))
        if (
            row.get("originalFileName") == args.get("file_name")
            and created
            and created.timestamp() >= submitted_at - SANDBOX_CLOCK_SKEW_SECONDS
        ):
            return row
    return None


@polling_function(
    name="threatmon-sandbox-file-submit",
    interval=60,
    timeout=1800,
    poll_message="The ThreatMon sandbox is analyzing the file:",
)
def sandbox_submit_command(args: dict[str, Any], client: Client, reliability: str) -> PollResult:
    """Submits a file to the ThreatMon sandbox once, then polls the submission until a verdict is available."""
    args = dict(args)
    if not args.get("submitted_at"):
        entry_id = args.get("entry_id")
        if not entry_id:
            raise DemistoException("The entry_id argument is required.")
        file = demisto.getFilePath(entry_id)
        file_name = file.get("name") or "file"
        file_size = os.path.getsize(file["path"])
        submitted_at = time.time()
        with open(file["path"], "rb") as handle:
            response = client.request(
                "POST",
                "/v1/sandbox/submit",
                params={"archivePassword": args.get("archive_password")},
                files={"file": (file_name, handle)},
                with_customer=False,
                retry=False,
            )
        if response.status_code == 500 and not response.text.strip():
            # The sandbox rejects a file that was already submitted with the same name. Follow that submission.
            earlier = next(
                (
                    r
                    for r in list_recent_submissions(client)
                    if r.get("originalFileName") == file_name and to_int(r.get("fileSize")) in (None, file_size)
                ),
                None,
            )
            if not earlier:
                raise DemistoException(
                    "The ThreatMon sandbox did not accept the file (HTTP 500). It does this when the same file was "
                    "submitted before under the same name: find it with threatmon-sandbox-submission-list and read its "
                    "verdict with threatmon-sandbox-result-get, or submit the file under another name."
                )
            demisto.debug(f"The file {file_name} was submitted before as submission {earlier.get('id')}.")
            args["submission_id"] = str(earlier.get("id"))
        elif response.status_code not in (200, 201):
            raise_api_error(response, client.customer_name)
        else:
            body = sandbox_data(parse_json(response))
            if isinstance(body, dict) and body.get("success") is False:
                raise DemistoException(f"The ThreatMon sandbox did not accept the file: {body.get('message') or body}")
            if isinstance(body, dict) and body.get("sid"):
                args["temporary_sid"] = str(body["sid"])
        args.update({"file_name": file_name, "submitted_at": str(submitted_at), "file_size": str(file_size)})
    submission = resolve_submission(client, args)
    if submission and submission.get("id") is not None:
        args["submission_id"] = str(submission["id"])
    if submission and str(submission.get("sid") or "").isdigit():
        args["sid"] = str(submission["sid"])
    if not submission or not sandbox_finished(submission):
        output = sandbox_submission_output(submission) if submission else {}
        return PollResult(
            response=CommandResults(
                outputs_prefix="ThreatMon.Sandbox",
                outputs_key_field="ID",
                outputs=output or None,
                readable_output=f"The ThreatMon sandbox is still analyzing {args.get('file_name')}.",
            ),
            continue_to_poll=True,
            args_for_next_run=args,
            partial_result=CommandResults(
                readable_output=f"The file {args.get('file_name')} was submitted to the ThreatMon sandbox. "
                "Waiting for the verdict."
            )
            if not args.get("hide_polling_output")
            else None,
        )
    if not submission.get("overallRating"):
        output = sandbox_submission_output(submission)
        return PollResult(
            response=CommandResults(
                outputs_prefix="ThreatMon.Sandbox",
                outputs_key_field="ID",
                outputs=output,
                readable_output=f"The ThreatMon sandbox ended the analysis of {args.get('file_name')} without a verdict "
                f"(status {submission.get('status')}).",
            ),
            continue_to_poll=False,
        )
    return PollResult(response=sandbox_results(client, str(submission["sid"]), reliability), continue_to_poll=False)


def sandbox_submission_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    size = arg_to_number(args.get("limit")) or 20
    if not 1 <= size <= 100:
        raise DemistoException("The limit argument must be between 1 and 100.")
    page = arg_to_number(args.get("page")) or 0
    data = sandbox_data(client.get_json("/v1/sandbox/submissions", params={"page": page, "size": size}, with_customer=False))
    rows = (data or {}).get("content") or [] if isinstance(data, dict) else []
    outputs = [sandbox_submission_output(row) for row in rows]
    total = data.get("totalElements") if isinstance(data, dict) else len(rows)
    return CommandResults(
        outputs_prefix="ThreatMon.Sandbox",
        outputs_key_field="ID",
        outputs=outputs,
        readable_output=tableToMarkdown(
            f"ThreatMon Sandbox Submissions (Total: {total})",
            outputs,
            headers=["SID", "FileName", "OverallRating", "TotalJobs", "CreatedAt", "UpdatedAt"],
            removeNull=True,
            headerTransform=nice_header,
        ),
        raw_response=data,
    )


def sandbox_result_get_command(client: Client, args: dict[str, Any], reliability: str) -> list[CommandResults]:
    sid = str(args.get("sid") or "").strip()
    if not sid:
        raise DemistoException("The sid argument is required.")
    size = arg_to_number(args.get("limit")) or 50
    if not 1 <= size <= 100:
        raise DemistoException("The limit argument must be between 1 and 100.")
    return sandbox_results(client, sid, reliability, page=arg_to_number(args.get("page")) or 0, size=size)


def customer_output(customer: dict[str, Any]) -> dict[str, Any]:
    return {
        "CustomerName": customer.get("customerName"),
        "License": customer.get("customerLicense"),
        "Domain": customer.get("domain"),
        "Keywords": customer.get("keywordList") or [],
        "ContractEndDate": customer.get("contractEndDate"),
    }


def customer_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    params = {"page": arg_to_number(args.get("page")) or 0, "customerName": args.get("customer_name")}
    response = client.request("GET", "/v1/customer", params=params, with_customer=False)
    if response.status_code != 200:
        raise_api_error(response, args.get("customer_name"))
    response = parse_json(response) or {}
    response = response if isinstance(response, dict) else {}
    customers = [customer_output(c) for c in response.get("data") or []]
    return CommandResults(
        outputs_prefix="ThreatMon.Customer",
        outputs_key_field="CustomerName",
        outputs=customers,
        readable_output=tableToMarkdown(
            f"ThreatMon MSSP Customers (Total Records: {response.get('totalRecords', len(customers))})",
            customers,
            headers=["CustomerName", "License", "Domain", "Keywords", "ContractEndDate"],
            removeNull=True,
            headerTransform=nice_header,
        ),
        raw_response=response,
    )


def send_customer_request(client: Client, method: str, url_suffix: str, **kwargs: Any) -> Any:
    response = client.request(method, url_suffix, with_customer=False, retry=method == "PATCH", **kwargs)
    if response.status_code not in (200, 201, 204):
        raise_api_error(
            response, kwargs.get("params", {}).get("customerName") or (kwargs.get("json_data") or {}).get("customerName")
        )
    try:
        return parse_json(response)
    except DemistoException:
        return response.text


def customer_body(args: dict[str, Any], create: bool) -> dict[str, Any]:
    name = str(args.get("customer_name") or "").strip()
    if not name:
        raise DemistoException("The customer_name argument is required.")
    body: dict[str, Any] = {"customerName": name}
    license_type = args.get("license")
    if license_type:
        if license_type not in ("TRIAL", "CUSTOMER"):
            raise DemistoException("The license argument must be TRIAL or CUSTOMER.")
        body["customerLicense"] = license_type
    if args.get("customer_domain"):
        body["domain"] = args["customer_domain"]
    if args.get("keywords"):
        body["keywordList"] = argToList(args["keywords"])
    if args.get("contract_end_date"):
        end = arg_to_datetime(args["contract_end_date"], arg_name="contract_end_date")
        body["contractEndDate"] = end.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if end else None
    if create and not (body.get("customerLicense") and body.get("domain")):
        raise DemistoException("The license and customer_domain arguments are required to create a customer.")
    if not create and len(body) == 1:
        raise DemistoException("Provide at least one of license, customer_domain or contract_end_date to change.")
    return body


def customer_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    body = customer_body(args, create=True)
    response = send_customer_request(client, "POST", "/v1/customer", json_data=body)
    return CommandResults(
        outputs_prefix="ThreatMon.Customer",
        outputs_key_field="CustomerName",
        outputs=customer_output(body),
        readable_output=f"The ThreatMon customer {body['customerName']} was created.",
        raw_response=response,
    )


def customer_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    body = customer_body({k: v for k, v in args.items() if k != "keywords"}, create=False)
    response = send_customer_request(client, "PATCH", "/v1/customer", json_data=body)
    return CommandResults(readable_output=f"The ThreatMon customer {body['customerName']} was updated.", raw_response=response)


def customer_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    name = str(args.get("customer_name") or "").strip()
    if not name:
        raise DemistoException("The customer_name argument is required.")
    response = send_customer_request(client, "DELETE", "/v1/customer", params={"customerName": name})
    return CommandResults(readable_output=f"The ThreatMon customer {name} was deleted.", raw_response=response)


def customer_keyword_command(client: Client, args: dict[str, Any], add: bool) -> CommandResults:
    name = str(args.get("customer_name") or "").strip()
    keyword = str(args.get("keyword") or "").strip()
    if not name or not keyword:
        raise DemistoException("The customer_name and keyword arguments are required.")
    response = send_customer_request(
        client, "POST" if add else "DELETE", "/v1/customer/keyword", json_data={"customerName": name, "keyword": keyword}
    )
    action = "added to" if add else "removed from"
    return CommandResults(
        readable_output=f"The keyword {keyword} was {action} the ThreatMon customer {name}.", raw_response=response
    )


def website_url_submit_command(client: Client, args: dict[str, Any]) -> CommandResults:
    urls = [u.strip() for u in argToList(args.get("urls")) if u.strip()]
    if not urls:
        raise DemistoException("The urls argument is required.")
    if len(urls) > 1000:
        raise DemistoException("At most 1000 URLs can be submitted in one request.")
    response = client.request("POST", "/v1/website/urls", json_data={"urls": [{"url": u} for u in urls]}, retry=False)
    if response.status_code not in (200, 201):
        raise_api_error(response, client.customer_name)
    body = parse_json(response) or {}
    body = body if isinstance(body, dict) else {}
    results = [
        {"URL": r.get("url"), "NormalizedURL": r.get("normalizedUrl"), "Status": r.get("status"), "Reason": r.get("reason")}
        for r in body.get("results") or []
    ]
    summary = {k: body.get(k) for k in ("received", "inserted", "updated", "failed")}
    readable = tableToMarkdown("ThreatMon Website URL Submission", summary, headerTransform=nice_header)
    readable += tableToMarkdown(
        "Results", results, headers=["URL", "Status", "Reason"], removeNull=True, headerTransform=nice_header
    )
    return CommandResults(
        outputs_prefix="ThreatMon.WebsiteURL",
        outputs_key_field="URL",
        outputs=results,
        readable_output=readable,
        raw_response=body,
    )


""" MAIN """


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    demisto.debug(f"ThreatMon command: {command}")
    try:
        credentials = params.get("credentials") or {}
        client = Client(
            base_url=params.get("url") or DEFAULT_BASE_URL,
            api_key=credentials.get("password") or "",
            verify=not argToBoolean(params.get("insecure", False)),
            proxy=argToBoolean(params.get("proxy", False)),
            customer_name=params.get("customer_name"),
        )
        if command == "test-module":
            return_results(test_module(client, params))
        elif command == "fetch-incidents":
            incidents, next_run = fetch_incidents(client, params, demisto.getLastRun() or {})
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif command == "get-modified-remote-data":
            return_results(get_modified_remote_data_command(client, args, params))
        elif command == "get-remote-data":
            return_results(get_remote_data_command(args, params))
        elif command == "update-remote-system":
            return_results(update_remote_system_command(client, args, params))
        elif command == "get-mapping-fields":
            return_results(get_mapping_fields_command())
        elif command == "threatmon-alarm-list":
            return_results(list_alarms_command(client, args))
        elif command == "threatmon-alarm-status-update":
            return_results(update_alarm_status_command(client, args))
        elif command == "threatmon-alarm-stats":
            return_results(alarm_stats_command(client, args))
        elif command == "threatmon-takedown-request":
            return_results(action_command(client, args, "takedown"))
        elif command == "threatmon-data-removal-request":
            return_results(action_command(client, args, "data_removal"))
        elif command == "cve":
            return_results(cve_reputation_command(client, args, get_reliability(params)))
        elif command == "threatmon-cve-get":
            return_results(cve_get_command(client, args))
        elif command == "threatmon-cve-search":
            return_results(cve_search_command(client, args))
        elif command == "threatmon-cve-subscription-list":
            return_results(cve_subscription_list_command(client, args))
        elif command == "threatmon-subscribed-cve-search":
            return_results(subscribed_cve_search_command(client, args))
        elif command == "threatmon-asset-list":
            return_results(asset_list_command(client, args))
        elif command == "threatmon-ciso-dashboard-get":
            return_results(ciso_dashboard_command(client, args))
        elif command == "threatmon-screenshot-get":
            return_results(screenshot_get_command(client, args))
        elif command == "threatmon-sandbox-file-submit":
            return_results(sandbox_submit_command(args, client, get_reliability(params)))
        elif command == "threatmon-sandbox-submission-list":
            return_results(sandbox_submission_list_command(client, args))
        elif command == "threatmon-sandbox-result-get":
            return_results(sandbox_result_get_command(client, args, get_reliability(params)))
        elif command == "threatmon-customer-list":
            return_results(customer_list_command(client, args))
        elif command == "threatmon-customer-create":
            return_results(customer_create_command(client, args))
        elif command == "threatmon-customer-update":
            return_results(customer_update_command(client, args))
        elif command == "threatmon-customer-delete":
            return_results(customer_delete_command(client, args))
        elif command == "threatmon-customer-keyword-add":
            return_results(customer_keyword_command(client, args, add=True))
        elif command == "threatmon-customer-keyword-remove":
            return_results(customer_keyword_command(client, args, add=False))
        elif command == "threatmon-website-url-submit":
            return_results(website_url_submit_command(client, args))
        elif command == "threatmon_list_cves":
            return_results(list_cves_command(client, args))
        elif command == "threatmon_list_subscribed_cves":
            return_results(list_subscribed_cves_command(client, args))
        elif command == "threatmon_update_incident_status":
            return_results(legacy_update_status_command(client, args))
        elif command == "threatmon_request_takedown":
            return_results(legacy_action_command(client, args, "takedown"))
        elif command == "threatmon_request_data_removal":
            return_results(legacy_action_command(client, args, "data_removal"))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as error:
        return_error(f"Failed to execute {command} command.\nError:\n{error}")


if __name__ in ("__main__", "builtin", "builtins"):  # pragma: no cover
    main()
