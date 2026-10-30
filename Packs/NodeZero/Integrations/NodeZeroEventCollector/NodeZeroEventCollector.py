import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import base64
import hashlib
import ipaddress
import json
import math
import re
import time
import uuid
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, TypedDict

# ----- constants -----

VENDOR = "horizon3"
PRODUCT = "nodezero"  # events land in the horizon3_nodezero_raw dataset
SOURCE_LOG_TYPE = "weakness"

AUTH_SUFFIX = "/v1/auth"
GRAPHQL_SUFFIX = "/v1/graphql"

PAGE_SIZE = 100  # the largest page the API serves
FINISHED_STATES = ["done"]  # collected once etl_completed_at is set; an ended pentest (stopped early by a user) never is
LOOKBACK = timedelta(hours=24)  # each sweep re-checks this far behind the watermark, for pentests that appear late
SENT_RETENTION = timedelta(days=30)  # how long the IDs of fully sent pentests are remembered
RUN_BUDGET_SECONDS = 180  # time budget of one command run
MIN_SECONDS_FOR_NEW_PENTEST = 30  # a fetch doesn't start another pentest with less time than this left
MAX_SWEEP_PAGES = 10  # at most this many pages of finished pentests per sweep
MIN_SECONDS_FOR_SWEEP_PAGE = 60  # the sweep doesn't read another page with less time than this left

MAX_EVENT_BYTES = 1_000_000  # a larger event has its long text fields truncated; it is never dropped
TEXT_FIELD_CAP = 10_000  # characters kept in each truncated field
TRUNCATABLE_FIELDS = (
    "vuln_description",
    "context_score_description",
    "vuln_mitigations",
    "vuln_references",
    "affected_asset_display_name",
)
UNTRUNCATED_FIELDS = (
    "_time",
    "time_fallback",
    "source_log_type",
    "event_id",
    "truncated",
    "uuid",
    "op_id",
    "created_at",
    "vuln_id",
)

TOKEN_REFRESH_MARGIN_SECONDS = 300  # a token this close to its expiry is replaced
DEFAULT_TOKEN_LIFETIME_SECONDS = 3600 - 60  # used when a token has no readable expiry
TOKEN_CONTEXT_KEY = "auth_token"
TOKEN_EXPIRY_CONTEXT_KEY = "auth_token_expires_at"
TOKEN_OWNER_CONTEXT_KEY = "auth_token_owner"  # the URL and API key the token belongs to

REQUEST_TIMEOUT_SECONDS = 60
MIN_REQUEST_TIMEOUT_SECONDS = 5
MAX_RETRIES = 4
NO_RETRY_BELOW_SECONDS = 20  # with less time than this left in the run, a request is not retried
RETRY_STATUSES = [429, 500, 502, 503, 504]
BACKOFF_FACTOR = 2
BACKOFF_JITTER = 1.0
MAX_ERROR_DETAIL_LENGTH = 500

# Every request identifies the collector. The headers carry no key, token, tenant URL, instance name or license ID.
INTEGRATION_NAME = "NodeZeroEventCollector"
USER_AGENT_PRODUCT = "NodeZero-Cortex"
UNKNOWN_VERSION = "unknown"
VERSION_PATTERN = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}")  # a version that is safe in a header, used with fullmatch
REQUEST_ID_HEADER = "X-Request-ID"

LAST_RUN_VERSION = 1
NEXT_TRIGGER_NOW = "0"
DEFAULT_FIRST_FETCH = "7 days"
DEFAULT_MAX_FETCH = 10_000
DEFAULT_EVENT_LIST_LIMIT = 10
DEFAULT_EVENT_LIST_SINCE = "7 days"

# The fetch and a manual push share one record of what was sent, kept in the integration context, and take turns
# through a lease there, so neither sends a pentest the other already sent.
# Known limitations of the shared record:
# - A wiped integration context loses the record of pentests that only a manual push sent; a later fetch sends them
#   again. The fetch's own record is restored from its checkpoint.
# - A pentest whose results appear in NodeZero more than SENT_RETENTION after its etl_completed_at counts as sent and is
#   never sent (the fetch already misses pentests that appear more than LOOKBACK late).
# - Lease expiry times are epoch seconds, so clock skew between the hosts that run the fetch and the command shortens or
#   lengthens a lease by the skew. LEASE_SAFETY_SECONDS leaves room for that.
STATE_CONTEXT_KEY = "nodezero_state"
LEASE_CONTEXT_KEY = "nodezero_lease"
OWNER_FETCH = "fetch"
OWNER_COMMAND = "command"
LEASE_TTL_SECONDS = 600  # a lease that isn't renewed expires after this; a crashed run blocks the other path no longer
LEASE_SAFETY_SECONDS = 200  # no send starts this close to the lease expiry; covers one 1 MiB send with its retries
LEASE_SETTLE_SECONDS = 2  # pause before re-reading a new lease, in case the platform doesn't enforce context versions
CONTEXT_WRITE_ATTEMPTS = 3
SEND_BATCH_BYTES = 1_000_000  # events are sent in batches below the 1 MiB XSIAM chunk, with a lease check before each

FILTER_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"  # naive UTC with whole seconds, the form the API filters accept
MAX_HOSTNAME_LENGTH = 253
HOSTNAME_LABEL_PATTERN = re.compile(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)")  # one RFC 1123 label, used with fullmatch

AUTH_FAILED_MESSAGE = "Authorization failed. Verify that the API key is valid and has read access to pentests and weaknesses."
EVENT_TABLE_HEADERS = ["_time", "op_id", "vuln_id", "vuln_short_name", "severity", "target_hostname", "target_ipv4_addresses"]

# GraphQL values are always passed as variables, never formatted into the query text.
# Each use has its own operation name, with the CortexXsiam prefix, so NodeZero can tell the collector's requests apart.
FINISHED_PENTESTS_QUERY = """
query CortexXsiamFinishedPentests($page_input: PageInput!) {
  pentests_page(page_input: $page_input) {
    pentests {
      op_id
      name
      op_type
      state
      client_name
      completed_at
      etl_completed_at
      weaknesses_count
    }
  }
}
"""

# The single-pentest lookup: the sweep query's body under its own operation name.
PENTEST_QUERY = """
query CortexXsiamPentest($page_input: PageInput!) {
  pentests_page(page_input: $page_input) {
    pentests {
      op_id
      name
      op_type
      state
      client_name
      completed_at
      etl_completed_at
      weaknesses_count
    }
  }
}
"""

# weaknesses_page is always scoped to a single pentest through input.op_id.
PENTEST_WEAKNESSES_QUERY = """
query CortexXsiamPentestWeaknesses($op_id: String!, $page_input: PageInput!) {
  weaknesses_page(input: {op_id: $op_id}, page_input: $page_input) {
    weaknesses {
      uuid
      op_id
      created_at
      vuln_id
      vuln_name
      vuln_short_name
      vuln_category
      vuln_cisa_kev
      vuln_known_ransomware_campaign_use
      severity
      score
      base_severity
      base_score
      context_severity
      context_score
      context_score_description
      has_proof
      proofs { proof_type }
      proof_failure_code
      proof_failure_reason
      ip
      affected_asset_uuid
      affected_asset_display_name
      affected_asset_short_name
      attack_paths_count
      affected_credentials_count
      impacts { impact_type score severity impact_paths_count }
      downstream_impact_types
      mitre_mappings { mitre_tactic_id mitre_technique_id mitre_subtechnique_id }
      time_to_finding_s
      time_to_finding_hms
      weakness_ref
      portal_url
      affected_host { uuid host_name host_names ip mac os_names is_in_scope }
      vuln { description mitigations { description } references { name url } }
    }
  }
}
"""

CONNECTIVITY_QUERY = """
query CortexXsiamConnectivity($page_input: PageInput!) {
  pentests_page(page_input: $page_input) {
    pentests {
      op_id
    }
  }
}
"""


class Pentest(TypedDict):
    op_id: str
    name: str | None
    op_type: str | None
    state: str | None
    client_name: str | None
    completed_at: str | None
    etl_completed_at: str | None
    weaknesses_count: int | None


class InProgress(TypedDict):
    pentest: Pentest
    next_page: int
    sent: int


class LastRun(TypedDict):
    """The collection state: kept in the integration context, mirrored in the fetch checkpoint.

    floor and watermark are None until the first fetch, when only manual pushes have run. pruned_before is the largest
    pruning cutoff so far: every pentest whose results became available from floor up to it was sent.
    """

    version: int
    floor: str | None
    watermark: str | None
    pruned_before: str | None
    sent_ops: dict[str, str]
    in_progress: InProgress | None


def monotonic_seconds() -> float:
    """Read the monotonic clock at call time."""
    return time.monotonic()


def wall_seconds() -> float:
    """Epoch seconds, for lease expiry times that other runs read."""
    return time.time()


def pause(seconds: float) -> None:
    # The only sleep in the integration: the short settle before a new lease is read back (see acquire_lease). It isn't
    # retry or rate-limit waiting.
    time.sleep(seconds)  # pylint: disable=E9003


@dataclass
class Deadline:
    """The monotonic deadline of one command run. Tests can pass a fake clock."""

    started_at: float
    expires_at: float
    clock: Callable[[], float] = monotonic_seconds

    @classmethod
    def after(cls: type["Deadline"], seconds: float, clock: Callable[[], float] = monotonic_seconds) -> "Deadline":
        now = clock()
        return cls(started_at=now, expires_at=now + seconds, clock=clock)

    def seconds_left(self) -> float:
        return self.expires_at - self.clock()

    def elapsed(self) -> float:
        return self.clock() - self.started_at


# ----- value helpers -----


def as_text(value: Any) -> str | None:
    """A non-empty string, or None, so a missing value is always null and never an empty string."""
    return value if isinstance(value, str) and value else None


def as_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def as_float(value: Any) -> float | None:
    """A finite number as a float (the API sends whole-number scores as integers), or None."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def as_text_list(value: Any) -> list[str]:
    """The non-empty strings of a list; anything else gives an empty list."""
    return [item for item in value if isinstance(item, str) and item] if isinstance(value, list) else []


def as_text_list_or_none(value: Any) -> list[str] | None:
    """Like as_text_list, but keeps the API's own null."""
    return None if value is None else as_text_list(value)


def dict_items(value: Any) -> list[dict[str, Any]]:
    """The dictionary entries of a list; anything else gives an empty list."""
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def unique(values: Iterable[str]) -> list[str]:
    """Distinct values in first-seen order."""
    return list(dict.fromkeys(values))


def to_naive_utc(value: datetime) -> datetime:
    return value.astimezone(UTC).replace(tzinfo=None) if value.tzinfo else value


def parse_api_time(value: Any) -> datetime | None:
    """Parse an ISO 8601 timestamp as naive UTC. A value without a zone is UTC, which is how the API sends it."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text[-1] in "Zz":
        text = f"{text[:-1]}+00:00"
    try:
        return to_naive_utc(datetime.fromisoformat(text))
    except ValueError:
        return None


def to_iso_utc(value: Any) -> str | None:
    """Format an API timestamp as YYYY-MM-DDTHH:MM:SS.mmmZ, or None when it can't be parsed."""
    parsed = parse_api_time(value)
    if parsed is None:
        return None
    return f"{parsed.strftime('%Y-%m-%dT%H:%M:%S')}.{parsed.microsecond // 1000:03d}Z"


def format_filter_time(value: datetime) -> str:
    """Format a time for an API filter: naive UTC with whole seconds."""
    return to_naive_utc(value).strftime(FILTER_TIME_FORMAT)


def require_time(value: str | None) -> datetime:
    parsed = parse_api_time(value)
    if parsed is None:
        raise DemistoException("The fetch checkpoint holds a timestamp that can't be read.")
    return parsed


# ----- shared layer: host-name validation, host fields, MITRE flattening, reserved-key check (pure functions) -----


def normalize_host_value(value: Any) -> str | None:
    """Trim whitespace and remove one trailing dot."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("."):
        text = text[:-1]
    return text or None


def parse_ip_literal(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The address in an IP literal, or None. The value is normalized first; an IPv6 literal may be in brackets."""
    text = normalize_host_value(value)
    if text is None:
        return None
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def is_ip_literal(value: str | None) -> bool:
    return parse_ip_literal(value) is not None


def is_valid_hostname(value: str | None) -> bool:
    """RFC 1123 host-name check that also rejects IP literals and version-like strings such as 6.7.0."""
    name = normalize_host_value(value)
    if not name or len(name) > MAX_HOSTNAME_LENGTH or is_ip_literal(name):
        return False
    labels = name.split(".")
    if not all(HOSTNAME_LABEL_PATTERN.fullmatch(label) for label in labels):
        return False
    if labels[-1].isdigit():  # for example 6.7.0, 1234 or 10.0.0.256
        return False
    return len(labels) == 1 or not all(label[0].isdigit() for label in labels)  # for example 6.7.0-beta or 1.2.3


def host_name_candidates(host: dict[str, Any]) -> list[str]:
    """affected_host.host_name, then each entry of affected_host.host_names."""
    return [name for name in [host.get("host_name"), *as_text_list(host.get("host_names"))] if isinstance(name, str)]


def valid_hostnames(candidates: list[str]) -> list[str]:
    """The distinct, normalized candidates that are valid host names, in order."""
    names: list[str] = []
    for candidate in candidates:
        name = normalize_host_value(candidate)
        if name and name not in names and is_valid_hostname(candidate):
            names.append(name)
    return names


def split_addresses(candidates: list[Any]) -> tuple[list[str], list[str]]:
    """The distinct IPv4 and IPv6 addresses among the candidates, in order."""
    ipv4: list[str] = []
    ipv6: list[str] = []
    for candidate in candidates:
        address = parse_ip_literal(candidate)
        if address is None:
            continue
        bucket = ipv4 if address.version == 4 else ipv6
        if str(address) not in bucket:
            bucket.append(str(address))
    return ipv4, ipv6


def join_os_names(os_names: Any) -> str | None:
    names = unique(as_text_list(os_names))
    return ", ".join(names) if names else None


def build_host_fields(weakness: dict[str, Any]) -> dict[str, Any]:
    """The target_* fields. Only valid host names reach the name fields, and IP literals go to the address fields."""
    host = weakness.get("affected_host")
    host = host if isinstance(host, dict) else {}
    names = host_name_candidates(host)
    hostnames = valid_hostnames(names)
    ipv4, ipv6 = split_addresses([host.get("ip"), weakness.get("ip"), *names])
    mac = host.get("mac")
    return {
        "target_hostname": hostnames[0] if hostnames else None,
        "target_fqdn": next((name for name in hostnames if "." in name), None),
        "target_ipv4_addresses": ipv4,
        "target_ipv6_addresses": ipv6,
        "target_mac_addresses": [mac] if isinstance(mac, str) and mac.strip() else [],
        "target_os": join_os_names(host.get("os_names")),
    }


def flatten_mitre(mappings: list[dict[str, Any]] | None) -> tuple[list[str], list[str]]:
    """Distinct tactic IDs, and distinct technique IDs plus any sub-technique IDs, in first-seen order."""
    tactic_ids: list[str] = []
    technique_ids: list[str] = []
    for mapping in dict_items(mappings):
        tactic_ids.append(mapping.get("mitre_tactic_id") or "")
        technique_ids.extend([mapping.get("mitre_technique_id") or "", mapping.get("mitre_subtechnique_id") or ""])
    return clean_ids(tactic_ids), clean_ids(technique_ids)


def clean_ids(values: list[Any]) -> list[str]:
    return unique(value.strip() for value in values if isinstance(value, str) and value.strip())


def find_reserved_keys(event: dict[str, Any]) -> list[str]:
    """Event keys that start with an underscore, other than _time. Such keys are reserved by Cortex."""
    return [key for key in event if key.startswith("_") and key != "_time"]


# ----- client -----


# Known limitation: a run can overrun RUN_BUDGET_SECONDS.
# A request that starts with NO_RETRY_BELOW_SECONDS or more left keeps MAX_RETRIES retries, each with a timeout of up to
# REQUEST_TIMEOUT_SECONDS, plus backoff and any Retry-After sleep the server asks for. The deadline is only checked between
# requests, so a hung or throttling server can hold one request for several minutes. If the platform kills the run, the
# state committed to the integration context after each page means only the page in flight is sent again, and event_id
# lets queries drop those duplicates. The lease (LEASE_TTL_SECONDS) outlasts such an overrun, and no send starts once
# fewer than LEASE_SAFETY_SECONDS of it are left, so an overrunning run never sends alongside another run.
# Symptom: fetch runs that time out or last well past RUN_BUDGET_SECONDS, and repeated event_id values in the dataset.
# Proposed fix: make retries deadline-aware. Override BaseClient._implement_retry to mount a urllib3 Retry subclass that
# stops retrying, and caps Retry-After sleeps, once the next attempt can't finish before the deadline. Also split the time
# left across the attempts, for example timeout = seconds_left / (retries + 1).
def request_limits(seconds_left: float) -> tuple[float, int]:
    """The timeout and retry count of one request, bounded by the time left in the run."""
    timeout = max(MIN_REQUEST_TIMEOUT_SECONDS, min(REQUEST_TIMEOUT_SECONDS, seconds_left))
    retries = MAX_RETRIES if seconds_left >= NO_RETRY_BELOW_SECONDS else 0
    return timeout, retries


def response_json(response: requests.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return None


def graphql_error_text(errors: Any) -> str:
    """The servers' error messages, trimmed, so a message's own full stop isn't followed by another."""
    messages = [str(error.get("message")).strip() for error in dict_items(errors) if error.get("message")]
    text = "; ".join(message for message in messages if message)[:MAX_ERROR_DETAIL_LENGTH].rstrip()
    return text or "no error message was returned"


def version_text(read: Callable[[], Any]) -> str:
    """The version that read() returns, or UNKNOWN_VERSION when it raises, is empty, or isn't safe in a header."""
    try:
        value = read()
        text = str.strip(value) if isinstance(value, str) else ""  # str.strip gives a plain str, even for a subclass
    except Exception:
        return UNKNOWN_VERSION
    return text if VERSION_PATTERN.fullmatch(text) else UNKNOWN_VERSION


def read_pack_version() -> Any:
    """CONSTANT_PACK_VERSION, which demisto-sdk writes into this script when it unifies it. get_pack_version() reads the
    same global, but on Base packs older than 1.41.4 it makes internal API calls instead, so it is only the fallback."""
    return globals().get("CONSTANT_PACK_VERSION") or get_pack_version()


def read_platform_version() -> Any:
    return demisto.demistoVersion().get("version")


def build_user_agent() -> str:
    """NodeZero-Cortex/<pack version> (NodeZeroEventCollector; Cortex <platform version>). Raises no Exception: a
    version that can't be read is "unknown"."""
    pack_version = version_text(read_pack_version)  # '' until demisto-sdk unifies the integration, as in unit tests
    platform_version = version_text(read_platform_version)
    return f"{USER_AGENT_PRODUCT}/{pack_version} ({INTEGRATION_NAME}; Cortex {platform_version})"


def request_id_of(response: requests.Response | None) -> str | None:
    """The X-Request-ID that the failed request carried, or None when the response doesn't record its request."""
    headers = getattr(getattr(response, "request", None), "headers", None)
    request_id = headers.get(REQUEST_ID_HEADER) if isinstance(headers, Mapping) else None
    return request_id if isinstance(request_id, str) and request_id else None


def with_request_id(message: str, response: requests.Response | None) -> str:
    """The message, ending with the X-Request-ID of the request that got this response, when the response records it."""
    request_id = request_id_of(response)
    if request_id is None:
        return message
    message = message if message.endswith(".") else f"{message}."
    return f"{message} Request ID: {request_id}."


def raise_http_error(response: requests.Response) -> None:
    """Error handler for every NodeZero request. The message includes no header other than the request ID, and no body
    the collector sent."""
    body = response_json(response)
    message = f"NodeZero API request failed with HTTP {response.status_code}"
    if response.reason:
        message += f" ({response.reason})"
    if isinstance(body, dict) and body.get("errors"):
        message += f": {graphql_error_text(body['errors'])}"
    message = message if message.endswith(".") else f"{message}."  # server messages often end with a full stop
    if response.status_code in (401, 403):
        message += " Verify that the API key is valid and has read access to pentests and weaknesses."
    raise DemistoException(with_request_id(message, response), res=response)


def http_status(error: Exception) -> int | None:
    status = getattr(getattr(error, "res", None), "status_code", None)
    return status if isinstance(status, int) else None


def parse_graphql_data(response: requests.Response) -> dict[str, Any]:
    """The data of a GraphQL response. An errors array, which can come with HTTP 200, raises."""
    body = response_json(response)
    if not isinstance(body, dict):
        raise DemistoException(with_request_id("NodeZero returned a GraphQL response that is not a JSON object.", response))
    if body.get("errors"):
        message = f"NodeZero GraphQL request failed: {graphql_error_text(body['errors'])}"
        raise DemistoException(with_request_id(message, response))
    data = body.get("data")
    if not isinstance(data, dict):
        raise DemistoException(with_request_id("NodeZero returned a GraphQL response without data.", response))
    return data


def page_rows(
    data: dict[str, Any], page_field: str, rows_field: str, response: requests.Response | None = None
) -> list[dict[str, Any]]:
    """The rows of a *_page result. A missing list raises, because treating it as empty could skip data."""
    page = data.get(page_field)
    rows = page.get(rows_field) if isinstance(page, dict) else None
    if not isinstance(rows, list):
        message = f"NodeZero returned a {page_field} result without a {rows_field} list."
        raise DemistoException(with_request_id(message, response))
    return [row for row in rows if isinstance(row, dict)]


def parse_token(response: requests.Response) -> str:
    body = response_json(response)
    token = body.get("token") if isinstance(body, dict) else None
    if not isinstance(token, str) or not token:
        raise DemistoException(with_request_id("The NodeZero authentication response did not include a token.", response))
    return token


def decode_jwt_claims(token: str) -> dict[str, Any]:
    """The claims of a JWT, read without verifying the signature. Anything unreadable gives an empty dict."""
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except ValueError:
        return {}
    return claims if isinstance(claims, dict) else {}


def read_token_expiry(token: str, now: int) -> int:
    """The token's expiry in epoch seconds, from its exp claim, or now plus the default lifetime."""
    expiry = decode_jwt_claims(token).get("exp")
    if isinstance(expiry, int | float) and not isinstance(expiry, bool) and expiry > now:
        return int(expiry)
    return now + DEFAULT_TOKEN_LIFETIME_SECONDS


def load_cached_token(now: float, owner: str) -> str | None:
    """The token cached in the integration context, unless it expires within the refresh margin."""
    context = get_integration_context() or {}
    if context.get(TOKEN_OWNER_CONTEXT_KEY) != owner:
        return None
    token = context.get(TOKEN_CONTEXT_KEY)
    expires_at = as_int(context.get(TOKEN_EXPIRY_CONTEXT_KEY)) or 0
    if not isinstance(token, str) or not token or expires_at - TOKEN_REFRESH_MARGIN_SECONDS <= now:
        return None
    return token


def token_context_updates(token: str, expires_at: int, owner: str) -> dict[str, Any]:
    """The integration-context keys of the token cache. Only a lease holder writes them, merged into the context."""
    return {TOKEN_CONTEXT_KEY: token, TOKEN_EXPIRY_CONTEXT_KEY: expires_at, TOKEN_OWNER_CONTEXT_KEY: owner}


def build_sweep_variables(since: str, page_num: int) -> dict[str, Any]:
    """Variables for one sweep page: done pentests whose results became available at or after `since`."""
    return {
        "page_input": {
            "page_num": page_num,
            "page_size": PAGE_SIZE,
            "filter_by_inputs": [
                {"field_name": "state", "values": list(FINISHED_STATES)},
                {"field_name": "etl_completed_at", "greater_than_or_equal": since},
            ],
            "sort_inputs": [
                {"order_by": "etl_completed_at", "sort_order": "ASC"},
                {"order_by": "op_id", "sort_order": "ASC"},
            ],
        }
    }


def build_pentest_variables(op_id: str) -> dict[str, Any]:
    """Variables for reading one pentest by op_id with PENTEST_QUERY. The match is exact, so the ID must be trimmed."""
    return {"page_input": {"page_num": 1, "page_size": 1, "filter_by_inputs": [{"field_name": "op_id", "values": [op_id]}]}}


def build_weaknesses_variables(op_id: str, page_num: int) -> dict[str, Any]:
    """Variables for one page of one pentest's weaknesses, in uuid order so pages stay stable."""
    if not op_id:
        raise DemistoException("A pentest op_id is required to read weaknesses.")
    return {
        "op_id": op_id,
        "page_input": {"page_num": page_num, "page_size": PAGE_SIZE, "order_by": "uuid", "sort_order": "ASC"},
    }


class Client(BaseClient):
    """NodeZero API client: API-key exchange, token cache, and GraphQL requests bounded by the run deadline."""

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool, deadline: Deadline) -> None:
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._api_key = api_key
        self._owner = hashlib.sha256(f"{base_url}\n{api_key}".encode()).hexdigest()[:16]
        self.deadline = deadline
        self._token: str | None = None
        self._token_expires_at = 0
        # Set while the run holds the lease. Without it, a new token stays in memory: a run that doesn't hold the
        # lease never writes the integration context, so it can't overwrite the shared state with a stale copy.
        self.token_sink: Callable[[dict[str, Any]], None] | None = None
        add_sensitive_log_strs(api_key)
        # One client serves one command run, so the run ID is per run. Fetches and pushes also log it in their summary.
        self.run_id = uuid.uuid4().hex
        self.request_count = 0
        self.last_response: requests.Response | None = None  # the last GraphQL response, so page errors name its request
        self._user_agent = build_user_agent()
        demisto.debug(f"NodeZero run ID {self.run_id}, User-Agent {self._user_agent}.")

    def identity_headers(self) -> dict[str, str]:
        """The User-Agent and the next X-Request-ID of this run: <run id>-<n>, n counting the run's requests from 1.

        Retries that urllib3 makes inside one request, and a redirect that requests follows, resend the same headers,
        so they share its request ID.
        """
        self.request_count += 1
        return {"User-Agent": self._user_agent, REQUEST_ID_HEADER: f"{self.run_id}-{self.request_count}"}

    def _post(self, url_suffix: str, json_data: dict[str, Any], headers: dict[str, str] | None = None) -> requests.Response:
        timeout, retries = request_limits(self.deadline.seconds_left())
        if not retries:
            self._implement_retry(retries=0)  # replace a retrying adapter that an earlier request mounted
        return self._http_request(
            method="POST",
            url_suffix=url_suffix,
            json_data=json_data,
            # _http_request sends per-call headers instead of the client's own, so the identity goes into every call.
            headers={**(headers or {}), **self.identity_headers()},
            timeout=timeout,
            retries=retries,
            status_list_to_retry=RETRY_STATUSES,
            backoff_factor=BACKOFF_FACTOR,
            backoff_jitter=BACKOFF_JITTER,
            resp_type="response",
            error_handler=raise_http_error,
        )

    def authenticate(self) -> str:
        """Exchange the API key for a new token. A lease holder also caches it in the integration context."""
        now = int(time.time())
        token = parse_token(self._post(AUTH_SUFFIX, {"key": self._api_key}))
        add_sensitive_log_strs(token)
        self._token, self._token_expires_at = token, read_token_expiry(token, now)
        if self.token_sink is not None:
            self.token_sink(token_context_updates(token, self._token_expires_at, self._owner))
        demisto.debug("Received a new NodeZero API token.")
        return token

    def get_token(self) -> str:
        """This run's token, else the cached one, else a new one. A token about to expire is never used."""
        now = time.time()
        if self._token is not None and self._token_expires_at - TOKEN_REFRESH_MARGIN_SECONDS > now:
            return self._token
        token = load_cached_token(now, self._owner)
        if token is None:
            return self.authenticate()
        add_sensitive_log_strs(token)
        return token

    def _post_graphql(self, query: str, variables: dict[str, Any], token: str) -> requests.Response:
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        return self._post(GRAPHQL_SUFFIX, {"query": query, "variables": variables}, headers)

    def graphql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        """Run one GraphQL request and return its data. An HTTP 401 triggers one new authentication."""
        token = self.get_token()
        try:
            response = self._post_graphql(query, variables, token)
        except DemistoException as error:
            if http_status(error) != 401:
                raise
            demisto.debug("NodeZero rejected the cached token. Authenticating again once.")
            response = self._post_graphql(query, variables, self.authenticate())
        self.last_response = response
        return parse_graphql_data(response)

    def get_finished_pentests(self, since: str, page_num: int) -> list[dict[str, Any]]:
        """One sweep page of raw pentest rows."""
        data = self.graphql(FINISHED_PENTESTS_QUERY, build_sweep_variables(since, page_num))
        return page_rows(data, "pentests_page", "pentests", self.last_response)

    def get_pentest(self, op_id: str) -> list[dict[str, Any]]:
        """The raw row of one pentest, or no rows. The server returns no rows for an unknown or malformed op_id."""
        data = self.graphql(PENTEST_QUERY, build_pentest_variables(op_id))
        return page_rows(data, "pentests_page", "pentests", self.last_response)

    def get_weaknesses_page(self, op_id: str, page_num: int) -> list[dict[str, Any]]:
        """One page of raw weakness rows of one pentest. Any failure names the pentest."""
        variables = build_weaknesses_variables(op_id, page_num)
        try:
            data = self.graphql(PENTEST_WEAKNESSES_QUERY, variables)
            return page_rows(data, "weaknesses_page", "weaknesses", self.last_response)
        except LeaseLost:
            raise  # raised by the token cache write, not by the request
        except DemistoException as error:
            message = f"Failed to read page {page_num} of the weaknesses of pentest {op_id}. {error}"
            raise DemistoException(message, res=getattr(error, "res", None)) from error

    def check_connectivity(self) -> None:
        """Read one pentest, which proves the URL, the token and read access."""
        self.graphql(CONNECTIVITY_QUERY, {"page_input": {"page_num": 1, "page_size": 1}})


# ----- events -----


def to_pentest(row: Any) -> Pentest | None:
    """Keep the known pentest fields of an API row, or return None when the row has no op_id."""
    if not isinstance(row, dict) or as_text(row.get("op_id")) is None:
        return None
    return Pentest(
        op_id=row["op_id"],
        name=as_text(row.get("name")),
        op_type=as_text(row.get("op_type")),
        state=as_text(row.get("state")),
        client_name=as_text(row.get("client_name")),
        completed_at=as_text(row.get("completed_at")),
        etl_completed_at=as_text(row.get("etl_completed_at")),
        weaknesses_count=as_int(row.get("weaknesses_count")),
    )


def is_finished(pentest: Pentest) -> bool:
    """Done, with results available. Checked again here, on top of the query filters, so an ended pentest is skipped."""
    return pentest["state"] in FINISHED_STATES and parse_api_time(pentest["etl_completed_at"]) is not None


def finished_pentests(rows: list[dict[str, Any]]) -> list[Pentest]:
    pentests: list[Pentest] = []
    for row in rows:
        pentest = to_pentest(row)
        if pentest is not None and is_finished(pentest):
            pentests.append(pentest)
        else:
            demisto.debug(f"Skipped a pentest row that is not finished or has no op_id: {row.get('op_id')}.")
    return pentests


def event_time(weakness: dict[str, Any], pentest: Pentest) -> tuple[str | None, bool]:
    """_time is the discovery time (created_at, UTC). If it can't be read, fall back to the pentest's times."""
    discovered = to_iso_utc(weakness.get("created_at"))
    if discovered is not None:
        return discovered, False
    return to_iso_utc(pentest["completed_at"]) or to_iso_utc(pentest["etl_completed_at"]), True


def event_identity_fields(weakness: dict[str, Any], pentest: Pentest) -> dict[str, Any]:
    time_value, used_fallback = event_time(weakness, pentest)
    fields: dict[str, Any] = {"_time": time_value}
    if used_fallback:
        fields["time_fallback"] = True
    op_id = as_text(weakness.get("op_id")) or pentest["op_id"]
    fields["source_log_type"] = SOURCE_LOG_TYPE
    fields["event_id"] = f"{op_id}:{as_text(weakness.get('uuid')) or ''}"
    return fields


def pentest_fields(pentest: Pentest) -> dict[str, Any]:
    return {
        "pentest_name": pentest["name"],
        "pentest_type": pentest["op_type"],
        "pentest_state": pentest["state"],
        "pentest_client_name": pentest["client_name"],
        "pentest_completed_at": to_iso_utc(pentest["completed_at"]) or pentest["completed_at"],
        "pentest_etl_completed_at": to_iso_utc(pentest["etl_completed_at"]) or pentest["etl_completed_at"],
        "pentest_weaknesses_count": pentest["weaknesses_count"],
    }


def weakness_core_fields(weakness: dict[str, Any], pentest: Pentest) -> dict[str, Any]:
    """Identifiers and the vulnerability identity. vuln_id is kept exactly as NodeZero returns it."""
    return {
        "uuid": as_text(weakness.get("uuid")),
        "op_id": as_text(weakness.get("op_id")) or pentest["op_id"],
        "created_at": as_text(weakness.get("created_at")),
        "vuln_id": as_text(weakness.get("vuln_id")),
        "vuln_name": as_text(weakness.get("vuln_name")),
        "vuln_short_name": as_text(weakness.get("vuln_short_name")),
        "vuln_category": as_text(weakness.get("vuln_category")),
        "vuln_cisa_kev": as_bool(weakness.get("vuln_cisa_kev")),
        "vuln_known_ransomware_campaign_use": as_bool(weakness.get("vuln_known_ransomware_campaign_use")),
    }


def weakness_score_fields(weakness: dict[str, Any]) -> dict[str, Any]:
    """Severity, scores (always floats) and proof metadata. Proof contents are never selected."""
    return {
        "severity": as_text(weakness.get("severity")),
        "score": as_float(weakness.get("score")),
        "base_severity": as_text(weakness.get("base_severity")),
        "base_score": as_float(weakness.get("base_score")),
        "context_severity": as_text(weakness.get("context_severity")),
        "context_score": as_float(weakness.get("context_score")),
        "context_score_description": as_text(weakness.get("context_score_description")),
        "has_proof": as_bool(weakness.get("has_proof")),
        "proof_types": unique(text for proof in dict_items(weakness.get("proofs")) if (text := as_text(proof.get("proof_type")))),
        "proof_failure_code": as_text(weakness.get("proof_failure_code")),
        "proof_failure_reason": as_text(weakness.get("proof_failure_reason")),
    }


def normalize_impacts(impacts: Any) -> list[dict[str, Any]]:
    return [
        {
            "impact_type": as_text(impact.get("impact_type")),
            "score": as_float(impact.get("score")),
            "severity": as_text(impact.get("severity")),
            "impact_paths_count": as_int(impact.get("impact_paths_count")),
        }
        for impact in dict_items(impacts)
    ]


def normalize_mitre_mappings(mappings: Any) -> list[dict[str, str | None]] | None:
    """The tactic, technique and sub-technique triples, kept together; the API's null stays null."""
    if mappings is None:
        return None
    keys = ("mitre_tactic_id", "mitre_technique_id", "mitre_subtechnique_id")
    return [{key: as_text(mapping.get(key)) for key in keys} for mapping in dict_items(mappings)]


def weakness_context_fields(weakness: dict[str, Any]) -> dict[str, Any]:
    tactic_ids, technique_ids = flatten_mitre(weakness.get("mitre_mappings"))
    return {
        "ip": as_text(weakness.get("ip")),
        "affected_asset_uuid": as_text(weakness.get("affected_asset_uuid")),
        "affected_asset_display_name": as_text(weakness.get("affected_asset_display_name")),
        "affected_asset_short_name": as_text(weakness.get("affected_asset_short_name")),
        "attack_paths_count": as_int(weakness.get("attack_paths_count")),
        "affected_credentials_count": as_int(weakness.get("affected_credentials_count")),
        "impacts": normalize_impacts(weakness.get("impacts")),
        "downstream_impact_types": as_text_list_or_none(weakness.get("downstream_impact_types")),
        "mitre_mappings": normalize_mitre_mappings(weakness.get("mitre_mappings")),
        "mitre_tactic_ids": tactic_ids,
        "mitre_technique_ids": technique_ids,
        "time_to_finding_s": as_int(weakness.get("time_to_finding_s")),
        "time_to_finding_hms": as_text(weakness.get("time_to_finding_hms")),
        "weakness_ref": as_text(weakness.get("weakness_ref")),
        "portal_url": as_text(weakness.get("portal_url")),
    }


def affected_host_fields(host: Any) -> dict[str, Any]:
    """The affected host as NodeZero reports it, not validated."""
    host = host if isinstance(host, dict) else {}
    return {
        "affected_host_uuid": as_text(host.get("uuid")),
        "affected_host_name": as_text(host.get("host_name")),
        "affected_host_names": as_text_list_or_none(host.get("host_names")),
        "affected_host_ip": as_text(host.get("ip")),
        "affected_host_mac": as_text(host.get("mac")),
        "affected_host_os_names": as_text_list_or_none(host.get("os_names")),
        "affected_host_is_in_scope": as_bool(host.get("is_in_scope")),
    }


def vuln_catalog_fields(vuln: Any) -> dict[str, Any]:
    vuln = vuln if isinstance(vuln, dict) else {}
    return {
        "vuln_description": as_text(vuln.get("description")),
        "vuln_mitigations": [text for item in dict_items(vuln.get("mitigations")) if (text := as_text(item.get("description")))],
        "vuln_references": [
            {"name": as_text(item.get("name")), "url": as_text(item.get("url"))} for item in dict_items(vuln.get("references"))
        ],
    }


def build_event(weakness: dict[str, Any], pentest: Pentest) -> dict[str, Any]:
    """One raw event for one weakness of one finished pentest. Every key keeps the same JSON type on every event."""
    event = event_identity_fields(weakness, pentest)
    event.update(pentest_fields(pentest))
    event.update(weakness_core_fields(weakness, pentest))
    event.update(weakness_score_fields(weakness))
    event.update(weakness_context_fields(weakness))
    event.update(affected_host_fields(weakness.get("affected_host")))
    event.update(build_host_fields(weakness))
    event.update(vuln_catalog_fields(weakness.get("vuln")))
    return event


def event_size(event: dict[str, Any]) -> int:
    """The serialized size, measured the way the event is sent."""
    return len(json.dumps(event))


def truncate_item(item: Any) -> Any:
    if isinstance(item, str):
        return item[:TEXT_FIELD_CAP]
    if isinstance(item, dict):
        return {key: value[:TEXT_FIELD_CAP] if isinstance(value, str) else value for key, value in item.items()}
    return item


def truncate_value(value: Any) -> Any:
    """Cut a string to TEXT_FIELD_CAP characters, or keep a list's items, in order, within that many serialized characters.

    A string item that crosses the limit is cut to fit and ends the list. Any other item that doesn't fit is skipped, so
    one oversized reference doesn't empty the rest of the list.
    """
    if isinstance(value, str):
        return value[:TEXT_FIELD_CAP]
    if not isinstance(value, list):
        return value
    kept: list[Any] = []
    budget = TEXT_FIELD_CAP
    for item in value:
        short_item = truncate_item(item)
        size = len(json.dumps(short_item))
        if size > budget:
            if not isinstance(short_item, str):
                continue  # skipped; later, smaller items can still fit
            if budget > 2:
                kept.append(short_item[: budget - 2])  # the two quotes use the rest of the budget
            break
        kept.append(short_item)
        budget -= size
    return kept


def cap_event_size(event: dict[str, Any]) -> dict[str, Any]:
    """Keep an event within MAX_EVENT_BYTES by truncating long fields. The event is never dropped."""
    if event_size(event) <= MAX_EVENT_BYTES:
        return event
    capped = dict(event)
    for key in TRUNCATABLE_FIELDS:
        if key in capped:
            capped[key] = truncate_value(capped[key])
    if event_size(capped) > MAX_EVENT_BYTES:
        for key in capped:
            if key not in UNTRUNCATED_FIELDS:
                capped[key] = truncate_value(capped[key])
    capped["truncated"] = True
    demisto.debug(f"Event {event.get('event_id')} was larger than {MAX_EVENT_BYTES} bytes. Its long fields were truncated.")
    return capped


def build_page_events(rows: list[dict[str, Any]], pentest: Pentest, seen: set[str]) -> list[dict[str, Any]]:
    """The events of one page. A uuid already seen during this pull is skipped."""
    events: list[dict[str, Any]] = []
    for row in rows:
        uuid = as_text(row.get("uuid"))
        if uuid is not None and uuid in seen:
            demisto.debug(f"Pentest {pentest['op_id']}: skipped a repeated weakness {uuid}.")
            continue
        if uuid is not None:
            seen.add(uuid)
        events.append(cap_event_size(build_event(row, pentest)))
    return events


# ----- collection state -----


def new_last_run(first_fetch: datetime) -> LastRun:
    """The state of a first fetch. The floor is fixed here and later sweeps never go below it."""
    start = format_filter_time(first_fetch)
    return LastRun(version=LAST_RUN_VERSION, floor=start, watermark=start, pruned_before=None, sent_ops={}, in_progress=None)


def empty_state() -> LastRun:
    """The state a manual push starts when no fetch has run: nothing sent and no fetch window yet."""
    return LastRun(version=LAST_RUN_VERSION, floor=None, watermark=None, pruned_before=None, sent_ops={}, in_progress=None)


def copy_state(state: LastRun) -> LastRun:
    """A copy that can be changed without touching the original, which stays as committed."""
    cursor = state["in_progress"]
    in_progress = None
    if cursor is not None:
        in_progress = InProgress(pentest=cursor["pentest"], next_page=cursor["next_page"], sent=cursor["sent"])
    return LastRun(
        version=LAST_RUN_VERSION,
        floor=state["floor"],
        watermark=state["watermark"],
        pruned_before=state["pruned_before"],
        sent_ops=dict(state["sent_ops"]),
        in_progress=in_progress,
    )


def time_text_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and parse_api_time(value) is not None else None


def load_sent_ops(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {op_id: completed for op_id, completed in value.items() if isinstance(op_id, str) and isinstance(completed, str)}


def load_in_progress(value: Any) -> InProgress | None:
    """The page cursor of a half-sent pentest, or None when it is missing, malformed, or for an unfinished pentest."""
    if not isinstance(value, dict):
        return None
    pentest = to_pentest(value.get("pentest"))
    next_page = as_int(value.get("next_page"))
    sent = as_int(value.get("sent"))
    if pentest is None or not is_finished(pentest) or next_page is None or next_page < 1 or sent is None or sent < 0:
        return None
    return InProgress(pentest=pentest, next_page=next_page, sent=sent)


def parse_state(raw: Any) -> LastRun | None:
    """Rebuild a state from known keys only, or None when it is missing or has an unknown version."""
    if not isinstance(raw, dict) or raw.get("version") != LAST_RUN_VERSION:
        return None
    floor = time_text_or_none(raw.get("floor"))
    sent_ops = load_sent_ops(raw.get("sent_ops"))
    in_progress = load_in_progress(raw.get("in_progress"))
    if in_progress is not None and in_progress["pentest"]["op_id"] in sent_ops:
        in_progress = None
    return LastRun(
        version=LAST_RUN_VERSION,
        floor=floor,
        watermark=time_text_or_none(raw.get("watermark")) or floor,
        pruned_before=time_text_or_none(raw.get("pruned_before")),
        sent_ops=sent_ops,
        in_progress=in_progress,
    )


def with_fetch_window(state: LastRun, first_fetch: datetime) -> LastRun:
    """The state with a floor and a watermark. Until a fetch sets them, only manual pushes have run."""
    updated = copy_state(state)
    updated["floor"] = state["floor"] or format_filter_time(first_fetch)
    updated["watermark"] = state["watermark"] or updated["floor"]
    return updated


def load_last_run(raw: Any, first_fetch: datetime) -> LastRun:
    """Rebuild the state from the fetch checkpoint. A missing or unknown version starts a first fetch.

    A checkpoint written before pruned_before existed was already pruned up to SENT_RETENTION before its watermark, so
    that cutoff is restored; otherwise a pentest pruned from it would no longer count as sent.
    """
    state = parse_state(raw)
    if state is None:
        demisto.info("No fetch checkpoint with a known version was found. Starting a first fetch.")
        return new_last_run(first_fetch)
    state = with_fetch_window(state, first_fetch)
    if state["pruned_before"] is None:
        cutoff = require_time(state["watermark"]) - SENT_RETENTION
        state["pruned_before"] = cutoff.isoformat(timespec="microseconds")
    return state


def load_shared_state() -> LastRun | None:
    """The state in the integration context, or None when no run has stored one yet."""
    return parse_state((get_integration_context() or {}).get(STATE_CONTEXT_KEY))


def load_fetch_state(raw_last_run: Any, first_fetch: datetime) -> LastRun:
    """The state a fetch starts from. The integration context is authoritative; the checkpoint only seeds it.

    The context has no state on the first run of this version, or after it was wiped. The checkpoint then supplies the
    state of the last fetch, so nothing it sent is sent again.
    """
    state = load_shared_state()
    if state is None:
        demisto.info("The integration context holds no collection state. Starting from the fetch checkpoint.")
        return load_last_run(raw_last_run, first_fetch)
    if state["floor"] is None:  # only manual pushes stored this state: add what earlier fetches sent, if anything
        seed = load_last_run(raw_last_run, first_fetch)
        seed["sent_ops"].update(state["sent_ops"])
        cursor = state["in_progress"] or seed["in_progress"]
        seed["in_progress"] = cursor if cursor and cursor["pentest"]["op_id"] not in seed["sent_ops"] else None
        return seed
    return with_fetch_window(state, first_fetch)


def save_last_run(last_run: LastRun, more_pending: bool) -> None:
    """Store the checkpoint mirror. nextTrigger is added only when work remains, so a stale value never carries over."""
    payload: dict[str, Any] = dict(last_run)
    if more_pending:
        payload["nextTrigger"] = NEXT_TRIGGER_NOW
    demisto.setLastRun(payload)


def later_time_text(current: str | None, candidate: str | None) -> str | None:
    """The later of two API timestamps, keeping the text exactly as the API returned it."""
    current_time, candidate_time = parse_api_time(current), parse_api_time(candidate)
    if candidate_time is None or (current_time is not None and candidate_time <= current_time):
        return current
    return candidate


def is_sent(state: LastRun, pentest: Pentest) -> bool:
    """Whether the pentest was fully sent: it is recorded, or its results became available from floor to pruned_before."""
    if pentest["op_id"] in state["sent_ops"]:
        return True
    completed = parse_api_time(pentest["etl_completed_at"])
    floor = parse_api_time(state["floor"])
    pruned_before = parse_api_time(state["pruned_before"])
    if completed is None or floor is None or pruned_before is None:
        return False
    return floor <= completed < pruned_before


def with_pentest_sent(state: LastRun, pentest: Pentest) -> LastRun:
    """The state with the pentest recorded as fully sent and no page cursor."""
    updated = copy_state(state)
    updated["sent_ops"][pentest["op_id"]] = pentest["etl_completed_at"] or ""
    updated["in_progress"] = None
    return updated


def with_cursor(state: LastRun, pentest: Pentest, next_page: int, sent: int) -> LastRun:
    updated = copy_state(state)
    updated["in_progress"] = InProgress(pentest=pentest, next_page=next_page, sent=sent)
    return updated


def unchanged(state: LastRun) -> LastRun:
    return state


def advance_watermark(state: LastRun, swept: list[Pentest]) -> LastRun:
    """Move the watermark over the oldest-first prefix of the sweep that is all sent, whoever sent it.

    A manual push can send a pentest that is newer than one the fetch hasn't sent yet, so the watermark never moves past
    an unsent pentest; a sweep window that starts after it would skip it.
    """
    updated = copy_state(state)
    for pentest in swept:
        if not is_sent(updated, pentest):
            break
        updated["watermark"] = later_time_text(updated["watermark"], pentest["etl_completed_at"])
    return updated


def prune_sent_ops(state: LastRun) -> LastRun:
    """Forget sent pentests whose results became available from floor up to SENT_RETENTION before the watermark.

    pruned_before records the cutoff, so a forgotten pentest still counts as sent (is_sent). A pentest older than floor
    can only have been sent by a manual push, and nothing else records it, so it is kept.
    """
    floor = require_time(state["floor"])
    cutoff = require_time(state["watermark"]) - SENT_RETENTION

    def keep(completed: str) -> bool:
        completed_time = parse_api_time(completed)
        return completed_time is not None and not floor <= completed_time < cutoff

    updated = copy_state(state)
    updated["sent_ops"] = {op_id: completed for op_id, completed in state["sent_ops"].items() if keep(completed)}
    updated["pruned_before"] = later_time_text(state["pruned_before"], cutoff.isoformat(timespec="microseconds"))
    return updated


def sweep_start(state: LastRun) -> str:
    """The sweep window start: the watermark minus LOOKBACK, never before the floor or the pruned range."""
    floor = require_time(state["floor"])
    watermark = parse_api_time(state["watermark"]) or floor
    pruned_before = parse_api_time(state["pruned_before"]) or floor
    return format_filter_time(max(watermark - LOOKBACK, floor, pruned_before))


# ----- coordination between the fetch and a manual push -----


@dataclass
class Lease:
    owner: str
    token: str
    expires_at: float  # epoch seconds


def describe_lease(lease: Lease | None) -> str:
    if lease is None:
        return "another run"
    owners = {OWNER_FETCH: "a scheduled fetch", OWNER_COMMAND: "a manual run of nodezero-fetch-events"}
    owner = owners.get(lease.owner, "another run")
    until = datetime.fromtimestamp(lease.expires_at, UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    return f"{owner} (until {until} at the latest)"


class LeaseBusy(DemistoException):
    """Another run holds an unexpired lease."""

    def __init__(self, holder: Lease | None) -> None:
        self.holder = holder
        super().__init__(f"The collection lease is held by {describe_lease(holder)}.")


class LeaseLost(DemistoException):
    """The lease expired and another run took it. The run stops without sending more."""


def parse_lease(value: Any) -> Lease | None:
    if not isinstance(value, dict):
        return None
    owner, token, expires_at = value.get("owner"), value.get("token"), as_float(value.get("expires_at"))
    if not isinstance(owner, str) or not isinstance(token, str) or expires_at is None:
        return None
    return Lease(owner=owner, token=token, expires_at=expires_at)


def lease_payload(lease: Lease) -> dict[str, Any]:
    return {"owner": lease.owner, "token": lease.token, "expires_at": lease.expires_at}


def update_context(change: Callable[[dict[str, Any]], None]) -> None:
    """Read, change and write the integration context as one versioned write, retried when another write got in first.

    A write that carries a stale version fails on the platform, and the change is applied again to a fresh read. The
    error a version conflict raises isn't documented, so any failed write is retried. change may raise LeaseBusy or
    LeaseLost, which end the update without a write.
    """
    last_error: Exception | None = None
    for _ in range(CONTEXT_WRITE_ATTEMPTS):
        context, version = get_integration_context_with_version(sync=True)
        updated = dict(context or {})
        change(updated)
        try:
            set_integration_context(updated, sync=True, version=version)
            return
        except Exception as error:
            last_error = error
            demisto.debug(f"An integration context write failed, probably because another run wrote first: {error}")
    raise DemistoException("Failed to update the integration context after several attempts.") from last_error


def acquire_lease(owner: str) -> Lease:
    """Take the lease, or raise LeaseBusy when another run holds an unexpired one."""
    lease = Lease(owner=owner, token=uuid.uuid4().hex, expires_at=wall_seconds() + LEASE_TTL_SECONDS)

    def take(context: dict[str, Any]) -> None:
        holder = parse_lease(context.get(LEASE_CONTEXT_KEY))
        if holder is not None and holder.token != lease.token and holder.expires_at > wall_seconds():
            raise LeaseBusy(holder)
        context[LEASE_CONTEXT_KEY] = lease_payload(lease)

    update_context(take)
    # Without enforced context versions, two runs can both write a lease and the later write wins. Reading the lease
    # back after a pause lets the run that lost see the other token and back off.
    try:
        pause(LEASE_SETTLE_SECONDS)
        holder = parse_lease((get_integration_context() or {}).get(LEASE_CONTEXT_KEY))
    except Exception:
        release_lease(lease)
        raise
    if holder is None or holder.token != lease.token:
        raise LeaseBusy(holder)
    demisto.debug(f"Took the collection lease as {owner}.")
    return lease


def release_lease(lease: Lease) -> None:
    """Give the lease back if this run still holds it. A failure only delays the other path until the lease expires."""

    def give_back(context: dict[str, Any]) -> None:
        holder = parse_lease(context.get(LEASE_CONTEXT_KEY))
        if holder is None or holder.token != lease.token:
            raise LeaseLost("Another run holds the collection lease, so there is nothing to release.")
        context.pop(LEASE_CONTEXT_KEY, None)

    try:
        update_context(give_back)
    except LeaseLost:
        demisto.debug("The collection lease was already taken by another run. Nothing to release.")
    except Exception as error:
        demisto.debug(f"Failed to release the collection lease. It expires on its own. {error}")


@dataclass
class Holder:
    """A run that holds the lease: the only kind of run that sends events or writes the integration context."""

    lease: Lease
    state: LastRun
    mirror_to_last_run: bool  # the fetch also keeps the state in its checkpoint

    def write(self, updates: dict[str, Any]) -> None:
        """Merge keys into the integration context in one versioned write that checks and renews the lease."""
        renewed = Lease(owner=self.lease.owner, token=self.lease.token, expires_at=wall_seconds() + LEASE_TTL_SECONDS)

        def apply(context: dict[str, Any]) -> None:
            holder = parse_lease(context.get(LEASE_CONTEXT_KEY))
            if holder is None or holder.token != self.lease.token:
                raise LeaseLost("The collection lease expired and another run took it, so this run stopped sending.")
            context.update(updates)
            context[LEASE_CONTEXT_KEY] = lease_payload(renewed)

        update_context(apply)
        self.lease = renewed

    def commit(self, state: LastRun) -> None:
        """Store a new state: first in the integration context, then in the checkpoint mirror. Memory changes last."""
        self.write({STATE_CONTEXT_KEY: state})
        if self.mirror_to_last_run:
            save_last_run(state, more_pending=False)
        self.state = state

    def can_send(self) -> bool:
        """Whether a send can finish before the lease expires."""
        return wall_seconds() < self.lease.expires_at - LEASE_SAFETY_SECONDS


# ----- fetch and commands -----


@dataclass
class RunState:
    """What one run did, for its checkpoint, its health report and its summary log line."""

    deadline: Deadline
    run_id: str  # the client's run ID, logged in the summary line
    events_sent: int = 0
    finished: list[str] = field(default_factory=list)
    per_pentest: dict[str, int] = field(default_factory=dict)
    mismatches: dict[str, tuple[int, int]] = field(default_factory=dict)
    more_pending: bool = False

    @property
    def made_progress(self) -> bool:
        """Whether the run sent events or finished a pentest. Without progress, an immediate re-run would only repeat it."""
        return bool(self.events_sent or self.finished)


def sweep_finished_pentests(client: Client, since: str) -> tuple[list[Pentest], bool]:
    """Distinct finished pentests whose results became available at or after `since`, oldest first.

    Returns the pentests and whether the sweep stopped before its last page, at MAX_SWEEP_PAGES or because the run
    deadline was near. Unread pages hold only newer pentests, so stopping early never skips one.
    """
    pentests: list[Pentest] = []
    seen: set[str] = set()
    for page_num in range(1, MAX_SWEEP_PAGES + 1):
        rows = client.get_finished_pentests(since, page_num)
        for pentest in finished_pentests(rows):
            if pentest["op_id"] not in seen:
                seen.add(pentest["op_id"])
                pentests.append(pentest)
        if len(rows) < PAGE_SIZE:
            return pentests, False
        if client.deadline.seconds_left() < MIN_SECONDS_FOR_SWEEP_PAGE:
            return pentests, True
    return pentests, True


# Known limitation: the sweep can stall.
# A sweep reads at most MAX_SWEEP_PAGES pages of PAGE_SIZE pentests, oldest first, starting LOOKBACK before the watermark.
# It reads fewer when the run deadline is near (see MIN_SECONDS_FOR_SWEEP_PAGE).
# If the look-back window holds more already-sent pentests than that, every page fills with them and newer pentests are
# never reached. Nothing new is sent, so the watermark never moves, and every later run repeats the same sweep. Nothing
# loops or fails; collection just stops. It takes MAX_SWEEP_PAGES * PAGE_SIZE or more pentests finishing within LOOKBACK
# on one account (fewer while sweep pages are slow), which is far beyond expected volumes.
# Symptom: runs keep sending 0 events while NodeZero shows newly finished pentests.
# Proposed fix: keep a sweep cursor in the state, the (etl_completed_at, op_id) of the last pentest a capped sweep read,
# and start the next sweep after it instead of at the window start. Then set more_pending whenever a sweep is capped.
# Count a cursor move as progress in RunState.made_progress, or a run that sent nothing won't ask to run again at once.
# Each re-run moves the cursor forward, so this can't loop, and the cursor is cleared once a sweep reaches the end.
def pending_pentests(state: LastRun, swept: list[Pentest]) -> list[Pentest]:
    """The swept pentests that weren't sent yet, oldest first. The half-sent pentest is resumed separately."""
    cursor = state["in_progress"]
    cursor_op_id = cursor["pentest"]["op_id"] if cursor is not None else None
    return [pentest for pentest in swept if pentest["op_id"] != cursor_op_id and not is_sent(state, pentest)]


def is_last_weakness_page(row_count: int, new_events: int, pentest_events: int, expected: int | None) -> bool:
    """Whether a page of weaknesses ends its pentest.

    row_count is the number of rows the page returned and new_events the number of events it added. pentest_events counts
    the pentest's events so far, this page and pages that earlier runs sent included; expected is its weaknesses_count.
    An empty page ends the pentest and a full page never does. A short page ends it when the count is unknown or has been
    reached, or when the page added no new events; otherwise the next page is read, which is normally empty.
    """
    if row_count == 0:
        return True
    if row_count >= PAGE_SIZE:
        return False
    # A short page alone isn't trusted: if the server ever serves fewer rows than asked (it already caps page_size
    # silently), the pentest would end early and its later pages would be dropped without an error. A page that adds
    # nothing new still ends it, so a server that repeats a page can't keep the loop going.
    return expected is None or pentest_events >= expected or new_events == 0


def pull_weakness_page(
    client: Client, pentest: Pentest, page_num: int, seen: set[str], earlier_events: int
) -> tuple[list[dict[str, Any]], bool]:
    """Read one page of a pentest's weaknesses and build its events.

    earlier_events is the number of the pentest's events from earlier pages, including pages that earlier runs sent.
    Returns the page's events and whether the page ends the pentest (is_last_weakness_page).
    """
    rows = client.get_weaknesses_page(pentest["op_id"], page_num)
    demisto.debug(f"Pentest {pentest['op_id']}: page {page_num} returned {len(rows)} weaknesses.")
    events = build_page_events(rows, pentest, seen)
    is_last = is_last_weakness_page(len(rows), len(events), earlier_events + len(events), pentest["weaknesses_count"])
    return events, is_last


def event_batches(events: list[dict[str, Any]]) -> Iterator[list[dict[str, Any]]]:
    """Consecutive batches of at most SEND_BATCH_BYTES serialized. An event that is larger on its own is sent alone."""
    batch: list[dict[str, Any]] = []
    size = 0
    for event in events:
        event_bytes = event_size(event) + 1
        if batch and size + event_bytes > SEND_BATCH_BYTES:
            yield batch
            batch, size = [], 0
        batch.append(event)
        size += event_bytes
    if batch:
        yield batch


def send_page(holder: Holder, events: list[dict[str, Any]]) -> int:
    """Send one page in batches. Before a batch that could outlast the lease, the lease is renewed by a lease-checked
    write, which raises LeaseLost if another run took it. An empty page is never sent (an empty send resets health)."""
    for batch in event_batches(events):
        if not holder.can_send():
            holder.write({})
        send_events_to_xsiam(batch, VENDOR, PRODUCT, should_update_health_module=False)
    return len(events)


def record_sent(run: RunState, op_id: str, count: int) -> None:
    run.events_sent += count
    run.per_pentest[op_id] = run.per_pentest.get(op_id, 0) + count


def note_finished(run: RunState, pentest: Pentest, sent: int) -> None:
    """Record a fully sent pentest. A count that differs from weaknesses_count is recorded, never raised."""
    run.finished.append(pentest["op_id"])
    expected = pentest["weaknesses_count"]
    if expected is not None and sent != expected:
        run.mismatches[pentest["op_id"]] = (sent, expected)


def push_pentest(
    client: Client,
    holder: Holder,
    run: RunState,
    pentest: Pentest,
    cursor: tuple[int, int],
    finish: Callable[[LastRun], LastRun],
    keep: Callable[[list[dict[str, Any]]], None] | None = None,
) -> bool:
    """Send a pentest page by page from the cursor (next page, events earlier runs sent), committing after each page.

    finish applies the caller's bookkeeping to the state that records the pentest as sent, and keep receives each sent
    page's events. Returns True when the pentest is fully sent, or False when the run deadline or the lease stopped it.
    """
    page_num, sent = cursor
    seen: set[str] = set()
    while run.deadline.seconds_left() > 0:
        events, is_last_page = pull_weakness_page(client, pentest, page_num, seen, sent)
        sent += send_page(holder, events)
        record_sent(run, pentest["op_id"], len(events))
        if keep is not None:
            keep(events)
        if is_last_page:
            holder.commit(finish(with_pentest_sent(holder.state, pentest)))
            note_finished(run, pentest, sent)
            return True
        page_num += 1
        holder.commit(with_cursor(holder.state, pentest, page_num, sent))
    run.more_pending = True
    return False


def resume_in_progress(client: Client, holder: Holder, run: RunState) -> bool:
    """Finish the pentest an earlier run, a fetch or a manual push, left half sent. Returns False when the run has to stop."""
    in_progress = holder.state["in_progress"]
    if in_progress is None:
        return True
    pentest = in_progress["pentest"]
    demisto.debug(f"Resuming pentest {pentest['op_id']} at page {in_progress['next_page']}.")
    return push_pentest(client, holder, run, pentest, (in_progress["next_page"], in_progress["sent"]), unchanged)


def fetch_events(client: Client, holder: Holder, max_events: int, run: RunState) -> None:
    """One fetch: finish a half-sent pentest, then send newly finished pentests, oldest first.

    max_events and the time budget are checked only before a new pentest starts, so a pentest is never split by them.
    """
    if not resume_in_progress(client, holder, run):
        return
    if run.deadline.seconds_left() < MIN_SECONDS_FOR_NEW_PENTEST:
        run.more_pending = True  # the resume used the budget; the next run sweeps with a full budget
        return
    swept, capped = sweep_finished_pentests(client, sweep_start(holder.state))

    def bookkeeping(state: LastRun) -> LastRun:
        return prune_sent_ops(advance_watermark(state, swept))

    holder.commit(bookkeeping(holder.state))
    pending = pending_pentests(holder.state, swept)
    if capped and pending:
        run.more_pending = True
    for pentest in pending:
        if is_sent(holder.state, pentest):
            continue  # checked again before each pentest, so a repeated entry is never sent twice
        if run.events_sent >= max_events or run.deadline.seconds_left() < MIN_SECONDS_FOR_NEW_PENTEST:
            run.more_pending = True
            return
        if not push_pentest(client, holder, run, pentest, (1, 0), bookkeeping):
            return


def report_health(run: RunState) -> None:
    """Once per run: an empty heartbeat when nothing was sent, otherwise the number of events pulled."""
    if run.events_sent == 0:
        send_events_to_xsiam([], VENDOR, PRODUCT)
        return
    demisto.updateModuleHealth({"eventsPulled": run.events_sent})


def log_run_summary(run: RunState, outcome: str, kind: str = "fetch") -> None:
    """The run's summary line. Its run ID is the prefix of the X-Request-ID of every request the run made."""
    demisto.info(
        f"NodeZero {kind} {outcome} (run ID {run.run_id}): {len(run.finished)} pentests fully sent, "
        f"{run.events_sent} events sent, events per pentest {run.per_pentest}, "
        f"count mismatches (sent, expected) {run.mismatches}, "
        f"more work pending {run.more_pending}, {run.deadline.elapsed():.1f} seconds."
    )


def parse_positive_int(value: Any, name: str, default: int) -> int:
    number = arg_to_number(value, arg_name=name)
    if number is None:
        return default
    if number < 1:
        raise DemistoException(f"{name} must be a positive integer.")
    return number


def parse_time_arg(value: Any, name: str) -> datetime:
    """An ISO 8601 or relative time (for example, 7 days) as naive UTC."""
    parsed = arg_to_datetime(value, arg_name=name, required=True)
    if parsed is None:
        raise DemistoException(f"{name} is not a valid time.")
    return to_naive_utc(parsed)


def parse_fetch_settings(params: dict[str, Any]) -> tuple[datetime, int]:
    """The first-fetch time and the maximum number of events per fetch."""
    first_fetch = parse_time_arg(params.get("first_fetch") or DEFAULT_FIRST_FETCH, "First fetch time")
    max_events = parse_positive_int(params.get("max_fetch"), "Maximum number of events per fetch", DEFAULT_MAX_FETCH)
    return first_fetch, max_events


def save_failed_run(last_run: LastRun | None, raw_last_run: Any) -> None:
    """After a failure or a skip, keep the checkpoint of the last good page but drop nextTrigger, so it isn't re-run at once."""
    if last_run is not None:
        save_last_run(last_run, more_pending=False)
    elif isinstance(raw_last_run, dict) and "nextTrigger" in raw_last_run:
        demisto.setLastRun({key: value for key, value in raw_last_run.items() if key != "nextTrigger"})


def fetch_events_command(client: Client, params: dict[str, Any]) -> None:
    """fetch-events: one run from the shared state, then the health report and the final checkpoint.

    When a manual push holds the lease, the run sends nothing and the next scheduled run tries again.
    """
    raw_last_run = demisto.getLastRun()
    run = RunState(deadline=client.deadline, run_id=client.run_id)
    holder: Holder | None = None
    try:
        first_fetch, max_events = parse_fetch_settings(params)
        lease = acquire_lease(OWNER_FETCH)
        try:
            holder = Holder(lease=lease, state=load_fetch_state(raw_last_run, first_fetch), mirror_to_last_run=True)
            holder.commit(holder.state)  # stores the state the push reads, seeded from the checkpoint if needed
            client.token_sink = holder.write
            fetch_events(client, holder, max_events, run)
        finally:
            client.token_sink = None
            release_lease(holder.lease if holder is not None else lease)
    except LeaseBusy as busy:
        demisto.info(f"Skipped this fetch, because {describe_lease(busy.holder)} is sending events.")
        save_failed_run(None, raw_last_run)
        report_health(run)
        log_run_summary(run, "skipped")
        return
    except Exception:
        save_failed_run(holder.state if holder is not None else None, raw_last_run)
        log_run_summary(run, "failed")
        raise
    report_health(run)
    if run.more_pending and not run.made_progress:
        demisto.debug("Work is pending, but this run made no progress, so the next run waits for the fetch interval.")
    if holder is not None:
        save_last_run(holder.state, more_pending=run.more_pending and run.made_progress)
    log_run_summary(run, "finished")


def iter_weakness_pages(client: Client, pentest: Pentest) -> Iterator[list[dict[str, Any]]]:
    """The events of a pentest, one page at a time. The pentest ends by the same rule as in a fetch."""
    seen: set[str] = set()
    page_num = 1
    collected = 0
    while True:
        events, is_last_page = pull_weakness_page(client, pentest, page_num, seen, collected)
        yield events
        if is_last_page:
            return
        collected += len(events)
        page_num += 1


def find_pentest(client: Client, op_id: str) -> Pentest:
    """The finished pentest with this op_id. Raises when there is none, or when it isn't done."""
    rows = client.get_pentest(op_id)
    pentest = to_pentest(rows[0]) if rows else None
    if pentest is None or pentest["op_id"] != op_id:
        raise DemistoException(
            f"No pentest with ID {op_id} was found in this account. It may be archived, not a pentest, or mistyped."
        )
    if not is_finished(pentest):
        raise DemistoException(
            f"Pentest {op_id} isn't done, or its results aren't ready yet (state: {pentest['state'] or 'unknown'}). "
            "Only done pentests can be fetched."
        )
    return pentest


def select_pentests(client: Client, pentest_id: str | None, since: str | None) -> tuple[list[Pentest], bool]:
    """The pentests a command covers, oldest first: the one named by pentest_id, else the ones finished since `since`.

    Also returns whether the sweep stopped early (see sweep_finished_pentests).
    """
    if pentest_id is not None:
        return [find_pentest(client, pentest_id)], False
    return sweep_finished_pentests(client, since or "")


def read_events(client: Client, pentests: list[Pentest], limit: int, events: list[dict[str, Any]]) -> bool:
    """Add the pentests' events to `events`, without sending them, until it holds `limit`.

    Returns whether the run deadline stopped it first.
    """
    for pentest in pentests:
        if len(events) >= limit:
            return False
        for page_events in iter_weakness_pages(client, pentest):
            events.extend(page_events[: limit - len(events)])
            if len(events) >= limit:
                return False
            if client.deadline.seconds_left() <= 0:
                return True
    return False


STOPPED_EARLY_MESSAGE = "The command stopped early because it reached its time limit."
NO_SHARED_STATE_MESSAGE = (
    "Events can't be sent yet, because the scheduled fetch hasn't recorded which pentests it sent. Wait for the next "
    "scheduled fetch, then try again. To view events without sending them, set should_push_events to false."
)


def view_events(client: Client, pentest_id: str | None, since: str | None, limit: int) -> tuple[list[dict[str, Any]], list[str]]:
    """A display-only run: no lease, no writes to the integration context, nothing sent."""
    pentests, capped = select_pentests(client, pentest_id, since)
    events: list[dict[str, Any]] = []
    timed_out = read_events(client, pentests, limit, events)
    # A sweep cut short by the deadline may have left newer pentests unread, so report that as stopping early too.
    if timed_out or (len(events) < limit and capped and client.deadline.seconds_left() < MIN_SECONDS_FOR_SWEEP_PAGE):
        return events, [STOPPED_EARLY_MESSAGE]
    return events, []


@dataclass
class PushReport:
    """What a manual push did, for its output."""

    resumed: str | None = None  # a pentest an earlier run left half sent, finished first
    resumed_events: int = 0
    pushed: list[str] = field(default_factory=list)
    already_sent: list[str] = field(default_factory=list)
    left: list[str] = field(default_factory=list)  # not started, because of the limit or the time budget
    stopped_in: str | None = None  # a pentest the run stopped partway through


def load_push_state(fetch_enabled: bool) -> LastRun:
    """The state a push starts from. While the fetch is enabled, a push needs the state the fetch stored; without it,
    the push can't tell which pentests the fetch already sent."""
    state = load_shared_state()
    if state is not None:
        return state
    if fetch_enabled:
        raise DemistoException(NO_SHARED_STATE_MESSAGE)
    return empty_state()


def start_push(params: dict[str, Any], run: RunState) -> Holder:
    """Take the lease for a manual push and read the state under it."""
    fetch_enabled = argToBoolean(params.get("isFetchEvents", False))
    load_push_state(fetch_enabled)  # fail before taking the lease when the push can't run
    try:
        lease = acquire_lease(OWNER_COMMAND)
    except LeaseBusy as busy:
        raise DemistoException(
            f"Events can't be sent right now, because {describe_lease(busy.holder)} is sending events. Try again later, "
            "or set should_push_events to false to view events without sending them."
        ) from busy
    try:
        state = load_push_state(fetch_enabled)  # read again under the lease
    except Exception:
        release_lease(lease)
        log_run_summary(run, "failed", kind="manual push")
        raise
    return Holder(lease=lease, state=state, mirror_to_last_run=False)


def push_scope(
    client: Client,
    holder: Holder,
    run: RunState,
    pentests: list[Pentest],
    report: PushReport,
    events: list[dict[str, Any]],
    limit: int,
) -> None:
    """Send the pentests that weren't sent yet, each in full, oldest first; show the events of the others.

    Up to `limit` events are shown. Once this run sent `limit` events in the scope, no new pentest starts; a pentest is
    never split by it, so a single pentest (pentest_id) is always sent in full.
    """

    def keep(page_events: list[dict[str, Any]]) -> None:
        events.extend(page_events[: max(0, limit - len(events))])

    for index, pentest in enumerate(pentests):
        if is_sent(holder.state, pentest):
            report.already_sent.append(pentest["op_id"])
            if run.deadline.seconds_left() > 0:
                read_events(client, [pentest], limit, events)
            continue
        in_scope_sent = run.events_sent - report.resumed_events
        if in_scope_sent >= limit or run.deadline.seconds_left() < MIN_SECONDS_FOR_NEW_PENTEST:
            report.left.extend(item["op_id"] for item in pentests[index:] if not is_sent(holder.state, item))
            return
        if not push_pentest(client, holder, run, pentest, (1, 0), unchanged, keep):
            report.stopped_in = pentest["op_id"]
            return
        report.pushed.append(pentest["op_id"])


def push_lines(run: RunState, report: PushReport) -> list[str]:
    lines: list[str] = []
    if report.resumed is not None:
        verb = "Continued" if report.stopped_in == report.resumed else "Finished"
        lines.append(
            f"{verb} sending pentest {report.resumed}, which an earlier run left half sent ({report.resumed_events} events)."
        )
    in_scope_sent = run.events_sent - report.resumed_events
    lines.append(f"Sent {in_scope_sent} events to Cortex XSIAM from {len(report.pushed)} pentests.")
    if report.already_sent:
        lines.append(f"Not sent again, because they were already sent: {', '.join(report.already_sent)}.")
    if report.stopped_in is not None:
        lines.append(
            f"Stopped partway through pentest {report.stopped_in}. The next scheduled fetch, or the next run of this "
            "command with should_push_events, sends the rest of it."
        )
    if report.left:
        lines.append(
            "Not sent, because the run reached its limit or its time budget. Run the command again, or let the scheduled "
            f"fetch send them: {', '.join(report.left)}."
        )
    return lines


def push_events(
    client: Client, params: dict[str, Any], pentest_id: str | None, since: str | None, limit: int
) -> tuple[list[dict[str, Any]], list[str]]:
    """A pushing run: hold the lease, finish a half-sent pentest, then send what wasn't sent yet in the scope."""
    run = RunState(deadline=client.deadline, run_id=client.run_id)
    holder = start_push(params, run)
    report = PushReport()
    events: list[dict[str, Any]] = []
    capped = False
    outcome = "failed"
    try:
        client.token_sink = holder.write
        cursor = holder.state["in_progress"]
        if cursor is not None:
            report.resumed = cursor["pentest"]["op_id"]
            finished = resume_in_progress(client, holder, run)
            report.resumed_events = run.events_sent
            if not finished:
                report.stopped_in = report.resumed
        if report.stopped_in is None:
            pentests, capped = select_pentests(client, pentest_id, since)
            push_scope(client, holder, run, pentests, report, events, limit)
        outcome = "finished"
    finally:
        client.token_sink = None
        release_lease(holder.lease)
        log_run_summary(run, outcome, kind="manual push")
    lines = push_lines(run, report)
    if report.stopped_in is not None and report.stopped_in == report.resumed:
        scope = f"pentest {pentest_id}" if pentest_id else f"the pentests that finished since {since}"
        lines.append(f"Not started, because the run's time went to pentest {report.resumed}: {scope}. Run the command again.")
    if capped and client.deadline.seconds_left() < MIN_SECONDS_FOR_SWEEP_PAGE:
        lines.append(STOPPED_EARLY_MESSAGE)
    return events, lines


def events_markdown(events: list[dict[str, Any]], lines: list[str]) -> str:
    return "\n\n".join([*lines, tableToMarkdown("NodeZero Events", events, headers=EVENT_TABLE_HEADERS, removeNull=True)])


def nodezero_fetch_events_command(client: Client, args: dict[str, Any], params: dict[str, Any]) -> CommandResults:
    """nodezero-fetch-events: show events, and with should_push_events, also send the ones that weren't sent yet.

    A run that only shows events never writes the integration context. A pushing run holds the lease, so it never
    overlaps a fetch, and it skips the pentests a fetch or an earlier push already sent.
    """
    should_push = argToBoolean(args.get("should_push_events", False))
    limit = parse_positive_int(args.get("limit"), "limit", DEFAULT_EVENT_LIST_LIMIT)
    pentest_id = str(args.get("pentest_id") or "").strip() or None  # the server matches the ID exactly
    since = None
    if pentest_id is None:
        since = format_filter_time(parse_time_arg(args.get("since") or DEFAULT_EVENT_LIST_SINCE, "since"))
    if should_push:
        events, lines = push_events(client, params, pentest_id, since, limit)
    else:
        events, lines = view_events(client, pentest_id, since, limit)
    return CommandResults(
        outputs_prefix="NodeZero.Event",
        outputs_key_field="event_id",
        outputs=events,
        readable_output=events_markdown(events, lines),
        raw_response=events,
    )


def test_module(client: Client, params: dict[str, Any]) -> str:
    """Check the fetch settings, then get a new token and read one pentest."""
    if argToBoolean(params.get("isFetchEvents", False)):
        parse_fetch_settings(params)
    try:
        client.authenticate()
        client.check_connectivity()
    except DemistoException as error:
        if http_status(error) in (401, 403):
            return with_request_id(AUTH_FAILED_MESSAGE, getattr(error, "res", None))
        raise
    return "ok"


def build_client(params: dict[str, Any], deadline: Deadline) -> Client:
    base_url = str(params.get("url") or "").strip().rstrip("/")
    credentials = params.get("credentials")
    api_key = credentials.get("password") if isinstance(credentials, dict) else None
    if not base_url:
        raise DemistoException("The Server URL parameter is required.")
    if not isinstance(api_key, str) or not api_key:
        raise DemistoException("The API Key parameter is required.")
    return Client(
        base_url=base_url,
        api_key=api_key,
        verify=not argToBoolean(params.get("insecure", False)),
        proxy=argToBoolean(params.get("proxy", False)),
        deadline=deadline,
    )


def main() -> None:
    command = demisto.command()
    params = demisto.params()
    demisto.debug(f"Command being called is {command}.")
    try:
        client = build_client(params, Deadline.after(RUN_BUDGET_SECONDS))
        if command == "test-module":
            return_results(test_module(client, params))
        elif command == "fetch-events":
            fetch_events_command(client, params)
        elif command == "nodezero-fetch-events":
            return_results(nodezero_fetch_events_command(client, demisto.args(), params))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as error:
        return_error(f"Failed to execute {command} command.\nError:\n{error}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
