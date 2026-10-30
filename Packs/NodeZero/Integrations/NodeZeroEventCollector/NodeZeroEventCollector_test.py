"""Unit tests for the NodeZero Event Collector. Every value in these tests and in test_data is synthetic."""

import base64
import copy
import hashlib
import itertools
import json
import re
import threading
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import CommonServerPython
import demistomock as demisto
import pytest
import requests
import yaml
from CommonServerPython import CommandResults, DemistoException
from freezegun import freeze_time

import NodeZeroEventCollector

TEST_DATA = Path(__file__).parent / "test_data"
INTEGRATION_YML = Path(__file__).parent / "NodeZeroEventCollector.yml"
MODELING_RULE_DIR = Path(__file__).resolve().parents[2] / "ModelingRules" / "NodeZeroModelingRules"
XIF_PATH = MODELING_RULE_DIR / "NodeZeroModelingRules.xif"
SCHEMA_PATH = MODELING_RULE_DIR / "NodeZeroModelingRules_schema.json"

BASE_URL = "https://nodezero.example.com"
API_KEY = "nz-unit-test-api-key-0001"
NOW = "2025-03-15T12:00:00Z"
NOW_EPOCH = int(datetime(2025, 3, 15, 12, 0, tzinfo=UTC).timestamp())
FIRST_FETCH_FLOOR = "2025-03-12T12:00:00"  # NOW minus the "3 days" first fetch below
FETCH_PARAMS = {
    "url": BASE_URL,
    "credentials": {"password": API_KEY},
    "isFetchEvents": True,
    "first_fetch": "3 days",
    "max_fetch": "10000",
}
NO_FETCH_PARAMS = {**FETCH_PARAMS, "isFetchEvents": False}  # an instance with fetching turned off
STATE_KEY = "nodezero_state"
LEASE_KEY = "nodezero_lease"
CSP_EVENT_LIMIT_BYTES = 5 * 1024 * 1024  # CommonServerPython skips events this large


def load_json(name: str) -> Any:
    return json.loads((TEST_DATA / name).read_text())


def page_rows(body: dict[str, Any]) -> list[dict[str, Any]]:
    return body["data"]["weaknesses_page"]["weaknesses"]


FINISHED_PAGE = load_json("pentests_page_finished.json")
UNFINISHED_ETL_PAGE = load_json("pentests_page_with_unfinished_etl.json")
EMPTY_PENTESTS_PAGE = load_json("pentests_page_empty.json")
OP_A, OP_B = FINISHED_PAGE["data"]["pentests_page"]["pentests"]
OP_A_PAGES = [load_json("weaknesses_op_a_page_1.json"), load_json("weaknesses_op_a_page_2.json")]
OP_B_PAGES = [load_json("weaknesses_op_b_page_1.json")]
A1, A2 = page_rows(OP_A_PAGES[0])
(A3,) = page_rows(OP_A_PAGES[1])
B1, B2 = page_rows(OP_B_PAGES[0])
ALL_ROWS = [A1, A2, A3, B1, B2]
HOST_NAME_CASES = load_json("host_name_cases.json")["cases"]
CONTRACT_EXAMPLE = load_json("contract_example.json")


# ----- helpers -----


def make_jwt(expires_at: int | None, subject: str = "unit-test") -> str:
    """An unsigned, synthetic JWT. Only its claims matter to the collector."""

    def segment(payload: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

    claims: dict[str, Any] = {"sub": subject}
    if expires_at is not None:
        claims["exp"] = expires_at
    return f"{segment({'alg': 'HS256', 'typ': 'JWT'})}.{segment(claims)}.signature"


def make_weakness(op_id: str, index: int) -> dict[str, Any]:
    """A copy of fixture row A1 with its own uuid, for generated pentests."""
    row = copy.deepcopy(A1)
    uuid = f"{index:08d}-0000-4000-8000-000000000000"
    row.update(uuid=uuid, op_id=op_id, portal_url=f"https://portal.horizon3ai.com/pentests/{op_id}/weaknesses/{uuid}")
    return row


def weakness_rows(op_id: str, count: int) -> list[dict[str, Any]]:
    """Generated weaknesses for one pentest, in uuid order."""
    return [make_weakness(op_id, index) for index in range(count)]


def pentest_row(op_id: str, weaknesses_count: int, **fields: Any) -> dict[str, Any]:
    return {**OP_A, "op_id": op_id, "weaknesses_count": weaknesses_count, **fields}


def pentests_body(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {"data": {"pentests_page": {"pentests": rows}}}


def weaknesses_body(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {"data": {"weaknesses_page": {"weaknesses": rows}}}


def operation_name(query: str) -> str:
    match = re.search(r"query\s+(\w+)", query)
    assert match, query
    return match.group(1)


def parse_naive(value: str) -> datetime:
    return datetime.fromisoformat(value)


def uuids(events: list[dict[str, Any]]) -> list[str]:
    return [event["uuid"] for event in events]


def build(row: dict[str, Any], pentest: dict[str, Any] = OP_A) -> dict[str, Any]:
    """The event for one API weakness row of one API pentest row."""
    return NodeZeroEventCollector.build_event(row, NodeZeroEventCollector.to_pentest(pentest))


def fixture_events() -> list[dict[str, Any]]:
    pentests = {"op-a": OP_A, "op-b": OP_B}
    return [build(row, pentests[row["op_id"]]) for row in ALL_ROWS]


class FakeClock:
    """A monotonic clock that only moves when a test moves it."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeNodeZero:
    """A requests_mock stand-in for the NodeZero API.

    Sweeps are filtered, sorted and paged the way the server does it, unless raw sweep pages are given. Every
    weaknesses_page request is checked for a non-empty input.op_id, so every test that fetches enforces that rule.
    """

    def __init__(
        self,
        pentests: list[dict[str, Any]] | None = None,
        weaknesses: dict[str, list[dict[str, Any]]] | None = None,
        sweep_pages: list[dict[str, Any]] | None = None,
        weakness_pages: dict[str, list[dict[str, Any]]] | None = None,
    ) -> None:
        self.pentests = pentests if pentests is not None else []
        self.weaknesses = weaknesses or {}
        self.sweep_pages = sweep_pages
        self.weakness_pages = weakness_pages or {}
        self.issued_tokens: list[str] = []
        self.api_key = API_KEY  # the key the server accepts; a test that changes the key changes it here too
        self.token_keys: dict[str, str] = {}  # the API key each token was issued for
        self.on_request: dict[str, list[Callable[[], None]]] = {}  # hooks run when an operation is requested, once each
        self.graphql_requests: list[dict[str, Any]] = []
        self.authorization_headers: list[str] = []
        self.weakness_page_calls: list[tuple[str, int]] = []
        self.queued: list[tuple[str, int, str]] = []
        self.page_failures: dict[tuple[str, int], tuple[int, str]] = {}
        self.page_cost: tuple[FakeClock, float] | None = None

    def register(self, requests_mock: Any) -> "FakeNodeZero":
        requests_mock.post(f"{BASE_URL}/v1/auth", text=self.auth)
        requests_mock.post(f"{BASE_URL}/v1/graphql", text=self.graphql)
        return self

    def queue(self, operation: str, status: int, body: Any = None, raw: str | None = None) -> None:
        """Answer the next request for this operation ("auth" or a GraphQL operation name) with this response."""
        text = raw if raw is not None else ("" if body is None else json.dumps(body))
        self.queued.append((operation, status, text))

    def fail_page(self, op_id: str, page_num: int, status: int, raw: str = "") -> None:
        self.page_failures[(op_id, page_num)] = (status, raw)

    def charge_weakness_pages(self, clock: FakeClock, seconds: float) -> None:
        """Make every weaknesses page cost this much time on the fake clock."""
        self.page_cost = (clock, seconds)

    def auth(self, request: Any, context: Any) -> str:
        assert request.json() == {"key": self.api_key}
        queued = self.take_queued("auth", context)
        if queued is not None:
            return queued
        token = make_jwt(int(time.time()) + 3600, subject=f"token-{len(self.issued_tokens) + 1}")
        self.issued_tokens.append(token)
        self.token_keys[token] = self.api_key
        return self.reply(context, {"token": token})

    def graphql(self, request: Any, context: Any) -> str:
        body = request.json()
        self.graphql_requests.append(body)
        self.authorization_headers.append(request.headers.get("Authorization", ""))
        operation = operation_name(body["query"])
        hooks = self.on_request.get(operation)
        if hooks:
            hooks.pop(0)()
        queued = self.take_queued(operation, context)
        if queued is not None:
            return queued
        variables = body["variables"]
        if operation == "CortexXsiamPentestWeaknesses":
            return self.weakness_page(body["query"], variables, context)
        if operation in ("CortexXsiamFinishedPentests", "CortexXsiamPentest"):  # the sweep and the single-pentest lookup
            return self.reply(context, self.sweep_page(variables["page_input"]))
        if operation == "CortexXsiamConnectivity":
            return self.reply(context, pentests_body([{"op_id": row["op_id"]} for row in self.pentests[:1]]))
        raise AssertionError(f"Unexpected GraphQL operation {operation}")

    def take_queued(self, operation: str, context: Any) -> str | None:
        for index, (queued_operation, status, text) in enumerate(self.queued):
            if queued_operation == operation:
                del self.queued[index]
                context.status_code = status
                return text
        return None

    @staticmethod
    def reply(context: Any, body: dict[str, Any]) -> str:
        context.status_code = 200
        context.headers["Content-Type"] = "application/json"
        return json.dumps(body)

    def weakness_page(self, query: str, variables: dict[str, Any], context: Any) -> str:
        op_id = variables.get("op_id")
        assert "weaknesses_page(input: {op_id: $op_id}" in query
        assert isinstance(op_id, str), "weaknesses_page must always be scoped to one pentest"
        assert op_id, "weaknesses_page must always be scoped to one pentest"
        page_num, page_size = variables["page_input"]["page_num"], variables["page_input"]["page_size"]
        self.weakness_page_calls.append((op_id, page_num))
        assert len(self.weakness_page_calls) <= 1_000, "runaway paging: the pentest never ended"
        if self.page_cost is not None:
            self.page_cost[0].advance(self.page_cost[1])
        if (op_id, page_num) in self.page_failures:
            context.status_code, text = self.page_failures[(op_id, page_num)]
            return text
        if op_id in self.weakness_pages:
            pages = self.weakness_pages[op_id]
            return self.reply(context, pages[page_num - 1] if page_num <= len(pages) else weaknesses_body([]))
        start = (page_num - 1) * page_size
        return self.reply(context, weaknesses_body(self.weaknesses.get(op_id, [])[start : start + page_size]))

    def sweep_page(self, page_input: dict[str, Any]) -> dict[str, Any]:
        page_num, page_size = page_input["page_num"], page_input["page_size"]
        if self.sweep_pages is not None:
            return self.sweep_pages[page_num - 1] if page_num <= len(self.sweep_pages) else pentests_body([])
        rows = [row for row in self.pentests if self.matches(row, page_input.get("filter_by_inputs", []))]
        rows.sort(key=lambda row: (parse_naive(row["etl_completed_at"] or "0001-01-01T00:00:00"), row["op_id"]))
        start = (page_num - 1) * page_size
        return pentests_body(rows[start : start + page_size])

    @staticmethod
    def matches(row: dict[str, Any], filters: list[dict[str, Any]]) -> bool:
        for item in filters:
            value = row.get(item["field_name"])
            if "values" in item and value not in item["values"]:
                return False
            since = item.get("greater_than_or_equal")
            if since is not None and (value is None or parse_naive(value) < parse_naive(since)):
                return False
        return True

    def requests_for(self, operation: str) -> list[dict[str, Any]]:
        return [body for body in self.graphql_requests if operation_name(body["query"]) == operation]


class FakeWallClock:
    """Epoch seconds for lease expiry times. Only moves when a test moves it."""

    def __init__(self, start: float = float(NOW_EPOCH)) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class StaleVersionError(ValueError):
    """What the platform raises for a write that carries a stale context version."""


class ContextStore:
    """The integration context of one instance, as the platform keeps it.

    mode "enforced": a versioned write with a stale version raises, like the platform documents.
    mode "ignored": versioned writes always land, whatever version they carry.
    mode "unversioned": is_versioned_context_available() is False, so CommonServerPython writes without versions.
    Hooks and failures are keyed by the number of the write attempt (1 for the first write of the test).
    """

    def __init__(self) -> None:
        self.context: dict[str, Any] = {}
        self.version = 0
        self.mode = "enforced"
        self.write_attempts = 0
        self.writes: list[dict[str, Any]] = []  # every write that landed, in order
        self.hooks: dict[int, Callable[[dict[str, Any]], None]] = {}
        self.failures: dict[int, BaseException] = {}
        self.reads = 0
        self.read_failures: dict[int, BaseException] = {}  # keyed by the number of the read, like write failures
        self.crashed = False  # set when a test kills the run: no later write lands
        self.stale_writes = 0

    def read(self) -> dict[str, Any]:
        self.reads += 1
        if self.reads in self.read_failures:
            raise self.read_failures.pop(self.reads)
        return copy.deepcopy(self.context)

    def get_versioned(self, refresh: bool = False) -> dict[str, Any]:
        assert self.mode != "unversioned", "this platform has no versioned integration context"
        return {"context": self.read(), "version": self.version}

    def set_versioned(self, context: dict[str, Any], version: int = -1, sync: bool = False) -> None:
        assert self.mode != "unversioned", "this platform has no versioned integration context"
        self.write(context, version)

    def get_plain(self) -> dict[str, Any]:
        return self.read()

    def set_plain(self, context: dict[str, Any]) -> None:
        self.write(context, -1)

    def write(self, context: dict[str, Any], version: int) -> None:
        self.write_attempts += 1
        attempt = self.write_attempts
        if attempt in self.hooks:
            self.hooks.pop(attempt)(copy.deepcopy(context))
        if attempt in self.failures:
            raise self.failures.pop(attempt)
        if self.crashed:
            raise SimulatedCrash
        if self.mode == "enforced" and version != -1 and version != self.version:
            self.stale_writes += 1
            raise StaleVersionError(f"DB version {version} is older than {self.version}")
        self.land(context)

    def land(self, context: dict[str, Any]) -> None:
        self.context = copy.deepcopy(context)
        self.version += 1
        self.writes.append(copy.deepcopy(context))

    def other_writer(self, change: Callable[[dict[str, Any]], None]) -> None:
        """A write by another run. It moves the version, so a write based on an earlier read is stale."""
        context = copy.deepcopy(self.context)
        change(context)
        self.land(context)

    def on_write(self, offset: int, hook: Callable[[dict[str, Any]], None]) -> None:
        """Run hook(pending context) just before the offset-th write attempt from now lands."""
        self.hooks[self.write_attempts + offset] = hook

    def fail_write(self, offset: int, error: BaseException) -> None:
        self.failures[self.write_attempts + offset] = error

    def written_states(self) -> list[dict[str, Any] | None]:
        return [written.get(STATE_KEY) for written in self.writes]

    def state(self) -> dict[str, Any] | None:
        return self.context.get(STATE_KEY)

    def lease(self) -> dict[str, Any] | None:
        return self.context.get(LEASE_KEY)


class SimulatedCrash(BaseException):
    """The platform killing the run: nothing in the collector gets to handle it."""


class Harness:
    """Patches the platform calls a command makes and records what the collector did."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, requests_mock: Any) -> None:
        self.requests_mock = requests_mock
        self.last_run: Any = {}
        self.saved_last_runs: list[dict[str, Any]] = []
        self.get_last_run_calls = 0
        self.sends: list[tuple[list[dict[str, Any]], str, str, dict[str, Any]]] = []
        self.send_lease_margins: list[float] = []  # seconds left on the stored lease when each page send started
        self.on_send: list[Callable[[list[dict[str, Any]]], None]] = []  # one hook per send, after it lands
        self.health: list[Any] = []
        self.logs: list[tuple[str, str]] = []
        self.store = ContextStore()
        self.wall = FakeWallClock()
        self.clock = FakeClock()  # the monotonic run clock of any Deadline the test doesn't build itself
        self.pauses: list[float] = []
        self.on_pause: list[Callable[[], None]] = []  # one hook per pause, to run another run during the settle
        monkeypatch.setattr(demisto, "getLastRun", self.get_last_run)
        monkeypatch.setattr(demisto, "setLastRun", self.set_last_run)
        monkeypatch.setattr(demisto, "updateModuleHealth", self.update_module_health)
        # CommonServerPython looks is_versioned_context_available up in its own module globals.
        monkeypatch.setattr(CommonServerPython, "is_versioned_context_available", lambda: self.store.mode != "unversioned")
        monkeypatch.setattr(demisto, "getIntegrationContextVersioned", self.store.get_versioned)
        monkeypatch.setattr(demisto, "setIntegrationContextVersioned", self.store.set_versioned)
        monkeypatch.setattr(demisto, "getIntegrationContext", self.store.get_plain)
        monkeypatch.setattr(demisto, "setIntegrationContext", self.store.set_plain)
        monkeypatch.setattr(NodeZeroEventCollector, "pause", self.pause)
        monkeypatch.setattr(NodeZeroEventCollector, "wall_seconds", self.wall)
        real_after = NodeZeroEventCollector.Deadline.after.__func__

        def deadline_after(cls: Any, seconds: float, clock: Callable[[], float] | None = None) -> Any:
            return real_after(cls, seconds, clock or self.clock)  # main() never reads the real monotonic clock

        monkeypatch.setattr(NodeZeroEventCollector.Deadline, "after", classmethod(deadline_after))
        for level in ("debug", "info", "error"):
            monkeypatch.setattr(demisto, level, self.logger(level))
        monkeypatch.setattr(NodeZeroEventCollector, "send_events_to_xsiam", self.send_events)
        monkeypatch.setattr(NodeZeroEventCollector, "PAGE_SIZE", 2)

    @property
    def context(self) -> dict[str, Any]:
        return self.store.context

    def get_last_run(self) -> Any:
        self.get_last_run_calls += 1
        return copy.deepcopy(self.last_run)

    def set_last_run(self, obj: dict[str, Any]) -> None:
        stored = json.loads(json.dumps(obj))  # the platform stores last run as JSON
        self.saved_last_runs.append(stored)
        self.last_run = stored

    def update_module_health(self, data: Any, is_error: bool = False) -> None:
        self.health.append(data)

    def pause(self, seconds: float) -> None:
        self.pauses.append(seconds)
        if self.on_pause:
            self.on_pause.pop(0)()

    def logger(self, level: str) -> Callable[..., None]:
        def log(message: Any, *args: Any) -> None:
            self.logs.append((level, str(message)))

        return log

    def send_events(self, events: list[dict[str, Any]], vendor: str, product: str, **kwargs: Any) -> None:
        if events:
            lease = self.store.lease()
            self.send_lease_margins.append(lease["expires_at"] - self.wall() if lease else float("-inf"))
        self.sends.append((list(events), vendor, product, kwargs))
        if self.on_send:
            self.on_send.pop(0)(list(events))

    def sent_events(self) -> list[dict[str, Any]]:
        return [event for events, _, _, _ in self.sends for event in events]

    def sent_ids(self) -> list[str]:
        return [event["event_id"] for event in self.sent_events()]

    def duplicate_ids(self) -> list[str]:
        ids = self.sent_ids()
        return sorted({event_id for event_id in ids if ids.count(event_id) > 1})

    def page_sends(self) -> list[list[dict[str, Any]]]:
        return [events for events, _, _, kwargs in self.sends if kwargs == {"should_update_health_module": False}]

    def messages(self, level: str) -> list[str]:
        return [message for logged_level, message in self.logs if logged_level == level]

    def summary(self) -> str:
        summaries = [message for message in self.messages("info") if message.startswith("NodeZero fetch ")]
        assert len(summaries) == 1, summaries
        return summaries[0]

    def auth_calls(self) -> int:
        return sum(1 for request in self.requests_mock.request_history if request.path == "/v1/auth")


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch, requests_mock: Any) -> Harness:
    return Harness(monkeypatch, requests_mock)


def standard_api(harness: Harness) -> FakeNodeZero:
    """op-a: 3 weaknesses over two pages of 2. op-b: 2 weaknesses, then an empty page. Served from the fixtures."""
    fake = FakeNodeZero(pentests=[OP_A, OP_B], weakness_pages={"op-a": OP_A_PAGES, "op-b": OP_B_PAGES})
    return fake.register(harness.requests_mock)


def make_client(
    clock: FakeClock | None = None, budget: float = 180.0, api_key: str = API_KEY, base_url: str = BASE_URL
) -> NodeZeroEventCollector.Client:
    """A client whose run deadline reads an injected clock, never the real monotonic clock."""
    deadline = NodeZeroEventCollector.Deadline.after(budget, clock or FakeClock())
    return NodeZeroEventCollector.Client(base_url=base_url, api_key=api_key, verify=True, proxy=False, deadline=deadline)


def token_owner(base_url: str = BASE_URL, api_key: str = API_KEY) -> str:
    """The owner the token cache records: a short hash of the server URL and the API key, never the key itself."""
    return hashlib.sha256(f"{base_url}\n{api_key}".encode()).hexdigest()[:16]


def cached_token(token: str, expires_at: int) -> dict[str, Any]:
    """Token-cache keys as a lease holder stores them for BASE_URL and API_KEY."""
    return {"auth_token": token, "auth_token_expires_at": expires_at, "auth_token_owner": token_owner()}


def run_fetch(params: dict[str, Any] | None = None, clock: FakeClock | None = None) -> None:
    NodeZeroEventCollector.fetch_events_command(make_client(clock), params or FETCH_PARAMS)


def event_list(args: dict[str, Any], clock: FakeClock | None = None, params: dict[str, Any] | None = None) -> CommandResults:
    return NodeZeroEventCollector.nodezero_fetch_events_command(
        make_client(clock), args, FETCH_PARAMS if params is None else params
    )


def push(
    args: dict[str, Any] | None = None, clock: FakeClock | None = None, params: dict[str, Any] | None = None
) -> CommandResults:
    """nodezero-fetch-events with should_push_events."""
    return event_list({"should_push_events": "true", "limit": "100", **(args or {})}, clock, params)


def view(args: dict[str, Any] | None = None, clock: FakeClock | None = None) -> CommandResults:
    """nodezero-fetch-events without should_push_events."""
    return event_list({"should_push_events": "false", "limit": "100", **(args or {})}, clock)


# ----- shared layer: host names, host fields, MITRE, reserved keys -----


@pytest.mark.parametrize(
    "case", HOST_NAME_CASES, ids=[f"{index:02d}-{case['reason']}" for index, case in enumerate(HOST_NAME_CASES)]
)
def test_hostname_cases(case: dict[str, Any]) -> None:
    value = case["value"]
    assert NodeZeroEventCollector.is_valid_hostname(value) is case["valid_hostname"]
    assert NodeZeroEventCollector.is_ip_literal(value) is case["ip_literal"]
    fields = NodeZeroEventCollector.build_host_fields({"affected_host": {"host_name": value}, "ip": None})
    assert fields["target_hostname"] == case["target_hostname"]
    assert fields["target_fqdn"] == case["target_fqdn"]
    assert fields["target_ipv4_addresses"] == case["target_ipv4_addresses"]
    assert fields["target_ipv6_addresses"] == case["target_ipv6_addresses"]


def test_6_7_0_is_not_a_hostname() -> None:
    assert NodeZeroEventCollector.is_valid_hostname("6.7.0") is False
    assert NodeZeroEventCollector.is_ip_literal("6.7.0") is False
    weakness = {"affected_host": {"host_name": "6.7.0", "host_names": ["6.7.0", "6.7.0-beta"], "ip": None}, "ip": None}
    fields = NodeZeroEventCollector.build_host_fields(weakness)
    assert fields["target_hostname"] is None
    assert fields["target_fqdn"] is None
    assert fields["target_ipv4_addresses"] == []
    event = build(A2)  # host_name 10.0.0.4 with 6.7.0 among its host_names
    assert event["target_hostname"] is None
    assert event["target_fqdn"] is None
    assert event["affected_host_names"] == ["10.0.0.4", "6.7.0"]  # the raw field keeps what NodeZero reported


def test_ip_literal_host_name_routed_to_address() -> None:
    fields = NodeZeroEventCollector.build_host_fields(A2)
    assert fields["target_hostname"] is None
    assert fields["target_ipv4_addresses"] == ["10.0.0.4"]
    assert fields["target_ipv6_addresses"] == []


def test_ipv6_split_from_ipv4() -> None:
    fields = NodeZeroEventCollector.build_host_fields(A1)
    assert fields["target_ipv4_addresses"] == ["10.0.0.4"]
    assert fields["target_ipv6_addresses"] == ["2001:db8::100f"]
    bracketed = {"affected_host": {"host_name": None, "host_names": ["[2001:db8::100f]"], "ip": "2001:DB8::100F"}, "ip": None}
    assert NodeZeroEventCollector.build_host_fields(bracketed)["target_ipv6_addresses"] == ["2001:db8::100f"]


def test_address_candidates_deduplicated_in_order() -> None:
    weakness = {
        "affected_host": {"host_name": "10.0.0.1", "host_names": ["10.0.0.4", "10.0.0.1"], "ip": "10.0.0.4"},
        "ip": "10.0.0.2",
    }
    assert NodeZeroEventCollector.build_host_fields(weakness)["target_ipv4_addresses"] == ["10.0.0.4", "10.0.0.2", "10.0.0.1"]


def test_fqdn_and_hostname_selection() -> None:
    short_first = NodeZeroEventCollector.build_host_fields(B2)  # host_name web01, then web01.corp.example.com
    assert short_first["target_hostname"] == "web01"
    assert short_first["target_fqdn"] == "web01.corp.example.com"
    fqdn_first = NodeZeroEventCollector.build_host_fields(A1)
    assert fqdn_first["target_hostname"] == "dc01.corp.example.com"
    assert fqdn_first["target_fqdn"] == "dc01.corp.example.com"
    invalid_first = {"affected_host": {"host_name": "6.7.0", "host_names": ["dc01.corp.example.com."]}, "ip": None}
    fields = NodeZeroEventCollector.build_host_fields(invalid_first)
    assert fields["target_hostname"] == "dc01.corp.example.com"
    assert fields["target_fqdn"] == "dc01.corp.example.com"


def test_display_name_never_parsed_for_host_names() -> None:
    weakness = {"affected_host": None, "ip": None, "affected_asset_display_name": "dc01.corp.example.com on 10.0.0.4 Port 443"}
    fields = NodeZeroEventCollector.build_host_fields(weakness)
    assert fields["target_hostname"] is None
    assert fields["target_ipv4_addresses"] == []


def test_os_names_joined() -> None:
    assert NodeZeroEventCollector.build_host_fields(A1)["target_os"] == "Windows, Windows Server"
    assert NodeZeroEventCollector.build_host_fields(A3)["target_os"] == "Windows"
    assert NodeZeroEventCollector.build_host_fields(A2)["target_os"] is None
    assert NodeZeroEventCollector.join_os_names([]) is None


def test_mac_passthrough() -> None:
    assert NodeZeroEventCollector.build_host_fields(A1)["target_mac_addresses"] == ["00:00:5e:00:53:01"]
    dashed = {"affected_host": {"mac": "00-00-5E-00-53-01"}, "ip": None}
    assert NodeZeroEventCollector.build_host_fields(dashed)["target_mac_addresses"] == ["00-00-5E-00-53-01"]
    for missing in (None, "", "   "):
        weakness = {"affected_host": {"mac": missing}, "ip": None}
        assert NodeZeroEventCollector.build_host_fields(weakness)["target_mac_addresses"] == []
    assert build(A1)["affected_host_mac"] == "00:00:5e:00:53:01"


def test_web_weakness_without_host() -> None:
    fields = NodeZeroEventCollector.build_host_fields(B1)  # affected_host and ip are both null
    assert fields == {
        "target_hostname": None,
        "target_fqdn": None,
        "target_ipv4_addresses": [],
        "target_ipv6_addresses": [],
        "target_mac_addresses": [],
        "target_os": None,
    }


def test_flatten_mitre() -> None:
    mappings = [
        {"mitre_tactic_id": "TA0043", "mitre_technique_id": "T1595", "mitre_subtechnique_id": "T1595.002"},
        {"mitre_tactic_id": "TA0043", "mitre_technique_id": "T1595", "mitre_subtechnique_id": "T1595.001"},
        {"mitre_tactic_id": " TA0001 ", "mitre_technique_id": "T1190", "mitre_subtechnique_id": None},
        {"mitre_tactic_id": None, "mitre_technique_id": "", "mitre_subtechnique_id": None},
    ]
    tactics, techniques = NodeZeroEventCollector.flatten_mitre(mappings)
    assert tactics == ["TA0043", "TA0001"]
    assert techniques == ["T1595", "T1595.002", "T1595.001", "T1190"]
    assert NodeZeroEventCollector.flatten_mitre(None) == ([], [])
    assert NodeZeroEventCollector.flatten_mitre([]) == ([], [])


def test_find_reserved_keys() -> None:
    assert NodeZeroEventCollector.find_reserved_keys({"_time": "x", "op_id": "y"}) == []
    assert NodeZeroEventCollector.find_reserved_keys({"_time": "x", "_insert_time": "y", "_id": "z"}) == ["_insert_time", "_id"]


def test_no_reserved_keys_in_events() -> None:
    oversized = copy.deepcopy(A1)
    oversized["vuln"]["description"] = "d" * 2_000_000
    fallback = {**A2, "created_at": None}
    events = [*fixture_events(), build(fallback), NodeZeroEventCollector.cap_event_size(build(oversized))]
    for event in events:
        assert NodeZeroEventCollector.find_reserved_keys(event) == []
        assert "_time" in event


# ----- events: the raw schema -----


def test_build_event_matches_contract_example() -> None:
    pentest = NodeZeroEventCollector.to_pentest(CONTRACT_EXAMPLE["pentest"])
    event = NodeZeroEventCollector.build_event(CONTRACT_EXAMPLE["weakness"], pentest)
    assert event == CONTRACT_EXAMPLE["event"]
    assert list(event) == list(CONTRACT_EXAMPLE["event"])
    assert isinstance(event["score"], float)
    assert isinstance(event["base_score"], float)


def test_event_id_is_op_id_and_uuid() -> None:
    assert build(A1)["event_id"] == "op-a:a1000000-0000-4000-8000-000000000001"
    legacy = build(A3)  # a legacy composite uuid is kept as an opaque string
    assert legacy["uuid"] == "a3000000-0000-4000-8000-000000000003/H3-2022-0086/HasWeakness"
    assert legacy["event_id"] == "op-a:a3000000-0000-4000-8000-000000000003/H3-2022-0086/HasWeakness"
    assert len({event["event_id"] for event in fixture_events()}) == len(ALL_ROWS)


def test_h3_vuln_id_kept_verbatim() -> None:
    assert build(A2)["vuln_id"] == "H3-2021-0030"
    assert build(B1, OP_B)["vuln_id"] == "H3-2023-0042"
    assert build(A1)["vuln_id"] == "CVE-2021-44228"


def test_every_event_has_vuln_id() -> None:
    for event, row in zip(fixture_events(), ALL_ROWS, strict=True):
        assert event["vuln_id"] == row["vuln_id"]
        assert isinstance(event["vuln_id"], str)
        assert event["vuln_id"]


@freeze_time(NOW)
def test_time_is_created_at_utc_not_now() -> None:
    expected = [
        "2025-03-14T09:12:30.123Z",
        "2025-03-14T09:20:05.000Z",
        "2025-03-14T09:31:47.000Z",
        "2025-03-14T10:05:00.000Z",
        "2025-03-14T10:15:59.999Z",  # milliseconds are truncated, never rounded up
    ]
    events = fixture_events()
    assert [event["_time"] for event in events] == expected
    assert [event["created_at"] for event in events] == [row["created_at"] for row in ALL_ROWS]
    assert all("time_fallback" not in event for event in events)
    assert "2025-03-15T12:00:00.000Z" not in expected
    with_offset = {**A1, "created_at": "2025-03-14T11:12:30.123456+02:00"}
    assert build(with_offset)["_time"] == "2025-03-14T09:12:30.123Z"
    with_zulu = {**A1, "created_at": "2025-03-14T09:12:30.123456Z"}
    assert build(with_zulu)["_time"] == "2025-03-14T09:12:30.123Z"


@pytest.mark.parametrize(
    ("created_at", "completed_at", "expected_time"),
    [
        ("not a timestamp", "2025-03-14T09:50:00", "2025-03-14T09:50:00.000Z"),
        (None, "2025-03-14T09:50:00", "2025-03-14T09:50:00.000Z"),
        (None, None, "2025-03-14T10:00:00.250Z"),  # then the time the pentest's results became available
    ],
)
def test_time_fallback_flagged(created_at: str | None, completed_at: str | None, expected_time: str) -> None:
    event = build({**A1, "created_at": created_at}, {**OP_A, "completed_at": completed_at})
    assert event["_time"] == expected_time
    assert event["time_fallback"] is True
    assert event["created_at"] == (created_at or None)


def test_null_optional_fields_kept() -> None:
    event = build(B1, OP_B)  # a web weakness: affected_host and ip are null
    for key in (
        "ip",
        "affected_host_uuid",
        "affected_host_name",
        "affected_host_names",
        "affected_host_ip",
        "affected_host_mac",
        "affected_host_os_names",
        "affected_host_is_in_scope",
        "target_hostname",
        "target_fqdn",
        "target_os",
        "context_score",
        "context_severity",
        "downstream_impact_types",
        "pentest_client_name",
        "weakness_ref",
    ):
        assert event[key] is None, key
    for key in ("target_ipv4_addresses", "target_ipv6_addresses", "target_mac_addresses", "impacts", "proof_types"):
        assert event[key] == [], key
    assert build(A3)["mitre_mappings"] is None  # the API's null stays null
    assert build(A3)["mitre_tactic_ids"] == []


def test_empty_strings_become_null() -> None:
    row = {**A1, "vuln_short_name": "", "weakness_ref": "", "proof_failure_reason": ""}
    event = build(row)
    assert event["vuln_short_name"] is None
    assert event["weakness_ref"] is None
    assert event["proof_failure_reason"] is None


def test_scores_are_floats() -> None:
    event = build(B1, OP_B)  # the API sends whole-number scores as integers
    assert event["score"] == 3.0
    assert isinstance(event["score"], float)
    assert isinstance(event["base_score"], float)
    assert all(isinstance(impact["score"], float) for impact in build(A1)["impacts"])
    for bad_score in (float("nan"), float("inf"), "7.5", True):
        assert build({**A1, "score": bad_score})["score"] is None


def test_proof_types_are_distinct_metadata_only() -> None:
    event = build(A1)
    assert event["proof_types"] == ["CommandOutputProofResource", "ScreenshotProofResource"]
    assert "proofs" not in event


JSON_TYPES = {str: "string", bool: "boolean", int: "integer", float: "number", list: "array", dict: "object"}
ALWAYS_ARRAYS = (
    "proof_types",
    "impacts",
    "mitre_tactic_ids",
    "mitre_technique_ids",
    "target_ipv4_addresses",
    "target_ipv6_addresses",
    "target_mac_addresses",
    "vuln_mitigations",
    "vuln_references",
)


def test_all_values_json_serializable_and_type_stable() -> None:
    events = [*fixture_events(), build(CONTRACT_EXAMPLE["weakness"], CONTRACT_EXAMPLE["pentest"])]
    assert len({tuple(event) for event in events}) == 1  # the same keys, in the same order, on every event
    types: dict[str, set[str]] = {}
    for event in events:
        json.dumps(event, allow_nan=False)
        for key, value in event.items():
            if value is not None:
                types.setdefault(key, set()).add(JSON_TYPES[type(value)])
        for key in ALWAYS_ARRAYS:
            assert isinstance(event[key], list), key
    assert {key: kinds for key, kinds in types.items() if len(kinds) > 1} == {}
    assert types["score"] == {"number"}
    assert types["pentest_weaknesses_count"] == {"integer"}
    assert types["attack_paths_count"] == {"integer"}


def test_oversized_event_truncated_not_dropped() -> None:
    row = copy.deepcopy(A1)
    row["vuln"]["description"] = "d" * 2_000_000
    event = build(row)
    assert NodeZeroEventCollector.event_size(event) > NodeZeroEventCollector.MAX_EVENT_BYTES
    capped = NodeZeroEventCollector.cap_event_size(event)
    assert capped["truncated"] is True
    assert capped["vuln_description"] == "d" * NodeZeroEventCollector.TEXT_FIELD_CAP
    assert NodeZeroEventCollector.event_size(capped) <= NodeZeroEventCollector.MAX_EVENT_BYTES
    assert {key: value for key, value in capped.items() if key not in ("vuln_description", "truncated")} == {
        key: value for key, value in event.items() if key != "vuln_description"
    }
    assert len(event["vuln_description"]) == 2_000_000  # the original event is not changed
    small = build(A1)
    assert NodeZeroEventCollector.cap_event_size(small) is small
    assert "truncated" not in small


def oversized_variants() -> dict[str, dict[str, Any]]:
    big = "x" * 2_000_000
    description = copy.deepcopy(A1)
    description["vuln"]["description"] = big
    mitigations = copy.deepcopy(A1)
    mitigations["vuln"]["mitigations"] = [{"description": "m" * 10_000} for _ in range(400)]
    two_named_fields = {**A1, "context_score_description": big, "affected_asset_display_name": big}
    unnamed_field = {**A1, "proof_failure_reason": big}
    non_ascii = copy.deepcopy(A1)
    non_ascii["vuln"]["description"] = "é" * 1_500_000  # 6 bytes each once JSON-escaped
    return {
        "description": description,
        "mitigations": mitigations,
        "two_named_fields": two_named_fields,
        "unnamed_field": unnamed_field,
        "non_ascii": non_ascii,
    }


@pytest.mark.parametrize("variant", sorted(oversized_variants()))
def test_event_cap_keeps_events_under_csp_limit(variant: str) -> None:
    event = build(oversized_variants()[variant])
    capped = NodeZeroEventCollector.cap_event_size(event)
    assert capped["truncated"] is True
    assert NodeZeroEventCollector.event_size(capped) <= NodeZeroEventCollector.MAX_EVENT_BYTES
    assert len(json.dumps(capped)) < CSP_EVENT_LIMIT_BYTES
    for key in NodeZeroEventCollector.UNTRUNCATED_FIELDS:
        if key != "truncated":
            assert capped.get(key) == event.get(key), key


def test_oversized_list_field_keeps_leading_content() -> None:
    row = copy.deepcopy(A1)
    row["vuln"]["mitigations"] = [{"description": "m" * 2_000_000}, {"description": "Second mitigation."}]
    capped = NodeZeroEventCollector.cap_event_size(build(row))
    mitigations = capped["vuln_mitigations"]
    assert mitigations, "truncating a list field must keep its leading content, not empty it"
    assert set(mitigations[0]) == {"m"}
    assert len(mitigations[0]) >= NodeZeroEventCollector.TEXT_FIELD_CAP - 2
    assert len(json.dumps(mitigations)) <= NodeZeroEventCollector.TEXT_FIELD_CAP + 2


def test_truncate_value_keeps_leading_items() -> None:
    cap = NodeZeroEventCollector.TEXT_FIELD_CAP
    assert NodeZeroEventCollector.truncate_value("y" * (cap + 5)) == "y" * cap
    items = ["a" * 4_000, "b" * 4_000, "c" * 4_000]
    kept = NodeZeroEventCollector.truncate_value(items)
    assert kept[:2] == items[:2]
    assert len(kept) == 3  # the item that crosses the limit is cut, not dropped
    assert kept[2]
    assert items[2].startswith(kept[2])
    assert len(json.dumps(kept)) <= cap + 10
    assert NodeZeroEventCollector.truncate_value(42) == 42
    assert NodeZeroEventCollector.truncate_value([1, None, 2.5]) == [1, None, 2.5]


def test_oversized_dict_item_skipped_without_emptying_the_list() -> None:
    big = {"name": "big", "url": "https://example.com/" + "x" * 20_000}
    small = {"name": "small", "url": "https://example.com/small"}
    assert NodeZeroEventCollector.truncate_value([big, small]) == [small]
    assert NodeZeroEventCollector.truncate_value([small, big, small]) == [small, small]
    row = copy.deepcopy(A1)
    row["vuln"]["description"] = "d" * 2_000_000
    row["vuln"]["references"] = [big, small]
    assert NodeZeroEventCollector.cap_event_size(build(row))["vuln_references"] == [small]


def test_counts_are_integers() -> None:
    pentest = NodeZeroEventCollector.to_pentest({**OP_A, "weaknesses_count": True})
    assert pentest is not None
    assert pentest["weaknesses_count"] is None  # a boolean is not a count
    event = build({**A1, "attack_paths_count": 2.0, "affected_credentials_count": 1.5})
    assert event["attack_paths_count"] == 2
    assert isinstance(event["attack_paths_count"], int)
    assert event["affected_credentials_count"] is None


# ----- client: authentication, token cache, GraphQL errors, HTTP settings -----


@freeze_time(NOW)
def test_token_cached_in_integration_context(harness: Harness) -> None:
    fake = standard_api(harness)
    harness.context["unrelated"] = "kept"
    run_fetch()  # the fetch holds the lease, so it caches its token
    token = fake.issued_tokens[0]
    assert harness.context["auth_token"] == token
    assert harness.context["auth_token_expires_at"] == NOW_EPOCH + 3600
    assert harness.context["auth_token_owner"] == token_owner()
    assert harness.context["unrelated"] == "kept"
    assert make_client().get_token() == token  # a later run reuses the cached token
    assert harness.auth_calls() == 1


@freeze_time(NOW)
def test_token_of_a_run_without_the_lease_stays_in_memory(harness: Harness) -> None:
    fake = standard_api(harness)
    harness.context["unrelated"] = "kept"
    client = make_client()
    token = client.get_token()
    assert token == fake.issued_tokens[0]
    assert client.get_token() == token  # reused within the run
    assert harness.auth_calls() == 1
    assert harness.context == {"unrelated": "kept"}  # never written: this run doesn't hold the lease
    assert harness.store.write_attempts == 0
    make_client().get_token()
    assert harness.auth_calls() == 2  # nothing was cached for the next run


@pytest.mark.parametrize(("seconds_to_expiry", "refreshed"), [(299, True), (300, True), (301, False), (-60, True)])
@freeze_time(NOW)
def test_token_refreshed_inside_margin(harness: Harness, seconds_to_expiry: int, refreshed: bool) -> None:
    fake = standard_api(harness)
    harness.context.update(cached_token("cached-token", NOW_EPOCH + seconds_to_expiry))
    token = make_client().get_token()
    assert token == (fake.issued_tokens[0] if refreshed else "cached-token")
    assert harness.auth_calls() == (1 if refreshed else 0)


def test_token_expiry_from_jwt_exp_with_fallback() -> None:
    now = 1_000_000
    fallback = now + NodeZeroEventCollector.DEFAULT_TOKEN_LIFETIME_SECONDS
    assert NodeZeroEventCollector.DEFAULT_TOKEN_LIFETIME_SECONDS == 3540
    assert NodeZeroEventCollector.read_token_expiry(make_jwt(now + 1800), now) == now + 1800
    assert NodeZeroEventCollector.read_token_expiry(make_jwt(None), now) == fallback
    assert NodeZeroEventCollector.read_token_expiry(make_jwt(now - 1), now) == fallback  # an exp in the past is not trusted
    assert NodeZeroEventCollector.read_token_expiry("not-a-jwt", now) == fallback
    assert NodeZeroEventCollector.read_token_expiry("a.%%%.c", now) == fallback
    payload = base64.urlsafe_b64encode(json.dumps({"exp": "soon"}).encode()).decode().rstrip("=")
    assert NodeZeroEventCollector.read_token_expiry(f"a.{payload}.c", now) == fallback
    boolean = base64.urlsafe_b64encode(json.dumps({"exp": True}).encode()).decode().rstrip("=")
    assert NodeZeroEventCollector.read_token_expiry(f"a.{boolean}.c", now) == fallback
    listed = base64.urlsafe_b64encode(json.dumps([1, 2]).encode()).decode().rstrip("=")
    assert NodeZeroEventCollector.decode_jwt_claims(f"a.{listed}.c") == {}


@freeze_time(NOW)
def test_reauth_once_on_401(harness: Harness) -> None:
    fake = standard_api(harness)
    harness.context.update({**cached_token("revoked-token", NOW_EPOCH + 3600), "unrelated": "kept"})
    fake.queue("CortexXsiamConnectivity", 401)
    make_client().check_connectivity()
    assert harness.auth_calls() == 1
    assert fake.authorization_headers == ["Bearer revoked-token", f"Bearer {fake.issued_tokens[0]}"]
    assert harness.context["auth_token"] == "revoked-token"  # a run without the lease keeps the new token in memory
    assert harness.store.write_attempts == 0


@freeze_time(NOW)
def test_reauth_on_401_during_a_fetch_replaces_the_cached_token(harness: Harness) -> None:
    fake = standard_api(harness)
    harness.context.update({**cached_token("revoked-token", NOW_EPOCH + 3600), "unrelated": "kept"})
    fake.queue("CortexXsiamFinishedPentests", 401)
    run_fetch()
    assert harness.auth_calls() == 1
    assert fake.authorization_headers[:2] == ["Bearer revoked-token", f"Bearer {fake.issued_tokens[0]}"]
    assert harness.context["auth_token"] == fake.issued_tokens[0]
    assert harness.context["unrelated"] == "kept"
    assert len(harness.sent_events()) == 5


@freeze_time(NOW)
def test_reauth_only_once(harness: Harness) -> None:
    fake = standard_api(harness)
    fake.queue("CortexXsiamConnectivity", 401)
    fake.queue("CortexXsiamConnectivity", 401)
    with pytest.raises(DemistoException, match="HTTP 401"):
        make_client().check_connectivity()
    assert harness.auth_calls() == 2  # the first token, then the single re-authentication


@freeze_time(NOW)
def test_integration_context_merged_not_replaced(harness: Harness) -> None:
    standard_api(harness)
    harness.context.update({"unrelated": {"nested": [1, 2]}, **cached_token("old", 1)})
    run_fetch()
    assert harness.context["unrelated"] == {"nested": [1, 2]}
    assert harness.context["auth_token"] != "old"
    assert harness.context["auth_token_owner"] == token_owner()
    keys = {"unrelated", "auth_token", "auth_token_expires_at", "auth_token_owner", STATE_KEY}
    assert set(harness.context) == keys  # the lease was released
    for written in harness.store.writes:
        assert written["unrelated"] == {"nested": [1, 2]}  # every write merges into the context


@freeze_time(NOW)
def test_graphql_errors_raise(harness: Harness) -> None:
    fake = standard_api(harness)
    client = make_client()
    fake.queue("CortexXsiamConnectivity", 200, load_json("graphql_errors.json"))
    with pytest.raises(DemistoException) as error:
        client.check_connectivity()
    assert 'Cannot query field "nope" on type "Pentest".' in str(error.value)
    assert "got an invalid value" in str(error.value)
    fake.queue("CortexXsiamConnectivity", 200, {"data": None})
    with pytest.raises(DemistoException, match="without data"):
        client.check_connectivity()
    fake.queue("CortexXsiamConnectivity", 200, raw="<html>gateway</html>")
    with pytest.raises(DemistoException, match="not a JSON object"):
        client.check_connectivity()
    fake.queue("CortexXsiamFinishedPentests", 200, {"data": {"pentests_page": None}})
    with pytest.raises(DemistoException, match="without a pentests list"):
        client.get_finished_pentests(FIRST_FETCH_FLOOR, 1)


def make_response(status: int, reason: str, body: Any) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response.reason = reason
    response._content = json.dumps(body).encode()
    return response


def test_http_error_message() -> None:
    body = {"errors": [{"message": 'Variable "$op_id" of required type "String!" was not provided.'}]}
    with pytest.raises(DemistoException) as error:
        NodeZeroEventCollector.raise_http_error(make_response(400, "Bad Request", body))
    assert str(error.value) == (
        'NodeZero API request failed with HTTP 400 (Bad Request): Variable "$op_id" of required type "String!" was not provided.'
    )
    assert NodeZeroEventCollector.http_status(error.value) == 400
    with pytest.raises(DemistoException) as error:
        NodeZeroEventCollector.raise_http_error(make_response(403, "Forbidden", {"message": "no"}))
    assert str(error.value) == (
        "NodeZero API request failed with HTTP 403 (Forbidden). "
        "Verify that the API key is valid and has read access to pentests and weaknesses."
    )
    assert NodeZeroEventCollector.http_status(ValueError("no response")) is None


@freeze_time(NOW)
def test_graphql_errors_with_http_error_status(harness: Harness) -> None:
    fake = standard_api(harness)
    fake.queue("CortexXsiamConnectivity", 400, load_json("graphql_errors.json"))
    with pytest.raises(DemistoException, match="HTTP 400") as error:
        make_client().check_connectivity()
    assert 'Cannot query field "nope" on type "Pentest".' in str(error.value)


@freeze_time(NOW)
def test_auth_response_without_token_raises(harness: Harness) -> None:
    fake = standard_api(harness)
    fake.queue("auth", 200, {"jwt": "missing"})
    with pytest.raises(DemistoException, match="did not include a token"):
        make_client().authenticate()


@freeze_time(NOW)
def test_bare_400_raises_with_op_id(harness: Harness) -> None:
    fake = standard_api(harness)
    fake.fail_page("op-a", 2, status=400)
    with pytest.raises(DemistoException) as error:
        run_fetch()
    assert "page 2 of the weaknesses of pentest op-a" in str(error.value)
    assert "HTTP 400" in str(error.value)
    assert harness.last_run["in_progress"]["pentest"]["op_id"] == "op-a"
    assert harness.last_run["in_progress"]["next_page"] == 2
    assert harness.last_run["in_progress"]["sent"] == 2
    assert harness.last_run["sent_ops"] == {}
    assert "nextTrigger" not in harness.last_run
    assert uuids(harness.sent_events()) == [A1["uuid"], A2["uuid"]]
    assert harness.health == []
    assert harness.summary().startswith("NodeZero fetch failed")


@freeze_time(NOW)
def test_http_retry_settings(harness: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    standard_api(harness)
    calls: list[dict[str, Any]] = []
    real_request = NodeZeroEventCollector.Client._http_request

    def spy(self: NodeZeroEventCollector.Client, **kwargs: Any) -> Any:
        calls.append(kwargs)
        return real_request(self, **kwargs)

    monkeypatch.setattr(NodeZeroEventCollector.Client, "_http_request", spy)
    run_fetch()
    assert len(calls) == 7  # auth, two sweep pages, and four weakness pages
    for kwargs in calls:
        assert kwargs["method"] == "POST"
        assert kwargs["retries"] == 4
        assert kwargs["status_list_to_retry"] == [429, 500, 502, 503, 504]
        assert kwargs["backoff_factor"] == 2
        assert kwargs["backoff_jitter"] > 0
        assert kwargs["timeout"] == 60
        assert kwargs["error_handler"] is NodeZeroEventCollector.raise_http_error


@pytest.mark.parametrize(
    ("seconds_left", "expected"),
    [(180, (60, 4)), (60, (60, 4)), (30, (30, 4)), (20, (20, 4)), (19.5, (19.5, 0)), (5, (5, 0)), (1, (5, 0)), (-30, (5, 0))],
)
def test_request_limits(seconds_left: float, expected: tuple[float, int]) -> None:
    assert NodeZeroEventCollector.request_limits(seconds_left) == expected


def test_shipped_paging_and_budget_constants() -> None:
    # The API caps page_size at 100 without an error, so with a larger PAGE_SIZE every page would come back short: each
    # sweep would end after its first page, and so would every pentest without a weaknesses_count. The other two bound
    # the time and the sweep of one run.
    assert NodeZeroEventCollector.PAGE_SIZE == 100
    assert NodeZeroEventCollector.RUN_BUDGET_SECONDS == 180
    assert NodeZeroEventCollector.MAX_SWEEP_PAGES == 10


class SlowRetryingServer:
    """Stands in for urllib3's retry loop in front of a slow, throttled server.

    Every attempt takes attempt_seconds of fake time, capped at the request timeout. The first attempt of every
    request is throttled with HTTP 503 and a retry succeeds; with no retries left the request fails the way
    _http_request fails after a 503.
    """

    def __init__(self, client: NodeZeroEventCollector.Client, clock: FakeClock, attempt_seconds: float) -> None:
        self.client = client
        self.clock = clock
        self.attempt_seconds = attempt_seconds
        self.real_request = client._http_request
        self.calls: list[tuple[float, float, int]] = []

    def __call__(self, **kwargs: Any) -> Any:
        self.calls.append((self.client.deadline.seconds_left(), kwargs["timeout"], kwargs["retries"]))
        self.clock.advance(min(self.attempt_seconds, kwargs["timeout"]))
        if kwargs["retries"] == 0:
            raise DemistoException("NodeZero API request failed with HTTP 503 (Service Unavailable).")
        self.clock.advance(min(self.attempt_seconds, kwargs["timeout"]))  # urllib3 sleeps 0 s before the first retry
        return self.real_request(**kwargs)


@freeze_time(NOW)
def test_request_timeout_bounded_by_deadline(harness: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    rows = weakness_rows("op-x", 7)  # four pages of 2, 2, 2 and 1
    FakeNodeZero(pentests=[pentest_row("op-x", 7)], weaknesses={"op-x": rows}).register(harness.requests_mock)
    clock = FakeClock(start=0.0)
    client = make_client(clock)
    server = SlowRetryingServer(client, clock, attempt_seconds=17.5)
    resets: list[tuple[float, Any]] = []
    real_reset = client._implement_retry

    def reset_spy(*args: Any, **kwargs: Any) -> None:
        resets.append((client.deadline.seconds_left(), kwargs.get("retries", args[0] if args else None)))
        real_reset(*args, **kwargs)

    monkeypatch.setattr(client, "_http_request", server)
    monkeypatch.setattr(client, "_implement_retry", reset_spy)
    with pytest.raises(DemistoException, match="page 4 of the weaknesses of pentest op-x"):
        NodeZeroEventCollector.fetch_events_command(client, FETCH_PARAMS)

    # auth, sweep, then weakness pages 1 to 4; the slow retries eat the budget as the run goes
    assert server.calls == [(180, 60, 4), (145, 60, 4), (110, 60, 4), (75, 60, 4), (40, 40, 4), (5, 5, 0)]
    for seconds_left, timeout, retries in server.calls:
        assert timeout == max(5, min(60, seconds_left))
        assert retries == (4 if seconds_left >= 20 else 0)
    assert [seconds_left for seconds_left, retries in resets if retries == 0] == [5]  # the retrying adapter is reset
    assert client.deadline.seconds_left() >= 0  # every attempt fit inside the run budget
    assert harness.last_run["in_progress"]["next_page"] == 4
    assert harness.last_run["in_progress"]["sent"] == 6
    assert "nextTrigger" not in harness.last_run

    run_fetch()  # the next run resumes at page 4 and sends only the last weakness
    assert len({event["event_id"] for event in harness.sent_events()}) == 7
    assert len(harness.sent_events()) == 7
    assert "op-x" in harness.last_run["sent_ops"]


@freeze_time(NOW)
def test_real_retry_adapter_reset_near_deadline(harness: Harness) -> None:
    standard_api(harness)
    clock = FakeClock(start=0.0)
    client = make_client(clock)
    client.authenticate()  # 180 s left: CommonServerPython mounts an adapter that retries
    assert client._session.adapters["https://"].max_retries.total == 4
    clock.advance(170)
    client.authenticate()  # 10 s left: the adapter is replaced with one that never retries
    assert client._session.adapters["https://"].max_retries.total == 0


def test_build_weaknesses_variables_requires_op_id() -> None:
    with pytest.raises(DemistoException, match="op_id is required"):
        NodeZeroEventCollector.build_weaknesses_variables("", 1)
    assert NodeZeroEventCollector.build_weaknesses_variables("op-a", 3) == {
        "op_id": "op-a",
        "page_input": {"page_num": 3, "page_size": NodeZeroEventCollector.PAGE_SIZE, "order_by": "uuid", "sort_order": "ASC"},
    }


@freeze_time(NOW)
def test_weaknesses_page_always_scoped_to_op_id(harness: Harness) -> None:
    fake = standard_api(harness)
    run_fetch()
    event_list({"should_push_events": "false", "limit": "100"})
    weakness_requests = [body for body in fake.graphql_requests if "weaknesses_page" in body["query"]]
    assert len(weakness_requests) == 8  # four pages for the fetch and four for nodezero-fetch-events
    for body in weakness_requests:
        assert "weaknesses_page(input: {op_id: $op_id}" in body["query"]
        assert body["variables"]["op_id"] in {"op-a", "op-b"}
        assert body["variables"]["page_input"]["order_by"] == "uuid"
        assert body["variables"]["page_input"]["sort_order"] == "ASC"
    assert all("weaknesses_page" not in body["query"] for body in fake.requests_for("CortexXsiamFinishedPentests"))


@freeze_time(NOW)
def test_api_key_and_token_never_logged(harness: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    """Covers every demisto.debug, info and error line, the messages given to return_error, the saved last runs and the
    sent events. It does not cover CommonServerPython's debug-mode wire log, which starts only when CommonServerPython is
    imported with debug mode on, or the traceback the real return_error adds in debug mode, because the test replaces it."""
    fake = standard_api(harness)
    errors: list[str] = []
    masked: list[str] = []
    real_mask = NodeZeroEventCollector.add_sensitive_log_strs

    def mask_spy(value: str) -> None:
        masked.append(value)
        real_mask(value)

    monkeypatch.setattr(NodeZeroEventCollector, "add_sensitive_log_strs", mask_spy)
    monkeypatch.setattr(NodeZeroEventCollector, "return_error", lambda message, *args, **kwargs: errors.append(str(message)))
    monkeypatch.setattr(NodeZeroEventCollector, "return_results", lambda *args, **kwargs: None)
    monkeypatch.setattr(demisto, "params", lambda: FETCH_PARAMS)
    monkeypatch.setattr(demisto, "args", lambda: {"should_push_events": "true", "limit": "3"})
    for command in ("test-module", "fetch-events", "nodezero-fetch-events"):
        monkeypatch.setattr(demisto, "command", lambda command=command: command)
        NodeZeroEventCollector.main()
    fake.queue("CortexXsiamFinishedPentests", 401)
    fake.queue("CortexXsiamFinishedPentests", 401)
    monkeypatch.setattr(demisto, "command", lambda: "nodezero-fetch-events")
    NodeZeroEventCollector.main()  # fails after the single re-authentication
    harness.context.clear()
    fake.queue("auth", 403, {"message": "denied"})
    monkeypatch.setattr(demisto, "command", lambda: "fetch-events")
    NodeZeroEventCollector.main()  # fails at authentication
    assert len(errors) == 2
    assert harness.messages("debug")
    secrets = [API_KEY, *fake.issued_tokens]
    # test-module's token stays in memory, the fetch caches its own for the push, and one comes from the re-authentication
    assert len(fake.issued_tokens) == 3
    texts = [message for _, message in harness.logs] + errors + [json.dumps(saved) for saved in harness.saved_last_runs]
    texts.append(json.dumps(harness.sent_events()))
    for secret in secrets:
        assert all(secret not in text for text in texts)
        assert secret in masked  # registered for masking in the platform logger


# ----- checkpoint -----


@freeze_time(NOW)
@pytest.mark.parametrize(
    "raw",
    [
        {},
        {"lastRun": "2018-10-24T14:13:20+00:00"},
        {"version": 2, "floor": "2025-01-01T00:00:00", "watermark": "2025-03-01T00:00:00", "sent_ops": {}},
        "not a dict",
    ],
)
def test_unknown_last_run_version_restarts_safely(harness: Harness, raw: Any) -> None:
    fake = standard_api(harness)
    harness.last_run = raw
    run_fetch()
    since = fake.requests_for("CortexXsiamFinishedPentests")[0]["variables"]["page_input"]["filter_by_inputs"][1]
    assert since == {"field_name": "etl_completed_at", "greater_than_or_equal": FIRST_FETCH_FLOOR}
    assert "No fetch checkpoint with a known version was found. Starting a first fetch." in harness.messages("info")
    assert harness.last_run["version"] == 1
    assert harness.last_run["floor"] == FIRST_FETCH_FLOOR
    assert len(harness.sent_events()) == 5


def test_load_last_run_ignores_unknown_keys() -> None:
    first_fetch = datetime(2025, 3, 12, 12, 0)
    raw = {
        "version": 1,
        "floor": "2025-03-01T00:00:00",
        "watermark": "2025-03-14T10:00:00.250000",
        "sent_ops": {"op-a": "2025-03-14T10:00:00.250000", "op-bad": 3, "7": None},
        "in_progress": {"pentest": {**OP_B, "unexpected": "dropped"}, "next_page": 2, "sent": 2, "extra": True},
        "nextTrigger": "0",
        "lastRun": "2018-10-24T14:13:20+00:00",
        "unknown": {"nested": True},
    }
    last_run = NodeZeroEventCollector.load_last_run(raw, first_fetch)
    assert last_run == {
        "version": 1,
        "floor": "2025-03-01T00:00:00",
        "watermark": "2025-03-14T10:00:00.250000",
        "pruned_before": "2025-02-12T10:00:00.250000",  # no pruned_before in the checkpoint: its cutoff is restored
        "sent_ops": {"op-a": "2025-03-14T10:00:00.250000"},
        "in_progress": {"pentest": NodeZeroEventCollector.to_pentest(OP_B), "next_page": 2, "sent": 2},
    }


@pytest.mark.parametrize(
    "in_progress",
    [
        {"pentest": {"op_id": ""}, "next_page": 2, "sent": 0},
        {"pentest": OP_B, "next_page": 0, "sent": 0},
        {"pentest": OP_B, "next_page": 2, "sent": -1},
        {"pentest": OP_B, "next_page": "two", "sent": 0},
        {"pentest": {**OP_A}, "next_page": 2, "sent": 2},  # already fully sent
        {"pentest": {**OP_B, "state": "ended"}, "next_page": 2, "sent": 2},  # an ended pentest is never resumed
        {"pentest": {**OP_B, "etl_completed_at": None}, "next_page": 2, "sent": 2},  # nor one without results
        "not a cursor",
    ],
)
def test_load_last_run_drops_bad_cursor(in_progress: Any) -> None:
    raw = {
        "version": 1,
        "floor": "2025-03-01T00:00:00",
        "watermark": "2025-03-14T10:00:00.250000",
        "sent_ops": {"op-a": "2025-03-14T10:00:00.250000"},
        "in_progress": in_progress,
    }
    assert NodeZeroEventCollector.load_last_run(raw, datetime(2025, 3, 12))["in_progress"] is None


def test_load_last_run_repairs_unreadable_times() -> None:
    raw = {"version": 1, "floor": "yesterday-ish", "watermark": None, "sent_ops": [], "in_progress": None}
    last_run = NodeZeroEventCollector.load_last_run(raw, datetime(2025, 3, 12, 12, 0, 0, 999))
    assert last_run["floor"] == FIRST_FETCH_FLOOR
    assert last_run["watermark"] == FIRST_FETCH_FLOOR
    assert last_run["sent_ops"] == {}


def test_sent_ops_pruned_after_retention() -> None:
    state = NodeZeroEventCollector.load_last_run(
        {
            "version": 1,
            "floor": "2025-01-01T00:00:00",
            "watermark": "2025-03-14T10:00:00",
            "sent_ops": {
                "op-old": "2025-02-12T09:59:59",  # more than 30 days before the new watermark
                "op-edge": "2025-02-12T10:00:00",  # exactly 30 days before it
                "op-recent": "2025-03-14T10:00:00",
            },
            "in_progress": None,
        },
        datetime(2025, 1, 1),
    )
    same_time = NodeZeroEventCollector.to_pentest(pentest_row("op-new", 1, etl_completed_at="2025-03-14T10:00:00"))
    state = NodeZeroEventCollector.with_pentest_sent(state, same_time)
    state = NodeZeroEventCollector.prune_sent_ops(NodeZeroEventCollector.advance_watermark(state, [same_time]))
    assert state["watermark"] == "2025-03-14T10:00:00"
    assert state["sent_ops"] == {
        "op-edge": "2025-02-12T10:00:00",
        "op-recent": "2025-03-14T10:00:00",
        "op-new": "2025-03-14T10:00:00",
    }
    assert state["pruned_before"] == "2025-02-12T10:00:00.000000"  # the cutoff, so op-old still counts as sent
    old = NodeZeroEventCollector.to_pentest(pentest_row("op-old", 1, etl_completed_at="2025-02-12T09:59:59"))
    assert NodeZeroEventCollector.is_sent(state, old)
    one_second_later = NodeZeroEventCollector.to_pentest(pentest_row("op-next", 1, etl_completed_at="2025-03-14T10:00:01"))
    state = NodeZeroEventCollector.with_pentest_sent(state, one_second_later)
    state = NodeZeroEventCollector.prune_sent_ops(NodeZeroEventCollector.advance_watermark(state, [one_second_later]))
    assert "op-edge" not in state["sent_ops"]
    assert state["pruned_before"] == "2025-02-12T10:00:01.000000"


def test_unreadable_checkpoint_time_raises() -> None:
    last_run = NodeZeroEventCollector.new_last_run(datetime(2025, 3, 12, 12, 0))
    last_run["watermark"] = "garbage"
    with pytest.raises(DemistoException, match="timestamp that can't be read"):
        NodeZeroEventCollector.prune_sent_ops(last_run)


def test_watermark_never_decreases() -> None:
    state = NodeZeroEventCollector.new_last_run(datetime(2025, 3, 12, 12, 0))
    op_a, op_b = NodeZeroEventCollector.to_pentest(OP_A), NodeZeroEventCollector.to_pentest(OP_B)
    state = NodeZeroEventCollector.with_pentest_sent(NodeZeroEventCollector.with_pentest_sent(state, op_b), op_a)
    state = NodeZeroEventCollector.advance_watermark(state, [op_a, op_b])
    assert state["watermark"] == OP_B["etl_completed_at"]
    state = NodeZeroEventCollector.advance_watermark(state, [op_a])  # a later sweep that sees only the older pentest
    assert state["watermark"] == OP_B["etl_completed_at"]
    assert set(state["sent_ops"]) == {"op-a", "op-b"}
    assert state["in_progress"] is None


def test_sweep_start_uses_lookback_never_below_floor() -> None:
    last_run = NodeZeroEventCollector.new_last_run(datetime(2025, 3, 12, 12, 0))
    assert NodeZeroEventCollector.sweep_start(last_run) == FIRST_FETCH_FLOOR
    last_run["watermark"] = "2025-03-12T20:00:00"  # less than 24 hours after the floor
    assert NodeZeroEventCollector.sweep_start(last_run) == FIRST_FETCH_FLOOR
    last_run["watermark"] = "2025-03-14T10:00:00.250000"
    assert NodeZeroEventCollector.sweep_start(last_run) == "2025-03-13T10:00:00"  # whole seconds, naive UTC


# ----- fetch-events -----


@freeze_time(NOW)
def test_sweep_filters_state_and_etl_completed_at(harness: Harness) -> None:
    fake = standard_api(harness)
    run_fetch()
    sweeps = fake.requests_for("CortexXsiamFinishedPentests")
    assert sweeps[0]["variables"] == {
        "page_input": {
            "page_num": 1,
            "page_size": 2,
            "filter_by_inputs": [
                {"field_name": "state", "values": ["done"]},
                {"field_name": "etl_completed_at", "greater_than_or_equal": FIRST_FETCH_FLOOR},
            ],
            "sort_inputs": [{"order_by": "etl_completed_at", "sort_order": "ASC"}, {"order_by": "op_id", "sort_order": "ASC"}],
        }
    }
    assert [body["variables"]["page_input"]["page_num"] for body in sweeps] == [1, 2]  # page 1 was full, page 2 was empty
    assert NodeZeroEventCollector.FINISHED_STATES == ["done"]


@freeze_time(NOW)
def test_no_severity_filter_in_any_query(harness: Harness) -> None:
    fake = standard_api(harness)
    run_fetch()
    event_list({"should_push_events": "false", "limit": "100"})
    view({"pentest_id": "op-a"})
    NodeZeroEventCollector.test_module(make_client(), FETCH_PARAMS)
    assert {operation_name(body["query"]) for body in fake.graphql_requests} == {
        "CortexXsiamFinishedPentests",
        "CortexXsiamPentest",
        "CortexXsiamPentestWeaknesses",
        "CortexXsiamConnectivity",
    }
    for body in fake.graphql_requests:
        assert "severity" not in json.dumps(body["variables"]).lower()
        assert re.search(r"\([^)]*severity", body["query"]) is None  # severity is only ever selected, never an argument
    severities = {event["severity"] for event in harness.sent_events()}
    assert severities == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


@freeze_time(NOW)
def test_pentest_without_etl_completed_at_skipped(harness: Harness) -> None:
    fake = FakeNodeZero(sweep_pages=[UNFINISHED_ETL_PAGE], weakness_pages={"op-a": OP_A_PAGES, "op-b": OP_B_PAGES})
    fake.register(harness.requests_mock)
    run_fetch()
    assert {op_id for op_id, _ in fake.weakness_page_calls} == {"op-a", "op-b"}
    assert set(harness.last_run["sent_ops"]) == {"op-a", "op-b"}
    assert len(harness.sent_events()) == 5


def test_pending_list_skips_sent_and_in_progress_pentests() -> None:
    state = NodeZeroEventCollector.new_last_run(datetime(2025, 3, 12, 12, 0))
    op_a, op_b = NodeZeroEventCollector.to_pentest(OP_A), NodeZeroEventCollector.to_pentest(OP_B)
    state["in_progress"] = {"pentest": op_a, "next_page": 2, "sent": 2}
    assert [pentest["op_id"] for pentest in NodeZeroEventCollector.pending_pentests(state, [op_a, op_b])] == ["op-b"]
    state["in_progress"] = None
    state["sent_ops"]["op-b"] = OP_B["etl_completed_at"]
    assert [pentest["op_id"] for pentest in NodeZeroEventCollector.pending_pentests(state, [op_a, op_b])] == ["op-a"]


@freeze_time(NOW)
def test_fetch_rechecks_sent_ops_before_each_pentest(harness: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = standard_api(harness)
    pentest = NodeZeroEventCollector.to_pentest(OP_A)
    monkeypatch.setattr(NodeZeroEventCollector, "pending_pentests", lambda *args: [pentest, pentest])
    run_fetch()
    assert fake.weakness_page_calls == [("op-a", 1), ("op-a", 2)]
    assert len(harness.sent_events()) == 3


def test_finished_pentests_rechecks_state_and_results() -> None:
    rows = [
        OP_A,
        {**OP_A, "op_id": "op-running", "state": "running"},
        {**OP_A, "op_id": "op-ended", "state": "ended"},  # stopped early by a user, even with its results available
        {**OP_A, "op_id": "op-no-results", "etl_completed_at": None},
        {**OP_A, "op_id": "op-bad-time", "etl_completed_at": "later"},
        {**OP_A, "op_id": ""},
    ]
    assert [pentest["op_id"] for pentest in NodeZeroEventCollector.finished_pentests(rows)] == ["op-a"]


NOT_COLLECTED = {
    "ended": {"state": "ended"},  # stopped early by a user, even with its results available
    "done-without-results": {"etl_completed_at": None},
    "done-with-an-unreadable-results-time": {"etl_completed_at": "later"},
}


def collect_with(harness: Harness, command: str) -> list[dict[str, Any]]:
    """Run fetch-events or nodezero-fetch-events and return the events it collected."""
    if command == "fetch-events":
        run_fetch()
        return harness.sent_events()
    return event_list({"should_push_events": "false", "limit": "100"}).raw_response


@freeze_time(NOW)
@pytest.mark.parametrize("command", ["fetch-events", "nodezero-fetch-events"])
@pytest.mark.parametrize("case", list(NOT_COLLECTED))
def test_pentest_returned_despite_the_query_filters_is_skipped(harness: Harness, command: str, case: str) -> None:
    fields = {"etl_completed_at": "2025-03-14T10:30:00", **NOT_COLLECTED[case]}
    skipped = pentest_row("op-skip", 2, **fields)
    # Raw sweep pages ignore the query filters, so only the collector's own check can skip op-skip.
    fake = FakeNodeZero(
        sweep_pages=[pentests_body([OP_A, skipped, OP_B])],
        weakness_pages={"op-a": OP_A_PAGES, "op-b": OP_B_PAGES},
        weaknesses={"op-skip": weakness_rows("op-skip", 2)},
    ).register(harness.requests_mock)
    assert uuids(collect_with(harness, command)) == uuids(ALL_ROWS)
    assert "op-skip" not in {op_id for op_id, _ in fake.weakness_page_calls}
    if command == "fetch-events":
        assert set(harness.last_run["sent_ops"]) == {"op-a", "op-b"}


@freeze_time(NOW)
def test_sweeps_ask_for_done_pentests_only(harness: Harness) -> None:
    ended = pentest_row("op-ended", 2, state="ended", etl_completed_at="2025-03-14T10:30:00")  # stopped early by a user
    fake = FakeNodeZero(
        pentests=[OP_A, ended, OP_B],
        weakness_pages={"op-a": OP_A_PAGES, "op-b": OP_B_PAGES},
        weaknesses={"op-ended": weakness_rows("op-ended", 2)},
    ).register(harness.requests_mock)
    run_fetch()
    result = event_list({"should_push_events": "false", "limit": "100"})
    sweeps = fake.requests_for("CortexXsiamFinishedPentests")
    assert len(sweeps) == 4  # two pages for the fetch and two for nodezero-fetch-events
    for body in sweeps:
        assert body["variables"]["page_input"]["filter_by_inputs"][0] == {"field_name": "state", "values": ["done"]}
    assert "op-ended" not in {op_id for op_id, _ in fake.weakness_page_calls}
    assert set(harness.last_run["sent_ops"]) == {"op-a", "op-b"}
    assert uuids(harness.sent_events()) == uuids(ALL_ROWS)
    assert uuids(result.raw_response) == uuids(ALL_ROWS)


@freeze_time(NOW)
@pytest.mark.parametrize("command", ["fetch-events", "nodezero-fetch-events"])
def test_full_sweep_page_of_skipped_pentests_keeps_the_sweep_going(harness: Harness, command: str) -> None:
    ended_1 = pentest_row("op-e1", 2, state="ended", etl_completed_at="2025-03-14T08:00:00")
    ended_2 = pentest_row("op-e2", 2, state="ended", etl_completed_at="2025-03-14T08:30:00")
    fake = FakeNodeZero(
        sweep_pages=[pentests_body([ended_1, ended_2]), pentests_body([OP_A, OP_B])],  # raw pages ignore the filters
        weakness_pages={"op-a": OP_A_PAGES, "op-b": OP_B_PAGES},
        weaknesses={"op-e1": weakness_rows("op-e1", 2), "op-e2": weakness_rows("op-e2", 2)},
    ).register(harness.requests_mock)
    if command == "fetch-events":
        run_fetch()
        events = harness.sent_events()
    else:
        events = event_list({"should_push_events": "false", "limit": "100"}).raw_response
    assert uuids(events) == uuids(ALL_ROWS)
    assert {op_id for op_id, _ in fake.weakness_page_calls} == {"op-a", "op-b"}
    assert len(fake.requests_for("CortexXsiamFinishedPentests")) == 3  # a full page of skipped rows still counts as a full page


@freeze_time(NOW)
def test_sweep_deduplicates_pentests_across_pages(harness: Harness) -> None:
    fake = FakeNodeZero(
        sweep_pages=[FINISHED_PAGE, pentests_body([OP_B])], weakness_pages={"op-a": OP_A_PAGES, "op-b": OP_B_PAGES}
    )
    fake.register(harness.requests_mock)  # op-b comes back on both sweep pages
    run_fetch()
    assert fake.weakness_page_calls == [("op-a", 1), ("op-a", 2), ("op-b", 1), ("op-b", 2)]
    fake.weakness_page_calls.clear()
    result = event_list({"should_push_events": "false", "limit": "100"})  # nodezero-fetch-events has no sent_ops to lean on
    assert uuids(result.raw_response) == uuids(ALL_ROWS)
    assert fake.weakness_page_calls == [("op-a", 1), ("op-a", 2), ("op-b", 1), ("op-b", 2)]


def test_pentest_collected_on_first_run_after_completion(harness: Harness) -> None:
    running = pentest_row("op-x", 3, state="running", completed_at=None, etl_completed_at=None)
    rows = weakness_rows("op-x", 3)
    fake = FakeNodeZero(pentests=[running], weaknesses={"op-x": rows}).register(harness.requests_mock)
    with freeze_time("2025-03-15T12:00:00Z"):
        run_fetch()
    assert harness.sent_events() == []
    assert fake.weakness_page_calls == []  # nothing is read before the pentest completes
    running.update(state="done", completed_at="2025-03-15T12:05:00", etl_completed_at="2025-03-15T12:10:00")
    with freeze_time("2025-03-15T12:30:00Z"):
        run_fetch()
    assert uuids(harness.sent_events()) == uuids(rows)
    assert harness.last_run["sent_ops"] == {"op-x": "2025-03-15T12:10:00"}


@freeze_time(NOW)
def test_lookback_catches_late_visible_pentest(harness: Harness) -> None:
    pentests = [OP_A]
    late_rows = [make_weakness("op-late", 0)]
    fake = FakeNodeZero(pentests=pentests, weakness_pages={"op-a": OP_A_PAGES}, weaknesses={"op-late": late_rows})
    fake.register(harness.requests_mock)
    run_fetch()
    assert harness.last_run["watermark"] == OP_A["etl_completed_at"]
    pentests.append(pentest_row("op-late", 1, etl_completed_at="2025-03-14T08:00:00"))  # appears after a later pentest was sent
    pentests.append(pentest_row("op-too-late", 1, etl_completed_at="2025-03-13T09:59:59"))  # older than the look-back
    harness.sends.clear()
    run_fetch()
    last_sweep = fake.requests_for("CortexXsiamFinishedPentests")[-1]
    since = last_sweep["variables"]["page_input"]["filter_by_inputs"][1]["greater_than_or_equal"]
    assert since == "2025-03-13T10:00:00"
    assert uuids(harness.sent_events()) == uuids(late_rows)  # op-a is not sent again
    assert set(harness.last_run["sent_ops"]) == {"op-a", "op-late"}
    assert harness.last_run["watermark"] == OP_A["etl_completed_at"]


@freeze_time(NOW)
def test_floor_bounds_first_run_window(harness: Harness) -> None:
    old = pentest_row("op-old", 1, etl_completed_at="2025-03-12T11:59:59")
    new = pentest_row("op-new", 1, etl_completed_at=FIRST_FETCH_FLOOR)
    weaknesses = {"op-old": [make_weakness("op-old", 0)], "op-new": [make_weakness("op-new", 0)]}
    fake = FakeNodeZero(pentests=[old, new], weaknesses=weaknesses).register(harness.requests_mock)
    run_fetch()
    run_fetch()
    for body in fake.requests_for("CortexXsiamFinishedPentests"):
        assert body["variables"]["page_input"]["filter_by_inputs"][1]["greater_than_or_equal"] == FIRST_FETCH_FLOOR
    assert harness.last_run["floor"] == FIRST_FETCH_FLOOR
    assert set(harness.last_run["sent_ops"]) == {"op-new"}
    assert {op_id for op_id, _ in fake.weakness_page_calls} == {"op-new"}


@freeze_time(NOW)
def test_drain_sends_every_weakness_across_pages(harness: Harness) -> None:
    standard_api(harness)
    run_fetch()
    assert uuids(harness.sent_events()) == uuids(ALL_ROWS)
    assert [len(events) for events in harness.page_sends()] == [2, 1, 2]
    assert all(vendor == "horizon3" for _, vendor, _, _ in harness.sends)
    assert all(product == "nodezero" for _, _, product, _ in harness.sends)
    assert harness.last_run == {
        "version": 1,
        "floor": FIRST_FETCH_FLOOR,
        "watermark": OP_B["etl_completed_at"],
        "pruned_before": "2025-02-12T11:00:00.000000",  # 30 days before the watermark, still before the floor
        "sent_ops": {"op-a": OP_A["etl_completed_at"], "op-b": OP_B["etl_completed_at"]},
        "in_progress": None,
    }
    assert harness.store.state() == harness.last_run  # the checkpoint mirrors the shared state
    assert harness.store.lease() is None  # released
    summary = harness.summary()
    assert "2 pentests fully sent, 5 events sent" in summary
    assert "events per pentest {'op-a': 3, 'op-b': 2}" in summary
    assert "count mismatches (sent, expected) {}" in summary


@freeze_time(NOW)
def test_short_and_empty_last_page_end_drain(harness: Harness) -> None:
    fake = standard_api(harness)
    run_fetch()
    # op-a ends on its short page 2, which brings it to its weaknesses_count of 3; op-b fills page 1, so page 2 is
    # read and is empty
    assert fake.weakness_page_calls == [("op-a", 1), ("op-a", 2), ("op-b", 1), ("op-b", 2)]


@pytest.mark.parametrize(
    ("row_count", "new_events", "pentest_events", "expected", "is_last"),
    [
        (0, 0, 3, 5, True),  # an empty page ends the pentest
        (2, 2, 5, 5, False),  # a full page never does, even once the count is reached
        (2, 0, 5, 5, False),  # nor does a full page of repeats
        (1, 1, 5, 5, True),  # a short page ends it once the count is reached
        (1, 1, 6, 5, True),  # or passed
        (1, 1, 1, None, True),  # or when the count is unknown
        (1, 0, 3, 5, True),  # or when every row on it was already seen
        (1, 1, 4, 5, False),  # otherwise the next page is read
    ],
)
def test_end_of_pentest_rule(
    monkeypatch: pytest.MonkeyPatch, row_count: int, new_events: int, pentest_events: int, expected: int | None, is_last: bool
) -> None:
    monkeypatch.setattr(NodeZeroEventCollector, "PAGE_SIZE", 2)
    assert NodeZeroEventCollector.is_last_weakness_page(row_count, new_events, pentest_events, expected) is is_last


@freeze_time(NOW)
def test_short_page_mid_pentest_is_read_past(harness: Harness) -> None:
    rows = weakness_rows("op-x", 4)
    pages = [weaknesses_body(rows[:2]), weaknesses_body(rows[2:3]), weaknesses_body(rows[3:])]  # page 2 comes back short
    fake = FakeNodeZero(pentests=[pentest_row("op-x", 4)], weakness_pages={"op-x": pages}).register(harness.requests_mock)
    run_fetch()
    assert fake.weakness_page_calls == [("op-x", 1), ("op-x", 2), ("op-x", 3)]  # page 3 reaches the count of 4
    assert uuids(harness.sent_events()) == uuids(rows)
    cursors = [(saved["in_progress"] or {}).get("next_page") for saved in harness.saved_last_runs]
    # the seed and the sweep's bookkeeping commits, a cursor after pages 1 and 2, the finish, then the final checkpoint;
    # the short page 2 saved a cursor, like a full page
    assert cursors == [None, None, 2, 3, None, None]
    assert committed_cursors(harness) == [None, None, 2, 3, None]  # the seed, the bookkeeping, then each page
    assert list(harness.last_run["sent_ops"]) == ["op-x"]
    assert "count mismatches (sent, expected) {}" in harness.summary()


@freeze_time(NOW)
def test_short_last_page_that_reaches_the_count_needs_no_extra_request(harness: Harness) -> None:
    rows = weakness_rows("op-x", 5)  # pages of 2, 2 and 1
    fake = FakeNodeZero(pentests=[pentest_row("op-x", 5)], weaknesses={"op-x": rows}).register(harness.requests_mock)
    run_fetch()
    assert fake.weakness_page_calls == [("op-x", 1), ("op-x", 2), ("op-x", 3)]  # no 4th, empty page
    assert uuids(harness.sent_events()) == uuids(rows)
    assert list(harness.last_run["sent_ops"]) == ["op-x"]
    assert "count mismatches (sent, expected) {}" in harness.summary()


@freeze_time(NOW)
def test_page_cursor_saved_after_every_page(harness: Harness) -> None:
    standard_api(harness)
    run_fetch()
    cursors = [(saved["in_progress"] or {}).get("next_page") for saved in harness.saved_last_runs]
    sent_ops = [sorted(saved["sent_ops"]) for saved in harness.saved_last_runs]
    # seed, bookkeeping, then after each page: op-a page 1, op-a done, op-b page 1, op-b done; then the final checkpoint
    assert cursors == [None, None, 2, None, 2, None, None]
    assert sent_ops == [[], [], [], ["op-a"], ["op-a"], ["op-a", "op-b"], ["op-a", "op-b"]]
    assert all("nextTrigger" not in saved for saved in harness.saved_last_runs)
    assert committed_cursors(harness) == [None, None, 2, None, 2, None]  # each page was committed to the shared state first


@freeze_time(NOW)
def test_zero_weakness_pentest_queried_once_then_marked_sent(harness: Harness) -> None:
    fake = FakeNodeZero(pentests=[pentest_row("op-z", 0)]).register(harness.requests_mock)
    run_fetch()
    assert fake.weakness_page_calls == [("op-z", 1)]
    assert list(harness.last_run["sent_ops"]) == ["op-z"]
    assert harness.sends == [([], "horizon3", "nodezero", {})]


@freeze_time(NOW)
def test_count_mismatch_logged_not_raised(harness: Harness) -> None:
    FakeNodeZero(pentests=[OP_A], weaknesses={"op-a": [A1, A2]}).register(harness.requests_mock)  # 2 of the 3 reported
    run_fetch()
    assert "op-a" in harness.last_run["sent_ops"]
    assert "count mismatches (sent, expected) {'op-a': (2, 3)}" in harness.summary()
    assert harness.messages("error") == []


@freeze_time(NOW)
def test_stale_larger_count_costs_one_empty_page_and_is_recorded(harness: Harness) -> None:
    stale = {**OP_A, "weaknesses_count": 4}  # op-a has 3 weaknesses
    fake = FakeNodeZero(pentests=[stale], weakness_pages={"op-a": OP_A_PAGES}).register(harness.requests_mock)
    run_fetch()
    assert fake.weakness_page_calls == [("op-a", 1), ("op-a", 2), ("op-a", 3)]  # one extra request: page 3, which is empty
    assert uuids(harness.sent_events()) == uuids([A1, A2, A3])
    assert list(harness.last_run["sent_ops"]) == ["op-a"]
    assert "count mismatches (sent, expected) {'op-a': (3, 4)}" in harness.summary()
    assert harness.messages("error") == []


@freeze_time(NOW)
def test_null_weakness_count_skips_mismatch_check(harness: Harness) -> None:
    FakeNodeZero(pentests=[{**OP_A, "weaknesses_count": None}], weakness_pages={"op-a": OP_A_PAGES}).register(
        harness.requests_mock
    )
    run_fetch()
    assert "count mismatches (sent, expected) {}" in harness.summary()
    assert len(harness.sent_events()) == 3


@freeze_time(NOW)
def test_unknown_count_ends_on_the_short_page(harness: Harness) -> None:
    unknown = {**OP_A, "weaknesses_count": None}
    fake = FakeNodeZero(pentests=[unknown], weakness_pages={"op-a": OP_A_PAGES}).register(harness.requests_mock)
    run_fetch()
    assert fake.weakness_page_calls == [("op-a", 1), ("op-a", 2)]  # no count to check, so no extra request
    assert list(harness.last_run["sent_ops"]) == ["op-a"]


@freeze_time(NOW)
def test_in_run_duplicate_uuid_dropped(harness: Harness) -> None:
    pages = [weaknesses_body([A1, A2]), weaknesses_body([A2, A3])]  # page drift repeats A2
    FakeNodeZero(pentests=[OP_A], weakness_pages={"op-a": pages}).register(harness.requests_mock)
    run_fetch()
    assert uuids(harness.sent_events()) == uuids([A1, A2, A3])
    assert "count mismatches (sent, expected) {}" in harness.summary()


@freeze_time(NOW)
def test_repeated_short_page_ends_the_pentest(harness: Harness) -> None:
    pages = [weaknesses_body([A1, A2]), *[weaknesses_body([A3])] * 50]  # every later page repeats page 2's row
    stale = {**OP_A, "weaknesses_count": 5}  # never reached, so only the repeat can end op-a
    fake = FakeNodeZero(pentests=[stale], weakness_pages={"op-a": pages}).register(harness.requests_mock)
    run_fetch()
    assert fake.weakness_page_calls == [("op-a", 1), ("op-a", 2), ("op-a", 3)]  # page 3 added nothing new
    assert uuids(harness.sent_events()) == uuids([A1, A2, A3])
    assert list(harness.last_run["sent_ops"]) == ["op-a"]
    assert "count mismatches (sent, expected) {'op-a': (3, 5)}" in harness.summary()


@freeze_time(NOW)
def test_per_page_send_skipped_when_empty(harness: Harness) -> None:
    pages = [weaknesses_body([A1, A2]), weaknesses_body([A1, A2]), weaknesses_body([A3])]  # page 2 holds only repeats
    empty_pentest = pentest_row("op-z", 0, etl_completed_at="2025-03-14T10:30:00")
    FakeNodeZero(pentests=[OP_A, empty_pentest], weakness_pages={"op-a": pages}).register(harness.requests_mock)
    run_fetch()
    assert [uuids(events) for events in harness.page_sends()] == [uuids([A1, A2]), uuids([A3])]
    assert all(events for events, _, _, _ in harness.sends)  # an empty list is never sent, not even for op-z
    assert harness.health == [{"eventsPulled": 3}]
    assert set(harness.last_run["sent_ops"]) == {"op-a", "op-z"}


@freeze_time(NOW)
def test_large_pentest_streams_bounded_pages(harness: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(NodeZeroEventCollector, "PAGE_SIZE", 100)
    rows = weakness_rows("op-big", 5000)
    fake = FakeNodeZero(pentests=[pentest_row("op-big", 5000)], weaknesses={"op-big": rows}).register(harness.requests_mock)
    run_fetch()
    page_sizes = [len(events) for events in harness.page_sends()]
    assert len(page_sizes) == 50
    assert max(page_sizes) <= 100
    assert sum(page_sizes) == 5000
    assert len({event["event_id"] for event in harness.sent_events()}) == 5000
    assert fake.weakness_page_calls == [("op-big", page_num) for page_num in range(1, 52)]
    assert harness.health == [{"eventsPulled": 5000}]
    assert harness.last_run["in_progress"] is None
    assert "op-big" in harness.last_run["sent_ops"]
    assert "count mismatches (sent, expected) {}" in harness.summary()


@freeze_time(NOW)
def test_oversized_event_sent_through_fetch(harness: Harness) -> None:
    row = copy.deepcopy(A1)
    row["vuln"]["description"] = "d" * 2_000_000
    FakeNodeZero(pentests=[pentest_row("op-a", 1)], weaknesses={"op-a": [row]}).register(harness.requests_mock)
    run_fetch()
    (event,) = harness.sent_events()
    assert event["truncated"] is True
    assert NodeZeroEventCollector.event_size(event) <= NodeZeroEventCollector.MAX_EVENT_BYTES
    assert "count mismatches (sent, expected) {}" in harness.summary()


@freeze_time(NOW)
def test_budget_exhaustion_sets_cursor_and_next_trigger(harness: Harness) -> None:
    rows = weakness_rows("op-x", 7)
    fake = FakeNodeZero(pentests=[pentest_row("op-x", 7)], weaknesses={"op-x": rows}).register(harness.requests_mock)
    clock = FakeClock()
    fake.charge_weakness_pages(clock, 70)  # pages 1 to 3 use 210 s of the 180 s budget
    run_fetch(clock=clock)
    assert fake.weakness_page_calls == [("op-x", 1), ("op-x", 2), ("op-x", 3)]
    assert harness.last_run["in_progress"] == {
        "pentest": NodeZeroEventCollector.to_pentest(pentest_row("op-x", 7)),
        "next_page": 4,
        "sent": 6,
    }
    assert harness.last_run["nextTrigger"] == "0"
    assert "op-x" not in harness.last_run["sent_ops"]
    assert harness.health == [{"eventsPulled": 6}]
    assert all("nextTrigger" not in saved for saved in harness.saved_last_runs[:-1])
    assert "more work pending True" in harness.summary()


@freeze_time(NOW)
def test_resume_from_cursor_sends_no_duplicates(harness: Harness) -> None:
    rows = weakness_rows("op-x", 7)
    fake = FakeNodeZero(pentests=[pentest_row("op-x", 7)], weaknesses={"op-x": rows}).register(harness.requests_mock)
    clock = FakeClock()
    fake.charge_weakness_pages(clock, 70)
    run_fetch(clock=clock)
    fake.page_cost = None
    fake.weakness_page_calls.clear()
    harness.logs.clear()
    run_fetch()
    assert fake.weakness_page_calls == [("op-x", 4)]  # resumed at the cursor; pages 1 to 3 are not read again
    assert sorted(uuids(harness.sent_events())) == uuids(rows)
    assert harness.last_run["in_progress"] is None
    assert harness.last_run["sent_ops"] == {"op-x": "2025-03-14T10:00:00.250000"}
    assert "nextTrigger" not in harness.last_run
    assert "count mismatches (sent, expected) {}" in harness.summary()


@freeze_time(NOW)
def test_resume_counts_the_events_earlier_runs_sent(harness: Harness) -> None:
    rows = weakness_rows("op-x", 4)
    pages = [weaknesses_body(rows[:2]), weaknesses_body(rows[2:3]), weaknesses_body(rows[3:])]
    fake = FakeNodeZero(pentests=[pentest_row("op-x", 4)], weakness_pages={"op-x": pages}).register(harness.requests_mock)
    harness.last_run = {
        "version": 1,
        "floor": FIRST_FETCH_FLOOR,
        "watermark": FIRST_FETCH_FLOOR,
        "sent_ops": {},
        "in_progress": {"pentest": pentest_row("op-x", 4), "next_page": 2, "sent": 2},  # an earlier run sent page 1
    }
    run_fetch()
    # page 2 is short at 3 of 4 events, so page 3 is read; with the 2 carried over it reaches 4, so page 4 is not read
    assert fake.weakness_page_calls == [("op-x", 2), ("op-x", 3)]
    assert uuids(harness.sent_events()) == uuids(rows[2:])
    assert list(harness.last_run["sent_ops"]) == ["op-x"]
    assert "count mismatches (sent, expected) {}" in harness.summary()


@freeze_time(NOW)
def test_resume_that_runs_out_of_time_skips_the_sweep(harness: Harness) -> None:
    rows = weakness_rows("op-x", 7)
    fake = FakeNodeZero(pentests=[pentest_row("op-x", 7)], weaknesses={"op-x": rows}).register(harness.requests_mock)
    harness.last_run = {
        "version": 1,
        "floor": FIRST_FETCH_FLOOR,
        "watermark": FIRST_FETCH_FLOOR,
        "sent_ops": {},
        "in_progress": {"pentest": pentest_row("op-x", 7), "next_page": 2, "sent": 2},
    }
    clock = FakeClock()
    fake.charge_weakness_pages(clock, 200)
    run_fetch(clock=clock)
    assert fake.weakness_page_calls == [("op-x", 2)]
    assert fake.requests_for("CortexXsiamFinishedPentests") == []  # no new pentest is looked for once time is up
    assert harness.last_run["in_progress"]["next_page"] == 3
    assert harness.last_run["in_progress"]["sent"] == 4
    assert harness.last_run["nextTrigger"] == "0"


@freeze_time(NOW)
def test_resume_that_finishes_near_the_deadline_skips_the_sweep(harness: Harness) -> None:
    fake = standard_api(harness)
    harness.last_run = {
        "version": 1,
        "floor": FIRST_FETCH_FLOOR,
        "watermark": FIRST_FETCH_FLOOR,
        "sent_ops": {},
        "in_progress": {"pentest": OP_A, "next_page": 2, "sent": 2},
    }
    clock = FakeClock()
    fake.charge_weakness_pages(clock, 160)  # op-a's last page leaves 20 s, under the 30 s needed to start a pentest
    run_fetch(clock=clock)
    assert fake.weakness_page_calls == [("op-a", 2)]
    assert fake.requests_for("CortexXsiamFinishedPentests") == []  # no sweep request that would have no retries left
    assert list(harness.last_run["sent_ops"]) == ["op-a"]
    assert harness.last_run["nextTrigger"] == "0"  # the next run sweeps with a full budget


@freeze_time(NOW)
def test_new_pentest_not_started_with_little_time_left(harness: Harness) -> None:
    fake = standard_api(harness)
    clock = FakeClock()
    fake.charge_weakness_pages(clock, 80)  # op-a's two pages leave 20 s, under the 30 s needed to start op-b
    run_fetch(clock=clock)
    assert {op_id for op_id, _ in fake.weakness_page_calls} == {"op-a"}
    assert list(harness.last_run["sent_ops"]) == ["op-a"]
    assert harness.last_run["in_progress"] is None
    assert harness.last_run["nextTrigger"] == "0"


class SlowSweepNodeZero(FakeNodeZero):
    """FakeNodeZero whose sweep pages cost time on a fake clock, like a slow or retrying pentests_page."""

    def __init__(self, *args: Any, clock: FakeClock, sweep_seconds: float, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.clock = clock
        self.sweep_seconds = sweep_seconds

    def sweep_page(self, page_input: dict[str, Any]) -> dict[str, Any]:
        self.clock.advance(self.sweep_seconds)
        return super().sweep_page(page_input)


@freeze_time(NOW)
def test_slow_sweep_without_progress_waits_for_the_next_interval(harness: Harness) -> None:
    clock = FakeClock()
    fake = SlowSweepNodeZero(
        pentests=[OP_A, OP_B], weakness_pages={"op-a": OP_A_PAGES, "op-b": OP_B_PAGES}, clock=clock, sweep_seconds=80
    )
    fake.register(harness.requests_mock)
    run_fetch(clock=clock)  # two sweep pages use 160 s and leave 20 s, so no pentest can start
    assert fake.weakness_page_calls == []
    assert "nextTrigger" not in harness.last_run  # no progress, so the run doesn't ask to run again at once
    assert harness.sends == [([], "horizon3", "nodezero", {})]
    assert "more work pending True" in harness.summary()  # work remains; it waits for the next interval


@freeze_time(NOW)
def test_slow_sweep_stops_early_and_sends_what_it_found(harness: Harness) -> None:
    clock = FakeClock()
    rows = [pentest_row(f"op-{index}", 1, etl_completed_at=f"2025-03-14T0{index}:00:00") for index in range(1, 7)]
    weaknesses = {row["op_id"]: [make_weakness(row["op_id"], index)] for index, row in enumerate(rows)}
    fake = SlowSweepNodeZero(pentests=rows, weaknesses=weaknesses, clock=clock, sweep_seconds=50)
    fake.register(harness.requests_mock)
    run_fetch(clock=clock)  # three full sweep pages leave 30 s, under the 60 s needed to read another page
    assert len(fake.requests_for("CortexXsiamFinishedPentests")) == 3
    assert sorted(harness.last_run["sent_ops"]) == [row["op_id"] for row in rows]
    assert harness.last_run["nextTrigger"] == "0"  # the sweep stopped early and the run made progress


@freeze_time(NOW)
def test_finished_pentest_without_events_counts_as_progress(harness: Harness) -> None:
    empty_pentest = pentest_row("op-z", 0, etl_completed_at="2025-03-14T09:00:00")
    fake = FakeNodeZero(pentests=[empty_pentest, OP_B], weakness_pages={"op-b": OP_B_PAGES}).register(harness.requests_mock)
    clock = FakeClock()
    fake.charge_weakness_pages(clock, 160)  # op-z's only page leaves 20 s, under the 30 s needed to start op-b
    run_fetch(clock=clock)
    assert fake.weakness_page_calls == [("op-z", 1)]
    assert list(harness.last_run["sent_ops"]) == ["op-z"]
    assert harness.sends == [([], "horizon3", "nodezero", {})]  # no events were sent
    assert harness.last_run["nextTrigger"] == "0"  # a finished pentest is progress, so op-b is fetched at once


@freeze_time(NOW)
def test_crash_between_send_and_checkpoint_resends_one_page(harness: Harness) -> None:
    standard_api(harness)

    def crash(events: list[dict[str, Any]]) -> None:
        harness.store.crashed = True  # the run dies: its cursor commit and its lease release never land

    harness.on_send.append(crash)
    with pytest.raises(SimulatedCrash):
        run_fetch()  # page 1 of op-a was sent, then the run died before its cursor was committed
    harness.store.crashed = False
    assert harness.store.state()["in_progress"] is None
    assert harness.store.state()["sent_ops"] == {}
    assert harness.last_run["in_progress"] is None
    dead_lease = harness.store.lease()
    assert dead_lease["expires_at"] == NOW_EPOCH + 600
    harness.wall.advance(599)
    run_fetch()  # the dead run's lease blocks the next fetch until it expires
    assert len(harness.sent_events()) == 2
    harness.wall.advance(1)
    run_fetch()
    assert harness.store.lease() is None
    event_ids = harness.sent_ids()
    duplicates = len(event_ids) - len(set(event_ids))
    assert 0 < duplicates <= NodeZeroEventCollector.PAGE_SIZE  # at most one page is sent twice
    assert sorted(set(event_ids)) == sorted(event["event_id"] for event in fixture_events())  # event_id removes it


@freeze_time(NOW)
def test_failing_pentest_blocks_later_pentests(harness: Harness) -> None:
    fake = standard_api(harness)
    fake.fail_page("op-a", 1, status=500)
    for _ in range(2):
        with pytest.raises(DemistoException, match="pentest op-a"):
            run_fetch()
    assert {op_id for op_id, _ in fake.weakness_page_calls} == {"op-a"}  # op-b waits behind op-a
    assert harness.last_run["watermark"] == FIRST_FETCH_FLOOR
    assert harness.last_run["sent_ops"] == {}
    assert harness.sent_events() == []


@freeze_time(NOW)
def test_retries_exhausted_keeps_checkpoint_and_raises(harness: Harness) -> None:
    fake = standard_api(harness)
    fake.fail_page("op-a", 2, status=429, raw=json.dumps({"message": "Too many requests"}))
    with pytest.raises(DemistoException, match="HTTP 429"):
        run_fetch()
    assert harness.last_run["in_progress"]["next_page"] == 2
    assert harness.last_run["sent_ops"] == {}
    assert "nextTrigger" not in harness.last_run
    assert harness.health == []
    del fake.page_failures[("op-a", 2)]
    run_fetch()  # the throttling has passed: the next run loses and repeats nothing
    assert uuids(harness.sent_events()) == uuids(ALL_ROWS)
    assert set(harness.last_run["sent_ops"]) == {"op-a", "op-b"}


@freeze_time(NOW)
def test_max_fetch_checked_only_between_pentests(harness: Harness) -> None:
    fake = standard_api(harness)
    params = {**FETCH_PARAMS, "max_fetch": "1"}
    run_fetch(params)
    assert uuids(harness.sent_events()) == uuids([A1, A2, A3])  # op-a is never split by the limit
    assert {op_id for op_id, _ in fake.weakness_page_calls} == {"op-a"}
    assert harness.last_run["nextTrigger"] == "0"
    harness.sends.clear()
    run_fetch(params)
    assert uuids(harness.sent_events()) == uuids([B1, B2])
    assert "nextTrigger" not in harness.last_run


@freeze_time(NOW)
def test_health_updated_once_per_run(harness: Harness) -> None:
    standard_api(harness)
    run_fetch()
    assert harness.health == [{"eventsPulled": 5}]
    assert all(kwargs == {"should_update_health_module": False} for _, _, _, kwargs in harness.sends)


@freeze_time(NOW)
def test_empty_run_sends_heartbeat(harness: Harness) -> None:
    FakeNodeZero(sweep_pages=[EMPTY_PENTESTS_PAGE]).register(harness.requests_mock)
    run_fetch()
    assert harness.sends == [([], "horizon3", "nodezero", {})]
    assert harness.health == []
    assert "nextTrigger" not in harness.last_run


@freeze_time(NOW)
def test_sent_pentest_sends_zero_events(harness: Harness) -> None:
    fake = standard_api(harness)
    run_fetch()
    checkpoint = copy.deepcopy(harness.last_run)
    harness.sends.clear()
    harness.health.clear()
    fake.weakness_page_calls.clear()
    run_fetch()
    run_fetch()
    assert fake.weakness_page_calls == []
    assert harness.sends == [([], "horizon3", "nodezero", {})] * 2  # heartbeats only
    assert harness.health == []
    assert harness.last_run == checkpoint


@freeze_time(NOW)
def test_next_trigger_absent_when_caught_up(harness: Harness) -> None:
    standard_api(harness)
    harness.last_run = {
        "version": 1,
        "floor": FIRST_FETCH_FLOOR,
        "watermark": FIRST_FETCH_FLOOR,
        "sent_ops": {},
        "in_progress": None,
        "nextTrigger": "0",  # left by a run that had more work
    }
    run_fetch()
    assert set(harness.last_run["sent_ops"]) == {"op-a", "op-b"}
    assert all("nextTrigger" not in saved for saved in harness.saved_last_runs)


@freeze_time(NOW)
def test_failed_run_drops_stale_next_trigger(harness: Harness) -> None:
    standard_api(harness)
    stale = {
        "version": 1,
        "floor": FIRST_FETCH_FLOOR,
        "watermark": FIRST_FETCH_FLOOR,
        "sent_ops": {"op-x": FIRST_FETCH_FLOOR},
        "in_progress": None,
        "nextTrigger": "0",
    }
    harness.last_run = copy.deepcopy(stale)
    with pytest.raises(ValueError):
        run_fetch({**FETCH_PARAMS, "max_fetch": "many"})  # fails before the checkpoint is loaded
    assert harness.last_run == {key: value for key, value in stale.items() if key != "nextTrigger"}
    harness.saved_last_runs.clear()
    with pytest.raises(DemistoException, match="positive integer"):
        run_fetch({**FETCH_PARAMS, "max_fetch": "0"})
    assert harness.saved_last_runs == []  # nothing stale left to remove


@freeze_time(NOW)
def test_sweep_cap_leaves_work_for_the_next_run(harness: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(NodeZeroEventCollector, "MAX_SWEEP_PAGES", 1)
    fake = standard_api(harness)
    run_fetch()
    assert len(fake.requests_for("CortexXsiamFinishedPentests")) == 1  # the sweep stopped at its cap with a full page
    assert set(harness.last_run["sent_ops"]) == {"op-a", "op-b"}
    assert harness.last_run["nextTrigger"] == "0"
    run_fetch()  # the capped sweep now finds only sent pentests, so the run doesn't ask to run again at once
    assert "nextTrigger" not in harness.last_run


@freeze_time(NOW)
def test_run_summary_and_page_logs(harness: Harness) -> None:
    standard_api(harness)
    run_fetch()
    summary = harness.summary()
    assert summary.endswith("more work pending False, 0.0 seconds.")
    debug = harness.messages("debug")
    for op_id, page_num, rows in (("op-a", 1, 2), ("op-a", 2, 1), ("op-b", 1, 2), ("op-b", 2, 0)):
        assert f"Pentest {op_id}: page {page_num} returned {rows} weaknesses." in debug
    logged = "\n".join(message for _, message in harness.logs)
    assert A1["vuln"]["description"] not in logged  # event bodies are never logged
    assert A1["portal_url"] not in logged
    assert harness.messages("error") == []
    harness.logs.clear()
    run_fetch()
    assert len(harness.messages("info")) == 1


# ----- nodezero-fetch-events -----


@freeze_time(NOW)
@pytest.mark.parametrize("push", ["true", "false"])
def test_event_list_never_touches_last_run(harness: Harness, push: str) -> None:
    standard_api(harness)
    harness.last_run = {"version": 1, "sentinel": True}
    event_list({"should_push_events": push, "limit": "10"}, params=NO_FETCH_PARAMS)
    assert harness.get_last_run_calls == 0
    assert harness.saved_last_runs == []


@freeze_time(NOW)
def test_event_list_push_only_when_requested(harness: Harness) -> None:
    standard_api(harness)
    result = event_list({"should_push_events": "false", "limit": "10"})
    assert uuids(result.raw_response) == uuids(ALL_ROWS)
    assert harness.sends == []
    assert "Sent" not in result.readable_output
    result = event_list({"should_push_events": "true", "limit": "10"}, params=NO_FETCH_PARAMS)
    assert [len(events) for events in harness.page_sends()] == [2, 1, 2]
    assert len(harness.sends) == 3  # page by page, with no empty send
    assert "Sent 5 events to Cortex XSIAM from 2 pentests." in result.readable_output
    assert harness.health == []


@freeze_time(NOW)
def test_event_list_limit(harness: Harness) -> None:
    fake = standard_api(harness)
    result = view({"limit": "3"})
    assert uuids(result.raw_response) == uuids([A1, A2, A3])
    assert {op_id for op_id, _ in fake.weakness_page_calls} == {"op-a"}  # stops once the limit is reached
    fake.weakness_page_calls.clear()
    result = view({"limit": "4"})
    assert uuids(result.raw_response) == uuids([A1, A2, A3, B1])
    assert fake.weakness_page_calls == [("op-a", 1), ("op-a", 2), ("op-b", 1)]
    assert harness.sends == []
    for bad_limit in ("0", "-2"):
        with pytest.raises(DemistoException, match="limit must be a positive integer"):
            view({"limit": bad_limit})
    with pytest.raises(ValueError):
        view({"limit": "many"})


@freeze_time(NOW)
@pytest.mark.parametrize(
    ("weaknesses_count", "pages", "pages_read", "events_read"),
    [
        (4, [[0, 1], [2], [3]], 3, 4),  # a short page mid-pentest is read past
        (5, [[0, 1], [2], [3]], 4, 4),  # a stale, larger count costs one extra, empty page
        (3, [[0, 1], [2]], 2, 3),  # the short last page reaches the count
        (None, [[0, 1], [2], [3]], 2, 3),  # with no count to check, the short page ends the pentest
        (5, [[0, 1], [2], [2], [2]], 3, 3),  # a repeated short page adds nothing new
    ],
)
def test_event_list_ends_a_pentest_by_the_fetch_rule(
    harness: Harness, weaknesses_count: int | None, pages: list[list[int]], pages_read: int, events_read: int
) -> None:
    rows = weakness_rows("op-x", 4)
    bodies = [weaknesses_body([rows[index] for index in page]) for page in pages]
    pentest = {**pentest_row("op-x", 0), "weaknesses_count": weaknesses_count}
    fake = FakeNodeZero(pentests=[pentest], weakness_pages={"op-x": bodies}).register(harness.requests_mock)
    result = event_list({"should_push_events": "false", "limit": "100"})
    assert fake.weakness_page_calls == [("op-x", page_num) for page_num in range(1, pages_read + 1)]
    assert uuids(result.raw_response) == uuids(rows[:events_read])


@freeze_time(NOW)
def test_event_list_default_limit_and_since(harness: Harness) -> None:
    rows = weakness_rows("op-big", 12)
    fake = FakeNodeZero(pentests=[pentest_row("op-big", 12)], weaknesses={"op-big": rows}).register(harness.requests_mock)
    result = event_list({"should_push_events": "false"})
    assert len(result.raw_response) == 10
    since = fake.requests_for("CortexXsiamFinishedPentests")[0]["variables"]["page_input"]["filter_by_inputs"][1]
    assert since == {"field_name": "etl_completed_at", "greater_than_or_equal": "2025-03-08T12:00:00"}  # 7 days


@freeze_time(NOW)
@pytest.mark.parametrize(
    ("since", "expected_since", "expected_rows"),
    [
        ("2 days", "2025-03-13T12:00:00", ALL_ROWS),
        ("2025-03-14T10:30:00Z", "2025-03-14T10:30:00", [B1, B2]),
        ("2025-03-14T12:30:00+02:00", "2025-03-14T10:30:00", [B1, B2]),
        ("2025-03-14T11:00:01", "2025-03-14T11:00:01", []),
    ],
)
def test_event_list_since_filters_by_etl_completed_at(
    harness: Harness, since: str, expected_since: str, expected_rows: list[dict[str, Any]]
) -> None:
    fake = standard_api(harness)
    result = event_list({"should_push_events": "false", "limit": "100", "since": since})
    filters = fake.requests_for("CortexXsiamFinishedPentests")[0]["variables"]["page_input"]["filter_by_inputs"]
    assert filters == [
        {"field_name": "state", "values": ["done"]},
        {"field_name": "etl_completed_at", "greater_than_or_equal": expected_since},
    ]
    assert uuids(result.raw_response) == uuids(expected_rows)


@freeze_time(NOW)
def test_event_list_rejects_bad_arguments(harness: Harness) -> None:
    standard_api(harness)
    with pytest.raises(ValueError):
        event_list({"should_push_events": "false", "since": "not a time"})
    with pytest.raises(ValueError):
        event_list({"should_push_events": "maybe"})
    result = event_list({})  # without should_push_events the command only displays events (design: default false)
    assert uuids(result.raw_response) == uuids(ALL_ROWS)  # all 5 fit in the default limit of 10
    assert harness.sends == []
    assert harness.store.write_attempts == 0


@freeze_time(NOW)
def test_event_list_reads_finished_pentests_only(harness: Harness) -> None:
    fake = FakeNodeZero(sweep_pages=[UNFINISHED_ETL_PAGE], weakness_pages={"op-a": OP_A_PAGES, "op-b": OP_B_PAGES})
    fake.register(harness.requests_mock)
    result = event_list({"should_push_events": "false", "limit": "100"})
    assert uuids(result.raw_response) == uuids(ALL_ROWS)
    assert "op-c" not in {op_id for op_id, _ in fake.weakness_page_calls}


@freeze_time(NOW)
def test_event_list_stops_at_deadline(harness: Harness) -> None:
    fake = standard_api(harness)
    clock = FakeClock()
    fake.charge_weakness_pages(clock, 100)
    result = event_list({"should_push_events": "false", "limit": "100"}, clock=clock)
    assert uuids(result.raw_response) == uuids([A1, A2, A3])
    assert "The command stopped early because it reached its time limit." in result.readable_output
    assert {op_id for op_id, _ in fake.weakness_page_calls} == {"op-a"}


@freeze_time(NOW)
def test_event_list_reports_a_sweep_cut_short_by_the_deadline(harness: Harness) -> None:
    clock = FakeClock()
    rows = [pentest_row(f"op-{index}", 1, etl_completed_at=f"2025-03-14T0{index}:00:00") for index in range(1, 9)]
    weaknesses = {row["op_id"]: [make_weakness(row["op_id"], index)] for index, row in enumerate(rows)}
    fake = SlowSweepNodeZero(pentests=rows, weaknesses=weaknesses, clock=clock, sweep_seconds=50)
    fake.register(harness.requests_mock)
    result = event_list({"should_push_events": "false", "limit": "100"}, clock=clock)
    # three sweep pages leave 30 s, under the 60 s for another page
    assert len(fake.requests_for("CortexXsiamFinishedPentests")) == 3
    assert len(result.raw_response) == 6  # op-7 and op-8 were never swept
    assert "The command stopped early because it reached its time limit." in result.readable_output


@freeze_time(NOW)
def test_event_list_readable_output(harness: Harness) -> None:
    standard_api(harness)
    result = event_list({"should_push_events": "false", "limit": "1"})
    assert result.outputs_prefix == "NodeZero.Event"
    assert result.outputs_key_field == "event_id"
    assert result.outputs == result.raw_response == [build(A1)]  # the full events, up to limit
    header = next(line for line in result.readable_output.splitlines() if line.startswith("|"))
    for column in NodeZeroEventCollector.EVENT_TABLE_HEADERS:
        assert column in header
    assert "dc01.corp.example.com" in result.readable_output


# ----- shared state and lease: a fetch and a manual push never send the same page -----


def lease_payload(owner: str, token: str, expires_at: float) -> dict[str, Any]:
    return {"owner": owner, "token": token, "expires_at": expires_at}


def state_payload(**fields: Any) -> dict[str, Any]:
    """A shared state as a fetch stores it, with the fetch window of FETCH_PARAMS."""
    return {
        "version": 1,
        "floor": FIRST_FETCH_FLOOR,
        "watermark": FIRST_FETCH_FLOOR,
        "pruned_before": None,
        "sent_ops": {},
        "in_progress": None,
        **fields,
    }


def generated_api(harness: Harness, pentests: list[dict[str, Any]]) -> FakeNodeZero:
    """Pentests with generated weaknesses: as many as each one's weaknesses_count, two to a page."""
    weaknesses = {row["op_id"]: weakness_rows(row["op_id"], row["weaknesses_count"]) for row in pentests}
    return FakeNodeZero(pentests=pentests, weaknesses=weaknesses).register(harness.requests_mock)


def ids_of(fake: FakeNodeZero, *op_ids: str) -> list[str]:
    """The event_id of every weakness of these pentests."""
    return [f"{op_id}:{row['uuid']}" for op_id in op_ids for row in fake.weaknesses[op_id]]


def test_shipped_lease_and_state_constants() -> None:
    # The lease outlasts a run that overruns its budget, and no send starts within the time one 1 MiB send can take.
    assert NodeZeroEventCollector.LEASE_TTL_SECONDS == 600
    assert NodeZeroEventCollector.LEASE_SAFETY_SECONDS == 200
    assert NodeZeroEventCollector.LEASE_SETTLE_SECONDS == 2
    assert NodeZeroEventCollector.CONTEXT_WRITE_ATTEMPTS == 3
    assert NodeZeroEventCollector.SEND_BATCH_BYTES == 1_000_000
    assert NodeZeroEventCollector.STATE_CONTEXT_KEY == STATE_KEY
    assert NodeZeroEventCollector.LEASE_CONTEXT_KEY == LEASE_KEY
    assert (NodeZeroEventCollector.OWNER_FETCH, NodeZeroEventCollector.OWNER_COMMAND) == ("fetch", "command")
    assert NodeZeroEventCollector.LAST_RUN_VERSION == 1  # an existing checkpoint must stay readable, or the seed is empty
    assert timedelta(days=30) == NodeZeroEventCollector.SENT_RETENTION
    assert timedelta(hours=24) == NodeZeroEventCollector.LOOKBACK
    assert NodeZeroEventCollector.MIN_SECONDS_FOR_NEW_PENTEST == 30
    assert NodeZeroEventCollector.MIN_SECONDS_FOR_SWEEP_PAGE == 60
    assert NodeZeroEventCollector.DEFAULT_EVENT_LIST_LIMIT == 10
    assert NodeZeroEventCollector.DEFAULT_EVENT_LIST_SINCE == "7 days"
    assert NodeZeroEventCollector.DEFAULT_FIRST_FETCH == "7 days"
    assert NodeZeroEventCollector.DEFAULT_MAX_FETCH == 10_000


@freeze_time(NOW)
def test_lease_taken_for_ttl_renewed_on_each_commit_and_released(harness: Harness) -> None:
    standard_api(harness)
    harness.on_send.extend([lambda events: harness.wall.advance(50)] * 3)  # each page send takes 50 s
    run_fetch()
    leases = [written.get(LEASE_KEY) for written in harness.store.writes]
    assert leases[0] == {"owner": "fetch", "token": leases[0]["token"], "expires_at": NOW_EPOCH + 600}
    assert {lease["token"] for lease in leases if lease} == {leases[0]["token"]}
    # every commit renews the lease to its own time plus the TTL: after the sends at +50, +100 and +150 s
    assert sorted({lease["expires_at"] - NOW_EPOCH for lease in leases if lease}) == [600, 650, 700, 750]
    assert leases[-1] is None  # released at the end
    assert harness.pauses == [2]  # one settle pause before the lease is read back


@freeze_time(NOW)
def test_fetch_skipped_while_a_command_holds_the_lease(harness: Harness) -> None:
    fake = standard_api(harness)
    harness.context.update({LEASE_KEY: lease_payload("command", "push-run", NOW_EPOCH + 1), STATE_KEY: state_payload()})
    before = copy.deepcopy(harness.context)
    harness.last_run = {**state_payload(), "nextTrigger": "0"}
    run_fetch()
    assert fake.graphql_requests == []
    assert harness.auth_calls() == 0
    assert harness.sends == [([], "horizon3", "nodezero", {})]  # the health heartbeat only
    assert harness.health == []
    assert harness.context == before
    assert harness.store.write_attempts == 0  # a busy run never writes the integration context
    assert harness.last_run == state_payload()  # the checkpoint is kept, without nextTrigger
    assert (
        "Skipped this fetch, because a manual run of nodezero-fetch-events (until 2025-03-15 12:00:01 UTC at the latest) "
        "is sending events." in harness.messages("info")
    )
    assert harness.summary().startswith("NodeZero fetch skipped")


@freeze_time(NOW)
@pytest.mark.parametrize(("expires_in", "taken"), [(1, False), (0, True), (-3600, True)])
def test_lease_taken_over_once_it_expires(harness: Harness, expires_in: int, taken: bool) -> None:
    standard_api(harness)
    harness.context[LEASE_KEY] = lease_payload("command", "crashed-run", NOW_EPOCH + expires_in)
    run_fetch()
    assert len(harness.sent_events()) == (5 if taken else 0)
    assert harness.store.lease() == (None if taken else lease_payload("command", "crashed-run", NOW_EPOCH + expires_in))


@freeze_time(NOW)
@pytest.mark.parametrize(
    "lease", ["not a lease", {"owner": "fetch", "token": "t"}, {"owner": 1, "token": "t", "expires_at": 1e12}]
)
def test_unreadable_lease_is_ignored(harness: Harness, lease: Any) -> None:
    standard_api(harness)
    harness.context[LEASE_KEY] = lease
    run_fetch()
    assert len(harness.sent_events()) == 5
    assert harness.store.lease() is None


@freeze_time(NOW)
@pytest.mark.parametrize(
    ("owner", "holder"),
    [("fetch", "a scheduled fetch"), ("command", "a manual run of nodezero-fetch-events"), ("other", "another run")],
)
def test_push_refused_while_another_run_holds_the_lease(harness: Harness, owner: str, holder: str) -> None:
    fake = standard_api(harness)
    harness.context.update({STATE_KEY: state_payload(), LEASE_KEY: lease_payload(owner, "fetch-run", NOW_EPOCH + 600)})
    before = copy.deepcopy(harness.context)
    with pytest.raises(DemistoException) as error:
        push()
    assert str(error.value) == (
        f"Events can't be sent right now, because {holder} (until 2025-03-15 12:10:00 UTC at the latest) is sending "
        "events. Try again later, or set should_push_events to false to view events without sending them."
    )
    assert fake.graphql_requests == []
    assert harness.sends == []
    assert harness.store.write_attempts == 0
    assert harness.context == before
    assert uuids(view().raw_response) == uuids(ALL_ROWS)  # viewing needs no lease
    assert harness.store.write_attempts == 0


@freeze_time(NOW)
def test_push_refused_without_shared_state_while_fetch_is_enabled(harness: Harness) -> None:
    fake = standard_api(harness)
    harness.last_run = state_payload(
        sent_ops={"op-a": OP_A["etl_completed_at"]}
    )  # a fetch checkpoint, which a command can't read
    with pytest.raises(DemistoException) as error:
        push(params=FETCH_PARAMS)
    assert str(error.value) == NodeZeroEventCollector.NO_SHARED_STATE_MESSAGE
    assert "Wait for the next scheduled fetch" in str(error.value)
    assert fake.graphql_requests == []
    assert harness.sends == []
    assert harness.store.write_attempts == 0
    assert harness.get_last_run_calls == 0


@freeze_time(NOW)
def test_push_rechecks_the_shared_state_under_the_lease(harness: Harness) -> None:
    fake = standard_api(harness)
    run_fetch()  # stores the shared state
    sends, requests = len(harness.sends), len(fake.graphql_requests)
    harness.on_pause.append(lambda: harness.store.other_writer(lambda context: context.pop(STATE_KEY)))  # wiped meanwhile
    with pytest.raises(DemistoException) as error:
        push(params=FETCH_PARAMS)
    assert str(error.value) == NodeZeroEventCollector.NO_SHARED_STATE_MESSAGE
    assert len(harness.sends) == sends
    assert len(fake.graphql_requests) == requests  # refused before reading anything
    assert harness.store.lease() is None  # released


@freeze_time(NOW)
def test_checkpoint_seed_without_pruned_before_keeps_pruned_pentests_sent(harness: Harness) -> None:
    old = pentest_row(
        "op-50", 2, etl_completed_at="2025-01-24T10:00:00"
    )  # an earlier fetch sent it, then pruned it from sent_ops
    half = pentest_row("op-x", 9, etl_completed_at="2025-03-14T09:00:00")
    fake = generated_api(harness, [old, half])
    harness.last_run = {  # a checkpoint without pruned_before: W - 30 days is past op-50, so it was already dropped
        "version": 1,
        "floor": "2025-01-20T00:00:00",
        "watermark": "2025-03-14T10:00:00",
        "sent_ops": {},
        "in_progress": {"pentest": half, "next_page": 2, "sent": 2},
    }
    clock = FakeClock()
    fake.charge_weakness_pages(clock, 70)
    run_fetch(clock=clock)  # the resume uses the budget, so the run ends before the sweep and the prune
    assert harness.store.state()["pruned_before"] == "2025-02-12T10:00:00.000000"
    fake.page_cost = None
    result = push(args={"pentest_id": "op-50"})  # first finishes op-x, which the fetch left half sent
    assert "Not sent again, because they were already sent: op-50." in result.readable_output
    assert not set(ids_of(fake, "op-50")) & set(harness.sent_ids())  # never sent by the push
    assert harness.duplicate_ids() == []
    assert [event["event_id"] for event in result.outputs] == ids_of(fake, "op-50")  # still displayed


def test_send_page_reports_a_whole_empty_page(harness: Harness) -> None:
    lease = NodeZeroEventCollector.Lease("fetch", "t", NOW_EPOCH + 600)
    holder = NodeZeroEventCollector.Holder(lease=lease, state=state_payload(), mirror_to_last_run=False)
    harness.wall.now = NOW_EPOCH
    harness.wall.now = NOW_EPOCH + 500  # even past the safety margin: nothing to send, so no renewal either
    assert NodeZeroEventCollector.send_page(holder, []) == 0
    assert harness.sends == []  # an empty page is never sent
    assert harness.store.write_attempts == 0


@freeze_time(NOW)
def test_push_with_fetch_disabled_starts_an_empty_state(harness: Harness) -> None:
    standard_api(harness)
    result = push(params=NO_FETCH_PARAMS)
    assert uuids(harness.sent_events()) == uuids(ALL_ROWS)
    assert harness.store.state() == {
        "version": 1,
        "floor": None,  # no fetch window until a fetch runs
        "watermark": None,
        "pruned_before": None,
        "sent_ops": {"op-a": OP_A["etl_completed_at"], "op-b": OP_B["etl_completed_at"]},
        "in_progress": None,
    }
    assert harness.store.lease() is None
    assert "Sent 5 events to Cortex XSIAM from 2 pentests." in result.readable_output
    harness.sends.clear()
    result = push(params=NO_FETCH_PARAMS)  # the second push finds both pentests sent
    assert harness.sends == []
    assert "Not sent again, because they were already sent: op-a, op-b." in result.readable_output
    assert uuids(result.raw_response) == uuids(ALL_ROWS)


@freeze_time(NOW)
def test_limitation_push_without_state_cannot_see_what_an_earlier_fetch_sent(harness: Harness) -> None:
    # Documented limitation: with fetch disabled and no shared state yet, a push can't know what an earlier
    # fetch sent, because that record is only in the fetch checkpoint, which a command can't read.
    standard_api(harness)
    sent = {"op-a": OP_A["etl_completed_at"], "op-b": OP_B["etl_completed_at"]}
    harness.last_run = state_payload(watermark=OP_B["etl_completed_at"], sent_ops=sent)
    push(params=NO_FETCH_PARAMS)
    assert uuids(harness.sent_events()) == uuids(ALL_ROWS)  # sent again


@freeze_time(NOW)
def test_limitation_wiped_context_lets_a_fetch_resend_a_pushed_pentest(harness: Harness) -> None:
    # Documented limitation: the record of pushed pentests is only in the integration context.
    pentests = [OP_A]
    FakeNodeZero(pentests=pentests, weakness_pages={"op-a": OP_A_PAGES, "op-b": OP_B_PAGES}).register(harness.requests_mock)
    run_fetch()
    pentests.append(OP_B)
    push()  # sends op-b; the fetch checkpoint doesn't know
    assert harness.duplicate_ids() == []
    harness.context.clear()
    run_fetch()  # seeds from the checkpoint, which lacks op-b
    assert harness.duplicate_ids() == sorted(ids_of_rows([B1, B2]))  # op-a, which the fetch itself sent, is not


def ids_of_rows(rows: list[dict[str, Any]]) -> list[str]:
    return [f"{row['op_id']}:{row['uuid']}" for row in rows]


@freeze_time(NOW)
def test_limitation_reset_last_run_sends_nothing_again(harness: Harness) -> None:
    # Documented limitation: resetting "last run" doesn't re-send anything, because the context state is authoritative.
    standard_api(harness)
    run_fetch()
    harness.last_run = {}
    harness.sends.clear()
    run_fetch()
    assert harness.sends == [([], "horizon3", "nodezero", {})]


@freeze_time(NOW)
def test_fetch_seeds_the_shared_state_from_a_checkpoint_without_it(harness: Harness) -> None:
    op_x = pentest_row("op-x", 4, etl_completed_at="2025-03-14T10:30:00")
    fake = FakeNodeZero(pentests=[OP_A, op_x], weakness_pages={"op-a": OP_A_PAGES}, weaknesses={"op-x": weakness_rows("op-x", 4)})
    fake.register(harness.requests_mock)
    old_checkpoint = {  # a checkpoint with no pruned_before, and no shared state in the integration context
        "version": 1,
        "floor": FIRST_FETCH_FLOOR,
        "watermark": OP_A["etl_completed_at"],
        "sent_ops": {"op-a": OP_A["etl_completed_at"]},
        "in_progress": {"pentest": op_x, "next_page": 2, "sent": 2},
    }
    harness.last_run = copy.deepcopy(old_checkpoint)
    run_fetch()
    assert "The integration context holds no collection state. Starting from the fetch checkpoint." in harness.messages("info")
    seeded = next(state for state in harness.store.written_states() if state is not None)
    assert seeded["sent_ops"] == old_checkpoint["sent_ops"]
    assert seeded["in_progress"]["next_page"] == 2
    assert fake.weakness_page_calls == [("op-x", 2), ("op-x", 3)]  # the cursor is resumed and op-a is not read
    assert harness.sent_ids() == ids_of(fake, "op-x")[2:]
    assert set(harness.store.state()["sent_ops"]) == {"op-a", "op-x"}


@freeze_time(NOW)
def test_shared_state_is_authoritative_over_a_stale_checkpoint(harness: Harness) -> None:
    op_x = pentest_row("op-x", 5, etl_completed_at="2025-03-14T10:30:00")
    fake = FakeNodeZero(pentests=[OP_A, op_x], weakness_pages={"op-a": OP_A_PAGES}, weaknesses={"op-x": weakness_rows("op-x", 5)})
    fake.register(harness.requests_mock)
    harness.context[STATE_KEY] = state_payload(
        sent_ops={"op-a": OP_A["etl_completed_at"]}, in_progress={"pentest": op_x, "next_page": 3, "sent": 4}
    )
    harness.last_run = state_payload(in_progress={"pentest": op_x, "next_page": 2, "sent": 2})  # an older mirror
    run_fetch()
    assert fake.weakness_page_calls == [("op-x", 3)]  # the cursor comes from the context, not the checkpoint
    assert harness.sent_ids() == ids_of(fake, "op-x")[4:]
    assert set(harness.store.state()["sent_ops"]) == {"op-a", "op-x"}
    assert harness.last_run == harness.store.state()


@freeze_time(NOW)
def test_fetch_sets_the_window_of_a_state_only_pushes_wrote(harness: Harness) -> None:
    standard_api(harness)
    push(params=NO_FETCH_PARAMS, args={"pentest_id": "op-b"})
    assert harness.store.state()["floor"] is None
    run_fetch()
    state = harness.store.state()
    assert state["floor"] == FIRST_FETCH_FLOOR
    assert state["watermark"] == OP_B["etl_completed_at"]
    assert harness.duplicate_ids() == []
    assert sorted(harness.sent_ids()) == sorted(ids_of_rows(ALL_ROWS))


@freeze_time(NOW)
def test_watermark_stays_before_an_unsent_older_pentest(harness: Harness) -> None:
    older = pentest_row("op-older", 1, etl_completed_at="2025-03-13T10:00:00")
    newer = pentest_row("op-newer", 1, etl_completed_at="2025-03-15T11:00:00")  # more than LOOKBACK after op-older
    fake = generated_api(harness, [older, newer])
    harness.context[STATE_KEY] = state_payload()
    push(args={"pentest_id": "op-newer"})  # a manual push sends the newer pentest first
    fake.fail_page("op-older", 1, status=500)
    with pytest.raises(DemistoException, match="pentest op-older"):
        run_fetch()
    assert harness.store.state()["watermark"] == FIRST_FETCH_FLOOR  # not moved past the unsent op-older
    del fake.page_failures[("op-older", 1)]
    run_fetch()
    assert sorted(harness.sent_ids()) == sorted(ids_of(fake, "op-older", "op-newer"))
    assert harness.duplicate_ids() == []
    assert harness.store.state()["watermark"] == newer["etl_completed_at"]


def test_advance_watermark_stops_at_the_first_unsent_pentest() -> None:
    state = state_payload(sent_ops={"op-1": "2025-03-13T00:00:00", "op-3": "2025-03-15T00:00:00"})
    swept = [
        NodeZeroEventCollector.to_pentest(pentest_row(op_id, 1, etl_completed_at=etl))
        for op_id, etl in (("op-1", "2025-03-13T00:00:00"), ("op-2", "2025-03-14T00:00:00"), ("op-3", "2025-03-15T00:00:00"))
    ]
    assert NodeZeroEventCollector.advance_watermark(state, swept)["watermark"] == "2025-03-13T00:00:00"
    state["pruned_before"] = "2025-03-14T00:00:01"  # op-2 is in the pruned range, so it counts as sent
    assert NodeZeroEventCollector.advance_watermark(state, swept)["watermark"] == "2025-03-15T00:00:00"


def test_pruning_keeps_entries_older_than_the_floor() -> None:
    state = state_payload(
        floor="2025-01-01T00:00:00",
        watermark="2025-03-15T00:00:00",  # the cutoff is 2025-02-13T00:00:00
        sent_ops={
            "op-pushed-before-floor": "2024-12-31T23:59:59",  # only a push can have sent it, and only this records it
            "op-at-floor": "2025-01-01T00:00:00",
            "op-before-cutoff": "2025-02-12T23:59:59",
            "op-at-cutoff": "2025-02-13T00:00:00",
        },
    )
    pruned = NodeZeroEventCollector.prune_sent_ops(state)
    assert pruned["sent_ops"] == {"op-pushed-before-floor": "2024-12-31T23:59:59", "op-at-cutoff": "2025-02-13T00:00:00"}
    assert pruned["pruned_before"] == "2025-02-13T00:00:00.000000"
    assert state["sent_ops"]["op-at-floor"]  # the input state is not changed
    for op_id, etl in state["sent_ops"].items():  # every pentest still counts as sent
        assert NodeZeroEventCollector.is_sent(
            pruned, NodeZeroEventCollector.to_pentest(pentest_row(op_id, 1, etl_completed_at=etl))
        )
    earlier = NodeZeroEventCollector.prune_sent_ops({**pruned, "watermark": "2025-03-01T00:00:00"})
    assert earlier["pruned_before"] == "2025-02-13T00:00:00.000000"  # the largest cutoff is kept


@pytest.mark.parametrize(
    ("etl", "sent"),
    [
        ("2024-12-31T23:59:59", False),  # before the floor: only sent_ops can say it was sent
        ("2025-01-01T00:00:00", True),  # at the floor
        ("2025-02-12T23:59:59", True),
        ("2025-02-13T00:00:00", False),  # at pruned_before
    ],
)
def test_pruned_range_is_floor_inclusive_and_pruned_before_exclusive(etl: str, sent: bool) -> None:
    state = state_payload(floor="2025-01-01T00:00:00", pruned_before="2025-02-13T00:00:00.000000")
    assert (
        NodeZeroEventCollector.is_sent(state, NodeZeroEventCollector.to_pentest(pentest_row("op-x", 1, etl_completed_at=etl)))
        is sent
    )
    assert (
        NodeZeroEventCollector.is_sent(
            {**state, "floor": None}, NodeZeroEventCollector.to_pentest(pentest_row("op-x", 1, etl_completed_at=etl))
        )
        is False
    )


def test_sweep_never_starts_inside_the_pruned_range() -> None:
    state = state_payload(floor="2025-01-01T00:00:00", watermark="2025-02-01T00:00:00", pruned_before="2025-02-05T00:00:00")
    assert NodeZeroEventCollector.sweep_start(state) == "2025-02-05T00:00:00"


def test_push_and_fetch_never_resend_a_pentest_sent_50_days_ago(harness: Harness) -> None:
    old = pentest_row("op-50", 2, etl_completed_at="2025-01-24T10:00:00")  # 50 days before NOW
    pentests = [old]
    fake = FakeNodeZero(pentests=pentests, weaknesses={"op-50": weakness_rows("op-50", 2), "op-new": weakness_rows("op-new", 1)})
    fake.register(harness.requests_mock)
    with freeze_time("2025-01-25T12:00:00Z"):
        run_fetch()
    pentests.append(pentest_row("op-new", 1, etl_completed_at="2025-03-14T10:00:00"))
    with freeze_time(NOW):
        run_fetch()
        state = harness.store.state()
        assert "op-50" not in state["sent_ops"]  # pruned: more than 30 days before the watermark
        assert state["pruned_before"] == "2025-02-12T10:00:00.000000"
        result = push(args={"pentest_id": "op-50"})
        assert "Not sent again, because they were already sent: op-50." in result.readable_output
        assert uuids(result.raw_response) == uuids(fake.weaknesses["op-50"])  # still displayed
        push(args={"since": "60 days"})
    assert sorted(harness.sent_ids()) == sorted(ids_of(fake, "op-50", "op-new"))
    assert harness.duplicate_ids() == []


@freeze_time(NOW)
def test_push_skips_sent_and_pruned_pentests_but_displays_them(harness: Harness) -> None:
    rows = [
        pentest_row("op-before-floor", 1, etl_completed_at="2025-03-12T11:59:59"),  # not recorded: pushed
        pentest_row("op-at-floor", 1, etl_completed_at=FIRST_FETCH_FLOOR),  # in the pruned range
        pentest_row("op-recorded", 1, etl_completed_at="2025-03-13T12:00:00"),  # in sent_ops
        pentest_row("op-at-pruned-before", 1, etl_completed_at="2025-03-14T00:00:00"),  # just past the range: pushed
    ]
    fake = generated_api(harness, rows)
    harness.context[STATE_KEY] = state_payload(
        watermark="2025-03-14T00:00:00",
        pruned_before="2025-03-14T00:00:00.000000",
        sent_ops={"op-recorded": "2025-03-13T12:00:00"},
    )
    result = push()
    assert sorted(harness.sent_ids()) == sorted(ids_of(fake, "op-before-floor", "op-at-pruned-before"))
    assert "Not sent again, because they were already sent: op-at-floor, op-recorded." in result.readable_output
    assert "Sent 2 events to Cortex XSIAM from 2 pentests." in result.readable_output
    assert [event["op_id"] for event in result.raw_response] == [row["op_id"] for row in rows]  # all four are displayed
    state = harness.store.state()
    assert state["watermark"] == "2025-03-14T00:00:00"  # a push never moves the watermark
    assert state["pruned_before"] == "2025-03-14T00:00:00.000000"  # and never prunes
    assert set(state["sent_ops"]) == {"op-recorded", "op-before-floor", "op-at-pruned-before"}


@freeze_time(NOW)
def test_push_finishes_a_cursor_first_without_counting_it_toward_limit(harness: Harness) -> None:
    half_sent = pentest_row("op-x", 5, etl_completed_at="2025-03-10T00:00:00")  # outside since, so not displayed
    in_scope = pentest_row("op-y", 1, etl_completed_at="2025-03-15T10:00:00")
    fake = generated_api(harness, [half_sent, in_scope])
    harness.context[STATE_KEY] = state_payload(in_progress={"pentest": half_sent, "next_page": 2, "sent": 2})
    result = push(args={"limit": "1", "since": "1 day"})
    assert fake.weakness_page_calls[:2] == [("op-x", 2), ("op-x", 3)]  # the cursor first
    assert harness.sent_ids() == ids_of(fake, "op-x")[2:] + ids_of(fake, "op-y")
    assert result.readable_output.startswith(
        "Finished sending pentest op-x, which an earlier run left half sent (3 events).\n\n"
        "Sent 1 events to Cortex XSIAM from 1 pentests."
    )
    assert [event["op_id"] for event in result.raw_response] == ["op-y"]  # the resumed events aren't in the table
    assert "Not started" not in result.readable_output  # the resume finished, so the scope was started
    assert harness.store.state()["in_progress"] is None
    assert set(harness.store.state()["sent_ops"]) == {"op-x", "op-y"}


@freeze_time(NOW)
def test_push_with_pentest_id_finishes_another_pentests_cursor_first(harness: Harness) -> None:
    half_sent = pentest_row("op-x", 5, etl_completed_at="2025-03-10T00:00:00")
    wanted = pentest_row("op-want", 3, etl_completed_at="2025-03-15T10:00:00")
    fake = generated_api(harness, [half_sent, wanted])
    harness.context[STATE_KEY] = state_payload(in_progress={"pentest": half_sent, "next_page": 3, "sent": 4})
    result = push(args={"limit": "1", "pentest_id": "op-want"})
    assert harness.sent_ids() == ids_of(fake, "op-x")[4:] + ids_of(fake, "op-want")  # the whole pentest, despite limit
    assert "Sent 3 events to Cortex XSIAM from 1 pentests." in result.readable_output
    assert len(result.raw_response) == 1


@freeze_time(NOW)
@pytest.mark.parametrize(("limit", "pushed"), [("1", ["op-a"]), ("3", ["op-a"]), ("4", ["op-a", "op-b"])])
def test_push_limit_never_splits_a_pentest(harness: Harness, limit: str, pushed: list[str]) -> None:
    standard_api(harness)
    result = push(args={"limit": limit}, params=NO_FETCH_PARAMS)
    rows = {"op-a": [A1, A2, A3], "op-b": [B1, B2]}
    assert uuids(harness.sent_events()) == uuids([row for op_id in pushed for row in rows[op_id]])
    assert len(result.raw_response) == min(int(limit), 5)  # limit caps what is shown, not what is sent
    sent = 3 if pushed == ["op-a"] else 5
    assert f"Sent {sent} events to Cortex XSIAM from {len(pushed)} pentests." in result.readable_output
    if pushed == ["op-a"]:
        assert result.readable_output.count("Not sent, because the run reached its limit or its time budget.") == 1
        assert "fetch send them: op-b." in result.readable_output
    assert set(harness.store.state()["sent_ops"]) == set(pushed)


@freeze_time(NOW)
def test_push_stopped_by_the_deadline_leaves_the_cursor_for_the_fetch(harness: Harness) -> None:
    fake = generated_api(harness, [pentest_row("op-x", 7)])
    harness.context[STATE_KEY] = state_payload()
    clock = FakeClock()
    fake.charge_weakness_pages(clock, 70)  # three pages use the 180 s budget
    result = push(clock=clock)
    assert "Stopped partway through pentest op-x. The next scheduled fetch" in result.readable_output
    assert harness.store.state()["in_progress"]["next_page"] == 4
    assert harness.store.lease() is None
    fake.page_cost = None
    run_fetch()  # the fetch finishes the pentest the push left half sent
    assert fake.weakness_page_calls[3:] == [("op-x", 4)]
    assert sorted(harness.sent_ids()) == sorted(ids_of(fake, "op-x"))
    assert harness.duplicate_ids() == []


@freeze_time(NOW)
def test_push_continues_a_cursor_it_cannot_finish(harness: Harness) -> None:
    fake = generated_api(harness, [pentest_row("op-x", 9), pentest_row("op-y", 1, etl_completed_at="2025-03-15T10:00:00")])
    harness.context[STATE_KEY] = state_payload(in_progress={"pentest": pentest_row("op-x", 9), "next_page": 2, "sent": 2})
    clock = FakeClock()
    fake.charge_weakness_pages(clock, 70)
    result = push(clock=clock)
    assert result.readable_output.startswith("Continued sending pentest op-x, which an earlier run left half sent (6 events).")
    assert "Stopped partway through pentest op-x." in result.readable_output
    assert {op_id for op_id, _ in fake.weakness_page_calls} == {"op-x"}  # no new pentest starts
    assert harness.store.state()["in_progress"]["next_page"] == 5


@freeze_time(NOW)
def test_push_leaves_new_pentests_when_little_time_is_left(harness: Harness) -> None:
    fake = standard_api(harness)
    harness.context[STATE_KEY] = state_payload()
    clock = FakeClock()
    fake.charge_weakness_pages(clock, 80)  # op-a's two pages leave 20 s, under the 30 s needed to start op-b
    result = push(clock=clock)
    assert uuids(harness.sent_events()) == uuids([A1, A2, A3])
    assert "fetch send them: op-b." in result.readable_output


# ----- nodezero-fetch-events: pentest_id -----


@freeze_time(NOW)
@pytest.mark.parametrize("pentest_id", ["op-a", "  op-a\n", "\top-a "])
def test_pentest_id_reads_that_pentest_only(harness: Harness, pentest_id: str) -> None:
    fake = standard_api(harness)
    result = view({"pentest_id": pentest_id, "since": "not a time"})  # since is ignored
    assert uuids(result.raw_response) == uuids([A1, A2, A3])
    (lookup,) = fake.requests_for("CortexXsiamPentest")
    assert fake.requests_for("CortexXsiamFinishedPentests") == []  # the lookup has its own operation name, not the sweep's
    assert lookup["query"] == NodeZeroEventCollector.PENTEST_QUERY
    assert lookup["variables"] == {
        "page_input": {"page_num": 1, "page_size": 1, "filter_by_inputs": [{"field_name": "op_id", "values": ["op-a"]}]}
    }
    assert {op_id for op_id, _ in fake.weakness_page_calls} == {"op-a"}
    assert harness.store.write_attempts == 0


@freeze_time(NOW)
def test_blank_pentest_id_means_since(harness: Harness) -> None:
    fake = standard_api(harness)
    result = view({"pentest_id": "   ", "since": "2 days"})
    assert uuids(result.raw_response) == uuids(ALL_ROWS)
    since = fake.requests_for("CortexXsiamFinishedPentests")[0]["variables"]["page_input"]["filter_by_inputs"][1]
    assert since == {"field_name": "etl_completed_at", "greater_than_or_equal": "2025-03-13T12:00:00"}


@freeze_time(NOW)
@pytest.mark.parametrize("should_push", ["false", "true"])
@pytest.mark.parametrize(
    ("rows", "message"),
    [
        ([], "No pentest with ID op-z was found in this account. It may be archived, not a pentest, or mistyped."),
        ([{**OP_A, "op_id": "op-other"}], "No pentest with ID op-z was found in this account."),
        ([{"name": "no op_id"}], "No pentest with ID op-z was found in this account."),
        (
            [pentest_row("op-z", 0, state="running", etl_completed_at=None)],
            "Pentest op-z isn't done, or its results aren't ready yet (state: running). Only done pentests can be fetched.",
        ),
        (
            [pentest_row("op-z", 0, etl_completed_at=None)],
            "Pentest op-z isn't done, or its results aren't ready yet (state: done).",
        ),
        ([pentest_row("op-z", 0, state="ended")], "(state: ended)"),
        ([pentest_row("op-z", 0, state=None)], "(state: unknown)"),
    ],
)
def test_pentest_id_not_found_or_not_done(harness: Harness, should_push: str, rows: list[dict[str, Any]], message: str) -> None:
    fake = FakeNodeZero(sweep_pages=[pentests_body(rows)]).register(harness.requests_mock)
    harness.context[STATE_KEY] = state_payload()
    with pytest.raises(DemistoException) as error:
        event_list({"should_push_events": should_push, "pentest_id": "op-z"})
    assert message in str(error.value)
    assert fake.weakness_page_calls == []
    assert harness.sends == []
    assert harness.store.lease() is None  # a push releases its lease after the error


@freeze_time(NOW)
def test_pentest_id_push_of_a_sent_pentest_only_displays_it(harness: Harness) -> None:
    standard_api(harness)
    run_fetch()
    harness.sends.clear()
    result = push(args={"pentest_id": "op-b"})
    assert harness.sends == []
    assert uuids(result.raw_response) == uuids([B1, B2])
    assert "Sent 0 events to Cortex XSIAM from 0 pentests." in result.readable_output
    assert "Not sent again, because they were already sent: op-b." in result.readable_output


# ----- display-only runs, test-module and busy runs never write the integration context -----


@freeze_time(NOW)
def test_runs_without_the_lease_never_write_the_context(harness: Harness) -> None:
    fake = standard_api(harness)
    harness.context.update({STATE_KEY: state_payload(sent_ops={"op-a": OP_A["etl_completed_at"]}), "unrelated": "kept"})
    before = copy.deepcopy(harness.context)
    view()  # no cached token, so it authenticates
    view({"pentest_id": "op-a"})
    fake.queue("CortexXsiamFinishedPentests", 401)
    view()  # re-authenticates after a 401
    assert NodeZeroEventCollector.test_module(make_client(), FETCH_PARAMS) == "ok"
    harness.context[LEASE_KEY] = lease_payload("fetch", "fetch-run", NOW_EPOCH + 600)
    before[LEASE_KEY] = copy.deepcopy(harness.context[LEASE_KEY])
    with pytest.raises(DemistoException, match="can't be sent right now"):
        push()
    harness.context[LEASE_KEY]["owner"] = "command"
    run_fetch()
    assert harness.auth_calls() == 5  # each run kept its own token in memory
    assert harness.store.write_attempts == 0
    assert harness.context == {**before, LEASE_KEY: {**before[LEASE_KEY], "owner": "command"}}


# ----- losing the lease, version conflicts and failed writes -----


@freeze_time(NOW)
@pytest.mark.parametrize("command", ["fetch-events", "push"])
def test_lease_lost_mid_run_stops_without_further_sends(harness: Harness, command: str) -> None:
    fake = standard_api(harness)
    harness.context[STATE_KEY] = state_payload()
    intruder = lease_payload("command", "intruder", NOW_EPOCH + 600)
    harness.on_send.append(lambda events: harness.store.other_writer(lambda context: context.update({LEASE_KEY: intruder})))
    with pytest.raises(NodeZeroEventCollector.LeaseLost, match="lease expired and another run took it"):
        run_fetch() if command == "fetch-events" else push()
    assert uuids(harness.sent_events()) == uuids([A1, A2])  # page 1, then nothing
    assert fake.weakness_page_calls == [("op-a", 1)]
    assert harness.store.lease() == intruder  # the release left the other run's lease
    assert harness.store.state()["in_progress"] is None  # the page's commit never landed
    if command == "fetch-events":
        assert "nextTrigger" not in harness.last_run
        assert harness.last_run["in_progress"] is None


@freeze_time(NOW)
def test_third_run_during_a_push_keeps_its_lease(harness: Harness) -> None:
    standard_api(harness)
    harness.context[STATE_KEY] = state_payload()
    taken: list[Any] = []

    def push_overruns_and_a_fetch_starts(events: list[dict[str, Any]]) -> None:
        harness.wall.advance(601)  # the push's lease expired during the send
        taken.append(NodeZeroEventCollector.acquire_lease("fetch"))

    harness.on_send.append(push_overruns_and_a_fetch_starts)
    with pytest.raises(NodeZeroEventCollector.LeaseLost):
        push()
    assert harness.store.lease() == lease_payload("fetch", taken[0].token, NOW_EPOCH + 601 + 600)
    assert len(harness.sent_events()) == 2


def test_release_removes_only_its_own_lease(harness: Harness) -> None:
    other = lease_payload("fetch", "other-run", NOW_EPOCH + 600)
    harness.context[LEASE_KEY] = copy.deepcopy(other)
    NodeZeroEventCollector.release_lease(NodeZeroEventCollector.Lease("command", "this-run", NOW_EPOCH + 600))
    assert harness.store.lease() == other
    NodeZeroEventCollector.release_lease(NodeZeroEventCollector.Lease("fetch", "other-run", NOW_EPOCH + 600))
    assert harness.store.lease() is None


def test_failed_release_is_logged_not_raised(harness: Harness) -> None:
    harness.context[LEASE_KEY] = lease_payload("fetch", "this-run", NOW_EPOCH + 600)
    for offset in (1, 2, 3):
        harness.store.fail_write(offset, RuntimeError("context service unavailable"))
    NodeZeroEventCollector.release_lease(NodeZeroEventCollector.Lease("fetch", "this-run", NOW_EPOCH + 600))
    assert harness.store.lease() is not None  # it expires on its own
    assert any(message.startswith("Failed to release the collection lease.") for message in harness.messages("debug"))


@freeze_time(NOW)
@pytest.mark.parametrize("command", ["fetch-events", "push"])
def test_lease_released_after_a_failure(harness: Harness, command: str) -> None:
    fake = standard_api(harness)
    harness.context[STATE_KEY] = state_payload()
    fake.fail_page("op-b", 1, status=500)
    with pytest.raises(DemistoException, match="pentest op-b"):
        run_fetch() if command == "fetch-events" else push()
    assert harness.store.lease() is None
    assert "op-a" in harness.store.state()["sent_ops"]


@freeze_time(NOW)
def test_push_releases_the_lease_when_the_state_read_fails(harness: Harness) -> None:
    standard_api(harness)
    harness.context[STATE_KEY] = state_payload()
    harness.store.read_failures[4] = RuntimeError("context read failed")  # the check, the lease, the settle, then this
    with pytest.raises(RuntimeError, match="context read failed"):
        push()
    assert harness.store.lease() is None
    assert harness.sends == []


@freeze_time(NOW)
def test_version_conflict_on_a_commit_is_retried_without_losing_either_write(harness: Harness) -> None:
    standard_api(harness)

    def another_write_lands_first(pending: dict[str, Any]) -> None:
        harness.store.other_writer(lambda context: context.update({"unrelated": "written by another run"}))

    harness.on_send.append(lambda events: harness.store.on_write(1, another_write_lands_first))
    run_fetch()
    assert harness.context["unrelated"] == "written by another run"  # the retry re-read the context
    assert harness.store.state()["sent_ops"].keys() == {"op-a", "op-b"}
    assert harness.duplicate_ids() == []
    assert len(harness.sent_events()) == 5
    assert harness.store.stale_writes == 1  # the stale write failed and was applied again to a fresh read
    assert any("probably because another run wrote first" in message for message in harness.messages("debug"))


@freeze_time(NOW)
def test_version_conflict_that_changed_the_lease_token_raises_lease_lost(harness: Harness) -> None:
    standard_api(harness)
    intruder = lease_payload("command", "intruder", NOW_EPOCH + 600)

    def lease_taken_before_the_commit_lands(pending: dict[str, Any]) -> None:
        harness.store.other_writer(lambda context: context.update({LEASE_KEY: intruder}))

    harness.on_send.append(lambda events: harness.store.on_write(1, lease_taken_before_the_commit_lands))
    with pytest.raises(NodeZeroEventCollector.LeaseLost):
        run_fetch()
    assert uuids(harness.sent_events()) == uuids([A1, A2])
    assert harness.store.lease() == intruder


@freeze_time(NOW)
@pytest.mark.parametrize(("failures", "succeeds"), [(2, True), (3, False)])
def test_context_write_gives_up_after_three_attempts(harness: Harness, failures: int, succeeds: bool) -> None:
    standard_api(harness)
    for offset in range(1, failures + 1):
        harness.store.fail_write(offset, RuntimeError("arbitrary failure"))  # the lease write
    if succeeds:
        run_fetch()
        assert len(harness.sent_events()) == 5
        return
    with pytest.raises(DemistoException, match="Failed to update the integration context after several attempts."):
        run_fetch()
    assert harness.sends == []
    assert harness.store.writes == []


# ----- writes that the platform doesn't check: the settle re-read -----


@freeze_time(NOW)
@pytest.mark.parametrize("mode", ["ignored", "unversioned"])
def test_settle_reread_catches_the_run_that_lost_the_lease_race(harness: Harness, mode: str) -> None:
    standard_api(harness)
    harness.store.mode = mode
    harness.context[STATE_KEY] = state_payload()
    refused: list[str] = []

    def push_reads_before_the_fetch_lease_lands(pending_fetch_write: dict[str, Any]) -> None:
        # The push reads the context before the fetch's lease lands, and the fetch's write lands during its settle.
        harness.on_pause.append(lambda: harness.store.land(pending_fetch_write))
        with pytest.raises(DemistoException) as error:
            push()
        refused.append(str(error.value))

    harness.store.on_write(1, push_reads_before_the_fetch_lease_lands)
    run_fetch()
    assert len(refused) == 1
    assert "because a scheduled fetch" in refused[0]
    assert harness.duplicate_ids() == []
    assert sorted(harness.sent_ids()) == sorted(ids_of_rows(ALL_ROWS))
    assert harness.pauses == [2, 2]


@freeze_time(NOW)
def test_unversioned_platform_runs_fetch_and_push(harness: Harness) -> None:
    standard_api(harness)
    harness.store.mode = "unversioned"
    run_fetch()
    push(args={"since": "7 days"})
    assert harness.duplicate_ids() == []
    assert len(harness.sent_events()) == 5
    assert harness.store.lease() is None


@freeze_time(NOW)
@pytest.mark.parametrize("whole_push", [True, False])
def test_enforced_versions_retry_a_stale_lease_write(harness: Harness, whole_push: bool) -> None:
    standard_api(harness)
    harness.context[STATE_KEY] = state_payload()

    def push_between_the_fetch_read_and_write(pending_fetch_write: dict[str, Any]) -> None:
        if whole_push:
            push()  # takes the lease, sends op-a and op-b, releases
        else:
            NodeZeroEventCollector.acquire_lease("command")  # still holds the lease

    harness.store.on_write(1, push_between_the_fetch_read_and_write)
    run_fetch()  # the fetch's lease write carries a stale version, so it is read and applied again
    assert harness.duplicate_ids() == []
    assert len(harness.sent_events()) == (5 if whole_push else 0)
    if not whole_push:
        assert any(message.startswith("Skipped this fetch, because a manual run") for message in harness.messages("info"))


@freeze_time(NOW)
def test_lease_that_vanished_during_the_settle_means_busy(harness: Harness) -> None:
    standard_api(harness)
    harness.on_pause.append(lambda: harness.store.other_writer(lambda context: context.pop(LEASE_KEY)))
    run_fetch()
    assert harness.sent_events() == []
    assert "Skipped this fetch, because another run is sending events." in harness.messages("info")


# ----- send batches -----


def padded_event(event_bytes: int) -> dict[str, Any]:
    """An event that takes exactly event_bytes in a batch: its serialized size plus one separator."""
    event = {"pad": "x" * (event_bytes - 12)}
    assert NodeZeroEventCollector.event_size(event) + 1 == event_bytes
    return event


@pytest.mark.parametrize(
    ("sizes", "batch_lengths"),
    [
        ([500_000, 500_000], [2]),  # exactly SEND_BATCH_BYTES
        ([500_000, 500_001], [1, 1]),
        ([400_000, 400_000, 200_000, 12], [3, 1]),
        ([1_200_000, 12, 12], [1, 2]),  # an event larger on its own is sent alone
        ([], []),
    ],
)
def test_event_batches_stay_within_send_batch_bytes(sizes: list[int], batch_lengths: list[int]) -> None:
    events = [padded_event(size) for size in sizes]
    batches = list(NodeZeroEventCollector.event_batches(events))
    assert [len(batch) for batch in batches] == batch_lengths
    assert [event for batch in batches for event in batch] == events  # in order, nothing lost or repeated


def large_rows(op_id: str, count: int) -> list[dict[str, Any]]:
    """Weaknesses of about 600 KB each, so two of them don't fit one send batch."""
    rows = weakness_rows(op_id, count)
    for row in rows:
        row["vuln"]["description"] = "d" * 600_000
    return rows


@freeze_time(NOW)
@pytest.mark.parametrize(("send_seconds", "renewed"), [(399, False), (400, True)])
def test_lease_checked_before_each_send_batch(harness: Harness, send_seconds: int, renewed: bool) -> None:
    fake = FakeNodeZero(pentests=[pentest_row("op-big", 3)], weaknesses={"op-big": large_rows("op-big", 3)})
    fake.register(harness.requests_mock)
    leases: list[float] = []
    harness.on_send.append(lambda events: harness.wall.advance(send_seconds))  # the first batch is slow
    harness.on_send.append(lambda events: leases.append(harness.store.lease()["expires_at"]))
    run_fetch()
    assert [len(events) for events in harness.page_sends()] == [1, 1, 1]  # page 1 in two batches, then page 2
    # Before page 1's second batch: with 201 s of the lease left it is sent as is, with 200 s the lease is renewed first.
    assert leases == [NOW_EPOCH + (send_seconds + 600 if renewed else 600)]
    assert min(harness.send_lease_margins) > NodeZeroEventCollector.LEASE_SAFETY_SECONDS  # no send starts closer
    assert harness.duplicate_ids() == []
    assert harness.store.state()["sent_ops"].keys() == {"op-big"}
    assert "events per pentest {'op-big': 3}" in harness.summary()


def test_can_send_boundary(harness: Harness) -> None:
    lease = NodeZeroEventCollector.Lease("fetch", "t", NOW_EPOCH + 600)
    holder = NodeZeroEventCollector.Holder(lease=lease, state=state_payload(), mirror_to_last_run=False)
    harness.wall.now = NOW_EPOCH + 399
    assert holder.can_send() is True
    harness.wall.now = NOW_EPOCH + 400
    assert holder.can_send() is False


def test_describe_lease() -> None:
    assert NodeZeroEventCollector.describe_lease(None) == "another run"
    lease = NodeZeroEventCollector.Lease("fetch", "t", NOW_EPOCH + 600)
    assert NodeZeroEventCollector.describe_lease(lease) == "a scheduled fetch (until 2025-03-15 12:10:00 UTC at the latest)"


# ----- interleaved runs: the dataset never holds a duplicate event_id -----


@freeze_time(NOW)
def test_push_between_two_fetches_sends_every_event_once(harness: Harness) -> None:
    rows = [
        pentest_row("op-1", 3, etl_completed_at="2025-03-14T01:00:00"),
        pentest_row("op-2", 2, etl_completed_at="2025-03-14T02:00:00"),
        pentest_row("op-3", 5, etl_completed_at="2025-03-14T03:00:00"),
    ]
    fake = generated_api(harness, rows)
    run_fetch({**FETCH_PARAMS, "max_fetch": "1"})  # sends op-1 only
    assert harness.last_run["nextTrigger"] == "0"
    fake.pentests.append(pentest_row("op-4", 1, etl_completed_at="2025-03-15T11:00:00"))
    fake.weaknesses["op-4"] = weakness_rows("op-4", 1)
    result = push(args={"limit": "100"})
    assert "Not sent again, because they were already sent: op-1." in result.readable_output
    assert "Sent 8 events to Cortex XSIAM from 3 pentests." in result.readable_output
    fake.pentests.append(pentest_row("op-5", 2, etl_completed_at="2025-03-15T11:30:00"))
    fake.weaknesses["op-5"] = weakness_rows("op-5", 2)
    run_fetch()  # sends op-5 only
    push(args={"pentest_id": "op-5"})
    assert harness.duplicate_ids() == []
    assert sorted(harness.sent_ids()) == sorted(ids_of(fake, "op-1", "op-2", "op-3", "op-4", "op-5"))
    assert harness.store.state()["watermark"] == "2025-03-15T11:30:00"


class DirectNodeZero(FakeNodeZero):
    """FakeNodeZero answering Client.graphql directly, without HTTP, for the interleaving simulation."""

    def install(self, monkeypatch: pytest.MonkeyPatch) -> "DirectNodeZero":
        def graphql(client: Any, query: str, variables: dict[str, Any]) -> dict[str, Any]:
            context = SimpleNamespace(status_code=200, headers={})
            if operation_name(query) == "CortexXsiamPentestWeaknesses":
                return json.loads(self.weakness_page(query, variables, context))["data"]
            return self.sweep_page(variables["page_input"])["data"]

        monkeypatch.setattr(NodeZeroEventCollector.Client, "graphql", graphql)
        return self


SIM_START = [
    pentest_row("op-old", 2, etl_completed_at="2025-03-10T00:00:00"),  # before the fetch floor: only a push sends it
    pentest_row("op-1", 5, etl_completed_at="2025-03-14T12:00:00"),
    pentest_row("op-2", 3, etl_completed_at="2025-03-14T20:00:00"),
]
SIM_ARRIVALS = [
    pentest_row("op-3", 2, etl_completed_at="2025-03-14T16:00:00"),  # appears later, but is older than op-2
    pentest_row("op-4", 4, etl_completed_at="2025-03-15T11:00:00"),
]
# F fetch, f fetch cut by the deadline, P push since 7 days, p push cut by the deadline, I push the newest pentest by ID,
# V view only, N the next pentest appears
SIM_SCHEDULES = ["".join(steps) for steps in itertools.product("FfPpIVN", repeat=3)]


def run_sim_step(harness: Harness, fake: FakeNodeZero, arrivals: list[dict[str, Any]], step: str, params: dict[str, Any]) -> None:
    clock = FakeClock()
    fake.charge_weakness_pages(clock, 70 if step in "fp" else 0)  # 70 s a page: the third page ends the run
    if step == "N":
        if arrivals:
            fake.pentests.append(arrivals.pop(0))
    elif step in "Ff":
        run_fetch(clock=clock)
    elif step == "V":
        writes = harness.store.write_attempts
        view(clock=clock)
        assert harness.store.write_attempts == writes
    else:
        newest = max(fake.pentests, key=lambda row: row["etl_completed_at"])["op_id"]
        args = {"pentest_id": newest} if step == "I" else {"since": "7 days"}
        try:
            push(args=args, clock=clock, params=params)
        except DemistoException as error:
            assert str(error) == NodeZeroEventCollector.NO_SHARED_STATE_MESSAGE  # before the first fetch only
            assert harness.store.state() is None


@freeze_time(NOW)
@pytest.mark.parametrize("fetch_enabled", [True, False], ids=["fetch-enabled", "fetch-disabled-at-first"])
@pytest.mark.parametrize("schedule", SIM_SCHEDULES)
def test_interleaved_fetches_and_pushes_send_every_event_once(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, schedule: str, fetch_enabled: bool
) -> None:
    rows = copy.deepcopy(SIM_START)
    arrivals = copy.deepcopy(SIM_ARRIVALS)
    weaknesses = {row["op_id"]: weakness_rows(row["op_id"], row["weaknesses_count"]) for row in rows + arrivals}
    fake = DirectNodeZero(pentests=rows, weaknesses=weaknesses).install(monkeypatch)
    params = FETCH_PARAMS if fetch_enabled else NO_FETCH_PARAMS
    for step in schedule + "NNFFF":  # then every pentest is visible, and the fetch drains what is left
        run_sim_step(harness, fake, arrivals, step, params)
    assert harness.duplicate_ids() == []
    fetched = {"op-1", "op-2", "op-3", "op-4"}
    assert set(ids_of(fake, *sorted(fetched))) <= set(harness.sent_ids())
    assert set(harness.sent_ids()) <= set(ids_of(fake, *sorted(fetched), "op-old"))
    state = harness.store.state()
    assert state["in_progress"] is None
    assert harness.store.lease() is None


# ----- shared state, lease and checkpoint mirror: regression tests -----


@freeze_time(NOW)
def test_slow_page_of_many_batches_is_sent_once_and_its_pentest_completes(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(NodeZeroEventCollector, "PAGE_SIZE", 5)
    fake = FakeNodeZero(pentests=[pentest_row("op-big", 5)], weaknesses={"op-big": large_rows("op-big", 5)})
    fake.register(harness.requests_mock)
    harness.on_send.extend([lambda events: harness.wall.advance(120)] * 5)  # one page of 5 batches, 120 s each
    run_fetch()
    assert [len(events) for events in harness.page_sends()] == [1] * 5
    assert min(harness.send_lease_margins) > NodeZeroEventCollector.LEASE_SAFETY_SECONDS  # renewed before batch 5
    assert harness.duplicate_ids() == []
    assert sorted(harness.sent_ids()) == sorted(ids_of(fake, "op-big"))
    assert harness.store.state()["sent_ops"].keys() == {"op-big"}
    assert harness.store.state()["in_progress"] is None
    assert "nextTrigger" not in harness.last_run
    run_fetch()  # nothing is left to send
    assert len(harness.sent_ids()) == 5


@freeze_time(NOW)
def test_lease_renewal_before_a_batch_raises_lease_lost_when_another_run_took_it(harness: Harness) -> None:
    FakeNodeZero(pentests=[pentest_row("op-big", 3)], weaknesses={"op-big": large_rows("op-big", 3)}).register(
        harness.requests_mock
    )
    intruder = lease_payload("command", "intruder", NOW_EPOCH + 1000)

    def slow_batch_then_lease_taken(events: list[dict[str, Any]]) -> None:
        harness.wall.advance(400)
        harness.store.other_writer(lambda context: context.update({LEASE_KEY: intruder}))

    harness.on_send.append(slow_batch_then_lease_taken)
    with pytest.raises(NodeZeroEventCollector.LeaseLost):
        run_fetch()
    assert [len(events) for events in harness.page_sends()] == [1]  # the second batch never started
    assert harness.store.lease() == intruder
    assert harness.store.state()["in_progress"] is None


@freeze_time(NOW)
def test_push_reads_sent_pentests_for_display_only_while_time_is_left(harness: Harness) -> None:
    fake = standard_api(harness)
    sent = {"op-a": OP_A["etl_completed_at"], "op-b": OP_B["etl_completed_at"]}
    harness.context[STATE_KEY] = state_payload(sent_ops=sent)
    clock = FakeClock()
    fake.charge_weakness_pages(clock, 100)  # op-a's two pages use the budget
    result = push(clock=clock)
    assert fake.weakness_page_calls == [("op-a", 1), ("op-a", 2)]  # op-b isn't read after the deadline
    assert "Not sent again, because they were already sent: op-a, op-b." in result.readable_output
    assert harness.sends == []


def test_release_after_losing_the_lease_never_writes(harness: Harness) -> None:
    other = lease_payload("fetch", "other-run", NOW_EPOCH + 600)
    harness.context[LEASE_KEY] = copy.deepcopy(other)
    NodeZeroEventCollector.release_lease(NodeZeroEventCollector.Lease("command", "this-run", NOW_EPOCH + 600))
    harness.context.pop(LEASE_KEY)
    NodeZeroEventCollector.release_lease(NodeZeroEventCollector.Lease("command", "this-run", NOW_EPOCH + 600))
    assert harness.store.write_attempts == 0  # not even an unchanged copy, which could revert another run's commit
    assert harness.messages("debug").count("The collection lease was already taken by another run. Nothing to release.") == 2


@freeze_time(NOW)
@pytest.mark.parametrize("command", ["fetch-events", "push"])
def test_run_that_lost_the_lease_writes_nothing_more(harness: Harness, command: str) -> None:
    standard_api(harness)
    harness.context[STATE_KEY] = state_payload()
    intruder = lease_payload("command", "intruder", NOW_EPOCH + 600)
    writes_at_loss: list[int] = []

    def lease_taken(events: list[dict[str, Any]]) -> None:
        harness.store.other_writer(lambda context: context.update({LEASE_KEY: intruder}))
        writes_at_loss.append(harness.store.write_attempts)

    harness.on_send.append(lease_taken)
    with pytest.raises(NodeZeroEventCollector.LeaseLost):
        run_fetch() if command == "fetch-events" else push()
    assert harness.store.write_attempts == writes_at_loss[0]  # no commit, no release write
    assert harness.store.lease() == intruder


@freeze_time(NOW)
def test_fetch_merges_a_push_only_state_with_its_checkpoint(harness: Harness) -> None:
    op_x = pentest_row("op-x", 1, etl_completed_at="2025-03-14T11:30:00")
    fake = FakeNodeZero(
        pentests=[OP_A, OP_B, op_x],
        weakness_pages={"op-a": OP_A_PAGES, "op-b": OP_B_PAGES},
        weaknesses={"op-x": weakness_rows("op-x", 1)},
    ).register(harness.requests_mock)
    fetched = {"op-a": OP_A["etl_completed_at"], "op-b": OP_B["etl_completed_at"]}
    harness.last_run = state_payload(watermark=OP_B["etl_completed_at"], sent_ops=fetched)  # what the fetch sent
    pushed = {"op-x": op_x["etl_completed_at"]}  # a push, while the context held no fetch state
    harness.context[STATE_KEY] = state_payload(floor=None, watermark=None, sent_ops=pushed)
    run_fetch()
    assert harness.sent_events() == []  # neither the fetch's pentests nor the pushed one is sent again
    assert fake.weakness_page_calls == []
    state = harness.store.state()
    assert state["sent_ops"].keys() == {"op-a", "op-b", "op-x"}
    assert state["floor"] == FIRST_FETCH_FLOOR


def checkpoint_cursor(op_id: str) -> dict[str, Any]:
    return {"pentest": pentest_row(op_id, 5), "next_page": 2, "sent": 2}


@pytest.mark.parametrize(
    ("context_cursor", "checkpoint", "expected"),
    [
        ("op-y", "op-z", "op-y"),  # the context's cursor is the newer one
        (None, "op-z", "op-z"),
        ("op-a", None, None),  # a cursor for a pentest the fetch already sent is dropped
    ],
)
def test_fetch_keeps_one_cursor_when_it_merges_a_push_only_state(
    harness: Harness, context_cursor: str | None, checkpoint: str | None, expected: str | None
) -> None:
    harness.last_run = state_payload(
        sent_ops={"op-a": OP_A["etl_completed_at"]}, in_progress=checkpoint and checkpoint_cursor(checkpoint)
    )
    harness.context[STATE_KEY] = state_payload(
        floor=None, watermark=None, in_progress=context_cursor and checkpoint_cursor(context_cursor)
    )
    state = NodeZeroEventCollector.load_fetch_state(harness.last_run, datetime(2025, 3, 12, 12, 0))
    assert (state["in_progress"] or {}).get("pentest", {}).get("op_id") == expected
    assert state["floor"] == FIRST_FETCH_FLOOR


def test_fetch_sets_a_window_on_a_push_only_state_without_a_checkpoint(harness: Harness) -> None:
    harness.context[STATE_KEY] = state_payload(floor=None, watermark=None, sent_ops={"op-x": "2025-03-14T11:30:00"})
    state = NodeZeroEventCollector.load_fetch_state({}, datetime(2025, 3, 12, 12, 0))
    assert state["floor"] == state["watermark"] == FIRST_FETCH_FLOOR
    assert state["sent_ops"] == {"op-x": "2025-03-14T11:30:00"}
    assert state["pruned_before"] is None


@freeze_time(NOW)
@pytest.mark.parametrize("command", ["fetch-events", "push"])
@pytest.mark.parametrize("failure", ["read", "pause"])
def test_failed_settle_releases_the_lease(harness: Harness, command: str, failure: str) -> None:
    standard_api(harness)
    harness.context[STATE_KEY] = state_payload()
    if failure == "read":  # the settle read follows the lease read (and, for a push, its state check)
        harness.store.read_failures[2 if command == "fetch-events" else 3] = RuntimeError("settle failed")
    else:
        harness.on_pause.append(lambda: (_ for _ in ()).throw(RuntimeError("settle failed")))
    with pytest.raises(RuntimeError, match="settle failed"):
        run_fetch() if command == "fetch-events" else push()
    assert harness.store.lease() is None
    assert harness.sends == []


@freeze_time(NOW)
@pytest.mark.parametrize(
    ("args", "scope"),
    [
        ({"pentest_id": "op-want"}, "pentest op-want"),
        ({"since": "2 days"}, "the pentests that finished since 2025-03-13T12:00:00"),
    ],
)
def test_push_names_the_scope_a_cut_resume_left_unstarted(harness: Harness, args: dict[str, str], scope: str) -> None:
    half_sent = pentest_row("op-x", 9, etl_completed_at="2025-03-10T00:00:00")
    fake = generated_api(harness, [half_sent, pentest_row("op-want", 1, etl_completed_at="2025-03-15T10:00:00")])
    harness.context[STATE_KEY] = state_payload(in_progress={"pentest": half_sent, "next_page": 2, "sent": 2})
    clock = FakeClock()
    fake.charge_weakness_pages(clock, 70)
    result = push(args=args, clock=clock)
    assert f"Not started, because the run's time went to pentest op-x: {scope}. Run the command again." in result.readable_output
    assert {op_id for op_id, _ in fake.weakness_page_calls} == {"op-x"}


def test_token_cache_belongs_to_one_url_and_api_key(harness: Harness) -> None:
    owner = token_owner()
    assert make_client()._owner == owner
    assert API_KEY not in owner
    harness.context.update(cached_token("cached-token", NOW_EPOCH + 3600))
    assert NodeZeroEventCollector.load_cached_token(NOW_EPOCH, owner) == "cached-token"
    assert NodeZeroEventCollector.load_cached_token(NOW_EPOCH, token_owner(api_key="nz-unit-test-api-key-0002")) is None
    assert NodeZeroEventCollector.load_cached_token(NOW_EPOCH, token_owner(base_url="https://other.example.com")) is None
    del harness.context["auth_token_owner"]  # a cache written before the owner was recorded
    assert NodeZeroEventCollector.load_cached_token(NOW_EPOCH, owner) is None


@freeze_time(NOW)
def test_new_api_key_after_test_module_makes_the_fetch_use_a_new_token(harness: Harness) -> None:
    fake = standard_api(harness)
    run_fetch()  # caches a token for the first key
    old_token = harness.context["auth_token"]
    new_key = "nz-unit-test-api-key-0002"
    fake.api_key = new_key  # the user enters a new key and clicks Test
    params = {**FETCH_PARAMS, "credentials": {"password": new_key}}
    assert NodeZeroEventCollector.test_module(make_client(api_key=new_key), params) == "ok"
    requests_before = len(fake.authorization_headers)
    NodeZeroEventCollector.fetch_events_command(make_client(api_key=new_key), params)
    tokens = [header.removeprefix("Bearer ") for header in fake.authorization_headers[requests_before:]]
    assert tokens
    assert all(fake.token_keys[token] == new_key for token in tokens)  # the previous key's token is never used
    assert harness.context["auth_token"] not in (old_token, None)
    assert harness.context["auth_token_owner"] == token_owner(api_key=new_key)


@freeze_time(NOW)
def test_lease_lost_while_caching_a_token_is_not_reported_as_a_page_failure(harness: Harness) -> None:
    fake = standard_api(harness)
    harness.context[STATE_KEY] = state_payload()
    intruder = lease_payload("command", "intruder", NOW_EPOCH + 600)
    fake.on_request["CortexXsiamPentestWeaknesses"] = [
        lambda: harness.store.other_writer(lambda context: context.update({LEASE_KEY: intruder}))
    ]
    fake.queue("CortexXsiamPentestWeaknesses", 401)  # the re-authentication's token write then finds the other run's lease
    with pytest.raises(NodeZeroEventCollector.LeaseLost) as error:
        run_fetch()
    assert str(error.value) == "The collection lease expired and another run took it, so this run stopped sending."
    assert harness.sent_events() == []
    assert harness.store.lease() == intruder


@freeze_time(NOW)
def test_resumed_cursor_never_moves_the_watermark_past_an_older_unsent_pentest(harness: Harness) -> None:
    # Finishing a half-sent pentest must not move the watermark past an older pentest that wasn't sent yet.
    older = pentest_row("op-older", 1, etl_completed_at="2025-03-13T00:00:00")
    newer = pentest_row("op-newer", 5, etl_completed_at="2025-03-15T11:00:00")  # more than LOOKBACK after op-older
    fake = generated_api(harness, [older, newer])
    harness.context[STATE_KEY] = state_payload()
    clock = FakeClock()
    fake.charge_weakness_pages(clock, 100)  # the push is cut after two pages: it leaves a cursor on op-newer
    push(args={"pentest_id": "op-newer"}, clock=clock)
    assert harness.store.state()["in_progress"]["pentest"]["op_id"] == "op-newer"
    fake.page_cost = None
    fake.fail_page("op-older", 1, status=500)  # the fetch resumes op-newer, then fails on op-older
    with pytest.raises(DemistoException, match="op-older"):
        run_fetch()
    assert harness.store.state()["watermark"] == FIRST_FETCH_FLOOR
    del fake.page_failures[("op-older", 1)]
    run_fetch()
    assert set(ids_of(fake, "op-older")) <= set(harness.sent_ids()), "op-older was skipped"
    assert harness.duplicate_ids() == []


@freeze_time(NOW)
def test_checkpoint_mirror_never_records_a_pentest_whose_final_commit_failed(harness: Harness) -> None:
    # A state copy that shares sent_ops would change memory before the commit lands.
    standard_api(harness)  # op-a: pages of 2 and 1
    harness.context[STATE_KEY] = state_payload()
    intruder = lease_payload("command", "intruder", NOW_EPOCH + 600)
    harness.on_send.extend(
        [lambda events: None, lambda events: harness.store.other_writer(lambda context: context.update({LEASE_KEY: intruder}))]
    )
    with pytest.raises(NodeZeroEventCollector.LeaseLost):
        run_fetch()  # page 2 of op-a is sent, then its final commit finds another run's lease
    assert "op-a" not in harness.store.state()["sent_ops"]
    assert "op-a" not in harness.last_run["sent_ops"], "the checkpoint mirror records op-a as sent"


# ----- request identity: User-Agent, X-Request-ID, operation names and the run ID -----

UNIT_TEST_USER_AGENT = "NodeZero-Cortex/unknown (NodeZeroEventCollector; Cortex 5.5.0)"  # demistomock's platform version
RUN_ID_PATTERN = r"[0-9a-f]{32}"
KNOWN_USER_AGENT = "NodeZero-Cortex/2.0.0 (NodeZeroEventCollector; Cortex 8.9.0)"
UNKNOWN_USER_AGENT = "NodeZero-Cortex/unknown (NodeZeroEventCollector; Cortex unknown)"


def sent_headers(harness: Harness) -> list[tuple[str, dict[str, str]]]:
    """The path and headers of every HTTP request the collector made, in order."""
    return [(request.path, dict(request.headers)) for request in harness.requests_mock.request_history]


def assert_identity_headers(harness: Harness, run_id: str) -> list[str]:
    """Every request carries the User-Agent and <run id>-<n>, n counting from 1. Returns the request paths."""
    requests_made = sent_headers(harness)
    assert requests_made, "the run made no request"
    for number, (_, headers) in enumerate(requests_made, start=1):
        assert headers["User-Agent"] == UNIT_TEST_USER_AGENT
        assert headers["X-Request-ID"] == f"{run_id}-{number}"
    return [path for path, _ in requests_made]


def test_operation_names() -> None:
    assert operation_name(NodeZeroEventCollector.FINISHED_PENTESTS_QUERY) == "CortexXsiamFinishedPentests"
    assert operation_name(NodeZeroEventCollector.PENTEST_QUERY) == "CortexXsiamPentest"
    assert operation_name(NodeZeroEventCollector.PENTEST_WEAKNESSES_QUERY) == "CortexXsiamPentestWeaknesses"
    assert operation_name(NodeZeroEventCollector.CONNECTIVITY_QUERY) == "CortexXsiamConnectivity"
    # The single-pentest lookup selects exactly what the sweep selects; only the operation name differs.
    lookup_body = NodeZeroEventCollector.PENTEST_QUERY.replace("CortexXsiamPentest(", "CortexXsiamFinishedPentests(")
    assert lookup_body == NodeZeroEventCollector.FINISHED_PENTESTS_QUERY


def test_user_agent_in_unit_tests_falls_back_for_the_pack_version() -> None:
    assert NodeZeroEventCollector.get_pack_version() == ""  # not unified, so there is no CONSTANT_PACK_VERSION
    assert NodeZeroEventCollector.build_user_agent() == UNIT_TEST_USER_AGENT


def raise_error() -> Any:
    raise RuntimeError("not available")


@pytest.mark.parametrize(
    ("pack_version", "platform_version", "expected"),
    [
        (lambda: "2.0.0", lambda: {"version": "8.9.0", "buildNumber": "1"}, KNOWN_USER_AGENT),
        (lambda: " 2.0.0 ", lambda: {"version": "8.9.0"}, KNOWN_USER_AGENT),
        (raise_error, raise_error, UNKNOWN_USER_AGENT),
        (lambda: None, lambda: None, UNKNOWN_USER_AGENT),
        (lambda: "", dict, UNKNOWN_USER_AGENT),
        (lambda: "   ", lambda: {"version": ""}, UNKNOWN_USER_AGENT),
        (lambda: 2, lambda: {"version": 8.9}, UNKNOWN_USER_AGENT),
        (lambda: "2.0.0\r\nX-Injected: 1", lambda: "8.9.0", UNKNOWN_USER_AGENT),
        (lambda: "2.0.0 (beta)", lambda: {"version": "8.9.0;x"}, UNKNOWN_USER_AGENT),
        (
            lambda: "1" * 65,  # longer than any real version
            lambda: {"version": "8.10.0-rc1"},
            "NodeZero-Cortex/unknown (NodeZeroEventCollector; Cortex 8.10.0-rc1)",
        ),
    ],
)
def test_user_agent_fallbacks(
    monkeypatch: pytest.MonkeyPatch, pack_version: Callable[[], Any], platform_version: Callable[[], Any], expected: str
) -> None:
    monkeypatch.setattr(NodeZeroEventCollector, "get_pack_version", pack_version)
    monkeypatch.setattr(demisto, "demistoVersion", platform_version)
    assert NodeZeroEventCollector.build_user_agent() == expected


def test_client_builds_its_user_agent_once(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(NodeZeroEventCollector, "get_pack_version", raise_error)
    monkeypatch.setattr(demisto, "demistoVersion", raise_error)
    client = make_client()  # a failing version lookup never stops the client from being built
    assert client.identity_headers()["User-Agent"] == UNKNOWN_USER_AGENT


def test_each_client_has_its_own_run_id() -> None:
    first, second = make_client(), make_client()
    assert re.fullmatch(RUN_ID_PATTERN, first.run_id)
    assert first.run_id != second.run_id
    assert [first.identity_headers()["X-Request-ID"] for _ in range(3)] == [f"{first.run_id}-{n}" for n in (1, 2, 3)]
    assert second.identity_headers()["X-Request-ID"] == f"{second.run_id}-1"


@freeze_time(NOW)
def test_every_fetch_request_carries_the_identity_headers(harness: Harness) -> None:
    standard_api(harness)
    client = make_client()
    NodeZeroEventCollector.fetch_events_command(client, FETCH_PARAMS)
    paths = assert_identity_headers(harness, client.run_id)
    assert paths == ["/v1/auth"] + ["/v1/graphql"] * 6  # the key exchange, two sweep pages and four weakness pages
    for path, headers in sent_headers(harness):
        assert headers["Content-Type"] == "application/json"  # the per-call headers didn't replace it
        if path == "/v1/graphql":
            assert headers["Authorization"].startswith("Bearer ")
        else:
            assert "Authorization" not in headers
        for value in (headers["User-Agent"], headers["X-Request-ID"]):
            assert API_KEY not in value
            assert "nodezero.example.com" not in value


@freeze_time(NOW)
def test_reauthentication_after_401_counts_every_request(harness: Harness) -> None:
    fake = standard_api(harness)
    harness.context.update(cached_token("revoked-token", NOW_EPOCH + 3600))
    fake.queue("CortexXsiamConnectivity", 401)
    client = make_client()
    client.check_connectivity()
    # The rejected request, the new key exchange and the repeated request each get their own number.
    assert assert_identity_headers(harness, client.run_id) == ["/v1/graphql", "/v1/auth", "/v1/graphql"]
    assert fake.authorization_headers == ["Bearer revoked-token", f"Bearer {fake.issued_tokens[0]}"]


@freeze_time(NOW)
def test_http_error_names_the_request_id_of_the_failed_request(harness: Harness) -> None:
    fake = standard_api(harness)
    fake.queue("CortexXsiamConnectivity", 500, {"message": "boom"})
    client = make_client()
    with pytest.raises(DemistoException) as error:
        client.check_connectivity()
    assert str(error.value).startswith("NodeZero API request failed with HTTP 500")
    assert str(error.value).endswith(f". Request ID: {client.run_id}-2.")  # auth was request 1


@freeze_time(NOW)
def test_failed_reauthentication_names_the_last_request(harness: Harness) -> None:
    fake = standard_api(harness)
    fake.queue("CortexXsiamConnectivity", 401)
    fake.queue("CortexXsiamConnectivity", 401)
    client = make_client()
    with pytest.raises(DemistoException) as error:
        client.check_connectivity()
    assert str(error.value).endswith(
        f"Verify that the API key is valid and has read access to pentests and weaknesses. Request ID: {client.run_id}-4."
    )


@freeze_time(NOW)
def test_weakness_page_error_keeps_the_request_id(harness: Harness) -> None:
    fake = standard_api(harness)
    fake.fail_page("op-a", 2, status=400)
    client = make_client()
    with pytest.raises(DemistoException) as error:
        NodeZeroEventCollector.fetch_events_command(client, FETCH_PARAMS)
    # auth, two sweep pages, op-a page 1, then the failed op-a page 2
    assert "page 2 of the weaknesses of pentest op-a" in str(error.value)
    assert str(error.value).endswith(f". Request ID: {client.run_id}-5.")
    assert harness.summary().startswith(f"NodeZero fetch failed (run ID {client.run_id}): ")


def test_http_error_message_with_and_without_a_recorded_request() -> None:
    response = make_response(503, "Service Unavailable", {"message": "busy"})
    response.request = requests.Request("POST", BASE_URL, headers={"X-Request-ID": "0123abcd-7"}).prepare()
    with pytest.raises(DemistoException) as error:
        NodeZeroEventCollector.raise_http_error(response)
    assert str(error.value) == "NodeZero API request failed with HTTP 503 (Service Unavailable). Request ID: 0123abcd-7."
    response.request = requests.Request("POST", BASE_URL, headers={"Authorization": "Bearer secret"}).prepare()
    with pytest.raises(DemistoException) as error:
        NodeZeroEventCollector.raise_http_error(response)
    assert str(error.value) == "NodeZero API request failed with HTTP 503 (Service Unavailable)."
    assert NodeZeroEventCollector.request_id_of(make_response(500, "", {})) is None  # no request recorded
    no_headers = SimpleNamespace(request=SimpleNamespace(headers=None))
    assert NodeZeroEventCollector.request_id_of(no_headers) is None  # type: ignore[arg-type]


@freeze_time(NOW)
def test_fetch_summary_names_the_run_id(harness: Harness) -> None:
    standard_api(harness)
    client = make_client()
    NodeZeroEventCollector.fetch_events_command(client, FETCH_PARAMS)
    assert harness.summary().startswith(f"NodeZero fetch finished (run ID {client.run_id}): 2 pentests fully sent, ")


@freeze_time(NOW)
def test_skipped_fetch_summary_names_the_run_id(harness: Harness) -> None:
    standard_api(harness)
    harness.context.update({LEASE_KEY: lease_payload("command", "push-run", NOW_EPOCH + 1), STATE_KEY: state_payload()})
    client = make_client()
    NodeZeroEventCollector.fetch_events_command(client, FETCH_PARAMS)
    assert harness.summary().startswith(f"NodeZero fetch skipped (run ID {client.run_id}): ")
    assert harness.requests_mock.request_history == []  # a skipped run sends no request


@freeze_time(NOW)
def test_manual_push_summary_names_the_run_id_of_its_requests(harness: Harness) -> None:
    standard_api(harness)
    run_fetch()
    harness.requests_mock.reset_mock()
    push()
    summaries = [message for message in harness.messages("info") if message.startswith("NodeZero manual push ")]
    assert len(summaries) == 1, summaries
    match = re.match(rf"NodeZero manual push finished \(run ID ({RUN_ID_PATTERN})\): ", summaries[0])
    assert match, summaries[0]
    assert assert_identity_headers(harness, match.group(1))  # the summary's run ID prefixes every request of the push


INSTANCE_NAME = "nodezero-collector-instance-under-test"
LICENSE_ID = "license-id-under-test-0001"
TENANT_HOST = "nodezero.example.com"
# Every header a request sends, besides Authorization on GraphQL calls. A new header, such as X-Content-LicenseID from
# get_x_content_info_headers(), fails the tests that use it.
REQUEST_HEADER_NAMES = {"Accept", "Accept-Encoding", "Connection", "Content-Length", "Content-Type", "User-Agent", "X-Request-ID"}
# sha256 of each query text with its operation name replaced by "Operation", computed from the queries of commit
# 370e113f7c, before the rename: the operation names are the only change to the query texts.
QUERY_DIGESTS = {
    "FINISHED_PENTESTS_QUERY": "6fbd8cd7a02204b8db75bc4314f3dc7ef1e9d1e4cecd3180b3654f1ced1cf13a",
    "PENTEST_QUERY": "6fbd8cd7a02204b8db75bc4314f3dc7ef1e9d1e4cecd3180b3654f1ced1cf13a",  # the sweep's text
    "PENTEST_WEAKNESSES_QUERY": "e5fbfb4190f91091a9f7ada12b8f53d378dcddee0b12deb8d1e7f65c34f65b52",
    "CONNECTIVITY_QUERY": "1eddffb3ed8201849a9d189fb57e581eec0c4cc984be0f5e8814c68b4802d568",
}


def test_identity_constants() -> None:
    assert NodeZeroEventCollector.INTEGRATION_NAME == "NodeZeroEventCollector"
    assert NodeZeroEventCollector.USER_AGENT_PRODUCT == "NodeZero-Cortex"
    assert NodeZeroEventCollector.UNKNOWN_VERSION == "unknown"
    assert NodeZeroEventCollector.REQUEST_ID_HEADER == "X-Request-ID"
    assert NodeZeroEventCollector.VERSION_PATTERN.pattern == r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}"


@pytest.mark.parametrize("name", sorted(QUERY_DIGESTS))
def test_query_texts_differ_from_before_only_in_their_operation_names(name: str) -> None:
    query = getattr(NodeZeroEventCollector, name)
    normalized = re.sub(r"query \w+\(", "query Operation(", query, count=1)
    assert hashlib.sha256(normalized.encode()).hexdigest() == QUERY_DIGESTS[name], f"the selection of {name} changed"


class BrokenVersionInfo(dict):
    """A platform answer whose lookup fails."""

    def get(self, *args: Any) -> Any:
        raise KeyError("version")


@pytest.mark.parametrize(
    ("pack_version", "platform_version", "expected_pack", "expected_platform"),
    [
        ("1" * 64, {"version": "8.9.0"}, "1" * 64, "8.9.0"),  # the longest version kept: 64 characters
        ("2.0.0+build_7", {"version": "8.9.0-rc.1"}, "2.0.0+build_7", "8.9.0-rc.1"),  # every punctuation mark allowed
        (".2.0.0", {"version": "-8.9.0"}, "unknown", "unknown"),  # a version starts with a letter or a digit
        (b"2.0.0", ["8.9.0"], "unknown", "unknown"),  # bytes, and a platform answer that isn't a dict
        ("2.0.0\n", {"version": "\t8.9.0 "}, "2.0.0", "8.9.0"),  # surrounding whitespace is trimmed, never sent
        ("2.0.0", BrokenVersionInfo(), "2.0.0", "unknown"),
    ],
    ids=["64-characters-kept", "allowed-punctuation", "leading-punctuation", "bytes-and-a-list", "trimmed", "lookup-raises"],
)
def test_user_agent_version_boundaries(
    monkeypatch: pytest.MonkeyPatch, pack_version: Any, platform_version: Any, expected_pack: str, expected_platform: str
) -> None:
    monkeypatch.setattr(NodeZeroEventCollector, "get_pack_version", lambda: pack_version)
    monkeypatch.setattr(demisto, "demistoVersion", lambda: platform_version)
    expected = f"NodeZero-Cortex/{expected_pack} (NodeZeroEventCollector; Cortex {expected_platform})"
    assert NodeZeroEventCollector.build_user_agent() == expected


@pytest.mark.parametrize(
    "headers",
    [{"X-Request-ID": b"0123abcd-7"}, {"X-Request-ID": ""}, {"X-Request-ID": None}, {}, ["X-Request-ID"], "X-Request-ID: 1"],
    ids=["bytes", "empty", "none", "missing", "list", "text"],
)
def test_request_id_of_ignores_values_that_are_not_text(headers: Any) -> None:
    response = SimpleNamespace(request=SimpleNamespace(headers=headers))
    assert NodeZeroEventCollector.request_id_of(response) is None  # type: ignore[arg-type]


def run_main(harness: Harness, monkeypatch: pytest.MonkeyPatch, command: str, args: dict[str, Any] | None = None) -> Any:
    """Run one command through main(). Returns the requests and the log lines of that run."""
    first_request, first_log = len(harness.requests_mock.request_history), len(harness.logs)
    monkeypatch.setattr(demisto, "command", lambda: command)
    monkeypatch.setattr(demisto, "args", lambda: args or {})
    NodeZeroEventCollector.main()
    return harness.requests_mock.request_history[first_request:], [message for _, message in harness.logs[first_log:]]


@freeze_time(NOW)
def test_every_command_run_sends_the_identity_headers_under_its_own_run_id(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = standard_api(harness)
    errors: list[str] = []
    monkeypatch.setattr(NodeZeroEventCollector, "return_error", lambda message, *args, **kwargs: errors.append(str(message)))
    monkeypatch.setattr(NodeZeroEventCollector, "return_results", lambda *args, **kwargs: None)
    monkeypatch.setattr(demisto, "params", lambda: FETCH_PARAMS)
    runs = [
        run_main(harness, monkeypatch, "test-module"),
        run_main(harness, monkeypatch, "fetch-events"),
        run_main(harness, monkeypatch, "nodezero-fetch-events", {"should_push_events": "false", "pentest_id": "op-a"}),
        run_main(harness, monkeypatch, "nodezero-fetch-events", {"should_push_events": "true", "since": "3 days"}),
    ]
    fake.queue("CortexXsiamConnectivity", 401)
    runs.append(run_main(harness, monkeypatch, "test-module"))  # the 401 re-authentication retry
    assert errors == []
    assert [request.path for request in runs[-1][0]] == ["/v1/auth", "/v1/graphql", "/v1/auth", "/v1/graphql"]
    run_ids: list[str] = []
    for requests_made, _ in runs:
        assert requests_made, "the run made no request"
        run_id = requests_made[0].headers["X-Request-ID"].rsplit("-", 1)[0]
        assert re.fullmatch(RUN_ID_PATTERN, run_id)
        assert [request.headers["X-Request-ID"] for request in requests_made] == [
            f"{run_id}-{number}" for number in range(1, len(requests_made) + 1)
        ]
        for request in requests_made:
            assert request.headers["User-Agent"] == UNIT_TEST_USER_AGENT
            extra = {"Authorization"} if request.path == "/v1/graphql" else set()
            assert set(request.headers) == REQUEST_HEADER_NAMES | extra
        run_ids.append(run_id)
    assert len(set(run_ids)) == len(run_ids)  # every run has its own run ID
    graphql_bodies = [request.json() for requests_made, _ in runs for request in requests_made if request.path == "/v1/graphql"]
    assert {operation_name(body["query"]) for body in graphql_bodies} == {
        "CortexXsiamFinishedPentests",
        "CortexXsiamPentest",
        "CortexXsiamPentestWeaknesses",
        "CortexXsiamConnectivity",
    }
    assert all(set(body) == {"query", "variables"} for body in graphql_bodies)  # no operationName field was added
    # The fetch and the push each log one summary line, which names the run ID their requests carry.
    for index, prefix in ((1, "NodeZero fetch finished"), (3, "NodeZero manual push finished")):
        summaries = [line for line in runs[index][1] if line.startswith(("NodeZero fetch ", "NodeZero manual push "))]
        assert summaries == [line for line in summaries if line.startswith(f"{prefix} (run ID {run_ids[index]}): ")]
        assert len(summaries) == 1


@freeze_time(NOW)
def test_no_secret_or_tenant_detail_in_headers_logs_or_errors(harness: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    """Covers the request headers as requests_mock records them, every demisto.debug, info and error line, and the
    messages given to return_error. It does not cover CommonServerPython's debug-mode wire log: that log starts only when
    CommonServerPython is imported with debug mode on, and requests_mock bypasses http.client, which writes it."""
    monkeypatch.setattr(demisto, "integrationInstance", lambda: INSTANCE_NAME)
    monkeypatch.setattr(demisto, "getLicenseID", lambda: LICENSE_ID)
    calling_context = {"context": {"IntegrationInstance": INSTANCE_NAME, "IntegrationBrand": "NodeZero Event Collector"}}
    monkeypatch.setattr(demisto, "callingContext", calling_context)
    fake = standard_api(harness)
    errors: list[str] = []
    monkeypatch.setattr(NodeZeroEventCollector, "return_error", lambda message, *args, **kwargs: errors.append(str(message)))
    monkeypatch.setattr(NodeZeroEventCollector, "return_results", lambda *args, **kwargs: None)
    monkeypatch.setattr(demisto, "params", lambda: FETCH_PARAMS)
    run_main(harness, monkeypatch, "test-module")
    run_main(harness, monkeypatch, "fetch-events")
    run_main(harness, monkeypatch, "nodezero-fetch-events", {"should_push_events": "true", "since": "3 days"})
    fake.queue("CortexXsiamFinishedPentests", 401)
    run_main(harness, monkeypatch, "nodezero-fetch-events", {"should_push_events": "false"})  # re-authenticates once
    fake.queue("CortexXsiamFinishedPentests", 500, {"message": "boom"})
    failed_requests, _ = run_main(harness, monkeypatch, "fetch-events")
    assert len(errors) == 1
    assert errors[0].endswith(f"Request ID: {failed_requests[-1].headers['X-Request-ID']}.")
    tokens = set(fake.issued_tokens)
    assert len(tokens) == 3  # test-module's, the fetch's (cached, so the push and the view reuse it), the re-authentication's
    forbidden = [API_KEY, *tokens, TENANT_HOST, BASE_URL, INSTANCE_NAME, LICENSE_ID]
    for request in harness.requests_mock.request_history:
        for name, value in request.headers.items():
            if name == "Authorization":
                assert value.removeprefix("Bearer ") in tokens  # the only header that carries a token
                continue
            for secret in forbidden:
                assert secret not in value, f"{name} carries a secret or a tenant detail"
    for text in [message for _, message in harness.logs] + errors:
        for secret in forbidden:
            assert secret not in text, text


class LocalNodeZero(BaseHTTPRequestHandler):
    """A local NodeZero over real HTTP. The first request is throttled with HTTP 503 and every later one succeeds."""

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        seen: list[tuple[str, str, str]] = self.server.seen  # type: ignore[attr-defined]
        seen.append((self.path, self.headers.get("X-Request-ID", ""), self.headers.get("User-Agent", "")))
        if len(seen) == 1:
            status, body = 503, {"message": "throttled"}  # no Retry-After, so urllib3 retries at once
        elif self.path == "/v1/auth":
            status, body = 200, {"token": make_jwt(int(time.time()) + 3600)}
        else:
            status, body = 200, pentests_body([])
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args: Any) -> None:
        """Silent: the test output must stay empty."""


def test_retried_attempts_share_the_request_id_of_their_request(monkeypatch: pytest.MonkeyPatch) -> None:
    """Accepted limitation (Client.identity_headers): urllib3 resends one prepared request, so the attempts of one request
    carry the same X-Request-ID. The next request gets the next number. requests_mock can't show this: it skips urllib3."""
    for level in ("debug", "info"):
        monkeypatch.setattr(demisto, level, lambda *args: None)
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalNodeZero)
    server.seen = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = make_client(base_url=f"http://127.0.0.1:{server.server_address[1]}")
        real_mount = client._session.mount

        def mount_for_http_too(prefix: str, adapter: Any) -> None:
            real_mount(prefix, adapter)
            if prefix == "https://":  # CommonServerPython mounts its retrying adapter for https only; this server is http
                real_mount("http://", adapter)

        monkeypatch.setattr(client._session, "mount", mount_for_http_too)
        client.authenticate()  # 180 s left on the fake clock, so this request may retry
        client.check_connectivity()
    finally:
        server.shutdown()
        server.server_close()
    assert [(path, request_id) for path, request_id, _ in server.seen] == [  # type: ignore[attr-defined]
        ("/v1/auth", f"{client.run_id}-1"),  # throttled
        ("/v1/auth", f"{client.run_id}-1"),  # the urllib3 retry of the same request
        ("/v1/graphql", f"{client.run_id}-2"),
    ]
    assert {user_agent for _, _, user_agent in server.seen} == {UNIT_TEST_USER_AGENT}  # type: ignore[attr-defined]


@freeze_time(NOW)
def test_fetch_that_fails_before_any_request_logs_its_run_id(harness: Harness) -> None:
    standard_api(harness)
    client = make_client()
    with pytest.raises(ValueError, match="Invalid number"):
        NodeZeroEventCollector.fetch_events_command(client, {**FETCH_PARAMS, "max_fetch": "not a number"})
    assert harness.summary().startswith(f"NodeZero fetch failed (run ID {client.run_id}): ")
    assert harness.requests_mock.request_history == []


# ----- the request ID in every error a NodeZero response causes -----

GRAPHQL_ERRORS_TEXT = 'Cannot query field "nope" on type "Pentest".; Variable "$page_input" got an invalid value.'
NOT_AN_OBJECT = "NodeZero returned a GraphQL response that is not a JSON object."
WITHOUT_DATA = "NodeZero returned a GraphQL response without data."
WITHOUT_TOKEN = "The NodeZero authentication response did not include a token."


def response_with_request_id(request_id: str, status: int = 200, body: Any = None) -> requests.Response:
    """A response whose request carried this X-Request-ID."""
    response = make_response(status, "OK", body if body is not None else {})
    response.request = requests.Request("POST", BASE_URL, headers={"X-Request-ID": request_id}).prepare()
    return response


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("Request failed", "Request failed. Request ID: 0123abcd-7."),  # a full stop is added before the ID
        ("Request failed.", "Request failed. Request ID: 0123abcd-7."),  # and never doubled
        ('Field "x" is invalid.; no data', 'Field "x" is invalid.; no data. Request ID: 0123abcd-7.'),
    ],
    ids=["without-full-stop", "with-full-stop", "full-stop-inside-only"],
)
def test_with_request_id(message: str, expected: str) -> None:
    assert NodeZeroEventCollector.with_request_id(message, response_with_request_id("0123abcd-7")) == expected
    # No ID, and no added full stop, when the response records no request or there is no response.
    assert NodeZeroEventCollector.with_request_id(message, make_response(500, "", {})) == message
    assert NodeZeroEventCollector.with_request_id(message, None) == message


@freeze_time(NOW)
@pytest.mark.parametrize(
    ("body", "raw", "message"),
    [
        (load_json("graphql_errors.json"), None, f"NodeZero GraphQL request failed: {GRAPHQL_ERRORS_TEXT}"),
        (
            {"errors": [{"message": "Field is not available"}], "data": {}},
            None,
            "NodeZero GraphQL request failed: Field is not available.",
        ),
        (None, "<html>gateway</html>", NOT_AN_OBJECT),
        ([{"data": {}}], None, NOT_AN_OBJECT),
        ({"data": None}, None, WITHOUT_DATA),
        ({"errors": []}, None, WITHOUT_DATA),
    ],
    ids=["errors-array", "errors-array-without-full-stop", "html", "json-list", "null-data", "empty-errors-no-data"],
)
def test_graphql_failure_with_http_200_names_the_request_id(harness: Harness, body: Any, raw: str | None, message: str) -> None:
    fake = standard_api(harness)
    fake.queue("CortexXsiamConnectivity", 200, body, raw=raw)
    client = make_client()
    with pytest.raises(DemistoException) as error:
        client.check_connectivity()
    assert str(error.value) == f"{message} Request ID: {client.run_id}-2."  # auth was request 1
    assert harness.requests_mock.request_history[-1].headers["X-Request-ID"] == f"{client.run_id}-2"


@freeze_time(NOW)
def test_graphql_errors_after_reauthentication_name_the_repeated_request(harness: Harness) -> None:
    fake = standard_api(harness)
    fake.queue("CortexXsiamConnectivity", 401)
    fake.queue("CortexXsiamConnectivity", 200, {"errors": [{"message": "Pentest access denied"}]})
    client = make_client()
    with pytest.raises(DemistoException) as error:
        client.check_connectivity()
    # auth 1, the rejected request 2, the new key exchange 3, the repeated request 4, whose response had the errors
    assert str(error.value) == f"NodeZero GraphQL request failed: Pentest access denied. Request ID: {client.run_id}-4."


@freeze_time(NOW)
def test_weakness_page_graphql_errors_name_the_request_id(harness: Harness) -> None:
    fake = standard_api(harness)
    client = make_client()
    fake.queue("CortexXsiamPentestWeaknesses", 200, load_json("graphql_errors.json"))
    with pytest.raises(DemistoException) as error:
        client.get_weaknesses_page("op-a", 1)
    assert str(error.value) == (
        "Failed to read page 1 of the weaknesses of pentest op-a. "
        f"NodeZero GraphQL request failed: {GRAPHQL_ERRORS_TEXT} Request ID: {client.run_id}-2."
    )


@freeze_time(NOW)
@pytest.mark.parametrize(
    "body", [{"jwt": "missing"}, {"token": ""}, {"token": 7}, ["token"]], ids=["absent", "empty", "number", "list"]
)
def test_auth_response_without_a_token_names_the_request_id(harness: Harness, body: Any) -> None:
    fake = standard_api(harness)
    fake.queue("auth", 200, body)
    client = make_client()
    with pytest.raises(DemistoException) as error:
        client.authenticate()
    assert str(error.value) == f"{WITHOUT_TOKEN} Request ID: {client.run_id}-1."


@pytest.mark.parametrize(
    ("parse", "body", "message"),
    [
        (
            NodeZeroEventCollector.parse_graphql_data,
            {"errors": [{"message": "no full stop"}]},
            "NodeZero GraphQL request failed: no full stop",
        ),
        (NodeZeroEventCollector.parse_graphql_data, ["not", "an", "object"], NOT_AN_OBJECT),
        (NodeZeroEventCollector.parse_graphql_data, {"data": None}, WITHOUT_DATA),
        (NodeZeroEventCollector.parse_token, {}, WITHOUT_TOKEN),
    ],
    ids=["errors", "not-an-object", "without-data", "without-token"],
)
def test_parse_errors_without_a_recorded_request_have_no_request_id(
    parse: Callable[[requests.Response], Any], body: Any, message: str
) -> None:
    with pytest.raises(DemistoException) as error:
        parse(make_response(200, "OK", body))  # response.request is None
    assert str(error.value) == message


@pytest.mark.parametrize(
    "parse", [NodeZeroEventCollector.parse_graphql_data, NodeZeroEventCollector.raise_http_error], ids=["graphql", "http"]
)
def test_error_names_the_request_id_it_sent_not_a_server_echo(parse: Callable[[requests.Response], Any]) -> None:
    response = response_with_request_id("0123abcd-7", status=500, body={"errors": [{"message": "boom"}]})
    response.headers["X-Request-ID"] = "set-by-a-proxy"
    with pytest.raises(DemistoException, match=r" Request ID: 0123abcd-7\.$") as error:
        parse(response)
    assert "set-by-a-proxy" not in str(error.value)


def last_request_id(harness: Harness) -> str:
    return harness.requests_mock.request_history[-1].headers["X-Request-ID"]


MALFORMED_PAGES = {
    "sweep page null": ("fetch", "CortexXsiamFinishedPentests", {"data": {"pentests_page": None}}),
    "sweep list missing": ("fetch", "CortexXsiamFinishedPentests", {"data": {"pentests_page": {}}}),
    "weaknesses list null": ("fetch", "CortexXsiamPentestWeaknesses", {"data": {"weaknesses_page": {"weaknesses": None}}}),
    "lookup page null": ("lookup", "CortexXsiamPentest", {"data": {"pentests_page": None}}),
}


@freeze_time(NOW)
@pytest.mark.parametrize("name", MALFORMED_PAGES)
def test_a_malformed_page_names_the_request_id(harness: Harness, name: str) -> None:
    command, operation, body = MALFORMED_PAGES[name]
    fake = standard_api(harness)
    fake.queue(operation, 200, body)
    client = make_client()
    with pytest.raises(DemistoException) as error:
        if command == "fetch":
            NodeZeroEventCollector.fetch_events_command(client, FETCH_PARAMS)
        else:
            NodeZeroEventCollector.nodezero_fetch_events_command(client, {"pentest_id": "op-a"}, FETCH_PARAMS)
    assert " result without a " in str(error.value)
    assert str(error.value).endswith(f" Request ID: {last_request_id(harness)}.")


@freeze_time(NOW)
@pytest.mark.parametrize("status", [200, 500])
@pytest.mark.parametrize("text", ["Pentest query failed. ", "Pentest query failed.\n", "Pentest query failed."])
def test_error_text_never_doubles_the_full_stop(harness: Harness, status: int, text: str) -> None:
    fake = standard_api(harness)
    fake.queue("CortexXsiamFinishedPentests", status, {"errors": [{"message": text}]})
    with pytest.raises(DemistoException) as error:
        NodeZeroEventCollector.fetch_events_command(make_client(), FETCH_PARAMS)
    message = str(error.value)
    assert message.endswith(f"Pentest query failed. Request ID: {last_request_id(harness)}.")
    assert not re.search(r"\.\s+\.", message), message


@freeze_time(NOW)
def test_a_weakness_page_error_after_reauthentication_names_one_request_id(harness: Harness) -> None:
    fake = standard_api(harness)
    fake.queue("CortexXsiamPentestWeaknesses", 401, {"errors": [{"message": "Unauthorized"}]})
    fake.queue("CortexXsiamPentestWeaknesses", 500, {"errors": [{"message": "boom"}]})
    with pytest.raises(DemistoException) as error:
        NodeZeroEventCollector.fetch_events_command(make_client(), FETCH_PARAMS)
    message = str(error.value)
    assert message.startswith("Failed to read page 1 of the weaknesses of pentest op-a.")
    assert message.endswith(f" Request ID: {last_request_id(harness)}.")  # the request sent after the new token
    assert message.count("Request ID:") == 1


# ----- the manual push summary and the client's identity log line -----


@freeze_time(NOW)
@pytest.mark.parametrize(
    ("failure", "outcome", "counts"),
    [
        ("http", "failed", "1 pentests fully sent, 3 events sent, "),  # op-a sent, then page 1 of op-b fails
        ("send", "failed", "0 pentests fully sent, 0 events sent, "),  # the first send to Cortex raises
        (None, "finished", "2 pentests fully sent, 5 events sent, "),
    ],
)
def test_manual_push_summary_outcome_and_lease_release(harness: Harness, failure: str | None, outcome: str, counts: str) -> None:
    fake = standard_api(harness)
    harness.context[STATE_KEY] = state_payload()
    if failure == "http":
        fake.fail_page("op-b", 1, status=500)

    def failing_send(events: list[dict[str, Any]]) -> None:
        raise RuntimeError("send failed")

    if failure == "send":
        harness.on_send.append(failing_send)
    client = make_client()
    args = {"should_push_events": "true", "limit": "100"}
    if failure is None:
        NodeZeroEventCollector.nodezero_fetch_events_command(client, args, FETCH_PARAMS)
    else:
        with pytest.raises((DemistoException, RuntimeError)):
            NodeZeroEventCollector.nodezero_fetch_events_command(client, args, FETCH_PARAMS)
    summaries = [message for message in harness.messages("info") if message.startswith("NodeZero manual push ")]
    assert len(summaries) == 1, summaries
    assert summaries[0].startswith(f"NodeZero manual push {outcome} (run ID {client.run_id}): {counts}")
    assert harness.store.lease() is None  # released whatever the outcome
    assert client.token_sink is None


def push_summaries(harness: Harness) -> list[str]:
    return [message for message in harness.messages("info") if message.startswith("NodeZero manual push ")]


PUSH_ARGS = {"should_push_events": "true", "limit": "100"}


@freeze_time(NOW)
def test_a_push_that_took_the_lease_then_lost_the_state_logs_failed(harness: Harness) -> None:
    standard_api(harness)
    NodeZeroEventCollector.fetch_events_command(make_client(), FETCH_PARAMS)  # stores the state a push needs while fetching is on
    harness.logs.clear()
    writes_before = len(harness.store.writes)
    # another writer removes the state while the push waits to confirm its lease
    harness.on_pause.append(lambda: harness.store.other_writer(lambda context: context.pop(STATE_KEY, None)))
    client = make_client()
    with pytest.raises(DemistoException, match="Events can't be sent yet"):
        NodeZeroEventCollector.nodezero_fetch_events_command(client, PUSH_ARGS, FETCH_PARAMS)
    assert "command" in [write[LEASE_KEY]["owner"] for write in harness.store.writes[writes_before:] if LEASE_KEY in write]
    assert harness.store.lease() is None
    summaries = push_summaries(harness)
    assert len(summaries) == 1, summaries
    assert summaries[0].startswith(f"NodeZero manual push failed (run ID {client.run_id})")


@freeze_time(NOW)
def test_a_push_that_took_the_lease_then_failed_to_read_the_context_logs_failed(harness: Harness) -> None:
    standard_api(harness)
    NodeZeroEventCollector.fetch_events_command(make_client(), FETCH_PARAMS)
    harness.logs.clear()
    # start_push reads: the state check, the lease take, the lease read-back after the pause, then the state under the lease
    harness.store.read_failures[harness.store.reads + 4] = RuntimeError("platform error")
    with pytest.raises(RuntimeError, match="platform error"):
        NodeZeroEventCollector.nodezero_fetch_events_command(make_client(), PUSH_ARGS, FETCH_PARAMS)
    assert harness.store.lease() is None
    summaries = push_summaries(harness)
    assert len(summaries) == 1, summaries
    assert summaries[0].startswith("NodeZero manual push failed")


@freeze_time(NOW)
def test_a_push_that_loses_its_lease_or_is_interrupted_logs_failed(harness: Harness) -> None:
    standard_api(harness)
    other = {"owner": "fetch", "token": "other-run", "expires_at": harness.wall() + 600}
    harness.on_send.append(lambda events: harness.store.other_writer(lambda context: context.__setitem__(LEASE_KEY, dict(other))))
    client = make_client()
    with pytest.raises(NodeZeroEventCollector.LeaseLost):
        NodeZeroEventCollector.nodezero_fetch_events_command(client, PUSH_ARGS, NO_FETCH_PARAMS)
    summaries = push_summaries(harness)
    assert len(summaries) == 1, summaries
    assert summaries[0].startswith("NodeZero manual push failed")
    assert harness.store.lease() == other  # the other run's lease is left alone
    assert client.token_sink is None

    harness.logs.clear()
    harness.on_send.clear()
    harness.store.other_writer(lambda context: context.pop(LEASE_KEY, None))

    def interrupt(events: list[dict[str, Any]]) -> None:
        raise KeyboardInterrupt

    harness.on_send.append(interrupt)
    client = make_client()
    with pytest.raises(KeyboardInterrupt):
        NodeZeroEventCollector.nodezero_fetch_events_command(client, PUSH_ARGS, NO_FETCH_PARAMS)
    summaries = push_summaries(harness)
    assert len(summaries) == 1, summaries
    assert summaries[0].startswith("NodeZero manual push failed")
    assert harness.store.lease() is None
    assert client.token_sink is None


@freeze_time(NOW)
def test_a_push_that_fails_while_resuming_a_pentest_logs_failed(harness: Harness) -> None:
    fake = standard_api(harness)
    pentest = NodeZeroEventCollector.to_pentest(OP_A)
    harness.context[STATE_KEY] = state_payload(in_progress={"pentest": pentest, "next_page": 2, "sent": 2})
    fake.fail_page("op-a", 2, 500, '{"errors": [{"message": "boom"}]}')
    client = make_client()
    with pytest.raises(DemistoException):
        NodeZeroEventCollector.nodezero_fetch_events_command(client, PUSH_ARGS, FETCH_PARAMS)
    summaries = push_summaries(harness)
    assert len(summaries) == 1, summaries
    assert summaries[0].startswith("NodeZero manual push failed")
    assert harness.store.lease() is None
    assert client.token_sink is None


@freeze_time(NOW)
def test_a_push_stopped_by_its_time_budget_logs_finished(harness: Harness) -> None:
    fake = standard_api(harness)
    clock = FakeClock()
    fake.charge_weakness_pages(clock, 200.0)
    client = make_client(clock)
    NodeZeroEventCollector.nodezero_fetch_events_command(client, PUSH_ARGS, NO_FETCH_PARAMS)
    summaries = push_summaries(harness)
    assert len(summaries) == 1, summaries
    assert summaries[0].startswith("NodeZero manual push finished")


@freeze_time(NOW)
def test_client_logs_its_run_id_and_user_agent_once(harness: Harness) -> None:
    standard_api(harness)
    client = make_client()
    expected = f"NodeZero run ID {client.run_id}, User-Agent {UNIT_TEST_USER_AGENT}."
    assert harness.messages("debug") == [expected]  # the client logs nothing else when it is built
    NodeZeroEventCollector.fetch_events_command(client, FETCH_PARAMS)
    assert len(harness.requests_mock.request_history) == 7
    assert [message for message in harness.messages("debug") if client.run_id in message] == [expected]  # not per request


# ----- the versions in the User-Agent -----


def test_read_pack_version_prefers_the_constant_demisto_sdk_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def pack_version() -> str:
        calls.append("get_pack_version")
        return "9.9.9"

    monkeypatch.setattr(NodeZeroEventCollector, "CONSTANT_PACK_VERSION", "2.0.0", raising=False)
    monkeypatch.setattr(NodeZeroEventCollector, "get_pack_version", pack_version)
    monkeypatch.setattr(demisto, "demistoVersion", lambda: {"version": "8.9.0"})
    assert NodeZeroEventCollector.read_pack_version() == "2.0.0"
    assert make_client().identity_headers()["User-Agent"] == KNOWN_USER_AGENT
    assert calls == []  # never called: on Base packs before 1.41.4 it makes internal API calls


@pytest.mark.parametrize(("set_constant", "constant"), [(False, None), (True, ""), (True, None)], ids=["absent", "empty", "none"])
def test_read_pack_version_falls_back_to_get_pack_version(
    monkeypatch: pytest.MonkeyPatch, set_constant: bool, constant: Any
) -> None:
    if set_constant:
        monkeypatch.setattr(NodeZeroEventCollector, "CONSTANT_PACK_VERSION", constant, raising=False)
    else:
        assert not hasattr(NodeZeroEventCollector, "CONSTANT_PACK_VERSION")  # as in these tests: not unified
    monkeypatch.setattr(NodeZeroEventCollector, "get_pack_version", lambda: "2.0.0")
    monkeypatch.setattr(demisto, "demistoVersion", lambda: {"version": "8.9.0"})
    assert NodeZeroEventCollector.read_pack_version() == "2.0.0"
    assert NodeZeroEventCollector.build_user_agent() == KNOWN_USER_AGENT


@pytest.mark.parametrize(
    "error",
    [Exception("platform call failed"), TypeError("bad"), ValueError("bad"), OSError("broken pipe"), LookupError("x")],
    ids=["Exception", "TypeError", "ValueError", "OSError", "LookupError"],
)
def test_user_agent_survives_any_reader_exception(monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
    def fail() -> Any:
        raise error

    monkeypatch.setattr(NodeZeroEventCollector, "get_pack_version", fail)
    monkeypatch.setattr(demisto, "demistoVersion", fail)
    assert NodeZeroEventCollector.build_user_agent() == UNKNOWN_USER_AGENT


@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit], ids=["KeyboardInterrupt", "SystemExit"])
def test_version_text_lets_interrupts_through(error: type[BaseException]) -> None:
    def interrupted() -> Any:
        raise error

    with pytest.raises(error):
        NodeZeroEventCollector.version_text(interrupted)  # on purpose: only Exception means "unknown"


class FailingStrip(str):
    """A str subclass whose strip fails."""

    def strip(self, *args: Any) -> str:
        raise RuntimeError("strip failed")


class OddStrip(str):
    """A str subclass whose strip returns something that isn't text."""

    def strip(self, *args: Any) -> Any:
        return object()


@pytest.mark.parametrize("text_type", [FailingStrip, OddStrip])
def test_user_agent_ignores_the_strip_of_a_str_subclass(monkeypatch: pytest.MonkeyPatch, text_type: type[str]) -> None:
    monkeypatch.setattr(NodeZeroEventCollector, "get_pack_version", lambda: text_type(" 2.0.0 "))
    monkeypatch.setattr(demisto, "demistoVersion", lambda: {"version": text_type("8.9.0")})
    assert NodeZeroEventCollector.build_user_agent() == KNOWN_USER_AGENT  # str.strip trims it as plain text


def test_run_id_is_a_random_uuid4() -> None:
    client = make_client()
    assert uuid.UUID(client.run_id).version == 4  # never uuid1, which carries the host's MAC address and the time
    assert uuid.UUID(client.run_id).hex == client.run_id


def test_client_reads_the_versions_once(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def pack_version() -> str:
        calls.append("pack")
        return "2.0.0"

    def platform_version() -> dict[str, str]:
        calls.append("platform")
        return {"version": "8.9.0"}

    monkeypatch.setattr(NodeZeroEventCollector, "get_pack_version", pack_version)
    monkeypatch.setattr(demisto, "demistoVersion", platform_version)
    client = make_client()
    headers = [client.identity_headers() for _ in range(3)]
    assert calls == ["pack", "platform"]  # one platform call per client, not one per request
    assert {item["User-Agent"] for item in headers} == {KNOWN_USER_AGENT}


# ----- test-module, client construction, and main -----


@freeze_time(NOW)
def test_module_ok(harness: Harness) -> None:
    fake = standard_api(harness)
    harness.context.update(cached_token("cached-token", NOW_EPOCH + 3600))
    assert NodeZeroEventCollector.test_module(make_client(), FETCH_PARAMS) == "ok"
    assert harness.auth_calls() == 1  # always a new token, so a cached token can't hide a bad API key
    assert fake.requests_for("CortexXsiamConnectivity") == [
        {"query": NodeZeroEventCollector.CONNECTIVITY_QUERY, "variables": {"page_input": {"page_num": 1, "page_size": 1}}}
    ]
    assert fake.authorization_headers == [f"Bearer {fake.issued_tokens[0]}"]


@freeze_time(NOW)
@pytest.mark.parametrize(
    ("failures", "failed_request"),
    [
        ([("auth", 401)], 1),
        ([("auth", 403)], 1),
        ([("CortexXsiamConnectivity", 403)], 2),  # a 403 is not retried: auth was request 1
        ([("CortexXsiamConnectivity", 401), ("CortexXsiamConnectivity", 401)], 4),  # the repeat after re-authenticating
    ],
)
def test_module_auth_error_message(harness: Harness, failures: list[tuple[str, int]], failed_request: int) -> None:
    fake = standard_api(harness)
    for operation, status in failures:
        fake.queue(operation, status, {"message": "denied"})
    client = make_client()
    message = NodeZeroEventCollector.test_module(client, FETCH_PARAMS)
    # AUTH_FAILED_MESSAGE, then the X-Request-ID of the request that failed, which is the run's last request.
    assert message == f"{NodeZeroEventCollector.AUTH_FAILED_MESSAGE} Request ID: {client.run_id}-{failed_request}."
    assert harness.requests_mock.request_history[-1].headers["X-Request-ID"] == f"{client.run_id}-{failed_request}"
    assert len(harness.requests_mock.request_history) == failed_request


@pytest.mark.parametrize("status", [401, 403])
def test_module_auth_error_without_a_recorded_request_has_no_request_id(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    client = make_client()
    response = make_response(status, "Unauthorized", {"message": "denied"})  # response.request is None

    def fail() -> str:
        raise DemistoException("denied", res=response)

    monkeypatch.setattr(client, "authenticate", fail)
    assert NodeZeroEventCollector.test_module(client, NO_FETCH_PARAMS) == NodeZeroEventCollector.AUTH_FAILED_MESSAGE


def test_module_reraises_an_error_without_a_response(monkeypatch: pytest.MonkeyPatch) -> None:
    client = make_client()

    def fail() -> str:
        raise DemistoException("no response at all")  # res is None, so there is no HTTP status to call it an auth failure

    monkeypatch.setattr(client, "authenticate", fail)
    with pytest.raises(DemistoException, match="^no response at all$"):
        NodeZeroEventCollector.test_module(client, NO_FETCH_PARAMS)


@freeze_time(NOW)
def test_module_other_errors_raise(harness: Harness) -> None:
    fake = standard_api(harness)
    fake.queue("CortexXsiamConnectivity", 500, {"message": "boom"})
    with pytest.raises(DemistoException, match="HTTP 500"):
        NodeZeroEventCollector.test_module(make_client(), FETCH_PARAMS)


@freeze_time(NOW)
@pytest.mark.parametrize(
    ("error", "message"),
    [
        (requests.exceptions.ConnectionError("refused"), "Verify that the server URL parameter is correct"),
        (requests.exceptions.SSLError("bad certificate"), "SSL Certificate Verification Failed"),
    ],
)
def test_module_unreachable_or_tls_error(harness: Harness, error: Exception, message: str) -> None:
    harness.requests_mock.post(f"{BASE_URL}/v1/auth", exc=error)
    with pytest.raises(DemistoException, match=message):
        NodeZeroEventCollector.test_module(make_client(), FETCH_PARAMS)


@freeze_time(NOW)
def test_module_checks_fetch_settings_only_when_fetching(harness: Harness) -> None:
    standard_api(harness)
    with pytest.raises(DemistoException, match="positive integer"):
        NodeZeroEventCollector.test_module(make_client(), {**FETCH_PARAMS, "max_fetch": "0"})
    with pytest.raises(ValueError):
        NodeZeroEventCollector.test_module(make_client(), {**FETCH_PARAMS, "first_fetch": "not a time"})
    params = {**FETCH_PARAMS, "isFetchEvents": False, "max_fetch": "0"}
    assert NodeZeroEventCollector.test_module(make_client(), params) == "ok"


def test_parse_fetch_settings_defaults() -> None:
    with freeze_time(NOW):
        first_fetch, max_events = NodeZeroEventCollector.parse_fetch_settings({})
    assert first_fetch == datetime(2025, 3, 8, 12, 0)
    assert max_events == 10_000


def test_build_client_from_params() -> None:
    deadline = NodeZeroEventCollector.Deadline.after(180)
    client = NodeZeroEventCollector.build_client(
        {"url": " https://nodezero.example.com/ ", "credentials": {"password": API_KEY}, "insecure": True, "proxy": False},
        deadline,
    )
    assert client._base_url == BASE_URL
    assert client._verify is False
    assert client.deadline is deadline
    with pytest.raises(DemistoException, match="Server URL parameter is required"):
        NodeZeroEventCollector.build_client({"credentials": {"password": API_KEY}}, deadline)
    with pytest.raises(DemistoException, match="API Key parameter is required"):
        NodeZeroEventCollector.build_client({"url": BASE_URL, "credentials": {"password": ""}}, deadline)


def test_deadline_with_fake_clock() -> None:
    clock = FakeClock(start=50.0)
    deadline = NodeZeroEventCollector.Deadline.after(180, clock)
    clock.advance(30)
    assert deadline.seconds_left() == 150
    assert deadline.elapsed() == 30


def committed_cursors(harness: Harness) -> list[int | None]:
    """The page cursor of each distinct state committed to the integration context, in order."""
    cursors: list[int | None] = []
    previous: Any = object()
    for state in harness.store.written_states():
        if state is None or state == previous:
            continue
        previous = state
        cursors.append((state["in_progress"] or {}).get("next_page"))
    return cursors


def test_real_wall_clock_pause_and_unparsable_time(monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []
    monkeypatch.setattr(NodeZeroEventCollector.time, "sleep", slept.append)
    NodeZeroEventCollector.pause(2)
    assert slept == [2]
    with freeze_time(NOW):
        assert NodeZeroEventCollector.wall_seconds() == NOW_EPOCH
    monkeypatch.setattr(NodeZeroEventCollector, "arg_to_datetime", lambda *args, **kwargs: None)
    with pytest.raises(DemistoException, match="since is not a valid time."):
        NodeZeroEventCollector.parse_time_arg("7 days", "since")


def capture_main(monkeypatch: pytest.MonkeyPatch) -> tuple[list[Any], list[str]]:
    results: list[Any] = []
    errors: list[str] = []
    monkeypatch.setattr(NodeZeroEventCollector, "return_results", results.append)
    monkeypatch.setattr(NodeZeroEventCollector, "return_error", lambda message, *args, **kwargs: errors.append(str(message)))
    monkeypatch.setattr(demisto, "params", lambda: FETCH_PARAMS)
    return results, errors


@freeze_time(NOW)
def test_main_routes_commands(harness: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    standard_api(harness)
    results, errors = capture_main(monkeypatch)
    monkeypatch.setattr(demisto, "command", lambda: "test-module")
    NodeZeroEventCollector.main()
    assert results == ["ok"]
    monkeypatch.setattr(demisto, "command", lambda: "fetch-events")
    NodeZeroEventCollector.main()
    assert len(harness.sent_events()) == 5
    assert set(harness.last_run["sent_ops"]) == {"op-a", "op-b"}
    assert len(results) == 1  # fetch-events returns nothing to the war room
    monkeypatch.setattr(demisto, "command", lambda: "nodezero-fetch-events")
    monkeypatch.setattr(demisto, "args", lambda: {"should_push_events": "false", "limit": "2"})
    NodeZeroEventCollector.main()
    assert isinstance(results[-1], CommandResults)
    assert uuids(results[-1].raw_response) == uuids([A1, A2])
    assert errors == []


def test_main_unknown_command(harness: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    results, errors = capture_main(monkeypatch)
    monkeypatch.setattr(demisto, "command", lambda: "nodezero-unknown")
    NodeZeroEventCollector.main()
    assert results == []
    assert errors == ["Failed to execute nodezero-unknown command.\nError:\nCommand nodezero-unknown is not implemented."]


@freeze_time(NOW)
def test_main_reports_failures(harness: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = standard_api(harness)
    results, errors = capture_main(monkeypatch)
    monkeypatch.setattr(demisto, "params", lambda: {**FETCH_PARAMS, "credentials": {}})
    monkeypatch.setattr(demisto, "command", lambda: "fetch-events")
    NodeZeroEventCollector.main()
    assert errors[-1] == "Failed to execute fetch-events command.\nError:\nThe API Key parameter is required."
    monkeypatch.setattr(demisto, "params", lambda: FETCH_PARAMS)
    fake.fail_page("op-a", 1, status=502)
    NodeZeroEventCollector.main()
    assert "Failed to read page 1 of the weaknesses of pentest op-a." in errors[-1]
    assert results == []


# ----- integration YAML -----


def load_integration_yml() -> dict[str, Any]:
    return yaml.safe_load(INTEGRATION_YML.read_text())


def test_default_event_fetch_interval_is_30_and_not_advanced() -> None:
    params = {param["name"]: param for param in load_integration_yml()["configuration"]}
    interval = params["eventFetchInterval"]
    assert interval["type"] == 19
    assert interval["defaultvalue"] == "30"
    assert not interval.get("advanced", False)
    assert interval["section"] == "Collect"


def test_nodezero_fetch_events_command_declares_its_arguments_and_outputs() -> None:
    commands = {command["name"]: command for command in load_integration_yml()["script"]["commands"]}
    assert set(commands) == {"nodezero-fetch-events"}
    arguments = {argument["name"]: argument for argument in commands["nodezero-fetch-events"]["arguments"]}
    assert set(arguments) == {"should_push_events", "limit", "since", "pentest_id"}
    assert arguments["should_push_events"]["required"] is True
    assert arguments["should_push_events"]["predefined"] == ["true", "false"]
    assert arguments["should_push_events"]["defaultValue"] == "false"
    assert arguments["limit"]["defaultValue"] == str(NodeZeroEventCollector.DEFAULT_EVENT_LIST_LIMIT)
    assert arguments["since"]["defaultValue"] == NodeZeroEventCollector.DEFAULT_EVENT_LIST_SINCE
    assert not arguments["pentest_id"].get("required", False)
    assert "defaultValue" not in arguments["pentest_id"]
    outputs = [output["contextPath"] for output in commands["nodezero-fetch-events"]["outputs"]]
    assert "NodeZero.Event.event_id" in outputs
    event = build(A1)
    for path in outputs:
        prefix, _, key = path.rpartition(".")
        assert prefix == "NodeZero.Event", path
        assert key in event, path  # every declared output is a field of the events the command returns


def test_yaml_fetch_defaults_match_code() -> None:
    yml = load_integration_yml()
    params = {param["name"]: param for param in yml["configuration"]}
    assert yml["script"]["isfetchevents"] is True
    assert params["first_fetch"]["defaultvalue"] == NodeZeroEventCollector.DEFAULT_FIRST_FETCH
    assert params["max_fetch"]["defaultvalue"] == str(NodeZeroEventCollector.DEFAULT_MAX_FETCH)
    assert params["credentials"]["type"] == 9
    assert params["credentials"]["hiddenusername"] is True


# ----- modeling rule contract: no Cortex-owned identifiers, and every field the rule reads is emitted -----


def read_modeling_rule_file(path: Path) -> str:
    if not path.is_file():
        pytest.skip(f"{path.name} is not in this checkout yet.")
    return path.read_text()


CORTEX_OWNED_TARGETS = (
    r"xdm\.[a-z_]+\.agent\.",
    r"xdm\.[a-z_]+\.host\.(device_id|hardware_uuid)\b",
    r"xdm\.asset\.",
)


def test_xif_has_no_cortex_owned_targets() -> None:
    rule = re.sub(r"//[^\n]*", "", read_modeling_rule_file(XIF_PATH))  # check the mappings, not the comments
    for pattern in CORTEX_OWNED_TARGETS:
        assert re.search(pattern, rule) is None, pattern
    for nodezero_id in ("affected_asset_uuid", "affected_host_uuid"):  # NodeZero's own IDs stay raw
        assert nodezero_id not in rule


CORTEX_SYSTEM_FIELDS = {"_vendor", "_product"}  # set by Cortex from the vendor and product the events are sent with


def test_modeling_rule_schema_fields_are_emitted() -> None:
    schema = json.loads(read_modeling_rule_file(SCHEMA_PATH))
    fields = set(schema["horizon3_nodezero_raw"])
    assert fields >= CORTEX_SYSTEM_FIELDS  # the rule reads them for the observer fields, so the schema lists them
    raw_fields = fields - CORTEX_SYSTEM_FIELDS
    assert raw_fields
    for event in fixture_events():
        assert raw_fields <= set(event), sorted(raw_fields - set(event))
        assert not CORTEX_SYSTEM_FIELDS & set(event)  # the collector never sets them itself
