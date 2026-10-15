import json
from collections import Counter
from typing import Any
from unittest.mock import MagicMock
from urllib.parse import parse_qs, urlparse

import pytest
from CommonServerPython import DemistoException

import KELAMonitor
from KELAMonitor import (
    SEEN_IDS_CAP,
    Client,
    ForbiddenError,
    build_incident_name,
    clean_text,
    fetch_incidents,
    incident_list_command,
    incident_scroll_command,
    incident_to_xsoar,
    mask_card_number,
    mask_record,
    mask_secret,
    parse_incident_types,
    parse_monitor_id,
    parse_severities,
    to_epoch_seconds,
)
from KELAMonitor import (
    test_module as run_test_module,
)

BASE_URL = "https://platform.ke-la.com/api/monitor"
TOKEN = "SuperSecretToken123"
MON = 9164
DAY = 86400
NOW = 1_800_000_000  # a fixed "now" in epoch seconds


@pytest.fixture(autouse=True)
def no_rate_limit_sleep(monkeypatch):
    """The 1 req/s throttle is irrelevant for unit tests."""
    monkeypatch.setattr(KELAMonitor, "RATE_LIMIT_SECONDS", 0)


# region Fakes ---------------------------------------------------------------------------------------------------
class FakeMonitorAPI:
    """Behaves like the Monitor API as far as fetch is concerned [POSTMAN]:

    - results come NEWEST FIRST, in batches of `limit`, followed by scroll pages until `incidents` is empty,
    - from_date / to_date are in seconds and INCLUSIVE (exclusive_from / exclusive_to flags test the other case),
    - `severities` filters on the server.
    """

    def __init__(self, exclusive_from: bool = False, exclusive_to: bool = False):
        self.records: dict[tuple[int, str], list[dict[str, Any]]] = {}
        self.scrolls: dict[str, tuple[list[dict[str, Any]], int]] = {}
        self.calls: list[dict[str, Any]] = []
        self.exclusive_from = exclusive_from
        self.exclusive_to = exclusive_to
        self.forbidden_types: set[str] = set()
        self._n = 0

    def add(self, monitor_id: int, incident_type: str, incident_id: str, date_s: int, severity: int = 2, **extra: Any) -> None:
        record = {
            "id": incident_id,
            "type": incident_type,
            "incident_date": date_s,
            "severity": severity,
            "user_actions": {"read": False, "hide": False, "delete": False},
            "tags": [],
        }
        record.update(extra)
        self.records.setdefault((monitor_id, incident_type), []).append(record)

    def _page(self, rows: list[dict[str, Any]], limit: int) -> dict[str, Any]:
        batch, rest = rows[:limit], rows[limit:]
        self._n += 1
        scroll_id = f"scroll-{self._n}"
        self.scrolls[scroll_id] = (rest, limit)
        return {"incidents": batch, "scrollId": scroll_id if batch else None}

    def incidents_list(
        self,
        monitor_id,
        incident_type,
        text=None,
        limit=20,
        from_date=None,
        to_date=None,
        severities=None,
        first_appearance=False,
    ):
        if incident_type in self.forbidden_types:
            raise ForbiddenError("Forbidden [403] - You are not authorized")
        self.calls.append(
            {
                "kind": "list",
                "monitor_id": monitor_id,
                "type": incident_type,
                "limit": limit,
                "from_date": from_date,
                "to_date": to_date,
                "severities": severities,
            }
        )
        rows = []
        for r in self.records.get((monitor_id, incident_type), []):
            d = r["incident_date"]
            if from_date is not None and (d <= from_date if self.exclusive_from else d < from_date):
                continue
            if to_date is not None and (d >= to_date if self.exclusive_to else d > to_date):
                continue
            if severities and r["severity"] not in severities:
                continue
            rows.append(r)
        rows.sort(key=lambda r: (r["incident_date"], r["id"]), reverse=True)  # newest first
        return self._page(rows, limit)

    def incidents_scroll(self, monitor_id, scroll_id):
        self.calls.append({"kind": "scroll", "monitor_id": monitor_id})
        rest, limit = self.scrolls.pop(scroll_id)
        return self._page(rest, limit)


class FakeRunStore:
    """Fake getLastRun/setLastRun. The state is JSON round-tripped on every cycle, like in the real platform."""

    def __init__(self):
        self.value: dict[str, Any] = {}
        self.created: Counter = Counter()
        self.order: list[str] = []

    def cycle(
        self,
        api,
        types=("leaked_credentials",),
        max_fetch=50,
        severities=(),
        first_fetch_s=NOW - 3 * DAY,
        now_s=NOW,
        mask=True,
    ) -> list[str]:
        last_run = json.loads(json.dumps(self.value))
        next_run, incidents = fetch_incidents(
            api, MON, list(types), last_run, first_fetch_s, max_fetch, list(severities), mask, now_s
        )
        self.value = json.loads(json.dumps(next_run))
        ids = [json.loads(i["rawJSON"])["id"] for i in incidents]
        self.created.update(ids)
        self.order.extend(ids)
        return ids

    def duplicates(self) -> dict[str, int]:
        return {k: v for k, v in self.created.items() if v > 1}

    def run_until_idle(self, api, max_cycles=200, **kwargs) -> int:
        """Run cycles until two in a row create nothing; returns the number of cycles used."""
        quiet = 0
        for n in range(1, max_cycles + 1):
            quiet = quiet + 1 if not self.cycle(api, **kwargs) else 0
            if quiet >= 2:
                return n
        raise AssertionError("fetch never became idle")


# endregion


# region Helpers / client ----------------------------------------------------------------------------------------
def make_client() -> Client:
    return Client(BASE_URL, TOKEN, verify=True, proxy=False)


def test_client_incidents_list_maps_params(requests_mock):
    """
    Given: a client and a mocked GET incidents endpoint.
    When: incidents_list is called with every filter.
    Then: monitor_id goes in the path and everything else (incl. apiToken) in the query string, with the documented names.
    """
    requests_mock.get(f"{BASE_URL}/monitor_id/{MON}/incidents", json={"data": {"incidents": [], "scrollId": None}})
    make_client().incidents_list(
        MON, "leaked_credentials", text="kela", limit=5, from_date=100, to_date=200, severities=[3, 4], first_appearance=True
    )
    query = parse_qs(urlparse(requests_mock.last_request.url).query)
    assert query == {
        "incident_type": ["leaked_credentials"],
        "limit": ["5"],
        "text": ["kela"],
        "from_date": ["100"],
        "to_date": ["200"],
        "severities": ["3,4"],
        "first_appearance": ["true"],
        "apiToken": [TOKEN],
    }


def test_client_scroll_encodes_scroll_id_in_path(requests_mock):
    """
    Given: a scroll ID with characters that are special in a URL path (base64 style, ending in '=').
    When: incidents_scroll runs.
    Then: the scroll ID is percent-encoded in the path and the token is sent in the query string.
    """
    requests_mock.get(f"{BASE_URL}/monitor_id/{MON}/incidents/scroll/AbC%2B%2F%3D", json={"data": {"incidents": []}})
    result = make_client().incidents_scroll(MON, "AbC+/=")
    assert result == {"incidents": []}
    assert parse_qs(urlparse(requests_mock.last_request.url).query) == {"apiToken": [TOKEN]}


@pytest.mark.parametrize(
    "status, kwargs, expected",
    [
        (401, {"json": {"message": "You are not authorized."}}, "Authorization Error"),
        (400, {"text": "<!DOCTYPE html><html><pre>Bad Request</pre></html>"}, "Bad Request"),
        (404, {"json": {"message": "Not Found"}}, "Not Found"),
        (403, {"json": {"message": "You are not authorized"}}, "Forbidden [403] - You are not authorized"),
        (429, {"json": {"message": "rate limit exceeded"}}, "Rate limit exceeded"),
        (500, {"json": {"error_msg": "internal server error"}}, "[500] - internal server error"),
    ],
)
def test_client_error_handling_never_leaks_token(requests_mock, status, kwargs, expected):
    """
    Given: the API answers with the real error shapes (HTML 400, {message} 401, {error_msg} 500).
    When: the client call fails.
    Then: a readable DemistoException is raised and it does not contain the API token.
    """
    requests_mock.get(f"{BASE_URL}/monitor_id/{MON}/incidents", status_code=status, **kwargs)
    with pytest.raises(DemistoException) as exc:
        make_client().incidents_list(MON, "botnets")
    assert expected in str(exc.value)
    assert TOKEN not in str(exc.value)


def test_mask_secret():
    """
    Given: a message with the token raw and URL-encoded.
    When: mask_secret runs.
    Then: no variant of the token survives.
    """
    token = "a/b+c d"
    masked = mask_secret("url?apiToken=a%2Fb%2Bc%20d and a/b+c d and a%2Fb%2Bc+d", token)
    assert "a%2Fb" not in masked and "a/b+c d" not in masked
    assert mask_secret("nothing", None) == "nothing"


def test_parse_helpers():
    """
    Given: user supplied settings.
    When: they are parsed.
    Then: valid input is normalised and invalid input fails with a readable error.
    """
    assert parse_monitor_id(" 9164 ") == 9164
    with pytest.raises(DemistoException):
        parse_monitor_id("abc")
    assert parse_incident_types("botnets, leaked_credentials,botnets") == ["botnets", "leaked_credentials"]
    with pytest.raises(DemistoException):
        parse_incident_types("")
    with pytest.raises(DemistoException):
        parse_incident_types("Botnets")  # enums are lowercase
    assert parse_severities("critical, low,3") == [4, 1, 3]
    assert parse_severities([]) == []
    with pytest.raises(DemistoException):
        parse_severities("urgent")


def test_to_epoch_seconds():
    """
    Given: dates in several formats.
    When: to_epoch_seconds converts them.
    Then: the result is epoch SECONDS; 13 digit milliseconds are downgraded; junk fails.
    """
    assert to_epoch_seconds("1791290783", "d") == 1791290783
    assert to_epoch_seconds("1791290783999", "d") == 1791290783
    assert to_epoch_seconds("2026-10-03T00:00:00Z", "d") == 1790985600
    assert len(str(to_epoch_seconds("3 days", "d"))) == 10
    assert to_epoch_seconds("", "d") is None
    with pytest.raises(DemistoException):
        to_epoch_seconds("12345", "d")


def test_clean_text():
    """
    Given: a snippet with <span> highlights and HTML entities.
    When: clean_text runs.
    Then: tags are removed and entities decoded.
    """
    assert clean_text("...<span>jane.doe</span>@x.com &apos;ok&apos;...") == "...jane.doe@x.com 'ok'..."
    assert clean_text(None) == ""


# endregion


# region Masking / mapping ---------------------------------------------------------------------------------------
def test_mask_record_masks_passwords_and_cards():
    """
    Given: a leaked credential, a credit card and a botnet with a nested password.
    When: mask_record runs.
    Then: passwords become ******** at any depth and the card keeps only BIN + last 4; the input is not modified.
    """
    leak = {"type": "leaked_credentials", "email": "a@b.com", "password": "hunter2"}
    assert mask_record(leak)["password"] == "********"
    assert leak["password"] == "hunter2"
    card = {"type": "credit_cards", "number": "4111111111111111", "bin": "411111"}
    assert mask_record(card)["number"] == "411111******1111"
    bot = {"type": "botnets", "available_data": {"Password": "x", "list": [{"password": "y"}, {"user": "z"}]}}
    masked = mask_record(bot)
    assert masked["available_data"]["Password"] == "********"
    assert masked["available_data"]["list"][0]["password"] == "********"
    assert masked["available_data"]["list"][1] == {"user": "z"}
    assert mask_record({"type": "leaked_credentials", "password": None})["password"] is None
    assert mask_card_number("12345") == "*****"


def test_incident_to_xsoar_mapping_and_masking():
    """
    Given: a leaked-credentials incident with a password and a card incident with a full number.
    When: they are mapped with masking on and off.
    Then: occurred comes from incident_date (seconds), severity is kept, the name never has secrets and rawJSON obeys the flag.
    """
    leak = {
        "id": "abc",
        "type": "leaked_credentials",
        "incident_date": 1791161538,
        "severity": 3,
        "email": "jane@example.com",
        "password": "hunter2",
    }
    masked = incident_to_xsoar(leak, mask=True)
    assert masked["name"] == "KELA Monitor - leaked_credentials: jane@example.com [abc]"
    assert masked["occurred"] == "2026-10-05T00:52:18Z"
    assert masked["severity"] == 3
    assert json.loads(masked["rawJSON"])["password"] == "********"
    assert "hunter2" not in json.dumps(masked)
    clear = incident_to_xsoar(leak, mask=False)
    assert json.loads(clear["rawJSON"])["password"] == "hunter2"
    assert "hunter2" not in clear["name"]

    card = {"id": "c1", "type": "credit_cards", "incident_date": 1, "severity": 4, "number": "4111111111111111", "bin": "411111"}
    mapped = incident_to_xsoar(card, mask=True)
    assert "4111111111111111" not in json.dumps(mapped)
    assert mapped["name"].startswith("KELA Monitor - credit_cards: Credit card 411111...1111")


@pytest.mark.parametrize(
    "record, expected_core",
    [
        ({"type": "hacking_discussions", "title": "Site hacked"}, "Site hacked"),
        ({"type": "instant_messaging", "chat_name": "Chan", "snippet": "<span>hi</span> there"}, "Chan: hi there"),
        ({"type": "network_vulnerabilities", "ip": "1.2.3.4", "port": 22, "description": "Open SSH"}, "1.2.3.4:22 Open SSH"),
        ({"type": "botnets", "username": "bob", "resource": "mail.example.com"}, "bob @ mail.example.com"),
    ],
)
def test_build_incident_name_per_type(record, expected_core):
    """
    Given: incidents of each type.
    When: the XSOAR name is built.
    Then: it uses the type-specific field and ends with the incident ID.
    """
    name = build_incident_name({"id": "X1", **record})
    assert name == f"KELA Monitor - {record['type']}: {expected_core} [X1]"


# endregion


# region Commands ------------------------------------------------------------------------------------------------
def test_incident_list_command_payload_mapping():
    """
    Given: command arguments using every filter and a scroll ID in the response.
    When: kela-monitor-incident-list runs.
    Then: the client receives the documented parameters (severities as 1-4, dates in seconds), the incidents are masked and
          a second result carries the scroll ID.
    """
    client = MagicMock()
    client.incidents_list.return_value = {
        "incidents": [{"id": "i1", "type": "leaked_credentials", "incident_date": 1791161538, "severity": 3, "password": "pw"}],
        "scrollId": "SCROLL",
    }
    args = {
        "incident_type": "leaked_credentials",
        "text": "kela",
        "severities": "critical,high",
        "from_date": "1791000000000",
        "to_date": "1791161538",
        "first_appearance": "true",
        "limit": "5",
    }
    results = incident_list_command(client, args, MON, mask=True)
    client.incidents_list.assert_called_once_with(
        MON,
        "leaked_credentials",
        text="kela",
        limit=5,
        from_date=1791000000,
        to_date=1791161538,
        severities=[4, 3],
        first_appearance=True,
    )
    assert results[0].outputs_prefix == "KELA.Monitor.Incident"
    assert results[0].outputs_key_field == "id"
    assert results[0].outputs[0]["password"] == "********"
    assert results[1].outputs_prefix == "KELA.Monitor.Scroll"
    assert results[1].outputs["scrollId"] == "SCROLL"
    assert "pw" not in json.dumps(results[0].raw_response)


def test_incident_list_command_defaults_and_no_scroll():
    """
    Given: only the mandatory incident_type and a response without scrollId.
    When: the command runs.
    Then: default limit is 20, monitor comes from the instance and only one result is returned.
    """
    client = MagicMock()
    client.incidents_list.return_value = {"incidents": [], "scrollId": None}
    results = incident_list_command(client, {"incident_type": "botnets"}, MON, mask=False)
    client.incidents_list.assert_called_once_with(
        MON, "botnets", text=None, limit=20, from_date=None, to_date=None, severities=[], first_appearance=False
    )
    assert len(results) == 1


@pytest.mark.parametrize("args", [{}, {"incident_type": "Botnets"}, {"incident_type": "botnets", "severities": "urgent"},
    {"incident_type": "botnets", "limit": "1001"}, {"incident_type": "botnets", "limit": "0"}])
def test_incident_list_command_rejects_bad_input(args):
    """
    Given: a missing or wrongly cased incident_type, or an unknown severity.
    When: the command runs.
    Then: it fails locally, before any request.
    """
    client = MagicMock()
    with pytest.raises(DemistoException):
        incident_list_command(client, args, MON, mask=True)
    client.incidents_list.assert_not_called()


def test_incident_scroll_command():
    """
    Given: a scroll ID.
    When: kela-monitor-incident-scroll runs, first with data and then with an empty page.
    Then: the client is called with the scroll ID; an empty page says there is nothing more.
    """
    client = MagicMock()
    client.incidents_scroll.return_value = {
        "incidents": [{"id": "i2", "type": "botnets", "incident_date": 5}],
        "scrollId": "NEXT",
    }
    results = incident_scroll_command(client, {"scroll_id": "S1"}, MON, mask=True)
    client.incidents_scroll.assert_called_once_with(MON, "S1")
    assert results[0].outputs[0]["id"] == "i2" and results[1].outputs["scrollId"] == "NEXT"
    client.incidents_scroll.return_value = {"incidents": [], "scrollId": None}
    empty = incident_scroll_command(client, {"scroll_id": "S2"}, MON, mask=True)
    assert "No more incidents" in empty[0].readable_output
    with pytest.raises(DemistoException):
        incident_scroll_command(client, {}, MON, mask=True)


def test_module_success_and_fetch_validation():
    """
    Given: a client that answers correctly.
    When: test-module runs.
    Then: it returns 'ok' after a limit=1 probe of the first selected type; with fetch enabled and no types it fails.
    """
    client = MagicMock()
    client.incidents_list.return_value = {"incidents": []}
    params = {"isFetch": True, "incident_types": ["botnets"], "first_fetch": "3 days", "max_fetch": "50"}
    assert run_test_module(client, MON, ["botnets"], params) == "ok"
    assert client.incidents_list.call_args.kwargs["limit"] == 1 and client.incidents_list.call_args.args[1] == "botnets"
    with pytest.raises(DemistoException, match="at least one"):
        run_test_module(client, MON, [], {"isFetch": True, "incident_types": []})
    with pytest.raises(DemistoException, match="max_fetch"):
        run_test_module(client, MON, ["botnets"], {**params, "max_fetch": "9999"})


def test_module_forbidden_types():
    """
    Given: the API answers 403 for some selected types, then for all of them.
    When: test-module runs.
    Then: partial access names the forbidden types; no access to any type fails with a clear error.
    """
    client = MagicMock()

    def partial(monitor_id, incident_type, limit=1):
        if incident_type == "botnets":
            raise ForbiddenError("Forbidden [403]")
        return {"incidents": []}

    client.incidents_list.side_effect = partial
    out = run_test_module(client, MON, ["leaked_credentials", "botnets"], {})
    assert out != "ok" and "botnets" in out and "leaked_credentials" not in out
    client.incidents_list.side_effect = ForbiddenError("Forbidden [403]")
    with pytest.raises(DemistoException, match="no access to this Monitor"):
        run_test_module(client, MON, ["leaked_credentials", "botnets"], {})


def test_module_authorization_and_other_failures():
    """
    Given: the API rejects the token, then answers 500.
    When: test-module runs.
    Then: a readable authorization message is returned; other errors propagate.
    """
    client = MagicMock()
    client.incidents_list.side_effect = DemistoException("Authorization Error: make sure the API Token is correct")
    assert "Authorization Error" in run_test_module(client, MON, [], {})
    client.incidents_list.side_effect = DemistoException("Error in API call [500] - x")
    with pytest.raises(DemistoException, match="500"):
        run_test_module(client, MON, [], {})


# endregion


# region Fetch ---------------------------------------------------------------------------------------------------
def test_fetch_no_duplicates_after_many_idle_cycles():
    """
    Given: incidents of two types, newest first, and an inclusive from_date.
    When: fetch runs 30 cycles with no new data.
    Then: each incident is created exactly once and idle cycles create nothing.
    """
    api, store = FakeMonitorAPI(), FakeRunStore()
    types = ("leaked_credentials", "botnets")
    for i, ts in enumerate([NOW - 2 * DAY, NOW - DAY, NOW - 3600]):
        api.add(MON, "leaked_credentials", f"l{i}", ts)
        api.add(MON, "botnets", f"b{i}", ts)
    assert sorted(store.cycle(api, types=types)) == ["b0", "b1", "b2", "l0", "l1", "l2"]
    for _ in range(30):
        assert store.cycle(api, types=types) == []
    assert store.duplicates() == {}
    assert sum(store.created.values()) == 6


def test_fetch_new_records_picked_up_exactly_once():
    """
    Given: a first cycle already done.
    When: new incidents appear later (including after idle cycles).
    Then: each is fetched exactly once.
    """
    api, store = FakeMonitorAPI(), FakeRunStore()
    api.add(MON, "leaked_credentials", "a", NOW - 7200)
    store.cycle(api)
    store.cycle(api)
    api.add(MON, "leaked_credentials", "b", NOW - 3600)
    assert store.cycle(api) == ["b"]
    assert store.cycle(api) == []
    api.add(MON, "leaked_credentials", "c", NOW - 1800)
    api.add(MON, "leaked_credentials", "d", NOW - 900)
    assert store.cycle(api) == ["c", "d"]
    for _ in range(5):
        assert store.cycle(api) == []
    assert store.duplicates() == {}


def test_fetch_records_sharing_the_watermark_second():
    """
    Given: several incidents with exactly the same second (typical of botnet dumps).
    When: a late incident with that same second shows up after the group was fetched.
    Then: only the late one is created.
    """
    api, store = FakeMonitorAPI(), FakeRunStore()
    for name in ("a", "b", "c"):
        api.add(MON, "botnets", name, NOW - 600)
    assert sorted(store.cycle(api, types=("botnets",))) == ["a", "b", "c"]
    assert store.cycle(api, types=("botnets",)) == []
    api.add(MON, "botnets", "d", NOW - 600)
    assert store.cycle(api, types=("botnets",)) == ["d"]
    assert store.cycle(api, types=("botnets",)) == []
    assert store.duplicates() == {}


def test_fetch_backlog_larger_than_max_fetch_is_oldest_first_and_loses_nothing():
    """
    Given: 10 incidents with different dates and a same-second group of 4 on top, and max_fetch=3,
           while the API answers newest first.
    When: fetch runs until idle.
    Then: incidents are created oldest first, none is lost and none is duplicated (newest-first order cannot cause gaps).
    """
    api, store = FakeMonitorAPI(), FakeRunStore()
    for i in range(10):
        api.add(MON, "leaked_credentials", f"r{i:02d}", NOW - 5000 + i * 100)
    for j in range(4):
        api.add(MON, "leaked_credentials", f"g{j}", NOW - 3000)
    store.run_until_idle(api, max_fetch=3)
    assert store.duplicates() == {}
    assert set(store.created) == {f"r{i:02d}" for i in range(10)} | {f"g{j}" for j in range(4)}
    dates = {r["id"]: r["incident_date"] for r in api.records[(MON, "leaked_credentials")]}
    emitted_dates = [dates[i] for i in store.order]
    assert emitted_dates == sorted(emitted_dates)


def test_fetch_windowed_backfill_crosses_empty_windows():
    """
    Given: a first_fetch 40 days back with incidents far apart.
    When: fetch runs until idle.
    Then: empty past windows are crossed within the cycle's call budget, every incident is created once, and no cycle
          exceeds the per-stream call budget.
    """
    api, store = FakeMonitorAPI(), FakeRunStore()
    for name, days_ago in (("old", 39), ("mid", 15), ("recent", 1)):
        api.add(MON, "leaked_credentials", name, NOW - days_ago * DAY)
    cycles = 0
    for _ in range(30):
        before = len(api.calls)
        store.cycle(api, first_fetch_s=NOW - 40 * DAY)
        assert len(api.calls) - before <= KELAMonitor.MAX_CALLS_PER_STREAM
        cycles += 1
        if set(store.created) == {"old", "mid", "recent"} and not store.cycle(api, first_fetch_s=NOW - 40 * DAY):
            break
    assert store.order == ["old", "mid", "recent"]
    assert store.duplicates() == {}
    assert cycles <= 4


def test_fetch_window_is_halved_when_it_cannot_be_read(monkeypatch):
    """
    Given: a window with more incidents than the call budget can read (tiny page size and budget).
    When: fetch runs until idle.
    Then: the window shrinks, nothing is created from a partially read window, and every incident ends up created exactly once.
    """
    monkeypatch.setattr(KELAMonitor, "PAGE_LIMIT", 2)
    monkeypatch.setattr(KELAMonitor, "MAX_CALLS_PER_STREAM", 3)
    api, store = FakeMonitorAPI(), FakeRunStore()
    for i in range(12):
        api.add(MON, "leaked_credentials", f"x{i:02d}", NOW - 20000 + i * 1500)
    windows_seen = set()
    for _ in range(200):
        store.cycle(api, first_fetch_s=NOW - 25000)
        windows_seen.add(store.value["streams"][f"{MON}:leaked_credentials"]["window"])
        if len(store.created) == 12:
            break
    assert min(windows_seen) < KELAMonitor.WINDOW_MAX_SECONDS
    assert set(store.created) == {f"x{i:02d}" for i in range(12)}
    assert store.duplicates() == {}


@pytest.mark.parametrize("exclusive_from, exclusive_to", [(True, False), (False, True), (True, True)])
def test_fetch_is_safe_whatever_the_date_boundaries_do(exclusive_from, exclusive_to):
    """
    Given: an API whose from_date and/or to_date are exclusive instead of inclusive (the spec does not say).
    When: fetch runs over incidents placed exactly on window boundaries and on the watermark second.
    Then: nothing is lost and nothing is duplicated.
    """
    api, store = FakeMonitorAPI(exclusive_from=exclusive_from, exclusive_to=exclusive_to), FakeRunStore()
    start = NOW - 10 * DAY
    for i, ts in enumerate([start, start + 1, start + DAY, start + DAY + 1, start + 2 * DAY - 1, start + 2 * DAY, NOW - 3600]):
        api.add(MON, "botnets", f"e{i}", ts)
    store.run_until_idle(api, types=("botnets",), first_fetch_s=start - 5)
    api.add(MON, "botnets", "late", NOW - 3600)  # same second as the last one, arrives later
    store.run_until_idle(api, types=("botnets",), first_fetch_s=start - 5)
    assert set(store.created) == {f"e{i}" for i in range(7)} | {"late"}
    assert store.duplicates() == {}


def test_fetch_record_one_second_before_the_watermark_is_not_repeated():
    """
    Given: two incidents one second apart at the live edge (the request always starts 1s before the watermark).
    When: fetch runs several cycles.
    Then: the older one, which is returned again by the 1s overlap, is not created twice.
    """
    api, store = FakeMonitorAPI(), FakeRunStore()
    api.add(MON, "botnets", "first", NOW - 3601)
    api.add(MON, "botnets", "second", NOW - 3600)
    assert store.cycle(api, types=("botnets",)) == ["first", "second"]
    for _ in range(3):
        assert store.cycle(api, types=("botnets",)) == []
    assert store.duplicates() == {}


def test_fetch_state_without_id_list_is_upgraded():
    """
    Given: a stored state with only a watermark (no seen_ids).
    When: the first cycle runs.
    Then: incidents on the watermark second are assumed ingested, newer ones are created, and the state now has the ID list.
    """
    api, store = FakeMonitorAPI(), FakeRunStore()
    api.add(MON, "botnets", "old", NOW - 7200)
    api.add(MON, "botnets", "new", NOW - 3600)
    store.value = {"streams": {f"{MON}:botnets": {"watermark": NOW - 7200}}}
    assert store.cycle(api, types=("botnets",)) == ["new"]
    state = store.value["streams"][f"{MON}:botnets"]
    assert state["watermark"] == NOW - 3600 and state["seen_ids"] == ["new"]
    assert store.cycle(api, types=("botnets",)) == []


def test_fetch_hidden_and_deleted_incidents_are_skipped_but_advance_the_watermark():
    """
    Given: incidents hidden or deleted by a user in KELA, the newest being hidden.
    When: fetch runs.
    Then: they are not created, the watermark moves past them and they are not re-read as new.
    """
    api, store = FakeMonitorAPI(), FakeRunStore()
    api.add(MON, "leaked_credentials", "ok", NOW - 3 * 3600)
    api.add(MON, "leaked_credentials", "hid", NOW - 2 * 3600, user_actions={"hide": True, "delete": False})
    api.add(MON, "leaked_credentials", "del", NOW - 3600, user_actions={"hide": False, "delete": True})
    assert store.cycle(api) == ["ok"]
    assert store.value["streams"][f"{MON}:leaked_credentials"]["watermark"] == NOW - 3600
    assert store.cycle(api) == []
    last_list = [c for c in api.calls if c["kind"] == "list"][-1]
    assert last_list["from_date"] == NOW - 3600 - 1


def test_fetch_passes_severity_filter_to_the_api():
    """
    Given: a severity filter of critical and high.
    When: fetch runs.
    Then: the API is asked for severities [4, 3] and only those are created.
    """
    api, store = FakeMonitorAPI(), FakeRunStore()
    api.add(MON, "botnets", "low", NOW - 3000, severity=1)
    api.add(MON, "botnets", "crit", NOW - 2000, severity=4)
    assert store.cycle(api, types=("botnets",), severities=[4, 3]) == ["crit"]
    assert api.calls[0]["severities"] == [4, 3]


def test_fetch_unselected_type_keeps_its_state_and_types_are_independent():
    """
    Given: two incident types fetched, then one is unselected for a while.
    When: it is selected again.
    Then: its state was preserved, it resumes without duplicates, and each type kept its own watermark.
    """
    api, store = FakeMonitorAPI(), FakeRunStore()
    api.add(MON, "botnets", "b1", NOW - 5000)
    api.add(MON, "leaked_credentials", "l1", NOW - 4000)
    assert sorted(store.cycle(api, types=("botnets", "leaked_credentials"))) == ["b1", "l1"]
    streams = store.value["streams"]
    assert streams[f"{MON}:botnets"]["watermark"] == NOW - 5000
    assert streams[f"{MON}:leaked_credentials"]["watermark"] == NOW - 4000
    saved = json.loads(json.dumps(streams[f"{MON}:leaked_credentials"]))

    api.add(MON, "botnets", "b2", NOW - 3000)
    api.add(MON, "leaked_credentials", "l2", NOW - 2000)
    assert store.cycle(api, types=("botnets",)) == ["b2"]
    assert store.value["streams"][f"{MON}:leaked_credentials"] == saved
    assert store.cycle(api, types=("botnets", "leaked_credentials")) == ["l2"]
    assert store.duplicates() == {}


def test_fetch_first_run_without_data_is_stable():
    """
    Given: an empty monitor.
    When: the first cycles run.
    Then: the watermark stays at first_fetch (nothing is skipped) and nothing is created.
    """
    api, store = FakeMonitorAPI(), FakeRunStore()
    first = NOW - 3600
    assert store.cycle(api, first_fetch_s=first) == []
    assert store.value["streams"][f"{MON}:leaked_credentials"]["watermark"] == first
    api.add(MON, "leaked_credentials", "n", first + 10)
    assert store.cycle(api, first_fetch_s=first) == ["n"]


def test_fetch_caps_the_stored_id_list():
    """
    Given: more same-second incidents than SEEN_IDS_CAP.
    When: fetch runs enough cycles.
    Then: the stored list never exceeds the cap.
    """
    api, store = FakeMonitorAPI(), FakeRunStore()
    for i in range(SEEN_IDS_CAP + 30):
        api.add(MON, "botnets", f"id{i:04d}", NOW - 600)
    for _ in range(4):
        store.cycle(api, types=("botnets",), max_fetch=200)
        assert len(store.value["streams"][f"{MON}:botnets"]["seen_ids"]) <= SEEN_IDS_CAP


def test_fetch_failure_does_not_save_partial_state():
    """
    Given: the second selected type fails.
    When: fetch_incidents raises.
    Then: nothing is returned, so the platform keeps the previous last run and retries cleanly.
    """
    api = FakeMonitorAPI()
    api.add(MON, "botnets", "a", NOW - 3000)
    original = api.incidents_list

    def flaky(monitor_id, incident_type, **kwargs):
        if incident_type == "leaked_credentials":
            raise DemistoException("boom")
        return original(monitor_id, incident_type, **kwargs)

    api.incidents_list = flaky  # type: ignore[method-assign]
    with pytest.raises(DemistoException):
        fetch_incidents(api, MON, ["botnets", "leaked_credentials"], {}, NOW - DAY, 50, [], True, NOW)


def test_fetch_masks_sensitive_data_in_created_incidents():
    """
    Given: a leaked credential with a password.
    When: fetch runs with masking on (default) and off.
    Then: the created incident's rawJSON follows the flag.
    """
    for mask, expected in ((True, "********"), (False, "hunter2")):
        api = FakeMonitorAPI()
        api.add(MON, "leaked_credentials", "p", NOW - 3000, email="a@b.com", password="hunter2")
        last_run, incidents = fetch_incidents(api, MON, ["leaked_credentials"], {}, NOW - DAY, 50, [], mask, NOW)
        assert json.loads(incidents[0]["rawJSON"])["password"] == expected
        assert last_run["streams"]


def test_fake_api_reproduces_the_duplicate_bug_without_dedup():
    """
    Given: the same FakeMonitorAPI and a NAIVE fetch (watermark only, re-requesting from the watermark, no seen IDs).
    When: it runs three cycles with no new data.
    Then: it re-creates the watermark incident every cycle. This proves the fake is faithful to the real bug and that the
          regression tests above are meaningful.
    """
    api = FakeMonitorAPI()
    api.add(MON, "botnets", "a", NOW - 7200)
    api.add(MON, "botnets", "b", NOW - 3600)
    watermark, created = NOW - DAY, Counter()
    for _ in range(3):
        rows = api.incidents_list(MON, "botnets", from_date=watermark, limit=100)["incidents"]
        for row in rows:
            created[row["id"]] += 1
            watermark = max(watermark, row["incident_date"])
    assert created["b"] == 3  # duplicated every cycle

def test_fetch_skips_forbidden_type_and_keeps_the_others():
    """
    Given: the token has no access to botnets, but does to leaked_credentials, and both have incidents.
    When: several cycles run.
    Then: leaked_credentials is fetched once with no duplicates, botnets never errors the cycle and never creates state.
    """
    api, store = FakeMonitorAPI(), FakeRunStore()
    api.forbidden_types = {"botnets"}
    for i in range(3):
        api.add(MON, "leaked_credentials", f"lc{i}", NOW - 1000 + i)
        api.add(MON, "botnets", f"bn{i}", NOW - 1000 + i)
    store.run_until_idle(api, types=("botnets", "leaked_credentials"))
    assert sorted(store.created) == ["lc0", "lc1", "lc2"]
    assert not store.duplicates()
    assert list(store.value["streams"]) == [f"{MON}:leaked_credentials"]


def test_fetch_forbidden_type_resumes_from_its_old_position_when_access_returns():
    """
    Given: botnets was fetched, then lost access for a while, then got it back with new incidents meanwhile.
    When: the cycles continue.
    Then: nothing already fetched is repeated and the incidents created during the gap arrive once.
    """
    api, store = FakeMonitorAPI(), FakeRunStore()
    api.add(MON, "botnets", "b0", NOW - 5000)
    store.run_until_idle(api, types=("botnets", "leaked_credentials"))
    saved = json.dumps(store.value["streams"][f"{MON}:botnets"])
    api.forbidden_types = {"botnets"}
    api.add(MON, "botnets", "b1", NOW - 3000)
    api.add(MON, "leaked_credentials", "l0", NOW - 2000)
    store.run_until_idle(api, types=("botnets", "leaked_credentials"))
    assert json.dumps(store.value["streams"][f"{MON}:botnets"]) == saved
    api.forbidden_types = set()
    store.run_until_idle(api, types=("botnets", "leaked_credentials"))
    assert sorted(store.created) == ["b0", "b1", "l0"]
    assert not store.duplicates()


def test_fetch_all_types_forbidden_raises_without_changing_state():
    """
    Given: every selected type answers 403 (no access to the Monitor).
    When: a cycle runs.
    Then: it raises a clear error and the saved state is untouched.
    """
    api, store = FakeMonitorAPI(), FakeRunStore()
    api.add(MON, "botnets", "b0", NOW - 100)
    store.run_until_idle(api, types=("botnets",))
    before = json.dumps(store.value)
    api.forbidden_types = {"botnets", "leaked_credentials"}
    with pytest.raises(DemistoException, match="no access to this Monitor"):
        store.cycle(api, types=("botnets", "leaked_credentials"))
    assert json.dumps(store.value) == before


def test_fetch_other_errors_still_abort_the_whole_cycle():
    """
    Given: one type fails with a non-403 error.
    When: a cycle runs.
    Then: the error propagates (all-or-nothing for non-403 failures).
    """
    api, store = FakeMonitorAPI(), FakeRunStore()
    api.add(MON, "leaked_credentials", "l0", NOW - 100)
    real = api.incidents_list

    def failing(monitor_id, incident_type, **kw):
        if incident_type == "botnets":
            raise DemistoException("Error in API call [500] - boom")
        return real(monitor_id, incident_type, **kw)

    api.incidents_list = failing
    with pytest.raises(DemistoException, match="500"):
        store.cycle(api, types=("leaked_credentials", "botnets"))
    assert store.value == {}



# endregion
