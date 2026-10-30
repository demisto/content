import json
import os
import random
import re
import time
from collections import Counter
from datetime import UTC, datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock
from urllib.parse import parse_qs, urlparse

import pytest
import requests
from CommonServerPython import DemistoException
from dateparser.freshness_date_parser import FreshnessDateDataParser
from pytest_mock import MockerFixture

import KELAMonitor
from KELAMonitor import (
    SEEN_IDS_CAP,
    Client,
    ForbiddenError,
    build_incident_name,
    clean_text,
    epoch_to_iso,
    fetch_incidents,
    incident_list_command,
    incident_scroll_command,
    incident_to_xsoar,
    mask_card_number,
    mask_record,
    mask_secret,
    parse_incident_types,
    parse_max_fetch,
    parse_monitor_id,
    parse_severities,
    to_epoch_seconds,
)
from KELAMonitor import (
    test_module as run_test_module,
)

BASE_URL = "https://platform.ke-la.com/api/monitor"
TOKEN = "test-token-not-real"
MON = 9164
DAY = 86400
NOW = 1_800_000_000  # a fixed "now" in epoch seconds


# Stage 10 (A3-MON-07): the client no longer throttles with time.sleep, so the autouse fixture that disabled the throttle
# (it patched RATE_LIMIT_SECONDS) was removed. test_stage10_fetch_never_sleeps pins the new behaviour.


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
    Then: monitor_id goes in the path, the filters go in the query string with the documented names, and the token
          travels only in the apiToken header (A5b-MON-02: header option documented by the KELA Monitor API; the B0
          assertion that the token is in the query string was replaced because that behaviour was removed on purpose).
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
    }
    assert requests_mock.last_request.headers["apiToken"] == TOKEN
    assert TOKEN not in requests_mock.last_request.url


def test_client_scroll_encodes_scroll_id_in_path(requests_mock):
    """
    Given: a scroll ID with characters that are special in a URL path (base64 style, ending in '=').
    When: incidents_scroll runs.
    Then: the scroll ID is percent-encoded in the path and the token is sent in the apiToken header, not in the URL.
    """
    requests_mock.get(f"{BASE_URL}/monitor_id/{MON}/incidents/scroll/AbC%2B%2F%3D", json={"data": {"incidents": []}})
    result = make_client().incidents_scroll(MON, "AbC+/=")
    assert result == {"incidents": []}
    assert parse_qs(urlparse(requests_mock.last_request.url).query) == {}
    assert requests_mock.last_request.headers["apiToken"] == TOKEN


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
    assert "a%2Fb" not in masked
    assert "a/b+c d" not in masked
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
    assert clean_text("...<span>jane.doe</span>@example.com &apos;ok&apos;...") == "...jane.doe@example.com 'ok'..."
    assert clean_text(None) == ""


# endregion


# region Masking / mapping ---------------------------------------------------------------------------------------
def test_mask_record_masks_passwords_and_cards():
    """
    Given: a leaked credential, a credit card and a botnet with a nested password.
    When: mask_record runs.
    Then: passwords become ******** at any depth and the card keeps only BIN + last 4; the input is not modified.
    """
    leak = {"type": "leaked_credentials", "email": "user@example.com", "password": "hunter2"}
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
          Stage 10 (A5b-MON-04): with masking on the name shows the email as j***@example.com; B0 expected the clear
          email, which was changed on purpose. With masking off the clear email is kept.
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
    assert masked["name"] == "KELA Monitor - leaked_credentials: j***@example.com [abc]"
    assert masked["occurred"] == "2026-10-05T00:52:18Z"
    assert masked["severity"] == 3
    assert json.loads(masked["rawJSON"])["password"] == "********"
    assert "hunter2" not in json.dumps(masked)
    clear = incident_to_xsoar(leak, mask=False)
    assert json.loads(clear["rawJSON"])["password"] == "hunter2"
    assert "hunter2" not in clear["name"]
    assert clear["name"] == "KELA Monitor - leaked_credentials: jane@example.com [abc]"

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


@pytest.mark.parametrize(
    "args",
    [
        {},
        {"incident_type": "Botnets"},
        {"incident_type": "botnets", "severities": "urgent"},
        {"incident_type": "botnets", "limit": "1001"},
        {"incident_type": "botnets", "limit": "0"},
    ],
)
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
    assert results[0].outputs[0]["id"] == "i2"
    assert results[1].outputs["scrollId"] == "NEXT"
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
    assert client.incidents_list.call_args.kwargs["limit"] == 1
    assert client.incidents_list.call_args.args[1] == "botnets"
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
    assert out != "ok"
    assert "botnets" in out
    assert "leaked_credentials" not in out
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


def test_fetch_state_without_id_list_starts_with_an_empty_list():
    """
    A3-MON-16 (replaces the B0 test of the seen_ids=None upgrade path, which was removed on purpose).
    Given: a stored state with only a watermark (no seen_ids key).
    When: the first cycle runs.
    Then: the state is read with an empty ID list, newer incidents are created once and the state now has the ID list.
    """
    api, store = FakeMonitorAPI(), FakeRunStore()
    api.add(MON, "botnets", "new", NOW - 3600)
    store.value = {"streams": {f"{MON}:botnets": {"watermark": NOW - 7200}}}
    assert store.cycle(api, types=("botnets",)) == ["new"]
    state = store.value["streams"][f"{MON}:botnets"]
    assert state["watermark"] == NOW - 3600
    assert state["seen_ids"] == ["new"]
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
        api.add(MON, "leaked_credentials", "p", NOW - 3000, email="user@example.com", password="hunter2")
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


# region Mission 05c additions -----------------------------------------------------------------------------------
# Cortex test-suite audit of B0. Tests whose docstring names an A5c-MON-NN id expose a B0 defect and are expected to
# fail on B0; every other test documents current B0 behaviour and passes.
MISSION_TOKEN = "test-api-key"
INTEGRATION_DIR = os.path.dirname(os.path.abspath(__file__))
MISSION_PARAMS = {
    "url": BASE_URL,
    "credentials": {"password": MISSION_TOKEN},
    "monitor_id": str(MON),
    "incident_types": ["hacking_discussions"],
    "first_fetch": "2026-01-01T00:00:00Z",
    "max_fetch": "50",
    "mask_sensitive_data": True,
}


def util_load_json(name: str) -> dict[str, Any]:
    with open(os.path.join(INTEGRATION_DIR, "test_data", name), encoding="utf-8") as f:
        return json.load(f)


def util_read_text(name: str) -> str:
    with open(os.path.join(INTEGRATION_DIR, name), encoding="utf-8") as f:
        return f.read()


def _yaml_context_paths() -> dict[str, list[str]]:
    paths: dict[str, list[str]] = {}
    current = None
    for line in util_read_text("KELAMonitor.yml").splitlines():
        command = re.match(r"^  - name: (\S+)$", line)
        if command:
            current = command.group(1)
            paths[current] = []
        path = re.match(r"^    - contextPath: (\S+)$", line)
        if path and current:
            paths[current].append(path.group(1))
    return paths


def _yaml_param_displays() -> list[str]:
    displays = []
    for line in util_read_text("KELAMonitor.yml").splitlines():
        match = re.match(r"^- (?:display|displaypassword): (.+)$", line) or re.match(
            r"^  (?:display|displaypassword): (.+)$", line
        )
        if match:
            displays.append(match.group(1).strip().strip("'\""))
    return displays


@pytest.fixture
def non_utc_local_timezone(monkeypatch):
    """Run the test as if the engine's local timezone were UTC+9 (POSIX TZ string, no tzdata needed)."""
    monkeypatch.setenv("TZ", "JST-9")
    if hasattr(time, "tzset"):
        time.tzset()
    monkeypatch.setattr(FreshnessDateDataParser, "get_local_tz", lambda self: timezone(timedelta(hours=9)))
    yield
    monkeypatch.undo()
    if hasattr(time, "tzset"):
        time.tzset()


@pytest.mark.parametrize(
    "severity, expected",
    [(1, 1), (2, 2), (3, 3), (4, 4), ("3", 3), ("critical", 4), (0, 1), (5, 1), (None, 1), ("urgent", 1)],
)
def test_mission_severity_maps_the_monitor_scale(severity, expected):
    """
    Given: each value of the Monitor severity scale (1 low .. 4 critical), its string and label forms and out-of-scale
           values.
    When: the incident is mapped for fetch.
    Then: 1-4 map to the same IncidentSeverity and anything else becomes LOW (1).
          Stage 10 (A3-MON-15, A6-MON-09): B0 pinned "3" -> 0 and unknown -> 0 (Unknown); the approved items accept the
          string form and default to LOW as the Cortex fetching-incidents doc recommends, so the expected values changed.
    """
    record = {"id": "x", "type": "hacking_discussions", "incident_date": 1767225600, "severity": severity}
    assert incident_to_xsoar(record, mask=True)["severity"] == expected


@pytest.mark.parametrize("seconds, expected", [(0, "1970-01-01T00:00:00Z"), (1767225600, "2026-01-01T00:00:00Z")])
def test_mission_occurred_is_iso_utc(seconds, expected):
    """
    Given: incident_date in epoch seconds.
    When: the incident is mapped.
    Then: occurred is the ISO 8601 UTC string with a 'Z' suffix.
    """
    assert epoch_to_iso(seconds) == expected
    record = {"id": "x", "type": "hacking_discussions", "incident_date": seconds, "severity": 2}
    assert incident_to_xsoar(record, mask=True)["occurred"] == expected


@pytest.mark.parametrize("value", ["3 days", "2026-10-01T00:00:00"])
def test_mission_first_fetch_window_is_utc_whatever_the_local_timezone(non_utc_local_timezone, value):
    """
    A5c-MON-01.
    Given: the engine's local timezone is not UTC, and a relative first_fetch ("3 days") or an ISO date without offset.
    When: to_epoch_seconds converts it to the epoch-seconds watermark.
    Then: the value is read as UTC. B0 calls .timestamp() on the naive UTC datetime returned by arg_to_datetime, so
          Python reads it as LOCAL time and the watermark shifts by the local UTC offset.
    """
    if value == "3 days":
        expected = (datetime.now(UTC) - timedelta(days=3)).timestamp()
    else:
        expected = datetime(2026, 10, 1, tzinfo=UTC).timestamp()
    assert abs(to_epoch_seconds(value, "first_fetch") - expected) < 120


@pytest.mark.parametrize("value, expected", [(None, 50), ("", 50), ("1", 1), ("200", 200)])
def test_mission_parse_max_fetch_accepts_the_documented_range(value, expected):
    """
    Given: max_fetch empty or at the documented bounds (1-200).
    When: it is parsed.
    Then: the default 50 or the value itself is used.
    """
    assert parse_max_fetch(value) == expected


@pytest.mark.parametrize("value", ["0", "-1", "201", "abc"])
def test_mission_parse_max_fetch_rejects_out_of_range(value):
    """
    Given: max_fetch outside 1-200 or not a number.
    When: it is parsed.
    Then: a readable error is raised.
    """
    with pytest.raises((DemistoException, ValueError)):
        parse_max_fetch(value)


def test_mission_fetch_skips_incidents_hidden_through_the_actions_flags():
    """
    Given: instant-messaging records that carry their flags under `actions` (not `user_actions`), one hidden, one
           deleted and one visible.
    When: fetch runs.
    Then: only the visible one is created.
    """
    api, store = FakeMonitorAPI(), FakeRunStore()
    for incident_id, flags in (("hidden", {"hide": True}), ("deleted", {"delete": True}), ("visible", {})):
        api.add(MON, "instant_messaging", incident_id, NOW - DAY, actions={"read": False, **flags})
        api.records[(MON, "instant_messaging")][-1].pop("user_actions")
    assert store.cycle(api, types=("instant_messaging",)) == ["visible"]


def test_mission_monitor_id_from_args_overrides_the_instance():
    """
    Given: an instance monitor and a monitor_id argument.
    When: kela-monitor-incident-list and kela-monitor-incident-scroll run.
    Then: the argument is used; a non-numeric argument fails before any request.
    """
    client = MagicMock()
    client.incidents_list.return_value = {"incidents": [], "scrollId": None}
    client.incidents_scroll.return_value = {"incidents": [], "scrollId": None}
    incident_list_command(client, {"incident_type": "botnets", "monitor_id": "123"}, MON, mask=True)
    assert client.incidents_list.call_args.args[0] == 123
    incident_scroll_command(client, {"scroll_id": "S", "monitor_id": "456"}, MON, mask=True)
    assert client.incidents_scroll.call_args.args[0] == 456
    client.reset_mock()
    with pytest.raises(DemistoException, match="Monitor ID"):
        incident_list_command(client, {"incident_type": "botnets", "monitor_id": "abc"}, MON, mask=True)
    client.incidents_list.assert_not_called()


@pytest.mark.parametrize("seed", range(10))
def test_mission_fetch_property_every_record_created_exactly_once(seed):
    """
    Given: a seeded random history over two incident types: records created over time (incident_date close to the
           moment they appear, several sharing a second), a clock that advances 60 s per cycle and a random max_fetch 1-4.
    When: fetch runs with the last run JSON round-tripped until it is idle.
    Then: every record is created exactly once.
    """
    rng = random.Random(seed)
    api, store = FakeMonitorAPI(), FakeRunStore()
    types = ("leaked_credentials", "hacking_discussions")
    pending = []
    for n, arrival in enumerate(sorted(rng.randint(0, 5) for _ in range(rng.randint(5, 30)))):
        pending.append((arrival, rng.choice(types), f"r{n}", NOW + arrival * 60 - rng.choice([0, 0, 5, 30])))
    max_fetch = rng.randint(1, 4)
    for cycle in range(80):
        for arrival, incident_type, incident_id, date_s in pending:
            if arrival == cycle:
                api.add(MON, incident_type, incident_id, date_s)
        store.cycle(api, types=types, max_fetch=max_fetch, now_s=NOW + cycle * 60, first_fetch_s=NOW - DAY)
    assert store.duplicates() == {}
    assert set(store.created) == {incident_id for _, _, incident_id, _ in pending}


def test_mission_fetch_drains_a_group_larger_than_the_seen_ids_cap():
    """
    A5c-MON-02.
    Given: SEEN_IDS_CAP + 20 incidents reported in the same second and max_fetch=200.
    When: fetch runs until idle.
    Then: every incident is created exactly once. B0 trims the stored IDs to the last SEEN_IDS_CAP while the watermark
          stays on that second, so the oldest IDs of the group are forgotten and re-created.
    """
    api, store = FakeMonitorAPI(), FakeRunStore()
    for i in range(SEEN_IDS_CAP + 20):
        api.add(MON, "leaked_credentials", f"id{i:04d}", NOW - DAY)
    for _ in range(10):
        store.cycle(api, max_fetch=200)
    assert store.duplicates() == {}
    assert len(store.created) == SEEN_IDS_CAP + 20


def test_mission_scroll_outputs_match_yaml_context_paths():
    """
    Given: a list response with a scroll ID and a realistic incident page (invented values, data-model field names).
    When: kela-monitor-incident-list runs.
    Then: the incident and scroll results use the YAML prefixes, the Scroll keys are exactly the YAML Scroll paths
          and the incident key field is declared.
    """
    page = util_load_json("incidents_list_response.json")["data"]
    client = MagicMock()
    client.incidents_list.return_value = {**page, "scrollId": "SCROLL"}
    incident_result, scroll_result = incident_list_command(client, {"incident_type": "hacking_discussions"}, MON, mask=True)
    for command in ("kela-monitor-incident-list", "kela-monitor-incident-scroll"):
        yaml_paths = _yaml_context_paths()[command]
        assert f"{incident_result.outputs_prefix}.{incident_result.outputs_key_field}" in yaml_paths
        scroll_paths = {p for p in yaml_paths if p.startswith(f"{scroll_result.outputs_prefix}.")}
        assert scroll_paths == {f"{scroll_result.outputs_prefix}.{key}" for key in scroll_result.outputs}
        assert all(p.startswith(("KELA.Monitor.Incident.", "KELA.Monitor.Scroll.")) for p in yaml_paths)


def test_mission_readme_documents_every_yaml_output_and_parameter():
    """
    Given: the integration YAML and README.
    When: they are compared.
    Then: every command, contextPath and parameter display name appears in the README.
    """
    readme = util_read_text("README.md")
    missing = [command for command in _yaml_context_paths() if command not in readme]
    missing += [path for paths in _yaml_context_paths().values() for path in paths if path not in readme]
    missing += [display for display in _yaml_param_displays() if display not in readme]
    assert missing == []


def _run_main(mocker: MockerFixture, command: str, params: dict | None = None, args: dict | None = None):
    mocker.patch.object(KELAMonitor.demisto, "params", return_value=params or MISSION_PARAMS)
    mocker.patch.object(KELAMonitor.demisto, "args", return_value=args or {})
    mocker.patch.object(KELAMonitor.demisto, "command", return_value=command)
    mocker.patch.object(KELAMonitor.demisto, "getLastRun", return_value={})
    set_last_run = mocker.patch.object(KELAMonitor.demisto, "setLastRun")
    incidents = mocker.patch.object(KELAMonitor.demisto, "incidents")
    logged: list[str] = []
    for level in ("debug", "info", "error"):
        mocker.patch.object(KELAMonitor.demisto, level, side_effect=lambda msg, *a, **k: logged.append(str(msg)))
    return_results = mocker.patch.object(KELAMonitor, "return_results")
    return_error = mocker.patch.object(KELAMonitor, "return_error")
    KELAMonitor.main()
    return {
        "return_error": return_error,
        "return_results": return_results,
        "incidents": incidents,
        "set_last_run": set_last_run,
        "logged": logged,
    }


def test_mission_main_fetch_calls_incidents_and_set_last_run_once(mocker: MockerFixture, requests_mock):
    """
    Given: fetch-incidents for hacking_discussions and an API page with one hacking-discussion record.
    When: main() runs.
    Then: demisto.incidents and demisto.setLastRun are each called once, the record is created once, the state is
          JSON-safe and no error is reported.
    """
    page = util_load_json("incidents_list_response.json")
    page["data"]["incidents"] = [i for i in page["data"]["incidents"] if i["type"] == "hacking_discussions"]
    requests_mock.get(f"{BASE_URL}/monitor_id/{MON}/incidents", json=page)
    calls = _run_main(mocker, "fetch-incidents")
    calls["return_error"].assert_not_called()
    assert calls["incidents"].call_count == 1
    created = [json.loads(i["rawJSON"])["id"] for i in calls["incidents"].call_args[0][0]]
    assert created == ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"]
    assert calls["set_last_run"].call_count == 1
    json.dumps(calls["set_last_run"].call_args[0][0])


@pytest.mark.parametrize(
    "command, args",
    [
        ("test-module", {}),
        ("kela-monitor-incident-list", {"incident_type": "hacking_discussions"}),
        ("kela-monitor-incident-scroll", {"scroll_id": "S1"}),
        ("kela-monitor-unknown", {}),
    ],
)
def test_mission_main_dispatch(mocker: MockerFixture, requests_mock, command, args):
    """
    Given: each command name (and an unknown one).
    When: main() runs against an API answering 200.
    Then: known commands return results without error; the unknown one reports 'not implemented'.
    """
    requests_mock.get(f"{BASE_URL}/monitor_id/{MON}/incidents", json={"data": {"incidents": [], "scrollId": None}})
    requests_mock.get(f"{BASE_URL}/monitor_id/{MON}/incidents/scroll/S1", json={"data": {"incidents": [], "scrollId": None}})
    calls = _run_main(mocker, command, args=args)
    if command == "kela-monitor-unknown":
        assert "not implemented" in calls["return_error"].call_args[0][0]
    else:
        calls["return_error"].assert_not_called()
        calls["return_results"].assert_called_once()


def test_mission_main_requires_an_api_token(mocker: MockerFixture):
    """
    Given: an instance without an API token.
    When: any command runs.
    Then: return_error asks for the token.
    """
    calls = _run_main(mocker, "test-module", params={**MISSION_PARAMS, "credentials": {}})
    assert "API Token is required" in calls["return_error"].call_args[0][0]


def test_mission_main_never_leaks_api_key_on_connection_error(mocker: MockerFixture, requests_mock):
    """
    Given: the host is unreachable and requests' ConnectionError text holds the request URL with '?apiToken=<key>'.
    When: a command runs through main().
    Then: neither the War Room error nor any log line contains the key.
    """
    error_text = (
        "HTTPSConnectionPool(host='platform.ke-la.com', port=443): Max retries exceeded with url: "
        f"/api/monitor/monitor_id/{MON}/incidents?incident_type=hacking_discussions&limit=20&apiToken={MISSION_TOKEN} "
        "(Caused by NewConnectionError('refused'))"
    )
    requests_mock.get(f"{BASE_URL}/monitor_id/{MON}/incidents", exc=requests.exceptions.ConnectionError(error_text))
    calls = _run_main(mocker, "kela-monitor-incident-list", args={"incident_type": "hacking_discussions"})
    message = calls["return_error"].call_args[0][0]
    assert "Verify that the server URL" in message
    assert MISSION_TOKEN not in message
    assert all(MISSION_TOKEN not in line for line in calls["logged"])


# endregion


# region Stage 10 additions -----------------------------------------------------------------------------------------
# Tests for the behaviour added or changed by the approved findings (ids in each docstring).
PACK_DIR = os.path.dirname(os.path.dirname(INTEGRATION_DIR))
BUILT_IN_LAYOUT_FIELDS = {
    "details",
    "type",
    "severity",
    "owner",
    "sourcebrand",
    "sourceinstance",
    "playbookid",
    "occurred",
    "dbotmodified",
    "dbotduedate",
    "dbotcreated",
    "dbotclosed",
    "closereason",
    "closenotes",
}


def _load_entities(folder: str) -> list[dict[str, Any]]:
    directory = os.path.join(PACK_DIR, folder)
    entities = []
    for name in sorted(os.listdir(directory)):
        with open(os.path.join(directory, name), encoding="utf-8") as f:
            entities.append({"_file": name, **json.load(f)})
    return entities


def _classifier() -> dict[str, Any]:
    return next(c for c in _load_entities("Classifiers") if c["type"] == "classification")


def _mapper() -> dict[str, Any]:
    return next(c for c in _load_entities("Classifiers") if c["type"] == "mapping-incoming")


def _get_path(data: Any, path: str) -> Any:
    for part in path.split("."):
        if not isinstance(data, dict):
            return None
        data = data.get(part)
    return data


def _evaluate_mapping(expression: dict[str, Any], raw: dict[str, Any]) -> Any:
    """Tiny evaluator for the mapper expressions this pack uses: simple paths, root/accessor, uniq and join."""
    if expression.get("simple"):
        return _get_path(raw, expression["simple"])
    complex_expression = expression["complex"]
    value = _get_path(raw, complex_expression["root"])
    accessor = complex_expression.get("accessor")
    if accessor and isinstance(value, list):
        value = [item.get(accessor) for item in value if isinstance(item, dict)]
    for transformer in complex_expression.get("transformers", []):
        if transformer["operator"] == "uniq":
            value = list(dict.fromkeys(value or []))
        elif transformer["operator"] == "join":
            value = transformer["args"]["separator"]["value"]["simple"].join(value or [])
        else:
            raise AssertionError(f"transformer {transformer['operator']} not handled by the test evaluator")
    return value


def _classify(raw: dict[str, Any]) -> str:
    classifier = _classifier()
    key = _get_path(raw, classifier["transformer"]["simple"])
    return classifier["keyTypeMap"].get(key, classifier["defaultIncidentType"])


def _yaml() -> dict[str, Any]:
    import yaml

    with open(os.path.join(INTEGRATION_DIR, "KELAMonitor.yml"), encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_stage10_fetched_incident_has_dbot_mirror_id_and_kela_meta():
    """
    A3-MON-08, A6-MON-04, A6-MON-02.
    Given: a leaked-credentials record fetched from monitor 9164.
    When: it is mapped for fetch.
    Then: dbotMirrorId is the KELA incident ID as a string and rawJSON.kelaMeta carries the Monitor ID and the ISO
          posting date.
    """
    record = {"id": "abc", "type": "leaked_credentials", "incident_date": 1767225900, "posted_date": 1767225600, "severity": 3}
    incident = incident_to_xsoar(record, mask=True, monitor_id=MON)
    assert incident["dbotMirrorId"] == "abc"
    meta = json.loads(incident["rawJSON"])["kelaMeta"]
    assert meta["monitorId"] == str(MON)
    assert meta["postedDateIso"] == "2026-01-01T00:00:00Z"


@pytest.mark.parametrize("mask", [True, False])
def test_stage10_kela_meta_values_for_the_mapper_are_always_masked(mask):
    """
    A6-MON-11.
    Given: a credential with a password, a card with a full number and a bot whose available data holds secrets.
    When: they are mapped with masking on and off.
    Then: the kelaMeta copies read by the mapper are masked either way; rawJSON follows the masking flag.
    """
    leak = {"id": "l", "type": "leaked_credentials", "incident_date": 1, "password": "Example-Secret-1"}
    card = {"id": "c", "type": "credit_cards", "incident_date": 1, "number": "4111111111111111"}
    bot = {"id": "b", "type": "botnets", "incident_date": 1, "available_data": {"password": "x", "cookie": "y", "login": "u"}}
    leak_raw = json.loads(incident_to_xsoar(leak, mask, MON)["rawJSON"])
    card_raw = json.loads(incident_to_xsoar(card, mask, MON)["rawJSON"])
    bot_raw = json.loads(incident_to_xsoar(bot, mask, MON)["rawJSON"])
    assert leak_raw["kelaMeta"]["passwordMasked"] == "********"
    assert card_raw["kelaMeta"]["cardNumberMasked"] == "411111******1111"
    assert json.loads(bot_raw["kelaMeta"]["availableDataJson"]) == {"password": "********", "cookie": "********", "login": "u"}
    assert (leak_raw["password"] == "********") is mask
    assert (card_raw["number"] == "411111******1111") is mask


@pytest.mark.parametrize("key", ["cookie", "Cookies", "token", "session", "secret", "CVV", "password"])
def test_stage10_mask_record_covers_the_extended_keys(key):
    """
    A6-MON-11.
    Given: a bot record with a sensitive key nested in available_data.
    When: mask_record runs.
    Then: the value is masked whatever the key's case.
    """
    record = {"type": "botnets", "available_data": {"nested": [{key: "value"}]}}
    assert mask_record(record)["available_data"]["nested"][0][key] == "********"


def test_stage10_name_and_details_come_from_the_masked_record():
    """
    A6-MON-11.
    Given: a credit-card record with a full number and a description.
    When: it is mapped with masking on.
    Then: no clear card number appears anywhere in the incident (name, details or rawJSON) and the details are kept.
    """
    card = {"id": "c", "type": "credit_cards", "incident_date": 1, "number": "4111111111111111", "description": "card dump"}
    incident = incident_to_xsoar(card, mask=True, monitor_id=MON)
    assert "4111111111111111" not in json.dumps(incident)
    assert incident["details"] == "card dump"


def test_stage10_command_outputs_use_iso_dates():
    """
    A3-MON-09.
    Given: a list response whose dates are epoch seconds and a posted_date_range in milliseconds.
    When: kela-monitor-incident-list runs.
    Then: context and human-readable output carry ISO 8601 UTC strings; the raw response keeps the API values.
    """
    client = MagicMock()
    client.incidents_list.return_value = {
        "incidents": [
            {
                "id": "i1",
                "type": "instant_messaging",
                "incident_date": 1767225600,
                "posted_date": 1767225600,
                "relevant_date": 1767225600,
                "posted_date_range": {"min": 1767225600000, "max": 1767225660000},
            }
        ]
    }
    result = incident_list_command(client, {"incident_type": "instant_messaging"}, MON, mask=True)[0]
    output = result.outputs[0]
    assert output["incident_date"] == output["posted_date"] == output["relevant_date"] == "2026-01-01T00:00:00Z"
    assert output["posted_date_range"] == {"min": "2026-01-01T00:00:00Z", "max": "2026-01-01T00:01:00Z"}
    assert "2026-01-01T00:00:00Z" in result.readable_output
    assert result.raw_response["incidents"][0]["incident_date"] == 1767225600


def test_stage10_yaml_declares_dates_as_date_and_the_classifier_and_mapper():
    """
    A3-MON-09, A3-MON-04, A7-MON-06.
    Given: the integration YAML.
    When: it is read.
    Then: every date output is typed Date, the default classifier and incoming mapper are the pack's, and the incident
          types parameter is optional.
    """
    yml = _yaml()
    for command in yml["script"]["commands"]:
        for output in command.get("outputs", []):
            path = output["contextPath"]
            if path.endswith(("_date", "posted_date_range.min", "posted_date_range.max")):
                assert output["type"] == "Date", path
    assert yml["defaultclassifier"] == _classifier()["id"]
    assert yml["defaultmapperin"] == _mapper()["id"]
    incident_types = next(p for p in yml["configuration"] if p["name"] == "incident_types")
    assert incident_types["required"] is False


def test_stage10_yaml_documents_every_connection_parameter():
    """
    A3-MON-11, A7-MON-01.
    Given: the integration YAML.
    When: its parameters are read.
    Then: every parameter has a tooltip, and the token tooltip names the header, the dedicated user and API access.
    """
    yml = _yaml()
    assert [p["name"] for p in yml["configuration"] if not p.get("additionalinfo")] == []
    token = next(p for p in yml["configuration"] if p["name"] == "credentials")["additionalinfo"]
    assert "header" in token
    assert "dedicated" in token
    assert "API access" in token


def test_stage10_test_module_does_not_need_incident_types_when_fetch_is_off():
    """
    A7-MON-06.
    Given: an instance with fetch off and no incident type selected.
    When: test-module runs.
    Then: it probes hacking_discussions and returns ok.
    """
    client = MagicMock()
    client.incidents_list.return_value = {"incidents": []}
    assert run_test_module(client, MON, [], {"isFetch": False}) == "ok"
    assert client.incidents_list.call_args.args[1] == "hacking_discussions"


def test_stage10_fetch_never_sleeps(monkeypatch, requests_mock):
    """
    A3-MON-07.
    Given: the real client against a mocked API and time.sleep patched to fail.
    When: a fetch cycle runs over two incident types.
    Then: it completes without sleeping (throttling is left to the retry/backoff of the HTTP layer on 429).
    """

    def no_sleep(*_args: Any) -> None:
        raise AssertionError("time.sleep must not be called")

    monkeypatch.setattr(time, "sleep", no_sleep)
    requests_mock.get(f"{BASE_URL}/monitor_id/{MON}/incidents", json={"data": {"incidents": [], "scrollId": None}})
    next_run, incidents = fetch_incidents(make_client(), MON, ["botnets", "leaked_credentials"], {}, NOW - DAY, 50, [], True, NOW)
    assert incidents == []
    assert set(next_run["streams"]) == {f"{MON}:botnets", f"{MON}:leaked_credentials"}
    assert not hasattr(Client, "_throttle")


def test_stage10_debug_mode_error_never_contains_the_token(mocker: MockerFixture, requests_mock):
    """
    A5b-MON-02.
    Given: the server runs the command in debug mode (return_error then appends the traceback of the handled exception)
           and the connection error text holds the token.
    When: kela-monitor-incident-list fails through main() with the real return_error.
    Then: the War Room entry and every log line are free of the token.
    """
    error_text = f"Max retries exceeded with url: /api/monitor/monitor_id/{MON}/incidents?apiToken={MISSION_TOKEN}"
    requests_mock.get(f"{BASE_URL}/monitor_id/{MON}/incidents", exc=requests.exceptions.ConnectionError(error_text))
    mocker.patch.object(KELAMonitor.demisto, "params", return_value=MISSION_PARAMS)
    mocker.patch.object(KELAMonitor.demisto, "args", return_value={"incident_type": "hacking_discussions"})
    mocker.patch.object(KELAMonitor.demisto, "command", return_value="kela-monitor-incident-list")
    mocker.patch.object(KELAMonitor.demisto, "is_debug", True, create=True)
    results = mocker.patch.object(KELAMonitor.demisto, "results")
    logged: list[str] = []
    for level in ("debug", "info", "error"):
        mocker.patch.object(KELAMonitor.demisto, level, side_effect=lambda msg, *a, **k: logged.append(str(msg)))
    with pytest.raises(SystemExit):
        KELAMonitor.main()
    contents = results.call_args[0][0]["Contents"]
    assert "Traceback" in contents  # debug mode really appended a traceback
    assert MISSION_TOKEN not in contents
    assert all(MISSION_TOKEN not in line for line in logged)


def test_stage10_fetch_after_a_compacted_group_still_creates_late_incidents():
    """
    A5c-MON-02.
    Given: a same-second group larger than SEEN_IDS_CAP that was fully fetched, then a late incident in that second
           sorting after every fetched ID and one in the next second.
    When: fetch runs until idle again.
    Then: the stored state stays within the cap, the late incidents are created once and nothing is duplicated.
    """
    api, store = FakeMonitorAPI(), FakeRunStore()
    for i in range(SEEN_IDS_CAP + 20):
        api.add(MON, "leaked_credentials", f"id{i:04d}", NOW - 600)
    store.run_until_idle(api, max_fetch=200)
    state = store.value["streams"][f"{MON}:leaked_credentials"]
    assert len(state["seen_ids"]) <= SEEN_IDS_CAP
    api.add(MON, "leaked_credentials", "zz-late", NOW - 600)
    api.add(MON, "leaked_credentials", "next", NOW - 599)
    store.run_until_idle(api, max_fetch=200)
    assert store.duplicates() == {}
    assert store.created["zz-late"] == 1
    assert store.created["next"] == 1


def test_stage10_entities_are_valid_json_with_consistent_ids():
    """
    A6-MON-01, A3-MON-04, A6-MON-07.
    Given: the pack's incident types, fields, classifier, mapper and layouts.
    When: they are loaded.
    Then: every file is valid JSON, field IDs follow incident_<cliName>, cliNames are the lowercased alphanumeric names,
          associated types and layouts exist, and every entity has the integration's fromversion.
    """
    from_version = _yaml()["fromversion"]
    types = {t["name"]: t for t in _load_entities("IncidentTypes")}
    layouts = {layout["id"]: layout for layout in _load_entities("Layouts")}
    fields = _load_entities("IncidentFields")
    assert len(types) == 7
    assert len(layouts) == 7
    assert len(fields) == 41
    for incident_type in types.values():
        assert incident_type["id"] == incident_type["name"]
        assert incident_type["layout"] in layouts
        assert incident_type["extractSettings"]["mode"] == "Specific"
    for field in fields:
        assert field["cliName"] == re.sub(r"[^a-z0-9]", "", field["name"].lower())
        assert field["id"] == f"incident_{field['cliName']}"
        assert field["associatedToAll"] is False
        assert set(field["associatedTypes"]) <= set(types)
    for entity in [*types.values(), *layouts.values(), *fields, *_load_entities("Classifiers")]:
        assert entity["fromVersion"] == from_version, entity["_file"]
        assert entity["version"] == -1


def test_stage10_layouts_reference_only_existing_fields():
    """
    A6-MON-01, A6-MON-06.
    Given: the seven layouts.
    When: their field items are listed.
    Then: each is a pack field or a built-in field, every layout shows the details field and the Aggregation ID, and a
          layout shows only fields associated with its incident type.
    """
    field_types = {f["cliName"]: set(f["associatedTypes"]) for f in _load_entities("IncidentFields")}
    type_by_layout = {t["layout"]: t["name"] for t in _load_entities("IncidentTypes")}
    for layout in _load_entities("Layouts"):
        assert "marketplaces" not in layout
        items = [
            item["fieldId"]
            for tab in layout["detailsV2"]["tabs"]
            for section in tab.get("sections", [])
            for item in section.get("items", [])
        ]
        assert "details" in items
        assert "kelamonitoraggregationid" in items
        for field_id in items:
            assert field_id in field_types or field_id in BUILT_IN_LAYOUT_FIELDS, (layout["id"], field_id)
            if field_id in field_types:
                assert type_by_layout[layout["id"]] in field_types[field_id], (layout["id"], field_id)


def test_stage10_classifier_routes_every_kela_type():
    """
    A6-MON-01, A6-MON-03.
    Given: the classifier.
    When: KELA type values are classified.
    Then: each fetched type gets its own incident type, botnets and compromised_accounts share the Compromised Accounts
          type, and reports, dld_source_codes and unknown values fall back to KELA Monitor Incident.
    """
    expected = {
        "hacking_discussions": "KELA Monitor Hacking Discussion",
        "instant_messaging": "KELA Monitor Instant Messaging",
        "leaked_credentials": "KELA Monitor Leaked Credentials",
        "network_vulnerabilities": "KELA Monitor Network Vulnerability",
        "credit_cards": "KELA Monitor Credit Cards",
        "botnets": "KELA Monitor Compromised Accounts",
        "compromised_accounts": "KELA Monitor Compromised Accounts",
        "reports": "KELA Monitor Incident",
        "dld_source_codes": "KELA Monitor Incident",
        "something_new": "KELA Monitor Incident",
    }
    assert {value: _classify({"type": value}) for value in expected} == expected
    assert set(KELAMonitor.INCIDENT_TYPES) <= set(_classifier()["keyTypeMap"])


def test_stage10_mapper_blocks_match_types_and_fields():
    """
    A6-MON-05, A6-MON-07.
    Given: the incoming mapper.
    When: its blocks are read.
    Then: there is one block per incident type, labels are not mapped, and every mapped field exists and is associated
          with that type.
    """
    field_types = {f["name"]: set(f["associatedTypes"]) for f in _load_entities("IncidentFields")}
    types = {t["name"] for t in _load_entities("IncidentTypes")}
    mapping = _mapper()["mapping"]
    assert set(mapping) == types
    for type_name, block in mapping.items():
        assert block["dontMapEventToLabels"] is True
        assert set(block["internalMapping"]) == {name for name, assoc in field_types.items() if type_name in assoc}


@pytest.mark.parametrize("mask", [True, False])
def test_stage10_mapper_expressions_on_sample_records(mask):
    """
    A6-MON-07, A6-MON-11, A6-MON-02.
    Given: one invented record per KELA type, mapped by the fetch code with masking on and off.
    When: the classifier and the mapper expressions run on the resulting rawJSON.
    Then: the record lands in the expected type, every expected field gets the expected value and the masked fields
          never receive a clear secret.
    """
    mapping = _mapper()["mapping"]
    for sample in util_load_json("mapper_records.json")["records"]:
        raw = json.loads(incident_to_xsoar(sample["record"], mask, MON)["rawJSON"])
        incident_type = _classify(raw)
        assert incident_type == sample["expected_type"]
        values = {name: _evaluate_mapping(expr, raw) for name, expr in mapping[incident_type]["internalMapping"].items()}
        for name, expected in sample["expected_fields"].items():
            assert values[name] == expected, (incident_type, name, values[name])
        masked_fields = {k: v for k, v in values.items() if "Masked" in k or "Available" in k}
        assert "Example-Secret" not in json.dumps(masked_fields)


# endregion


# region Stage 10 additions, items approved at 14:48 ----------------------------------------------------------------
@pytest.mark.parametrize(
    "record, mask, expected_core",
    [
        ({"type": "leaked_credentials", "email": "jane@example.com"}, True, "j***@example.com"),
        ({"type": "leaked_credentials", "email": "jane@example.com"}, False, "jane@example.com"),
        ({"type": "botnets", "username": "bob", "resource": "mail.example.com"}, True, "b*** @ mail.example.com"),
        ({"type": "botnets", "username": "bob", "resource": "mail.example.com"}, False, "bob @ mail.example.com"),
    ],
)
def test_stage10_incident_name_masks_identities_when_masking_is_on(record, mask, expected_core):
    """
    A5b-MON-04.
    Given: a leaked credential and a compromised account.
    When: the incident is mapped with masking on and off.
    Then: with masking on the email and the user name keep only their first character (and domain).
    """
    incident = incident_to_xsoar({"id": "X1", "incident_date": 1, **record}, mask=mask)
    assert incident["name"] == f"KELA Monitor - {record['type']}: {expected_core} [X1]"


def test_stage10_instant_messaging_details_prefer_the_full_text():
    """
    A6-MON-13.
    Given: an instant-messaging record with a snippet and a full text.
    When: it is mapped.
    Then: details hold the full text; without it, the cleaned snippet is used.
    """
    record = {
        "id": "m",
        "type": "instant_messaging",
        "incident_date": 1,
        "snippet": "...<span>a</span>...",
        "full_text": "full a",
    }
    assert incident_to_xsoar(record, mask=True)["details"] == "full a"
    record.pop("full_text")
    assert incident_to_xsoar(record, mask=True)["details"] == "...a..."


@pytest.mark.parametrize("skip_handled, expected", [(False, ["handled", "open"]), (True, ["open"])])
def test_stage10_fetch_can_skip_incidents_handled_in_kela(skip_handled, expected):
    """
    A6-MON-12.
    Given: one incident handled in KELA (handled holds the analyst's name) and one open incident.
    When: fetch runs with and without the "skip handled" option.
    Then: the handled one is skipped only when asked, and it is not re-read later either way.
    """
    api = FakeMonitorAPI()
    api.add(MON, "botnets", "handled", NOW - 3000, user_actions={"handled": "Analyst Name"})
    api.add(MON, "botnets", "open", NOW - 2000)
    last_run, incidents = fetch_incidents(api, MON, ["botnets"], {}, NOW - DAY, 50, [], True, NOW, skip_handled)
    assert [json.loads(i["rawJSON"])["id"] for i in incidents] == expected
    _, again = fetch_incidents(api, MON, ["botnets"], last_run, NOW - DAY, 50, [], True, NOW, skip_handled)
    assert again == []


@pytest.mark.parametrize("url", ["http://platform.ke-la.com/api/monitor", "platform.ke-la.com/api/monitor", "ftp://x"])
def test_stage10_server_url_must_be_https(mocker: MockerFixture, url):
    """
    A5b-MON-06.
    Given: a Server URL that is not https.
    When: any command runs.
    Then: it fails before any request with a clear message.
    """
    calls = _run_main(mocker, "test-module", params={**MISSION_PARAMS, "url": url})
    assert "https" in calls["return_error"].call_args[0][0]


def test_stage10_yaml_offers_the_skip_handled_option_and_documents_the_new_behaviour():
    """
    A6-MON-12, A3-MON-17, A7-MON-12, A5b-MON-09, A5b-MON-07.
    Given: the integration YAML.
    When: it is read.
    Then: the optional skip_handled parameter exists (default false), the description uses the "Use the ... integration"
          form, the limit and monitor_id arguments carry their advice, and no tooltip claims the token is "never" logged.
    """
    yml = _yaml()
    skip = next(p for p in yml["configuration"] if p["name"] == "skip_handled")
    assert skip["type"] == 8
    assert skip.get("required") is False
    assert yml["description"].startswith("Use the KELA Monitor integration to")
    arguments = {a["name"]: a["description"] for a in yml["script"]["commands"][0]["arguments"]}
    assert "100" in arguments["limit"]
    assert "any monitor" in arguments["monitor_id"].lower()
    assert all("never logged" not in str(p.get("additionalinfo")) for p in yml["configuration"])


# endregion


# region Stage 12 additions -----------------------------------------------------------------------------------------
# Tests for the fixes of the Stage 11 validate failures (demisto-sdk error code in each docstring).
PLATFORM_MODULES = {
    "agentix",
    "asm",
    "cloud",
    "cloud_appsec",
    "cloud_posture",
    "cloud_runtime_security",
    "data_security",
    "edr",
    "email_security",
    "exposure_management",
    "tim",
    "xsiam",
    "xti",
}
XSIAM_AND_AGENTIX_MODULES = {"agentix", "xsiam"}
FETCH_INCIDENTS_PARAMS = {"isFetch", "incidentType", "incidentFetchInterval", "max_fetch"}
XSIAM_UNSUPPORTED_LAYOUT_TABS = {"evidenceBoard", "relatedIncidents"}
XSIAM_UNSUPPORTED_LAYOUT_SECTIONS = {"evidence", "childInv", "linkedIncidents", "team", "droppedIncidents", "todoTasks"}


def _pack_metadata() -> dict[str, Any]:
    with open(os.path.join(PACK_DIR, "pack_metadata.json"), encoding="utf-8") as f:
        return json.load(f)


def _resolve_modules(own_modules: list[str] | None, inherited_modules: set[str]) -> set[str]:
    """Same resolution as demisto-sdk: the item's own supportedModules, else the inherited set (an empty list counts)."""
    return inherited_modules if own_modules is None else set(own_modules)


def test_stage12_incident_entities_and_fetch_params_resolve_to_xsiam_and_agentix():
    """
    BA131, BA133 (demisto-sdk validators InvalidSupportedModules / InvalidSupportedModulesForFetchType).
    Given: the pack ships to the platform marketplace.
    When: the supportedModules of the incident types, incident fields, classifier, mapper and the fetch-incidents
          parameters are resolved (item, then integration, then pack, then every platform module).
    Then: each resolves to a non-empty subset of {agentix, xsiam}, the only modules where these items and incident
          fetching exist.
    """
    metadata = _pack_metadata()
    assert "platform" in metadata["marketplaces"]
    pack_modules = _resolve_modules(metadata.get("supportedModules"), PLATFORM_MODULES)
    for entity in [*_load_entities("IncidentTypes"), *_load_entities("IncidentFields"), *_load_entities("Classifiers")]:
        entity_modules = _resolve_modules(entity.get("supportedModules"), pack_modules)
        assert entity_modules, entity["_file"]
        assert entity_modules <= XSIAM_AND_AGENTIX_MODULES, entity["_file"]
    yml = _yaml()
    integration_modules = _resolve_modules(yml.get("supportedModules"), pack_modules)
    fetch_params = [p for p in yml["configuration"] if p["name"] in FETCH_INCIDENTS_PARAMS]
    assert {p["name"] for p in fetch_params} == FETCH_INCIDENTS_PARAMS
    for param in fetch_params:
        param_modules = _resolve_modules(param.get("supportedModules"), integration_modules)
        assert param_modules, param["name"]
        assert param_modules <= XSIAM_AND_AGENTIX_MODULES, param["name"]


def test_stage12_classifier_and_mapper_ids_equal_their_names():
    """
    BA101 (demisto-sdk IDNameValidator).
    Given: the classifier and the incoming mapper.
    When: their id and name are compared.
    Then: they are identical, and the integration YAML names them as its default classifier and incoming mapper.
    """
    yml = _yaml()
    for entity in (_classifier(), _mapper()):
        assert entity["id"] == entity["name"], entity["_file"]
    assert yml["defaultclassifier"] == "KELA Monitor - Classifier"
    assert yml["defaultmapperin"] == "KELA Monitor - Incoming Mapper"


def test_stage12_layouts_use_only_types_supported_in_xsiam():
    """
    LO107 (demisto-sdk IsValidTypeValidator).
    Given: the seven layouts, which have no marketplaces key and so ship to every marketplace of the pack.
    When: their tab and section types are listed.
    Then: none is a type XSIAM does not support, and every layout keeps the Incident Info, War Room and Work Plan tabs.
    """
    assert "marketplacev2" in _pack_metadata()["marketplaces"]
    for layout in _load_entities("Layouts"):
        tabs = layout["detailsV2"]["tabs"]
        tab_types = {tab.get("type") for tab in tabs}
        section_types = {section.get("type") for tab in tabs for section in tab.get("sections", [])}
        assert not tab_types & XSIAM_UNSUPPORTED_LAYOUT_TABS, layout["_file"]
        assert not section_types & XSIAM_UNSUPPORTED_LAYOUT_SECTIONS, layout["_file"]
        assert [tab["id"] for tab in tabs] == ["caseinfoid", "warRoom", "workPlan"], layout["_file"]


# endregion


# region Merge candidate additions (behaviours ported from the PR version) ---------------------------------------------
def test_candidate_fetch_logs_start_and_completion_lines(mocker: MockerFixture):
    """
    Ported from the PR version (C-3-14 log prefixes).
    Given: one incident type with one new incident.
    When: a fetch cycle runs.
    Then: it logs a [Fetch] start line (debug) and a [Fetch] completion line with the incident count (info), and no
          line holds the API token.
    """
    logged: dict[str, list[str]] = {"debug": [], "info": []}
    for level in logged:
        mocker.patch.object(KELAMonitor.demisto, level, side_effect=lambda msg, *a, _level=level, **k: logged[_level].append(msg))
    client = MagicMock()
    client.incidents_list.return_value = {
        "incidents": [{"id": "i1", "type": "botnets", "incident_date": NOW - 600, "severity": 2}]
    }
    _, incidents = fetch_incidents(client, MON, ["botnets"], {}, NOW - 3600, 50, [], True, NOW)
    assert len(incidents) == 1
    assert any(line.startswith("[Fetch] KELA Monitor: fetch started") for line in logged["debug"])
    assert "[Fetch] KELA Monitor: fetch completed, 1 incident(s) created." in logged["info"]
    assert all(TOKEN not in line for lines in logged.values() for line in lines)


def test_candidate_argument_descriptions_follow_the_wording_conventions():
    """
    Ported from the PR version (documentation description templates).
    Given: the command arguments of the integration YAML.
    When: their descriptions are read.
    Then: boolean arguments start with "Whether" and array arguments start with "A comma-separated list of".
    """
    for command in _yaml()["script"]["commands"]:
        for argument in command.get("arguments", []):
            if argument.get("predefined") == ["true", "false"]:
                assert argument["description"].startswith("Whether"), argument["name"]
            if argument.get("isArray"):
                assert argument["description"].startswith("A comma-separated list of"), argument["name"]


# endregion
