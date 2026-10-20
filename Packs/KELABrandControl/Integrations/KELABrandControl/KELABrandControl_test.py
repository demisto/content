import json
from collections import Counter
from typing import Any
from unittest.mock import MagicMock

import pytest
from CommonServerPython import DemistoException
from pytest_mock import MockerFixture

import KELABrandControl
from KELABrandControl import (
    API_MAX_LIMIT,
    SEEN_IDS_CAP,
    Client,
    fetch_incidents,
    get_pagination,
    incident_list_command,
    incident_to_xsoar,
    mask_secret,
    parse_workspace_ids,
    to_epoch_ms,
)
from KELABrandControl import (
    test_module as run_test_module,
)

BASE_URL = "https://api.ke-la.com/brand-control/v1"
TOKEN = "SuperSecretToken123"
WS1 = "ws_one"
WS2 = "ws_two"


@pytest.fixture(autouse=True)
def no_rate_limit_sleep(monkeypatch):
    """The 1 req/s rate limiter is irrelevant for unit tests."""
    monkeypatch.setattr(KELABrandControl, "RATE_LIMIT_PER_SECOND", 0)


@pytest.fixture(autouse=True)
def mock_support_multithreading(mocker: MockerFixture) -> None:
    """Mock support_multithreading to prevent demistomock attribute errors.

    Called during ContentClient initialization; without this mock, tests fail with:
    AttributeError: module 'demistomock' has no attribute '_Demisto__do'
    """
    mocker.patch("ContentClientApiModule.support_multithreading")


# region Fakes ---------------------------------------------------------------------------------------------------
class FakeAPI:
    """Behaves like the real POST /incidents as far as fetch is concerned:

    - startDate is INCLUSIVE (the worst case for duplicates; an exclusive API only makes the dedup a no-op),
    - results are sorted ascending by incidentDate when sort asc is requested,
    - pagination.limit / pagination.offset are honored (limit capped at 1000),
    - isDeleted / isArchived filters are honored.
    Ties on the same timestamp are ordered by incident id (or reversed with tie_reverse=True).
    """

    def __init__(self, tie_reverse: bool = False):
        self.records: dict[str, list[dict[str, Any]]] = {}
        self.calls: list[dict[str, Any]] = []
        self.tie_reverse = tie_reverse

    def add(self, workspace_id: str, incident_id: str, date_ms: int, severity: str = "high", **extra: Any) -> None:
        record = {
            "incidentId": incident_id,
            "incidentDate": date_ms,
            "severity": severity,
            "type": "look_alike_domain",
            "status": "new",
            "title": f"title {incident_id}",
            "isDeleted": False,
            "isArchived": False,
        }
        record.update(extra)
        self.records.setdefault(workspace_id, []).append(record)

    def incidents_list(self, workspace_id, filters=None, sort=None, limit=50, offset=0):
        filters = filters or {}
        self.calls.append({"workspace_id": workspace_id, "filters": filters, "sort": sort, "limit": limit, "offset": offset})
        start = (filters.get("timeRange") or {}).get("startDate")
        rows = [
            r
            for r in self.records.get(workspace_id, [])
            if (start is None or r["incidentDate"] is None or r["incidentDate"] >= start)
            and r["isDeleted"] == filters.get("isDeleted", False)
            and r["isArchived"] == filters.get("isArchived", False)
        ]
        rows.sort(key=lambda r: r["incidentId"], reverse=self.tie_reverse)
        rows.sort(key=lambda r: r["incidentDate"] or 0)  # stable: keeps the tie order chosen above
        limit = min(limit, API_MAX_LIMIT)
        return {"incidents": rows[offset : offset + limit], "count": len(rows), "filteredCount": len(rows)}


class FakeRunStore:
    """Fake getLastRun/setLastRun. The state is JSON round-tripped on every cycle, like in the real platform."""

    def __init__(self):
        self.value: dict[str, Any] = {}
        self.created: Counter = Counter()

    def cycle(self, api, workspaces=(WS1,), max_fetch=50, severities=(), first_fetch_ms=0) -> list[str]:
        last_run = json.loads(json.dumps(self.value))
        next_run, incidents = fetch_incidents(api, list(workspaces), last_run, first_fetch_ms, max_fetch, list(severities))
        self.value = json.loads(json.dumps(next_run))
        ids = [json.loads(i["rawJSON"])["incidentId"] for i in incidents]
        self.created.update(ids)
        return ids

    def duplicates(self) -> dict[str, int]:
        return {k: v for k, v in self.created.items() if v > 1}


# endregion


# region Client / helpers ----------------------------------------------------------------------------------------
def make_client() -> Client:
    return Client(BASE_URL, TOKEN, verify=True, proxy=False)


def test_client_wires_the_api_token_through_a_query_param_auth_handler():
    """
    Given: a client constructed with an API token.
    When: it is built.
    Then: the token is wired through an APIKeyAuthHandler that injects it as the 'apiToken' query
          parameter on every request (rather than being passed manually with each call).
    """
    client = make_client()
    assert isinstance(client._auth_handler, KELABrandControl.APIKeyAuthHandler)
    assert client._auth_handler.key == TOKEN
    assert client._auth_handler.query_param == "apiToken"


def test_client_incidents_list_maps_payload(mocker: MockerFixture):
    """
    Given: a client with a mocked _http_request.
    When: incidents_list is called with filters, sort and pagination.
    Then: workspaceId travels in the query params and filters/sort/pagination in the JSON body
          (apiToken is injected separately by the auth handler, not passed here).
    """
    client = make_client()
    http_request = mocker.patch.object(client, "_http_request", return_value={"incidents": [], "count": 0})
    client.incidents_list(
        WS1,
        filters={"isDeleted": False},
        sort={"sortBy": "incidentDate", "order": "asc"},
        limit=10,
        offset=20,
    )
    http_request.assert_called_once_with(
        method="POST",
        url_suffix="/incidents",
        params={"workspaceId": WS1},
        json_data={
            "filters": {"isDeleted": False},
            "pagination": {"limit": 10, "offset": 20},
            "sort": {"sortBy": "incidentDate", "order": "asc"},
        },
        retries=KELABrandControl.RETRIES_ON_429,
        status_list_to_retry=[429],
        backoff_factor=1,
        error_handler=client._error_handler,
    )


@pytest.mark.parametrize(
    "status, body, expected",
    [
        (401, {"message": "You are not authorized."}, "Authorization Error"),
        (429, {"message": "rate limit exceeded"}, "Rate limit exceeded"),
        (400, {"message": "Bad Request"}, "[400] - Bad Request"),
        (500, {"message": "Internal Server Error"}, "[500] - Internal Server Error"),
    ],
)
def test_client_error_handling_never_leaks_token(status, body, expected):
    """
    Given: the API answers with an error status.
    When: Client._error_handler processes the response.
    Then: a readable DemistoException is raised and it never contains the API token (the handler only
          ever sees the response body/status, never the client's token).
    """
    response = MagicMock(status_code=status, text=json.dumps(body))
    response.json.return_value = body
    with pytest.raises(DemistoException) as exc:
        Client._error_handler(response)
    assert expected in str(exc.value)
    assert TOKEN not in str(exc.value)


def test_mask_secret():
    """
    Given: a message that contains the token raw and URL-encoded.
    When: mask_secret runs.
    Then: no variant of the token survives.
    """
    token = "a/b+c d"
    text = "url?apiToken=a%2Fb%2Bc%20d and a/b+c d and a%2Fb%2Bc+d"
    masked = mask_secret(text, token)
    assert "a%2Fb" not in masked and "a/b+c d" not in masked
    assert mask_secret("nothing", None) == "nothing"


def test_parse_workspace_ids():
    """
    Given: a comma separated workspace string with spaces and a repeated value.
    When: parse_workspace_ids runs.
    Then: a clean ordered de-duplicated list is returned; empty input fails.
    """
    assert parse_workspace_ids(" a, b ,a,, c") == ["a", "b", "c"]
    with pytest.raises(DemistoException):
        parse_workspace_ids("")
    with pytest.raises(DemistoException):
        parse_workspace_ids(" , ")


def test_to_epoch_ms():
    """
    Given: dates in several formats.
    When: to_epoch_ms converts them.
    Then: the result is always epoch milliseconds (13 digits); 10-digit seconds are upgraded; junk fails.
    """
    assert to_epoch_ms("1738493361000", "d") == 1738493361000
    assert to_epoch_ms("1738493361", "d") == 1738493361000
    assert to_epoch_ms("2026-10-03T00:00:00Z", "d") == 1790985600000
    assert len(str(to_epoch_ms("3 days", "d"))) == 13
    assert to_epoch_ms("", "d") is None
    with pytest.raises(DemistoException):
        to_epoch_ms("12345", "d")


@pytest.mark.parametrize(
    "args, expected",
    [
        ({}, (50, 0)),
        ({"limit": "10"}, (10, 0)),
        ({"page": "3", "page_size": "20"}, (20, 40)),
        ({"page": "2"}, (50, 50)),
        ({"limit": "5", "page_size": "7", "page": "1"}, (7, 0)),
    ],
)
def test_get_pagination(args, expected):
    """
    Given: XSOAR pagination arguments.
    When: get_pagination runs.
    Then: limit/offset follow the conventions (page_size wins over limit, page starts at 1).
    """
    assert get_pagination(args) == expected


@pytest.mark.parametrize("args", [{"limit": "0"}, {"page": "0"}, {"page_size": "-1"}])
def test_get_pagination_invalid(args):
    """
    Given: non-positive pagination arguments.
    When: get_pagination runs.
    Then: a DemistoException is raised.
    """
    with pytest.raises(DemistoException):
        get_pagination(args)


def test_get_pagination_does_not_cap_a_large_limit():
    """
    Given: a limit above the API's documented maximum (1000).
    When: get_pagination runs.
    Then: no local error is raised; the API itself disregards values above 1000 [SPEC], so enforcing a
          client-side cap here would be artificial.
    """
    assert get_pagination({"limit": "1001"}) == (1001, 0)


# endregion


# region Commands ------------------------------------------------------------------------------------------------
def test_incident_list_command_payload_mapping():
    """
    Given: command arguments using every filter.
    When: kela-brandcontrol-incident-list runs.
    Then: the client receives the exact documented payload, with lowercase enums, ms dates and pagination.
    """
    client = MagicMock()
    client.incidents_list.return_value = {
        "incidents": [
            {
                "incidentId": "i1",
                "incidentDate": 1790985600000,
                "type": "look_alike_domain",
                "severity": "high",
                "status": "new",
                "title": "t",
                "analysis": {"impersonatedAsset": "kela.com"},
                "detectedEntity": {"urls": ["http://kela-c0m.com"]},
            }
        ],
        "count": 10,
        "filteredCount": 1,
    }
    args = {
        "workspace_id": WS1,
        "search_term": "kela",
        "types": "look_alike_domain,phishing_website",
        "statuses": "new,in_review",
        "severities": "critical,low",
        "is_deleted": "false",
        "is_archived": "false",
        "new_updates_only": "true",
        "time_range_field": "incident_date",
        "start_date": "1790985600000",
        "end_date": "1791072000000",
        "sort_by": "incidentDate",
        "sort_order": "asc",
        "page": "2",
        "page_size": "25",
    }
    result = incident_list_command(client, args, [WS1])
    client.incidents_list.assert_called_once_with(
        WS1,
        filters={
            "isDeleted": False,
            "isArchived": False,
            "timeRange": {"fieldName": "incident_date", "startDate": 1790985600000, "endDate": 1791072000000},
            "searchTerm": "kela",
            "types": ["look_alike_domain", "phishing_website"],
            "statuses": ["new", "in_review"],
            "severities": ["critical", "low"],
            "newUpdatesOnly": True,
        },
        sort={"sortBy": "incidentDate", "order": "asc"},
        limit=25,
        offset=25,
    )
    assert result.outputs_prefix == "KELA.BrandControl.Incident"
    assert result.outputs_key_field == "incidentId"
    assert result.outputs[0]["incidentId"] == "i1"
    assert "kela.com" in result.readable_output
    assert result.raw_response["filteredCount"] == 1


def test_incident_list_command_defaults():
    """
    Given: no optional arguments and a single configured workspace.
    When: the command runs.
    Then: deleted and archived incidents are excluded, default limit is 50 and no sort/timeRange is sent.
    """
    client = MagicMock()
    client.incidents_list.return_value = {"incidents": [], "count": 0, "filteredCount": 0}
    incident_list_command(client, {}, [WS1])
    client.incidents_list.assert_called_once_with(
        WS1, filters={"isDeleted": False, "isArchived": False}, sort=None, limit=50, offset=0
    )


@pytest.mark.parametrize(
    "args",
    [
        {"types": "PHISHING_WEBSITE"},
        {"statuses": "IN_REVIEW"},
        {"severities": "High"},
        {"sort_by": "incident_date"},
        {"sort_by": "severity", "sort_order": "DESC"},
        {"time_range_field": "incidentDate"},
    ],
)
def test_incident_list_command_rejects_wrong_enum_casing(args):
    """
    Given: enum values with the wrong casing (the API expects lowercase).
    When: the command runs.
    Then: it fails locally, before any request is made.
    """
    client = MagicMock()
    with pytest.raises(DemistoException):
        incident_list_command(client, args, [WS1])
    client.incidents_list.assert_not_called()


def test_incident_list_command_requires_workspace_when_several_configured():
    """
    Given: an instance configured with two workspaces and no workspace_id argument.
    When: the command runs.
    Then: it asks for the workspace_id argument.
    """
    with pytest.raises(DemistoException, match="workspace_id"):
        incident_list_command(MagicMock(), {}, [WS1, WS2])


def test_module_success():
    """
    Given: a client that answers correctly for every configured workspace.
    When: test-module runs.
    Then: it returns 'ok' after probing each workspace with limit=1.
    """
    client = MagicMock()
    client.incidents_list.return_value = {"incidents": []}
    assert run_test_module(client, [WS1, WS2], {"isFetch": True, "first_fetch": "3 days", "max_fetch": "50"}) == "ok"
    assert client.incidents_list.call_count == 2
    assert client.incidents_list.call_args.kwargs["limit"] == 1


def test_module_authorization_failure():
    """
    Given: the API rejects the token.
    When: test-module runs.
    Then: a readable authorization message is returned instead of a stack trace.
    """
    client = MagicMock()
    client.incidents_list.side_effect = DemistoException("Authorization Error: make sure the API Token is correct")
    assert "Authorization Error" in run_test_module(client, [WS1], {})


def test_module_other_failure_is_raised():
    """
    Given: the API answers 500.
    When: test-module runs.
    Then: the exception propagates so main() reports it with return_error.
    """
    client = MagicMock()
    client.incidents_list.side_effect = DemistoException("Error in API call [500] - Internal Server Error")
    with pytest.raises(DemistoException, match="500"):
        run_test_module(client, [WS1], {})


def test_module_rejects_bad_fetch_settings():
    """
    Given: fetch enabled with an invalid max_fetch.
    When: test-module runs.
    Then: it fails before calling the API.
    """
    client = MagicMock()
    with pytest.raises(DemistoException, match="max_fetch"):
        run_test_module(client, [WS1], {"isFetch": True, "max_fetch": "9999"})
    client.incidents_list.assert_not_called()


# endregion


# region Fetch ---------------------------------------------------------------------------------------------------
def test_incident_to_xsoar_mapping():
    """
    Given: a Brand Control incident.
    When: it is mapped to an XSOAR incident.
    Then: occurred comes from incidentDate, severity is 1-4, the name is stable and rawJSON has the full record.
    """
    record = {
        "incidentId": "abc",
        "incidentDate": 1790985600123,
        "severity": "critical",
        "title": "Look-alike",
        "description": "d",
    }
    mapped = incident_to_xsoar(record)
    assert mapped["name"] == "KELA Brand Control - Look-alike [abc]"
    assert mapped["occurred"] == "2026-10-03T00:00:00.123Z"
    assert mapped["severity"] == 4
    assert json.loads(mapped["rawJSON"]) == record
    assert incident_to_xsoar(record)["name"] == mapped["name"]
    assert {incident_to_xsoar({**record, "severity": s})["severity"] for s in ("low", "medium", "high")} == {1, 2, 3}


def test_fetch_no_duplicates_after_many_idle_cycles():
    """
    Given: three incidents and a startDate-inclusive API.
    When: fetch runs 30 cycles with no new data.
    Then: each incident is created exactly once and idle cycles create nothing.
    """
    api, store = FakeAPI(), FakeRunStore()
    for i, ts in enumerate([1000, 2000, 3000]):
        api.add(WS1, f"id{i}", ts)
    assert store.cycle(api) == ["id0", "id1", "id2"]
    for _ in range(30):
        assert store.cycle(api) == []
    assert store.duplicates() == {}
    assert sum(store.created.values()) == 3


def test_fetch_new_records_picked_up_exactly_once():
    """
    Given: a first cycle already done.
    When: new incidents appear later (including after idle cycles).
    Then: each is fetched exactly once.
    """
    api, store = FakeAPI(), FakeRunStore()
    api.add(WS1, "a", 1000)
    store.cycle(api)
    store.cycle(api)
    api.add(WS1, "b", 2000)
    assert store.cycle(api) == ["b"]
    assert store.cycle(api) == []
    api.add(WS1, "c", 3000)
    api.add(WS1, "d", 3500)
    assert store.cycle(api) == ["c", "d"]
    for _ in range(5):
        assert store.cycle(api) == []
    assert store.duplicates() == {}


@pytest.mark.parametrize("tie_reverse", [False, True])
def test_fetch_records_sharing_the_watermark_timestamp(tie_reverse):
    """
    Given: several incidents with exactly the same timestamp (tie order may differ between API calls).
    When: a late incident with that same timestamp shows up after the group was fetched.
    Then: only the late one is created; nothing is duplicated whatever the tie order.
    """
    api, store = FakeAPI(tie_reverse=tie_reverse), FakeRunStore()
    for name in ("a", "b", "c"):
        api.add(WS1, name, 5000)
    assert sorted(store.cycle(api)) == ["a", "b", "c"]
    assert store.cycle(api) == []
    api.add(WS1, "d", 5000)
    assert store.cycle(api) == ["d"]
    assert store.cycle(api) == []
    assert store.duplicates() == {}


def test_fetch_max_fetch_smaller_than_same_timestamp_group():
    """
    Given: 7 incidents sharing one timestamp and a later one, with max_fetch=3.
    When: fetch runs repeatedly.
    Then: the watermark never stalls: 3 + 3 + (last group member + the later one), with no duplicates.
    """
    api, store = FakeAPI(), FakeRunStore()
    for i in range(7):
        api.add(WS1, f"g{i}", 5000)
    api.add(WS1, "later", 6000)
    sizes = [len(store.cycle(api, max_fetch=3)) for _ in range(6)]
    assert sizes == [3, 3, 2, 0, 0, 0]  # last group member + the later incident share cycle 3
    assert store.duplicates() == {}
    assert set(store.created) == {f"g{i}" for i in range(7)} | {"later"}


def test_fetch_page_size_is_max_fetch_plus_seen_ids():
    """
    Given: two incidents sharing the watermark already ingested.
    When: the next cycle runs with max_fetch=3.
    Then: the API is asked for max_fetch + len(seen_ids) = 5 records, from offset 0, sorted ascending.
    """
    api, store = FakeAPI(), FakeRunStore()
    api.add(WS1, "a", 1000)
    api.add(WS1, "b", 1000)
    store.cycle(api, max_fetch=3)
    store.cycle(api, max_fetch=3)
    last_call = api.calls[-1]
    assert last_call["limit"] == 5 and last_call["offset"] == 0
    assert last_call["sort"] == {"sortBy": "incidentDate", "order": "asc"}
    assert last_call["filters"]["timeRange"] == {"fieldName": "incident_date", "startDate": 1000}
    assert last_call["filters"]["isDeleted"] is False and last_call["filters"]["isArchived"] is False


def test_fetch_legacy_last_run_upgrade():
    """
    Given: last runs written without an ID list (flat 'last_fetch' and per-workspace 'watermark' only).
    When: the first cycle after the upgrade runs.
    Then: records on the old watermark are assumed ingested (no duplicates), newer ones are created, and the state
          now carries the ID list so the following cycles are idle.
    """
    for legacy in ({"last_fetch": 2000}, {"workspaces": {WS1: {"watermark": 2000}}}):
        api, store = FakeAPI(), FakeRunStore()
        for i, ts in enumerate([1000, 2000, 3000]):
            api.add(WS1, f"id{i}", ts)
        store.value = legacy
        assert store.cycle(api) == ["id2"]
        assert store.value["workspaces"][WS1] == {"watermark": 3000, "seen_ids": ["id2"]}
        assert store.cycle(api) == []
        assert store.duplicates() == {}


def test_fetch_legacy_with_nothing_new_records_ids_at_watermark():
    """
    Given: a legacy last run and no incident newer than the watermark.
    When: the cycle runs.
    Then: nothing is created and the IDs at the watermark are stored (upgrade completed).
    """
    api, store = FakeAPI(), FakeRunStore()
    api.add(WS1, "x", 2000)
    store.value = {"last_fetch": 2000}
    assert store.cycle(api) == []
    assert store.value["workspaces"][WS1] == {"watermark": 2000, "seen_ids": ["x"]}


def test_fetch_severity_filtered_records_advance_the_watermark():
    """
    Given: only 'critical' incidents are wanted, and the newest records are low severity.
    When: fetch runs.
    Then: low ones are not created but the watermark moves past them, so they are not re-requested forever.
    """
    api, store = FakeAPI(), FakeRunStore()
    api.add(WS1, "low1", 1000, severity="low")
    api.add(WS1, "crit", 2000, severity="critical")
    api.add(WS1, "low2", 3000, severity="low")
    assert store.cycle(api, severities=["critical"]) == ["crit"]
    assert store.value["workspaces"][WS1]["watermark"] == 3000
    assert store.cycle(api, severities=["Critical"]) == []
    assert api.calls[-1]["filters"]["timeRange"]["startDate"] == 3000
    api.add(WS1, "crit2", 4000, severity="critical")
    assert store.cycle(api, severities=["critical"]) == ["crit2"]
    assert store.duplicates() == {}


def test_fetch_disabled_source_keeps_state():
    """
    Given: two workspaces fetched, then one is removed from the configuration for a while.
    When: it is configured again.
    Then: its watermark and IDs were preserved, so it resumes without duplicates and without losing records.
    """
    api, store = FakeAPI(), FakeRunStore()
    api.add(WS1, "a1", 1000)
    api.add(WS2, "b1", 1500)
    assert sorted(store.cycle(api, workspaces=(WS1, WS2))) == ["a1", "b1"]
    saved_ws2 = json.loads(json.dumps(store.value["workspaces"][WS2]))

    api.add(WS1, "a2", 2000)
    api.add(WS2, "b2", 2500)  # appears while WS2 is disabled
    assert store.cycle(api, workspaces=(WS1,)) == ["a2"]
    assert store.value["workspaces"][WS2] == saved_ws2
    assert all(call["workspace_id"] == WS1 for call in api.calls[-1:])

    assert store.cycle(api, workspaces=(WS1, WS2)) == ["b2"]
    assert store.cycle(api, workspaces=(WS1, WS2)) == []
    assert store.duplicates() == {}


def test_fetch_independent_state_per_workspace():
    """
    Given: two workspaces with different timestamps.
    When: fetch runs.
    Then: each workspace has its own watermark and seen IDs.
    """
    api, store = FakeAPI(), FakeRunStore()
    api.add(WS1, "a", 1000)
    api.add(WS2, "b", 9000)
    store.cycle(api, workspaces=(WS1, WS2))
    assert store.value["workspaces"][WS1] == {"watermark": 1000, "seen_ids": ["a"]}
    assert store.value["workspaces"][WS2] == {"watermark": 9000, "seen_ids": ["b"]}


def test_fetch_first_run_without_data_pins_watermark_to_first_fetch():
    """
    Given: an empty workspace.
    When: the first cycle runs.
    Then: the watermark is stored at first_fetch (so a sliding relative window cannot skip anything).
    """
    api, store = FakeAPI(), FakeRunStore()
    assert store.cycle(api, first_fetch_ms=777) == []
    assert store.value["workspaces"][WS1] == {"watermark": 777, "seen_ids": []}


def test_fetch_ignores_records_without_id_or_date_and_deleted_archived():
    """
    Given: malformed records and deleted/archived incidents.
    When: fetch runs.
    Then: malformed ones are ignored and the API is asked to exclude deleted/archived incidents.
    """
    api, store = FakeAPI(), FakeRunStore()
    api.add(WS1, "ok", 1000)
    api.add(WS1, "del", 1100, isDeleted=True)
    api.add(WS1, "arc", 1200, isArchived=True)
    api.records[WS1].append({"incidentId": "nodate", "isDeleted": False, "isArchived": False, "incidentDate": None})
    assert store.cycle(api) == ["ok"]


def test_fetch_caps_the_stored_id_list():
    """
    Given: more same-timestamp incidents than SEEN_IDS_CAP.
    When: fetch runs enough cycles to consume them.
    Then: the stored list never exceeds the cap and the page size never exceeds the API maximum.
    """
    api, store = FakeAPI(), FakeRunStore()
    for i in range(SEEN_IDS_CAP + 30):
        api.add(WS1, f"id{i:04d}", 5000)
    for _ in range(4):
        store.cycle(api, max_fetch=200)
        assert len(store.value["workspaces"][WS1]["seen_ids"]) <= SEEN_IDS_CAP
    assert max(c["limit"] for c in api.calls) <= API_MAX_LIMIT


def test_fetch_failure_does_not_save_partial_state():
    """
    Given: the second workspace fails.
    When: fetch_incidents raises.
    Then: no state was returned, so the platform keeps the previous last run and retries cleanly.
    """
    api = FakeAPI()
    api.add(WS1, "a", 1000)
    original = api.incidents_list

    def flaky(workspace_id, **kwargs):
        if workspace_id == WS2:
            raise DemistoException("boom")
        return original(workspace_id, **kwargs)

    api.incidents_list = flaky  # type: ignore[method-assign]
    with pytest.raises(DemistoException):
        fetch_incidents(api, [WS1, WS2], {}, 0, 50, [])


def test_fake_api_reproduces_the_duplicate_bug_without_dedup():
    """
    Given: the same FakeAPI and a NAIVE fetch (watermark only, no seen IDs).
    When: it runs three cycles with no new data.
    Then: it re-creates the watermark record every cycle. This proves the fake API is faithful to the real bug
          and that the regression tests above are meaningful.
    """
    api = FakeAPI()
    api.add(WS1, "a", 1000)
    api.add(WS1, "b", 2000)
    watermark, created = 0, Counter()
    for _ in range(3):
        rows = api.incidents_list(WS1, filters={"timeRange": {"startDate": watermark}})["incidents"]
        for row in rows:
            created[row["incidentId"]] += 1
            watermark = max(watermark, row["incidentDate"])
    assert created["b"] == 3  # duplicated every cycle


# endregion
