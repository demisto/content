import demistomock as demisto
from DoppelDedupeIncidents import (
    _alert_key,
    _is_closed,
    _ranked,
    _to_dt,
    plan_dedupe,
    search_incidents,
    main,
)


def _inc(inc_id, alert_id, created, owner="", status=1, close_reason="", closed=""):
    return {
        "id": inc_id,
        "name": f"Doppel Alert {alert_id}",
        "created": created,
        "owner": owner,
        "status": status,
        "closeReason": close_reason,
        "closed": closed,
        "dbotMirrorId": alert_id,
    }


def test_to_dt():
    parsed = _to_dt("2025-01-27T07:55:10.063742Z")
    assert parsed is not None
    assert (parsed.year, parsed.month, parsed.day, parsed.hour, parsed.minute, parsed.second) == (2025, 1, 27, 7, 55, 10)
    assert parsed.tzinfo is not None  # arg_to_datetime returns a timezone-aware datetime
    assert _to_dt("") is None
    assert _to_dt(None) is None
    assert _to_dt("garbage") is None


def test_alert_key():
    assert _alert_key({"dbotMirrorId": "TET-1"}) == "TET-1"
    assert _alert_key({"CustomFields": {"doppelalertid": "TET-2"}}) == "TET-2"
    assert _alert_key({"CustomFields": {}}) == ""
    assert _alert_key({}) == ""


def test_is_closed():
    assert _is_closed({"status": 2}) is True
    assert _is_closed({"status": "2"}) is True
    assert _is_closed({"closeReason": "False Positive"}) is True
    assert _is_closed({"closed": "2025-01-27T07:55:10Z"}) is True
    # Open incident: status 1, no close reason, default (year 0001) closed timestamp.
    assert _is_closed({"status": 1, "closeReason": "", "closed": "0001-01-01T00:00:00Z"}) is False
    assert _is_closed({}) is False


def test_ranked_orders_by_created_then_id():
    group = [
        _inc("30", "TET-1", "2025-01-27T09:00:00"),
        _inc("10", "TET-1", "2025-01-27T07:00:00"),
        _inc("20", "TET-1", "2025-01-27T07:00:00"),
    ]
    ordered = _ranked(group)
    assert [i["id"] for i in ordered] == ["10", "20", "30"]


def test_plan_dedupe_keeps_oldest_open():
    incidents = [
        _inc("10", "TET-1", "2025-01-27T07:00:00"),
        _inc("11", "TET-1", "2025-01-27T08:00:00"),
        _inc("12", "TET-1", "2025-01-27T09:00:00"),
    ]
    plan = plan_dedupe(incidents)
    assert plan["group_count"] == 1
    assert len(plan["actions"]) == 2
    assert all(a["keep_id"] == "10" for a in plan["actions"])
    assert sorted(a["victim_id"] for a in plan["actions"]) == ["11", "12"]


def test_plan_dedupe_prefers_owned_survivor():
    incidents = [
        _inc("10", "TET-1", "2025-01-27T07:00:00"),  # oldest, unowned
        _inc("11", "TET-1", "2025-01-27T08:00:00", owner="analyst"),  # owned
        _inc("12", "TET-1", "2025-01-27T09:00:00"),
    ]
    plan = plan_dedupe(incidents)
    assert {a["keep_id"] for a in plan["actions"]} == {"11"}
    assert sorted(a["victim_id"] for a in plan["actions"]) == ["10", "12"]
    # The unowned victims are not flagged; owner-bearing victims would be.
    assert plan["flagged"] == []


def test_plan_dedupe_never_touches_closed():
    incidents = [
        _inc("10", "TET-1", "2025-01-27T07:00:00", status=2, close_reason="False Positive"),
        _inc("11", "TET-1", "2025-01-27T08:00:00"),
        _inc("12", "TET-1", "2025-01-27T09:00:00"),
    ]
    plan = plan_dedupe(incidents)
    assert plan["skipped_closed"] == 1
    # Only the two open ones are consolidated; the closed one is never a victim or survivor.
    victim_ids = {a["victim_id"] for a in plan["actions"]}
    keep_ids = {a["keep_id"] for a in plan["actions"]}
    assert "10" not in victim_ids and "10" not in keep_ids
    assert victim_ids == {"12"} and keep_ids == {"11"}


def test_plan_dedupe_single_open_no_action():
    incidents = [
        _inc("10", "TET-1", "2025-01-27T07:00:00", status=2, close_reason="Duplicate"),
        _inc("11", "TET-1", "2025-01-27T08:00:00"),
    ]
    plan = plan_dedupe(incidents)
    assert plan["actions"] == []
    assert plan["group_count"] == 0
    assert plan["skipped_closed"] == 1


def _page(data):
    # Mirror a real XSOAR command entry (note type) so is_error() can inspect it.
    return [{"Type": 1, "Contents": {"data": data}}]


def test_search_incidents_pages_until_short_page(mocker):
    """Robust against total=0: pages until a page returns fewer than page_size rows."""
    full = [_inc(str(i), f"TET-{i}", "2025-01-27T07:00:00") for i in range(100)]
    tail = [_inc("100", "TET-100", "2025-01-27T07:00:00")]
    mocker.patch.object(demisto, "executeCommand", side_effect=[_page(full), _page(tail)])
    result = search_incidents("query", page_size=100, max_pages=10)
    assert len(result) == 101


def test_search_incidents_stops_on_empty_page(mocker):
    mocker.patch.object(demisto, "executeCommand", side_effect=[_page([]), _page([{"id": "x"}])])
    result = search_incidents("query", page_size=100, max_pages=10)
    assert result == []


def test_main_dry_run_reports_without_changes(mocker):
    incidents = [
        _inc("10", "TET-1", "2025-01-27T07:00:00"),
        _inc("11", "TET-1", "2025-01-27T08:00:00"),
    ]
    mocker.patch.object(demisto, "args", return_value={"dry_run": "true"})
    exec_mock = mocker.patch.object(demisto, "executeCommand", side_effect=[_page(incidents), _page([])])
    return_results = mocker.patch("DoppelDedupeIncidents.return_results")

    main()

    # No close/delete executed in a dry run - only the getIncidents scan calls.
    assert all(c.args[0] == "getIncidents" for c in exec_mock.call_args_list)
    outputs = return_results.call_args[0][0][0].outputs
    assert outputs["dry_run"] is True
    assert outputs["total_actions"] == 1
    assert outputs["performed"] == []


def test_main_close_respects_limit(mocker):
    incidents = [
        _inc("10", "TET-1", "2025-01-27T07:00:00"),
        _inc("11", "TET-1", "2025-01-27T08:00:00"),
        _inc("12", "TET-1", "2025-01-27T09:00:00"),
    ]
    mocker.patch.object(demisto, "args", return_value={"dry_run": "false", "action": "close", "limit": "1"})
    exec_mock = mocker.patch.object(demisto, "executeCommand", side_effect=[_page(incidents), _page([]), None])
    return_results = mocker.patch("DoppelDedupeIncidents.return_results")

    main()

    close_calls = [c for c in exec_mock.call_args_list if c.args[0] == "closeInvestigation"]
    assert len(close_calls) == 1  # capped by limit
    outputs = return_results.call_args[0][0][0].outputs
    assert outputs["total_actions"] == 2
    assert outputs["remaining"] == 1
