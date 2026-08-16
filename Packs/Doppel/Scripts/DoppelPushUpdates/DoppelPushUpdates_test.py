import demistomock as demisto
import DoppelPushUpdates
from DoppelPushUpdates import (
    _closed_incidents_query,
    _get_closed_incidents,
    _should_push,
    main,
)

OK_ENTRY_TYPE = 1
ERROR_ENTRY_TYPE = 4


def _ok(contents):
    return [{"Type": OK_ENTRY_TYPE, "Contents": contents}]


def _error(message="boom"):
    return [{"Type": ERROR_ENTRY_TYPE, "Contents": message}]


def _incident(mirror_id, close_reason="Resolved", close_notes="Handled by analyst."):
    return {"id": "100", "dbotMirrorId": mirror_id, "closeReason": close_reason, "closeNotes": close_notes}


""" QUERY / PAGING """


def test_closed_incidents_query_contains_types_and_cursor():
    query = _closed_incidents_query("2026-08-10T00:00:00Z")
    assert 'type:"Doppel Alert Domains"' in query
    assert 'type:"Doppel Alert Telco"' in query
    assert 'type:"Doppel_Incident"' in query
    assert 'closed:>="2026-08-10T00:00:00Z"' in query


def test_get_closed_incidents_short_page_is_drained(mocker):
    mocker.patch.object(demisto, "executeCommand", return_value=_ok({"data": [_incident("TST-1")]}))
    incidents, drained = _get_closed_incidents("2026-08-10T00:00:00Z", max_incidents=500)
    assert len(incidents) == 1
    assert drained is True


def test_get_closed_incidents_cap_not_drained(mocker):
    full_page = {"data": [_incident(f"TST-{index}") for index in range(100)]}
    mocker.patch.object(demisto, "executeCommand", return_value=_ok(full_page))
    incidents, drained = _get_closed_incidents("2026-08-10T00:00:00Z", max_incidents=100)
    assert len(incidents) == 100
    assert drained is False


""" PUSH FILTERING """


def test_should_push_skips_duplicate_closures():
    assert _should_push(_incident("TST-1", close_reason="Duplicate")) is False
    assert _should_push(_incident("TST-1", close_reason="duplicate")) is False
    assert _should_push(_incident("TST-1", close_reason="False Positive")) is True
    assert _should_push(_incident("TST-1", close_reason="")) is True


""" MAIN """


def _main_execute_factory(closed_incidents, live_alerts, calls):
    def execute(command, args):
        calls.append((command, args))
        if command == "getList":
            return _ok("2026-08-10T00:00:00Z")
        if command == "getIncidents":
            page = int(args.get("page") or 0)
            return _ok({"data": closed_incidents if page == 0 else []})
        if command == "doppel-get-alert":
            return _ok(live_alerts.get(args["id"]) or {})
        return _ok("done")

    return execute


def test_main_archives_closed_incident_with_close_notes(mocker):
    calls = []
    live_alerts = {"TST-1": {"id": "TST-1", "queue_state": "actioned"}}
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "executeCommand", side_effect=_main_execute_factory([_incident("TST-1")], live_alerts, calls))
    results = mocker.patch.object(DoppelPushUpdates, "return_results")

    main()

    summary = results.call_args[0][0].outputs
    assert summary["AlertsArchived"] == 1
    assert summary["CursorAdvanced"] is True
    update_calls = [args for command, args in calls if command == "doppel-update-alert"]
    assert update_calls == [{"alert_id": "TST-1", "queue_state": "archived", "comment": "Handled by analyst."}]


def test_main_skips_already_archived_alert(mocker):
    calls = []
    live_alerts = {"TST-1": {"id": "TST-1", "queue_state": "archived"}}
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "executeCommand", side_effect=_main_execute_factory([_incident("TST-1")], live_alerts, calls))
    results = mocker.patch.object(DoppelPushUpdates, "return_results")

    main()

    summary = results.call_args[0][0].outputs
    assert summary["AlreadyArchived"] == 1
    assert summary["AlertsArchived"] == 0
    assert not any(command == "doppel-update-alert" for command, _ in calls)


def test_main_skips_duplicate_closures_and_dedupes_mirror_ids(mocker):
    calls = []
    closed = [
        _incident("TST-1", close_reason="Duplicate"),
        _incident("TST-2"),
        _incident("TST-2"),
    ]
    live_alerts = {"TST-2": {"id": "TST-2", "queue_state": "actioned"}}
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "executeCommand", side_effect=_main_execute_factory(closed, live_alerts, calls))
    results = mocker.patch.object(DoppelPushUpdates, "return_results")

    main()

    summary = results.call_args[0][0].outputs
    assert summary["AlertsArchived"] == 1
    assert summary["Skipped"] == 2
    update_calls = [args for command, args in calls if command == "doppel-update-alert"]
    assert len(update_calls) == 1


def test_main_push_close_notes_disabled_omits_comment(mocker):
    calls = []
    live_alerts = {"TST-1": {"id": "TST-1", "queue_state": "actioned"}}
    mocker.patch.object(demisto, "args", return_value={"push_close_notes": "false"})
    mocker.patch.object(demisto, "executeCommand", side_effect=_main_execute_factory([_incident("TST-1")], live_alerts, calls))
    mocker.patch.object(DoppelPushUpdates, "return_results")

    main()

    update_calls = [args for command, args in calls if command == "doppel-update-alert"]
    assert update_calls == [{"alert_id": "TST-1", "queue_state": "archived"}]


def test_main_dry_run_does_not_write(mocker):
    calls = []
    live_alerts = {"TST-1": {"id": "TST-1", "queue_state": "actioned"}}
    mocker.patch.object(demisto, "args", return_value={"dry_run": "true"})
    mocker.patch.object(demisto, "executeCommand", side_effect=_main_execute_factory([_incident("TST-1")], live_alerts, calls))
    results = mocker.patch.object(DoppelPushUpdates, "return_results")

    main()

    summary = results.call_args[0][0].outputs
    assert summary["AlertsArchived"] == 1  # counted, not written
    assert summary["CursorAdvanced"] is False
    commands = [command for command, _ in calls]
    assert "doppel-update-alert" not in commands
    assert "setList" not in commands


def test_main_error_keeps_cursor(mocker):
    calls = []

    def execute(command, args):
        calls.append((command, args))
        if command == "getList":
            return _ok("2026-08-10T00:00:00Z")
        if command == "getIncidents":
            return _ok({"data": [_incident("TST-1")] if int(args.get("page") or 0) == 0 else []})
        if command == "doppel-get-alert":
            return _error("api down")
        return _ok("done")

    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "executeCommand", side_effect=execute)
    results = mocker.patch.object(DoppelPushUpdates, "return_results")

    main()

    summary = results.call_args[0][0].outputs
    assert summary["Errors"] == 1
    assert summary["CursorAdvanced"] is False
    assert not any(command == "setList" for command, _ in calls)
