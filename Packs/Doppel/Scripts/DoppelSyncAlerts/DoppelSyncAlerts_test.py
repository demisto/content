import demistomock as demisto
import DoppelSyncAlerts
from datetime import UTC, datetime

from DoppelSyncAlerts import (
    _alert_severity,
    _build_custom_fields,
    _find_incidents_by_mirror_ids,
    _get_modified_alerts,
    _is_closed,
    _load_cursor,
    _save_cursor,
    _update_incident,
    _was_revived_after,
    main,
)

OK_ENTRY_TYPE = 1
ERROR_ENTRY_TYPE = 4


def _ok(contents):
    return [{"Type": OK_ENTRY_TYPE, "Contents": contents}]


def _error(message="boom"):
    return [{"Type": ERROR_ENTRY_TYPE, "Contents": message}]


def _alert(alert_id, queue_state="actioned", entity_state="active", severity="high", audit_logs=None):
    return {
        "id": alert_id,
        "queue_state": queue_state,
        "entity_state": entity_state,
        "severity": severity,
        "notes": None,
        "audit_logs": audit_logs if audit_logs is not None else [{"timestamp": "2026-08-01T00:00:00Z", "type": "queue_state"}],
    }


""" CURSOR """


def test_load_cursor_existing_list(mocker):
    mocker.patch.object(demisto, "executeCommand", return_value=_ok("2026-08-10T10:00:00Z"))
    assert _load_cursor("1 hour") == "2026-08-10T10:00:00Z"


def test_load_cursor_missing_list_falls_back_to_lookback(mocker):
    mocker.patch.object(demisto, "executeCommand", return_value=_error("Item not found"))
    cursor = _load_cursor("2026-08-01T00:00:00Z")
    assert cursor == "2026-08-01T00:00:00Z"


def test_save_cursor_creates_list_when_set_fails(mocker):
    calls = []

    def execute(command, args):
        calls.append(command)
        if command == "setList":
            return _error("no list")
        return _ok("done")

    mocker.patch.object(demisto, "executeCommand", side_effect=execute)
    _save_cursor("2026-08-10T10:00:00Z")
    assert calls == ["setList", "createList"]


""" MODIFIED ALERT PAGING """


def test_get_modified_alerts_short_page_is_drained(mocker):
    mocker.patch.object(demisto, "executeCommand", return_value=_ok({"alerts": [_alert("TST-1"), _alert("TST-2")]}))
    alerts, drained = _get_modified_alerts("2026-08-10T00:00:00Z", max_pages=5, instance_name=None)
    assert [alert["id"] for alert in alerts] == ["TST-1", "TST-2"]
    assert drained is True


def test_get_modified_alerts_page_cap_not_drained(mocker):
    full_page = {"alerts": [_alert(f"TST-{index}") for index in range(200)]}
    mocker.patch.object(demisto, "executeCommand", return_value=_ok(full_page))
    alerts, drained = _get_modified_alerts("2026-08-10T00:00:00Z", max_pages=2, instance_name=None)
    assert len(alerts) == 200  # duplicates across pages collapse by id
    assert drained is False


def test_get_modified_alerts_empty_first_page(mocker):
    mocker.patch.object(demisto, "executeCommand", return_value=_ok({"alerts": []}))
    alerts, drained = _get_modified_alerts("2026-08-10T00:00:00Z", max_pages=5, instance_name=None)
    assert alerts == []
    assert drained is True


""" INCIDENT MATCHING """


def test_find_incidents_by_mirror_ids_batches_and_groups(mocker):
    def execute(command, args):
        assert command == "getIncidents"
        return _ok({"data": [{"id": "100", "dbotMirrorId": "TST-1"}, {"id": "101", "dbotMirrorId": "TST-1"}]})

    mocker.patch.object(demisto, "executeCommand", side_effect=execute)
    found = _find_incidents_by_mirror_ids(["TST-1"])
    assert [incident["id"] for incident in found["TST-1"]] == ["100", "101"]


""" FIELD MAPPING """


def test_build_custom_fields_drops_missing_values():
    fields = _build_custom_fields(_alert("TST-1"))
    assert fields["doppelqueuestate"] == "actioned"
    assert fields["doppelentitystate"] == "active"
    assert "doppelnotes" not in fields
    assert isinstance(fields["doppelauditlogs"], list)


def test_build_custom_fields_skips_malformed_audit_logs():
    fields = _build_custom_fields(_alert("TST-1", audit_logs=["not-a-dict"]))
    assert "doppelauditlogs" not in fields


def test_alert_severity():
    assert _alert_severity(_alert("TST-1", severity="critical")) == 4
    assert _alert_severity(_alert("TST-1", severity="unknown")) == 0
    assert _alert_severity({"id": "TST-1"}) == 0


""" PLATFORM ADAPTER """


def test_update_incident_xsoar_uses_set_incident(mocker):
    execute = mocker.patch.object(demisto, "executeCommand", return_value=_ok("done"))
    _update_incident("100", {"doppelqueuestate": "actioned"}, 3, use_alert_commands=False)
    assert execute.call_args[0][0] == "setIncident"
    assert execute.call_args[0][1]["severity"] == 3


def test_update_incident_xsiam_uses_set_alert(mocker):
    execute = mocker.patch.object(demisto, "executeCommand", return_value=_ok("done"))
    _update_incident("100", {"doppelqueuestate": "actioned"}, 0, use_alert_commands=True)
    assert execute.call_args[0][0] == "setAlert"
    assert "severity" not in execute.call_args[0][1]


def test_update_incident_xsiam_falls_back_to_set_incident(mocker):
    calls = []

    def execute(command, args):
        calls.append(command)
        return _error("Unknown command") if command == "setAlert" else _ok("done")

    mocker.patch.object(demisto, "executeCommand", side_effect=execute)
    mocker.patch.object(demisto, "debug")
    _update_incident("100", {"doppelqueuestate": "actioned"}, 0, use_alert_commands=True)
    assert calls == ["setAlert", "setIncident"]


""" CLOSED DETECTION """


def test_is_closed():
    assert _is_closed({"status": 2}) is True
    assert _is_closed({"status": 1, "closed": "0001-01-01T00:00:00Z"}) is False
    assert _is_closed({"status": 1, "closed": "2026-08-10T10:00:00Z"}) is True
    assert _is_closed({"status": 1}) is False


""" REVIVAL """


CURSOR_DT = datetime(2026, 8, 10, 0, 0, 0, tzinfo=UTC)


def test_was_revived_after_fresh_transition_into_active_queue():
    alert = _alert(
        "TST-1",
        queue_state="doppel_review",
        audit_logs=[{"type": "queue_state_change", "value": "Doppel Review", "timestamp": "2026-08-11T00:00:00Z"}],
    )
    assert _was_revived_after(alert, CURSOR_DT) is True


def test_was_revived_after_stale_transition():
    alert = _alert(
        "TST-1",
        queue_state="actioned",
        audit_logs=[{"type": "queue_state_change", "value": "actioned", "timestamp": "2026-08-01T00:00:00Z"}],
    )
    assert _was_revived_after(alert, CURSOR_DT) is False


def test_was_revived_after_inactive_queue():
    alert = _alert(
        "TST-1",
        queue_state="monitoring",
        audit_logs=[{"type": "queue_state_change", "value": "monitoring", "timestamp": "2026-08-11T00:00:00Z"}],
    )
    assert _was_revived_after(alert, CURSOR_DT) is False


""" MAIN """


def _main_execute_factory(alerts, incidents_by_query, calls):
    def execute(command, args):
        calls.append((command, args))
        if command == "getList":
            return _ok("2026-08-10T00:00:00Z")
        if command == "doppel-get-alerts":
            page = int(args.get("page") or 0)
            return _ok({"alerts": alerts if page == 0 else []})
        if command == "getIncidents":
            return _ok({"data": incidents_by_query})
        return _ok("done")

    return execute


def test_main_updates_matched_incidents_and_advances_cursor(mocker):
    calls = []
    alerts = [_alert("TST-1"), _alert("TST-2")]
    incidents = [
        {"id": "100", "dbotMirrorId": "TST-1", "status": 1},
        {"id": "200", "dbotMirrorId": "TST-2", "status": 1},
    ]
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "executeCommand", side_effect=_main_execute_factory(alerts, incidents, calls))
    results = mocker.patch.object(DoppelSyncAlerts, "return_results")

    main()

    summary = results.call_args[0][0].outputs
    assert summary["ModifiedAlerts"] == 2
    assert summary["IncidentsUpdated"] == 2
    assert summary["IncidentsClosed"] == 0
    assert summary["CursorAdvanced"] is True
    set_incident_calls = [args for command, args in calls if command == "setIncident"]
    assert {args["id"] for args in set_incident_calls} == {"100", "200"}
    assert any(command == "setList" for command, _ in calls)


def test_main_counts_unmatched_alerts(mocker):
    calls = []
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "executeCommand", side_effect=_main_execute_factory([_alert("TST-9")], [], calls))
    results = mocker.patch.object(DoppelSyncAlerts, "return_results")

    main()

    summary = results.call_args[0][0].outputs
    assert summary["AlertsWithoutIncident"] == 1
    assert summary["IncidentsUpdated"] == 0


def test_main_close_archived_closes_open_incident(mocker):
    calls = []
    alerts = [_alert("TST-1", queue_state="archived")]
    incidents = [{"id": "100", "dbotMirrorId": "TST-1", "status": 1}]
    mocker.patch.object(demisto, "args", return_value={"close_archived": "true"})
    mocker.patch.object(demisto, "executeCommand", side_effect=_main_execute_factory(alerts, incidents, calls))
    results = mocker.patch.object(DoppelSyncAlerts, "return_results")

    main()

    summary = results.call_args[0][0].outputs
    assert summary["IncidentsClosed"] == 1
    close_calls = [args for command, args in calls if command == "closeInvestigation"]
    assert close_calls
    assert close_calls[0]["id"] == "100"


def test_main_reopens_closed_incident_for_revived_alert(mocker):
    calls = []
    alerts = [
        _alert(
            "TST-1",
            queue_state="doppel_review",
            audit_logs=[{"type": "queue_state_change", "value": "doppel_review", "timestamp": "2026-08-11T00:00:00Z"}],
        )
    ]
    incidents = [{"id": "100", "dbotMirrorId": "TST-1", "status": 2}]
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "executeCommand", side_effect=_main_execute_factory(alerts, incidents, calls))
    results = mocker.patch.object(DoppelSyncAlerts, "return_results")

    main()

    summary = results.call_args[0][0].outputs
    assert summary["IncidentsReopened"] == 1
    reopen_calls = [args for command, args in calls if command == "reopenInvestigation"]
    assert reopen_calls
    assert reopen_calls[0]["id"] == "100"


def test_main_does_not_reopen_when_transition_predates_cursor(mocker):
    calls = []
    alerts = [
        _alert(
            "TST-1",
            queue_state="doppel_review",
            audit_logs=[{"type": "queue_state_change", "value": "doppel_review", "timestamp": "2026-08-01T00:00:00Z"}],
        )
    ]
    incidents = [{"id": "100", "dbotMirrorId": "TST-1", "status": 2}]
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "executeCommand", side_effect=_main_execute_factory(alerts, incidents, calls))
    results = mocker.patch.object(DoppelSyncAlerts, "return_results")

    main()

    summary = results.call_args[0][0].outputs
    assert summary["IncidentsReopened"] == 0
    assert not any(command == "reopenInvestigation" for command, _ in calls)


def test_main_reopen_can_be_disabled(mocker):
    calls = []
    alerts = [
        _alert(
            "TST-1",
            queue_state="doppel_review",
            audit_logs=[{"type": "queue_state_change", "value": "doppel_review", "timestamp": "2026-08-11T00:00:00Z"}],
        )
    ]
    incidents = [{"id": "100", "dbotMirrorId": "TST-1", "status": 2}]
    mocker.patch.object(demisto, "args", return_value={"reopen_revived": "false"})
    mocker.patch.object(demisto, "executeCommand", side_effect=_main_execute_factory(alerts, incidents, calls))
    results = mocker.patch.object(DoppelSyncAlerts, "return_results")

    main()

    summary = results.call_args[0][0].outputs
    assert summary["IncidentsReopened"] == 0
    assert not any(command == "reopenInvestigation" for command, _ in calls)


def test_main_dry_run_does_not_write(mocker):
    calls = []
    alerts = [_alert("TST-1")]
    incidents = [{"id": "100", "dbotMirrorId": "TST-1", "status": 1}]
    mocker.patch.object(demisto, "args", return_value={"dry_run": "true"})
    mocker.patch.object(demisto, "executeCommand", side_effect=_main_execute_factory(alerts, incidents, calls))
    results = mocker.patch.object(DoppelSyncAlerts, "return_results")

    main()

    summary = results.call_args[0][0].outputs
    assert summary["IncidentsUpdated"] == 1  # counted, not written
    assert summary["CursorAdvanced"] is False
    commands = [command for command, _ in calls]
    assert "setIncident" not in commands
    assert "setList" not in commands


def test_main_error_keeps_cursor(mocker):
    calls = []
    alerts = [_alert("TST-1")]
    incidents = [{"id": "100", "dbotMirrorId": "TST-1", "status": 1}]

    def execute(command, args):
        calls.append((command, args))
        if command == "getList":
            return _ok("2026-08-10T00:00:00Z")
        if command == "doppel-get-alerts":
            return _ok({"alerts": alerts if int(args.get("page") or 0) == 0 else []})
        if command == "getIncidents":
            return _ok({"data": incidents})
        if command == "setIncident":
            return _error("write failed")
        return _ok("done")

    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "executeCommand", side_effect=execute)
    results = mocker.patch.object(DoppelSyncAlerts, "return_results")

    main()

    summary = results.call_args[0][0].outputs
    assert summary["Errors"] == 1
    assert summary["CursorAdvanced"] is False
    assert not any(command == "setList" for command, _ in calls)
