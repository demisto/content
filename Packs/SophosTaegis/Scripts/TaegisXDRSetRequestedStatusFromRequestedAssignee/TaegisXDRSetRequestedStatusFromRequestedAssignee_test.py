import demistomock as demisto
from TaegisXDRSetRequestedStatusFromRequestedAssignee import (
    _fetch_latest_incident,
    _get_incident,
    _normalize_assignee_id_raw,
    _resolve_current_assignee_queue,
    main,
)


def test_get_incident_unwraps_incident_key(mocker):
    mocker.patch.object(demisto, "incident", return_value={"incident": {"id": "1"}})
    assert _get_incident() == {"id": "1"}


def test_get_incident_unwraps_capital_incident_key(mocker):
    mocker.patch.object(demisto, "incident", return_value={"Incident": {"id": "1"}})
    assert _get_incident() == {"id": "1"}


def test_get_incident_returns_empty_dict_when_none(mocker):
    mocker.patch.object(demisto, "incident", return_value=None)
    assert _get_incident() == {}


def test_normalize_assignee_id_raw_variants():
    assert _normalize_assignee_id_raw("@customer") == "@customer"
    assert _normalize_assignee_id_raw("customer") == "@customer"
    assert _normalize_assignee_id_raw("@secureworks") == "@secureworks"
    assert _normalize_assignee_id_raw("some-uuid-1234") == "__specific_user__"
    assert _normalize_assignee_id_raw("") is None
    assert _normalize_assignee_id_raw(None) is None


def test_resolve_current_assignee_queue_from_id_field():
    incident = {"taegisxdrassigneeid": "@customer"}
    assert _resolve_current_assignee_queue(incident) == "@customer"


def test_resolve_current_assignee_queue_falls_back_to_display_name():
    incident = {"taegisxdrassignee": "customer"}
    assert _resolve_current_assignee_queue(incident) == "@customer"


def test_resolve_current_assignee_queue_specific_user_returns_none():
    incident = {"taegisxdrassigneeid": "uuid-real-user"}
    assert _resolve_current_assignee_queue(incident) is None


def test_fetch_latest_incident_returns_contents_dict(mocker):
    mocker.patch.object(demisto, "executeCommand", return_value=[{"Contents": {"id": "1", "foo": "bar"}}])
    assert _fetch_latest_incident("1") == {"id": "1", "foo": "bar"}


def test_fetch_latest_incident_handles_exception(mocker):
    mocker.patch.object(demisto, "executeCommand", side_effect=Exception("boom"))
    mocker.patch.object(demisto, "debug")
    assert _fetch_latest_incident("1") is None


def test_main_skips_when_no_requested_assignee(mocker):
    mocker.patch.object(demisto, "incident", return_value={})
    mocker.patch.object(demisto, "debug")
    execute_command_mock = mocker.patch.object(demisto, "executeCommand")

    main()

    execute_command_mock.assert_not_called()


def test_main_skips_when_placeholder_assignee(mocker):
    mocker.patch.object(demisto, "incident", return_value={"taegisrequestedassignee": "Select Assignee"})
    mocker.patch.object(demisto, "debug")
    execute_command_mock = mocker.patch.object(demisto, "executeCommand")

    main()

    execute_command_mock.assert_not_called()


def test_main_requested_secureworks_sets_awaiting_action(mocker):
    mocker.patch.object(
        demisto,
        "incident",
        return_value={"taegisrequestedassignee": "@secureworks", "taegisxdrassigneeid": "uuid-real-user"},
    )
    mocker.patch.object(demisto, "debug")
    execute_command_mock = mocker.patch.object(demisto, "executeCommand")

    main()

    execute_command_mock.assert_called_once_with("setIncident", {"taegisrequestedstatus": "AWAITING_ACTION"})


def test_main_requested_customer_from_secureworks_sets_awaiting_action(mocker):
    mocker.patch.object(
        demisto,
        "incident",
        return_value={"taegisrequestedassignee": "@customer", "taegisxdrassigneeid": "@secureworks"},
    )
    mocker.patch.object(demisto, "debug")
    execute_command_mock = mocker.patch.object(demisto, "executeCommand")

    main()

    execute_command_mock.assert_called_once_with("setIncident", {"taegisrequestedstatus": "AWAITING_ACTION"})


def test_main_customer_takes_ownership_sets_active(mocker):
    mocker.patch.object(
        demisto,
        "incident",
        return_value={"taegisrequestedassignee": "userA", "taegisxdrassigneeid": "@customer"},
    )
    mocker.patch.object(demisto, "debug")
    execute_command_mock = mocker.patch.object(demisto, "executeCommand")

    main()

    execute_command_mock.assert_called_once_with("setIncident", {"taegisrequestedstatus": "ACTIVE"})


def test_main_handoff_between_specific_users_sets_awaiting_action(mocker):
    mocker.patch.object(
        demisto,
        "incident",
        return_value={"taegisrequestedassignee": "userB", "taegisxdrassigneeid": "uuid-current-user"},
    )
    mocker.patch.object(demisto, "debug")
    execute_command_mock = mocker.patch.object(demisto, "executeCommand")

    main()

    execute_command_mock.assert_called_once_with("setIncident", {"taegisrequestedstatus": "AWAITING_ACTION"})


def test_main_take_from_queue_sets_active(mocker):
    mocker.patch.object(
        demisto,
        "incident",
        return_value={"taegisrequestedassignee": "userA", "taegisxdrassigneeid": "@secureworks"},
    )
    mocker.patch.object(demisto, "debug")
    execute_command_mock = mocker.patch.object(demisto, "executeCommand")

    main()

    execute_command_mock.assert_called_once_with("setIncident", {"taegisrequestedstatus": "ACTIVE"})
