import demistomock as demisto
from TaegisXDRPushAssigneeStatusForm import main


def test_main_no_incident_context(mocker):
    mocker.patch.object(demisto, "incident", return_value=None)
    return_results_mock = mocker.patch("TaegisXDRPushAssigneeStatusForm.return_results")

    main()

    entries = return_results_mock.call_args[0][0]
    assert "No incident context" in entries[0]["Contents"]


def test_main_no_fields_selected_prompts_user(mocker):
    mocker.patch.object(
        demisto,
        "incident",
        return_value={"CustomFields": {"taegisxdrrequestedassignee": "Select Assignee", "taegisxdrrequestedstatus": "Select Status"}},
    )
    return_results_mock = mocker.patch("TaegisXDRPushAssigneeStatusForm.return_results")

    main()

    entries = return_results_mock.call_args[0][0]
    assert "Select **Taegis XDR Requested Assignee**" in entries[0]["Contents"]


def test_main_no_mirror_id_blocks_push(mocker):
    mocker.patch.object(
        demisto,
        "incident",
        return_value={"CustomFields": {"taegisxdrrequestedassignee": "userA"}},
    )
    return_results_mock = mocker.patch("TaegisXDRPushAssigneeStatusForm.return_results")

    main()

    entries = return_results_mock.call_args[0][0]
    assert "not mirrored from Taegis" in entries[0]["Contents"]


def test_main_pushes_assignee_and_status_then_resets_placeholders(mocker):
    mocker.patch.object(
        demisto,
        "incident",
        return_value={
            "CustomFields": {
                "taegisxdrrequestedassignee": "userA",
                "taegisxdrrequestedstatus": "ACTIVE",
                "dbotMirrorId": "inv-42",
            }
        },
    )
    push_result = [{"Type": 1, "Contents": "pushed"}]
    execute_command_mock = mocker.patch.object(demisto, "executeCommand", return_value=push_result)
    return_results_mock = mocker.patch("TaegisXDRPushAssigneeStatusForm.return_results")

    main()

    push_call, reset_call = execute_command_mock.call_args_list
    assert push_call.args == ("taegis-push-assignee-status", {"id": "inv-42", "assignee_id": "userA", "status": "ACTIVE"})
    assert reset_call.args == (
        "setIncident",
        {"taegisxdrrequestedassignee": "Select Assignee", "taegisxdrrequestedstatus": "Select Status"},
    )
    return_results_mock.assert_called_once_with(push_result)


def test_main_handles_failed_push(mocker):
    mocker.patch.object(
        demisto,
        "incident",
        return_value={"CustomFields": {"taegisxdrrequestedassignee": "userA", "dbotMirrorId": "inv-42"}},
    )
    mocker.patch.object(demisto, "executeCommand", return_value=None)
    return_results_mock = mocker.patch("TaegisXDRPushAssigneeStatusForm.return_results")

    main()

    entries = return_results_mock.call_args[0][0]
    assert "Request could not be sent" in entries[0]["Contents"]
