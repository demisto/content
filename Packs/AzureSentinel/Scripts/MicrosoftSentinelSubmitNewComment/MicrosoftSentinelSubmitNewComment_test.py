import demistomock as demisto
import CommonServerPython


def test_add_new_comment(mocker):
    context_results = {
        "CustomFields": {"sourceid": "incident-123"},
        "sourceInstance": None,
    }
    demisto_args = {"new_comment": "This is a new comment"}
    expected_instance_name = None
    expected_incident_id = "incident-123"
    expected_new_comment = "This is a new comment"
    mocker.patch.object(demisto, "args", return_value=demisto_args)
    debug_mock = mocker.patch.object(demisto, "debug")
    execute_command_mock = mocker.patch.object(CommonServerPython, "execute_command")
    table_to_markdown_mock = mocker.patch.object(
        CommonServerPython, "tableToMarkdown", return_value="Markdown Table"
    )
    command_results_mock = mocker.patch.object(
        CommonServerPython, "CommandResults", return_value="Command Results"
    )

    from MicrosoftSentinelSubmitNewComment import add_new_comment

    result = add_new_comment(context_results)
    debug_mock.assert_any_call(
        f"update remote incident with new XSOAR comments: {expected_new_comment}"
    )

    execute_command_mock.assert_called_once_with(
        "azure-sentinel-incident-add-comment",
        {
            "using": expected_instance_name,
            "incident_id": expected_incident_id,
            "message": expected_new_comment,
        },
    )

    assert result == "Command Results"
    command_results_mock.assert_called_once_with(
        readable_output="Markdown Table",
        outputs_prefix="AzureSentinel.AddComment",
        outputs={"incident_id": expected_incident_id, "message": expected_new_comment},
    )