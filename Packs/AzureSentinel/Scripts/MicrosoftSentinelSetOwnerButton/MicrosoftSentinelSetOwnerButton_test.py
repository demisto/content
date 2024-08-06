import demistomock as demisto
import CommonServerPython


def test_set_owner(mocker):
    context_results = {
        "CustomFields": {"sourceid": "incident-123"},
        "labels": [{"type": "Instance", "value": "Azure Sentinel_instance_1"}],
    }

    demisto_args = {"owner_email": "test@test.com"}
    expected_instance_name = "Azure Sentinel_instance_1"
    expected_incident_id = "incident-123"
    expected_owner_email = "test@test.com"

    owner = {
        "assignedTo": "Owner Name",
        "email": "test@test.com",
        "objectId": "owner-object-id",
        "userPrincipalName": "test@test.com",
    }

    mocker.patch.object(demisto, "args", return_value=demisto_args)
    debug_mock = mocker.patch.object(demisto, "debug")
    execute_command_mock = mocker.patch.object(CommonServerPython, "execute_command")
    mocker.patch.object(CommonServerPython, "dict_safe_get", return_value=owner)
    table_to_markdown_mock = mocker.patch.object(
        CommonServerPython, "tableToMarkdown", return_value="Markdown Table"
    )
    command_results_mock = mocker.patch.object(
        CommonServerPython, "CommandResults", return_value="Command Results"
    )

    from MicrosoftSentinelSetOwnerButton import set_owner

    result = set_owner(context_results)

    debug_mock.assert_any_call(
        f"set owner remote incident with owner email {expected_owner_email}"
    )
    execute_command_mock.assert_called_once_with(
        "azure-sentinel-update-incident",
        {
            "using": expected_instance_name,
            "incident_id": expected_incident_id,
            "user_principal_name": expected_owner_email,
        },
    )
    table_to_markdown_mock.assert_called_once_with(
        f"Updated incident {expected_incident_id} with new owner",
        {
            "assignedTo": "Owner Name",
            "email": "test@test.com",
            "objectId": "owner-object-id",
            "userPrincipalName": "test@test.com",
        },
        headers=["assignedTo", "email", "objectId", "userPrincipalName"],
        headerTransform=lambda s: s.replace("_", " ").title(),
        removeNull=True,
    )
    command_results_mock.assert_called_once_with(
        readable_output="Markdown Table",
        outputs_prefix="AzureSentinel.Incident.Owner",
        outputs={
            "assignedTo": "Owner Name",
            "email": "test@test.com",
            "objectId": "owner-object-id",
            "userPrincipalName": "test@test.com",
        },
        raw_response={
            "properties": {
                "owner": {
                    "assignedTo": "Owner Name",
                    "email": "test@test.com",
                    "objectId": "owner-object-id",
                    "userPrincipalName": "test@test.com",
                }
            }
        },
    )
    assert result == "Command Results"
