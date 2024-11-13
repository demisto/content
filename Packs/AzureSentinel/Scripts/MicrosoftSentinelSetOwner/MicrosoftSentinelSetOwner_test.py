import demistomock as demisto
import CommonServerPython


def test_set_owner(mocker):
    context_results = {
        "CustomFields": {"sourceid": "incident-123"},
        "sourceInstance": "instance_test",
        "labels": [{"type": "Instance", "value": "Azure Sentinel_instance_1"}],
    }

    demisto_args = {"user_principal_name": "test@test.com"}
    expected_instance_name = "instance_test"
    expected_incident_id = "incident-123"
    expected_owner_email = "test@test.com"

    mocker.patch.object(demisto, "args", return_value=demisto_args)
    info_mock = mocker.patch.object(demisto, "info")
    execute_command_mock = mocker.patch.object(CommonServerPython, "execute_command")

    from MicrosoftSentinelSetOwner import set_owner

    result = set_owner(context_results)

    info_mock.assert_any_call(
        f"Assigned remote incident owner: Incident ID {expected_incident_id}, \
            Instance Name {expected_instance_name}, Owner Email {expected_owner_email}."
    )

    execute_command_mock.assert_called_once_with(
        "azure-sentinel-update-incident",
        {
            "using": expected_instance_name,
            "incident_id": expected_incident_id,
            "user_principal_name": expected_owner_email,
        },
    )

    assert result == execute_command_mock.return_value
