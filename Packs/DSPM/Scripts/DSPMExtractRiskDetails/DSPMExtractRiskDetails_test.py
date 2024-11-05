from unittest.mock import patch
import json
from datetime import datetime
from DSPMExtractRiskDetails import set_user_slack_email, get_incident_details_command


def test_set_user_slack_email_with_empty_owner_list():
    # Test case where 'Owner' is an empty list, so default email should be used
    incident_details = {
        "asset Dig Tags": json.dumps({"Owner": []})
    }
    defaultSlackUser = "default@example.com"

    with patch("demistomock.setContext") as mock_setContext:
        set_user_slack_email(incident_details, defaultSlackUser)
        mock_setContext.assert_called_once_with("userSlackEmail", defaultSlackUser)


def test_set_user_slack_email_with_non_list_owner():
    # Test case where 'Owner' is not a list; default email should be used or handled
    incident_details = {
        "asset Dig Tags": json.dumps({"Owner": "owner@example.com"})  # Not a list, incorrect format
    }
    defaultSlackUser = "default@example.com"

    with patch("demistomock.setContext") as mock_setContext:
        set_user_slack_email(incident_details, defaultSlackUser)
        mock_setContext.assert_called_once_with("userSlackEmail", defaultSlackUser)


def test_set_user_slack_email_missing_asset_dig_tags():
    # Test case where 'asset Dig Tags' is missing
    incident_details = {}
    defaultSlackUser = "default@example.com"

    with patch("demistomock.setContext") as mock_setContext:
        set_user_slack_email(incident_details, defaultSlackUser)
        mock_setContext.assert_called_once_with("userSlackEmail", defaultSlackUser)


def test_set_user_slack_email_with_null_asset_dig_tags():
    # Test case where 'asset Dig Tags' is None
    incident_details = {"asset Dig Tags": None}
    defaultSlackUser = "default@example.com"

    with patch("demistomock.setContext") as mock_setContext:
        set_user_slack_email(incident_details, defaultSlackUser)
        mock_setContext.assert_called_once_with("userSlackEmail", defaultSlackUser)


def test_set_user_slack_email_with_owner_email():
    # Test case where 'Owner' field contains an email
    incident_details = {"asset Dig Tags": json.dumps({"Owner": ["owner@example.com"]})}
    defaultSlackUser = "default@example.com"

    with patch("demistomock.setContext") as mock_setContext:
        set_user_slack_email(incident_details, defaultSlackUser)
        mock_setContext.assert_called_once_with("userSlackEmail", "owner@example.com")


def test_set_user_slack_email_with_multiple_owners():
    # Test case where 'Owner' contains multiple emails
    incident_details = {"asset Dig Tags": json.dumps({"Owner": ["owner1@example.com", "owner2@example.com"]})}
    defaultSlackUser = "default@example.com"

    with patch("demistomock.setContext") as mock_setContext:
        set_user_slack_email(incident_details, defaultSlackUser)
        mock_setContext.assert_called_once_with("userSlackEmail", "owner1@example.com")


def test_set_user_slack_email_with_invalid_json_format():
    # Test case where 'asset Dig Tags' has invalid JSON
    incident_details = {"asset Dig Tags": "invalid JSON"}
    defaultSlackUser = "default@example.com"

    with patch("demistomock.setContext") as mock_setContext:
        set_user_slack_email(incident_details, defaultSlackUser)
        mock_setContext.assert_called_once_with("userSlackEmail", defaultSlackUser)


def test_get_incident_details_command():
    # Sample incident data with various fields
    incident_data = {
        "id": "12345",
        "riskfindingid": "r123",
        "riskname": "High Risk",
        "severity": "Critical",
        "assetname": "Asset1",
        "assetid": "a123",
        "status": "Active",
        "projectid": "p123",
        "cloud": "AWS",
        "servicetype": "S3",
        "firstdetectedon": "2024-10-30T10:30:00Z",
        "assetdigtags": json.dumps({"Owner": ["owner@example.com"]}),
        "remediateinstruction": "Follow the steps to remediate."
    }

    args = {"incident_object": incident_data}
    expected_output = {
        "incidentId": "12345",
        "riskFindingId": "r123",
        "ruleName": "High Risk",
        "severity": "Critical",
        "assetName": "Asset1",
        "assetId": "a123",
        "Status": "Active",
        "projectId": "p123",
        "cloudProvider": "AWS",
        "serviceType": "S3",
        "firstDetectedOn": "2024-10-30T10:30:00Z",
        "asset Dig Tags": json.dumps({"Owner": ["owner@example.com"]}),
        "remediateInstruction": "Follow the steps to remediate.",
    }

    incident_object = get_incident_details_command(args)

    for key, value in expected_output.items():
        assert incident_object[key] == value


def test_get_incident_details_command_with_partial_date():
    # Test with partially formatted date
    incident_data = {
        "id": "12345",
        "riskfindingid": "r123",
        "riskname": "High Risk",
        "firstdetectedon": "2024-10-30T10:30"  # Missing seconds and timezone
    }

    args = {"incident_object": incident_data}
    incident_object = get_incident_details_command(args)

    assert incident_object["incidentId"] == "12345"
    assert incident_object["riskFindingId"] == "r123"
    assert incident_object["ruleName"] == "High Risk"


def test_get_incident_details_command_with_extra_fields():
    # Test with additional fields in incident data
    incident_data = {
        "id": "12345",
        "riskfindingid": "r123",
        "riskname": "High Risk",
        "extraField": "extraValue"
    }

    args = {"incident_object": incident_data}
    incident_object = get_incident_details_command(args)

    assert incident_object["incidentId"] == "12345"
    assert incident_object["riskFindingId"] == "r123"
    assert incident_object["ruleName"] == "High Risk"
    assert "extraField" not in incident_object  # Ensure extra fields are ignored


def test_get_incident_details_command_with_incorrect_date_format():
    # Test with an incorrectly formatted date
    incident_data = {
        "id": "12345",
        "riskfindingid": "r123",
        "riskname": "High Risk",
        "firstdetectedon": "incorrect-date-format"
    }

    args = {"incident_object": incident_data}
    incident_object = get_incident_details_command(args)

    assert incident_object["incidentId"] == "12345"
    assert incident_object["riskFindingId"] == "r123"
    assert incident_object["ruleName"] == "High Risk"


def test_get_incident_details_command_with_minimal_fields():
    # Test with only minimal required fields
    incident_data = {"id": "12345"}

    args = {"incident_object": incident_data}
    incident_object = get_incident_details_command(args)

    assert incident_object["incidentId"] == "12345"
    assert incident_object.get("riskFindingId") == "N/A"
    assert incident_object.get("severity") == "N/A"


def test_get_incident_details_command_with_unexpected_data_types():
    # Test with an integer for 'riskname' instead of a string
    incident_data = {
        "id": "12345",
        "riskfindingid": "r123",
        "riskname": 123  # Unexpected integer type
    }

    args = {"incident_object": incident_data}
    incident_object = get_incident_details_command(args)

    assert incident_object["incidentId"] == "12345"
    assert incident_object["riskFindingId"] == "r123"
    assert isinstance(incident_object["ruleName"], str)


def test_get_incident_details_command_with_mocked_exception():
    # Mocking an exception in demistomock
    with patch("demistomock.setContext", side_effect=Exception("Mocked Exception")):
        incident_details = {"asset Dig Tags": json.dumps({"Owner": []})}
        defaultSlackUser = "default@example.com"

        # Ensure function can handle exception without crashing
        try:
            set_user_slack_email(incident_details, defaultSlackUser)
        except Exception as e:
            assert False, f"Exception should have been handled, but got: {e}"
