from unittest.mock import patch
import json
import pytest
from DSPMExtractRiskDetails import set_user_slack_email, get_incident_details_command, main


def test_set_user_slack_email_with_valid_owner_email():
    incident_details = {
        "asset Dig Tags": json.dumps({"Owner": ["owner@example.com"]})
    }
    defaultSlackUser = "default@example.com"

    with patch("demistomock.setContext") as mock_setContext:
        set_user_slack_email(incident_details, defaultSlackUser)
        mock_setContext.assert_called_once_with("userSlackEmail", "owner@example.com")


def test_set_user_slack_email_with_empty_owner_list():
    incident_details = {
        "asset Dig Tags": json.dumps({"Owner": []})
    }
    defaultSlackUser = "default@example.com"

    with patch("demistomock.setContext") as mock_setContext:
        set_user_slack_email(incident_details, defaultSlackUser)
        mock_setContext.assert_called_once_with("userSlackEmail", defaultSlackUser)


def test_set_user_slack_email_with_non_list_owner():
    incident_details = {
        "asset Dig Tags": json.dumps({"Owner": "owner@example.com"})  # Not a list, incorrect format
    }
    defaultSlackUser = "default@example.com"

    with patch("demistomock.setContext") as mock_setContext:
        set_user_slack_email(incident_details, defaultSlackUser)
        mock_setContext.assert_called_once_with("userSlackEmail", defaultSlackUser)


def test_set_user_slack_email_with_missing_asset_dig_tags():
    incident_details = {}
    defaultSlackUser = "default@example.com"

    with patch("demistomock.setContext") as mock_setContext:
        set_user_slack_email(incident_details, defaultSlackUser)
        mock_setContext.assert_called_once_with("userSlackEmail", defaultSlackUser)


def test_set_user_slack_email_with_null_asset_dig_tags():
    incident_details = {
        "asset Dig Tags": None
    }
    defaultSlackUser = "default@example.com"

    with patch("demistomock.setContext") as mock_setContext:
        set_user_slack_email(incident_details, defaultSlackUser)
        mock_setContext.assert_called_once_with("userSlackEmail", defaultSlackUser)


def test_get_incident_details_command_with_valid_data():
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
    incident_object = get_incident_details_command(args)

    assert incident_object["incidentId"] == "12345"
    assert incident_object["riskFindingId"] == "r123"
    assert incident_object["ruleName"] == "High Risk"


def test_get_incident_details_command_with_missing_fields():
    incident_data = {
        "id": "12345",
        "riskfindingid": "r123",
        "riskname": "High Risk"
    }

    args = {"incident_object": incident_data}
    incident_object = get_incident_details_command(args)

    assert incident_object["incidentId"] == "12345"
    assert incident_object["riskFindingId"] == "r123"
    assert incident_object["ruleName"] == "High Risk"
    assert incident_object.get("severity") == "N/A"


def test_main_success_case():
    args = {
        "defaultSlackUser": "default@example.com",
        "incident_object": {
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
    }

    with patch("demistomock.args", return_value=args), \
            patch("demistomock.setContext") as mock_setContext, \
            patch("DSPMExtractRiskDetails.return_results") as mock_return_results:

        main()

        mock_setContext.assert_called_once_with("userSlackEmail", "owner@example.com")
        assert mock_return_results.called


# Run pytest with coverage
if __name__ == "__main__":
    pytest.main(["-v", "--cov=DSPMExtractRiskDetails", "--cov-report=term-missing"])
