import pytest
from AWS_SecurityHub_V2 import (
    disable_security_hub_command,
    enable_security_hub_command,
    parse_tag_field,
    validate_aws_params,
)
from CommonServerPython import DemistoException


def test_parse_tag_field():
    """
    Given: A string of key/value tag pairs separated by ';'.
    When: parse_tag_field is called.
    Then: It returns a list of {'Key': ..., 'Value': ...} dicts.
    """
    result = parse_tag_field("key=env,value=prod;key=team,value=security")
    assert result == [
        {"Key": "env", "Value": "prod"},
        {"Key": "team", "Value": "security"},
    ]


def test_parse_tag_field_empty():
    """
    Given: An empty tags string.
    When: parse_tag_field is called.
    Then: It returns an empty list.
    """
    assert parse_tag_field("") == []


def test_validate_aws_params_missing_region():
    """
    Given: Parameters without an AWS region.
    When: validate_aws_params is called.
    Then: It raises a DemistoException.
    """
    with pytest.raises(DemistoException, match="You must specify the AWS region."):
        validate_aws_params(None, None, None, None, None)


def test_validate_aws_params_partial_credentials():
    """
    Given: An access key without a secret key.
    When: validate_aws_params is called.
    Then: It raises a DemistoException.
    """
    with pytest.raises(DemistoException, match="both Access Key id and Secret Key"):
        validate_aws_params("us-east-1", None, None, "access_key", None)


def test_validate_aws_params_role_without_session_name():
    """
    Given: A role ARN without a role session name.
    When: validate_aws_params is called.
    Then: It raises a DemistoException.
    """
    with pytest.raises(DemistoException, match="Role session name is required"):
        validate_aws_params("us-east-1", "arn:aws:iam::123:role/r", None, None, None)


def test_enable_security_hub_command_success(mocker):
    """
    Given: A mocked securityhub client and a tags argument.
    When: enable_security_hub_command is called.
    Then: It calls enable_security_hub_v2 with a flat Tags mapping and returns the V2 ARN.
    """
    mock_client = mocker.Mock()
    mock_client.enable_security_hub_v2.return_value = {
        "SecurityHubV2Arn": "arn:aws:securityhub:us-east-1:123456789012:hub/v2",
        "ResponseMetadata": {"HTTPStatusCode": 200},
    }
    args = {"tags": "key=env,value=prod"}

    result = enable_security_hub_command(mock_client, args)

    call_kwargs = mock_client.enable_security_hub_v2.call_args[1]
    assert call_kwargs["Tags"] == {"env": "prod"}
    assert result.outputs_prefix == "AWS.SecurityHub.Hub"
    assert result.outputs == {"SecurityHubV2Arn": "arn:aws:securityhub:us-east-1:123456789012:hub/v2"}
    assert "AWS Security Hub V2 Enabled" in result.readable_output


def test_enable_security_hub_command_no_tags(mocker):
    """
    Given: A mocked securityhub client and no tags argument.
    When: enable_security_hub_command is called.
    Then: It calls enable_security_hub_v2 without a Tags parameter (empty kwargs).
    """
    mock_client = mocker.Mock()
    mock_client.enable_security_hub_v2.return_value = {
        "SecurityHubV2Arn": "arn:aws:securityhub:us-east-1:123456789012:hub/v2",
        "ResponseMetadata": {"HTTPStatusCode": 200},
    }

    result = enable_security_hub_command(mock_client, {})

    call_kwargs = mock_client.enable_security_hub_v2.call_args[1]
    assert "Tags" not in call_kwargs
    assert result.outputs["SecurityHubV2Arn"] == "arn:aws:securityhub:us-east-1:123456789012:hub/v2"


def test_enable_security_hub_command_error(mocker):
    """
    Given: A mocked securityhub client whose enable_security_hub_v2 raises an exception.
    When: enable_security_hub_command is called.
    Then: The exception propagates to be handled in main().
    """
    mock_client = mocker.Mock()
    mock_client.enable_security_hub_v2.side_effect = Exception("AccessDenied")

    with pytest.raises(Exception, match="AccessDenied"):
        enable_security_hub_command(mock_client, {})


def test_disable_security_hub_command_success(mocker):
    """
    Given: A mocked securityhub client.
    When: disable_security_hub_command is called.
    Then: It calls disable_security_hub_v2 and returns a confirmation message.
    """
    mock_client = mocker.Mock()
    mock_client.disable_security_hub_v2.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}

    result = disable_security_hub_command(mock_client, {})

    mock_client.disable_security_hub_v2.assert_called_once()
    assert "successfully disabled" in result.readable_output


def test_disable_security_hub_command_error(mocker):
    """
    Given: A mocked securityhub client whose disable_security_hub_v2 raises an exception.
    When: disable_security_hub_command is called.
    Then: The exception propagates to be handled in main().
    """
    mock_client = mocker.Mock()
    mock_client.disable_security_hub_v2.side_effect = Exception("AccessDenied")

    with pytest.raises(Exception, match="AccessDenied"):
        disable_security_hub_command(mock_client, {})
