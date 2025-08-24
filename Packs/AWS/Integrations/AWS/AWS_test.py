import json
from datetime import datetime, date
from http import HTTPStatus
import demistomock as demisto
import pytest

from CommonServerPython import CommandResults, DemistoException


def test_parse_resource_ids_with_valid_input():
    """
    Given: A comma-separated string of resource IDs with spaces.
    When: parse_resource_ids function processes the input.
    Then: It should return a list of cleaned resource IDs without spaces.
    """
    from AWS import parse_resource_ids

    result = parse_resource_ids("id1, id2 , id3")
    assert result == ["id1", "id2", "id3"]


def test_parse_resource_ids_with_none():
    """
    Given: A None value is passed to parse_resource_ids function.
    When: The function attempts to process the None input.
    Then: It should raise a ValueError indicating resource ID cannot be empty.
    """
    from AWS import parse_resource_ids

    with pytest.raises(ValueError, match="Resource ID cannot be empty"):
        parse_resource_ids(None)


def test_datetime_encoder_with_datetime():
    """
    Given: A DatetimeEncoder instance and a datetime object.
    When: The encoder processes the datetime object.
    Then: It should return a formatted string in ISO format.
    """
    from AWS import DatetimeEncoder

    encoder = DatetimeEncoder()
    test_datetime = datetime(2023, 10, 15, 14, 30, 45)
    result = encoder.default(test_datetime)
    assert result == "2023-10-15T14:30:45"


def test_datetime_encoder_with_date():
    """
    Given: A DatetimeEncoder instance and a date object.
    When: The encoder processes the date object.
    Then: It should return a formatted date string.
    """
    from AWS import DatetimeEncoder

    encoder = DatetimeEncoder()
    test_date = date(2023, 10, 15)
    result = encoder.default(test_date)
    assert result == "2023-10-15"


def test_s3_put_public_access_block_command_success(mocker):
    """
    Given: A mocked boto3 S3 client and valid arguments for public access block.
    When: put_public_access_block_command is called with successful response.
    Then: It should return CommandResults with success message.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.put_public_access_block.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    args = {"bucket": "test-bucket", "block_public_acls": "true", "ignore_public_acls": "false"}

    result = S3.put_public_access_block_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Successfully applied public access block" in result.readable_output


def test_s3_put_public_access_block_command_failure(mocker):
    """
    Given: A mocked boto3 S3 client and valid arguments for public access block.
    When: put_public_access_block_command is called with failed response.
    Then: It should raise DemistoException with error message.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.put_public_access_block.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.BAD_REQUEST}}

    args = {"bucket": "test-bucket", "block_public_acls": "true"}

    with pytest.raises(DemistoException, match="Couldn't apply public access block to the test-bucket bucket"):
        S3.put_public_access_block_command(mock_client, args)


def test_s3_put_bucket_versioning_command_exception(mocker):
    """
    Given: A mocked boto3 S3 client that raises an exception.
    When: put_bucket_versioning_command is called and encounters an error.
    Then: It should raise DemistoException with error message.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.put_bucket_versioning.side_effect = Exception("Test error")

    args = {"bucket": "test-bucket", "status": "Enabled"}

    with pytest.raises(DemistoException, match="Failed to update versioning configuration for bucket test-bucket"):
        S3.put_bucket_versioning_command(mock_client, args)


def test_s3_put_bucket_logging_command_enable_logging(mocker):
    """
    Given: A mocked boto3 S3 client and arguments to enable bucket logging.
    When: put_bucket_logging_command is called with target bucket.
    Then: It should return CommandResults with success message about enabled logging.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.put_bucket_logging.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    args = {"bucket": "test-bucket", "target_bucket": "log-bucket", "target_prefix": "logs/"}

    result = S3.put_bucket_logging_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Successfully enabled logging" in result.readable_output


def test_s3_put_bucket_logging_command_disable_logging(mocker):
    """
    Given: A mocked boto3 S3 client and arguments to disable bucket logging.
    When: put_bucket_logging_command is called without target bucket.
    Then: It should return CommandResults with success message about disabled logging.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.put_bucket_logging.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    args = {"bucket": "test-bucket"}

    result = S3.put_bucket_logging_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Successfully disabled logging" in result.readable_output


def test_s3_put_bucket_acl_command_success(mocker):
    """
    Given: A mocked boto3 S3 client and valid ACL arguments.
    When: put_bucket_acl_command is called successfully.
    Then: It should return CommandResults with ACL update success message.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.put_bucket_acl.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    args = {"bucket": "test-bucket", "acl": "private"}

    result = S3.put_bucket_acl_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Successfully updated ACL" in result.readable_output


def test_s3_put_bucket_acl_command_unexpected_status(mocker):
    """
    Given: A mocked boto3 S3 client returning unexpected status code.
    When: put_bucket_acl_command is called with non-200 response.
    Then: It should raise DemistoException with unexpected status message.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.put_bucket_acl.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.BAD_REQUEST}}

    args = {"bucket": "test-bucket", "acl": "private"}

    with pytest.raises(DemistoException, match="Request completed but received unexpected status code: 400"):
        S3.put_bucket_acl_command(mock_client, args)


def test_s3_put_bucket_policy_command_success(mocker):
    """
    Given: A mocked boto3 S3 client and valid bucket policy arguments.
    When: put_bucket_policy_command is called successfully.
    Then: It should return CommandResults with policy application success message.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.put_bucket_policy.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    args = {"bucket": "test-bucket", "policy": {"Version": "2012-10-17", "Statement": []}}

    result = S3.put_bucket_policy_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Successfully applied bucket policy" in result.readable_output


def test_s3_put_bucket_policy_command_exception(mocker):
    """
    Given: A mocked boto3 S3 client that raises an exception.
    When: put_bucket_policy_command is called and encounters an error.
    Then: It should raise DemistoException with error message.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.put_bucket_policy.side_effect = Exception("Test error")

    args = {"bucket": "test-bucket", "policy": {"Version": "2012-10-17"}}

    with pytest.raises(DemistoException, match="Couldn't apply bucket policy to test-bucket bucket"):
        S3.put_bucket_policy_command(mock_client, args)


def test_iam_get_account_password_policy_command_success(mocker):
    """
    Given: A mocked boto3 IAM client with password policy response.
    When: get_account_password_policy_command is called successfully.
    Then: It should return CommandResults with password policy data and outputs.
    """
    from AWS import IAM

    mock_client = mocker.Mock()
    mock_client.get_account_password_policy.return_value = {
        "PasswordPolicy": {"MinimumPasswordLength": 8, "RequireSymbols": True}
    }

    args = {"account_id": "123456789"}

    result = IAM.get_account_password_policy_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "AWS.IAM.PasswordPolicy"


def test_iam_get_account_password_policy_command_with_datetime(mocker):
    """
    Given: A mocked boto3 IAM client with password policy containing datetime objects.
    When: get_account_password_policy_command processes the response with DatetimeEncoder.
    Then: It should return CommandResults with properly serialized datetime data.
    """
    from AWS import IAM

    mock_client = mocker.Mock()
    mock_client.get_account_password_policy.return_value = {
        "PasswordPolicy": {"MinimumPasswordLength": 8, "CreatedDate": datetime(2023, 10, 15)}
    }

    args = {"account_id": "123456789"}

    result = IAM.get_account_password_policy_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs is not None


def test_iam_update_account_password_policy_command_success(mocker):
    """
    Given: A mocked boto3 IAM client and valid password policy update arguments.
    When: update_account_password_policy_command is called successfully.
    Then: It should return CommandResults with success message.
    """
    from AWS import IAM

    mock_client = mocker.Mock()
    mock_client.get_account_password_policy.return_value = {"PasswordPolicy": {"MinimumPasswordLength": 6}}
    mock_client.update_account_password_policy.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    args = {"account_id": "123456789", "minimum_password_length": "8", "require_symbols": "true"}

    result = IAM.update_account_password_policy_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Successfully updated account password policy" in result.readable_output


def test_iam_update_account_password_policy_command_get_policy_error(mocker):
    """
    Given: A mocked boto3 IAM client that fails to get current password policy.
    When: update_account_password_policy_command encounters an error getting current policy.
    Then: It should raise DemistoException with error message.
    """
    from AWS import IAM

    mock_client = mocker.Mock()
    mock_client.get_account_password_policy.side_effect = Exception("Access denied")

    args = {"account_id": "123456789"}

    with pytest.raises(DemistoException, match="Couldn't check current account password policy for account"):
        IAM.update_account_password_policy_command(mock_client, args)


def test_iam_put_role_policy_command_success(mocker):
    """
    Given: A mocked boto3 IAM client and valid role policy arguments.
    When: put_role_policy_command is called successfully.
    Then: It should return CommandResults with success message about policy addition.
    """
    from AWS import IAM

    mock_client = mocker.Mock()
    mock_client.put_user_policy.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    args = {"policy_document": '{"Version": "2012-10-17"}', "policy_name": "test-policy", "role_name": "test-role"}

    result = IAM.put_role_policy_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "successfully added to role" in result.readable_output


def test_iam_put_role_policy_command_exception(mocker):
    """
    Given: A mocked boto3 IAM client that raises an exception.
    When: put_role_policy_command encounters an error during execution.
    Then: It should raise DemistoException with error details.
    """
    from AWS import IAM

    mock_client = mocker.Mock()
    mock_client.put_role_policy.side_effect = Exception("Access denied")

    args = {"policy_document": '{"Version": "2012-10-17"}', "policy_name": "test-policy", "role_name": "test-role"}

    with pytest.raises(DemistoException):
        IAM.put_role_policy_command(mock_client, args)


def test_iam_delete_login_profile_command_success(mocker):
    """
    Given: A mocked boto3 IAM client and valid user name argument.
    When: delete_login_profile_command is called successfully.
    Then: It should return CommandResults with success message about profile deletion.
    """
    from AWS import IAM

    mock_client = mocker.Mock()
    mock_client.delete_login_profile.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    args = {"user_name": "test-user"}

    result = IAM.delete_login_profile_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Successfully deleted login profile" in result.readable_output


def test_iam_delete_login_profile_command_exception(mocker):
    """
    Given: A mocked boto3 IAM client that raises an exception.
    When: delete_login_profile_command encounters an error during execution.
    Then: It should raise DemistoException with error message.
    """
    from AWS import IAM

    mock_client = mocker.Mock()
    mock_client.delete_login_profile.side_effect = Exception("User not found")

    args = {"user_name": "test-user"}

    with pytest.raises(DemistoException, match="Error deleting login profile for user 'test-user'"):
        IAM.delete_login_profile_command(mock_client, args)


def test_iam_put_user_policy_command_success(mocker):
    """
    Given: A mocked boto3 IAM client and valid user policy arguments.
    When: put_user_policy_command is called successfully.
    Then: It should return CommandResults with success message about policy update.
    """
    from AWS import IAM

    mock_client = mocker.Mock()
    mock_client.put_user_policy.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    args = {"user_name": "test-user", "policy_name": "test-policy", "policy_document": '{"Version": "2012-10-17"}'}

    result = IAM.put_user_policy_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Successfully added/updated policy" in result.readable_output


def test_iam_put_user_policy_command_with_dict_policy(mocker):
    """
    Given: A mocked boto3 IAM client and policy document as dictionary.
    When: put_user_policy_command is called with dict policy document.
    Then: It should return CommandResults and properly serialize the policy document.
    """
    from AWS import IAM

    mock_client = mocker.Mock()
    mock_client.put_user_policy.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    args = {"user_name": "test-user", "policy_name": "test-policy", "policy_document": {"Version": "2012-10-17"}}

    result = IAM.put_user_policy_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Successfully added/updated policy" in result.readable_output


def test_iam_remove_role_from_instance_profile_command_success(mocker):
    """
    Given: A mocked boto3 IAM client and valid instance profile arguments.
    When: remove_role_from_instance_profile_command is called successfully.
    Then: It should return CommandResults with success message about role removal.
    """
    from AWS import IAM

    mock_client = mocker.Mock()
    mock_client.remove_role_from_instance_profile.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    args = {"instance_profile_name": "test-profile", "role_name": "test-role"}

    result = IAM.remove_role_from_instance_profile_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Successfully removed role" in result.readable_output


def test_iam_remove_role_from_instance_profile_command_exception(mocker):
    """
    Given: A mocked boto3 IAM client that raises an exception.
    When: remove_role_from_instance_profile_command encounters an error.
    Then: It should raise DemistoException with error message.
    """
    from AWS import IAM

    mock_client = mocker.Mock()
    mock_client.remove_role_from_instance_profile.side_effect = Exception("Profile not found")

    args = {"instance_profile_name": "test-profile", "role_name": "test-role"}

    with pytest.raises(DemistoException, match="Error removing role 'test-role' from instance profile"):
        IAM.remove_role_from_instance_profile_command(mock_client, args)


def test_iam_update_access_key_command_success(mocker):
    """
    Given: A mocked boto3 IAM client and valid access key update arguments.
    When: update_access_key_command is called successfully.
    Then: It should return CommandResults with success message about key status update.
    """
    from AWS import IAM

    mock_client = mocker.Mock()
    mock_client.update_access_key.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    args = {"access_key_id": "AKIATEST123", "status": "Inactive", "user_name": "test-user"}

    result = IAM.update_access_key_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Successfully updated access key" in result.readable_output


def test_iam_update_access_key_command_without_user(mocker):
    """
    Given: A mocked boto3 IAM client and access key arguments without user name.
    When: update_access_key_command is called without specifying user name.
    Then: It should return CommandResults with success message without user info.
    """
    from AWS import IAM

    mock_client = mocker.Mock()
    mock_client.update_access_key.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    args = {"access_key_id": "AKIATEST123", "status": "Active"}

    result = IAM.update_access_key_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Successfully updated access key" in result.readable_output


def test_ec2_modify_instance_metadata_options_command_success(mocker):
    """
    Given: A mocked boto3 EC2 client and valid metadata options arguments.
    When: modify_instance_metadata_options_command is called successfully.
    Then: It should return CommandResults with success message about metadata update.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.modify_instance_metadata_options.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    args = {"instance_id": "i-1234567890abcdef0", "http_tokens": "required", "http_endpoint": "enabled"}

    result = EC2.modify_instance_metadata_options_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Successfully updated EC2 instance metadata" in result.readable_output


def test_ec2_modify_instance_metadata_options_command_failure(mocker):
    """
    Given: A mocked boto3 EC2 client returning non-OK status code.
    When: modify_instance_metadata_options_command is called with failed response.
    Then: It should raise DemistoException with error message.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.modify_instance_metadata_options.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.BAD_REQUEST}}

    args = {"instance_id": "i-1234567890abcdef0", "http_tokens": "required"}

    with pytest.raises(DemistoException, match="Couldn't updated public EC2 instance metadata"):
        EC2.modify_instance_metadata_options_command(mock_client, args)


def test_ec2_modify_instance_attribute_command_success(mocker):
    """
    Given: A mocked boto3 EC2 client and valid instance attribute arguments.
    When: modify_instance_attribute_command is called successfully.
    Then: It should return CommandResults with success message about attribute modification.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.modify_instance_attribute.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    args = {"instance_id": "i-1234567890abcdef0", "attribute": "instanceType", "value": "t3.micro"}

    result = EC2.modify_instance_attribute_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Successfully modified EC2 instance" in result.readable_output


def test_ec2_modify_instance_attribute_command_with_groups(mocker):
    """
    Given: A mocked boto3 EC2 client and instance attribute arguments with security groups.
    When: modify_instance_attribute_command is called with groups parameter.
    Then: It should return CommandResults and properly parse the comma-separated groups.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.modify_instance_attribute.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    args = {"instance_id": "i-1234567890abcdef0", "groups": "sg-123, sg-456, sg-789"}

    result = EC2.modify_instance_attribute_command(mock_client, args)
    assert isinstance(result, CommandResults)
    mock_client.modify_instance_attribute.assert_called_once()


def test_ec2_modify_snapshot_attribute_command_success(mocker):
    """
    Given: A mocked boto3 EC2 client and valid snapshot attribute arguments.
    When: modify_snapshot_attribute_command is called successfully.
    Then: It should return CommandResults with success message about permission update.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.modify_snapshot_attribute.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    args = {
        "snapshot_id": "snap-1234567890abcdef0",
        "attribute": "createVolumePermission",
        "operation_type": "add",
        "user_ids": "123456789012, 987654321098",
    }

    result = EC2.modify_snapshot_attribute_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "permissions was successfully updated" in result.readable_output


def test_ec2_modify_snapshot_attribute_command_unexpected_response(mocker):
    """
    Given: A mocked boto3 EC2 client returning unexpected status code.
    When: modify_snapshot_attribute_command is called with non-OK response.
    Then: It should raise DemistoException with unexpected response message.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.modify_snapshot_attribute.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.BAD_REQUEST}}

    args = {"snapshot_id": "snap-1234567890abcdef0", "attribute": "createVolumePermission", "operation_type": "add"}

    with pytest.raises(DemistoException):
        EC2.modify_snapshot_attribute_command(mock_client, args)


def test_ec2_modify_image_attribute_command_success(mocker):
    """
    Given: A mocked boto3 EC2 client and valid image attribute arguments.
    When: modify_image_attribute_command is called successfully.
    Then: It should return CommandResults with success message about attribute modification.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.modify_image_attribute.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    args = {
        "image_id": "ami-1234567890abcdef0",
        "attribute": "launchPermission",
        "operation_type": "add",
        "launch_permission_add_user_id": "123456789012",
    }

    result = EC2.modify_image_attribute_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Image attribute successfully modified" in result.readable_output


def test_ec2_modify_image_attribute_command_with_description(mocker):
    """
    Given: A mocked boto3 EC2 client and image attribute arguments with description.
    When: modify_image_attribute_command is called with description parameter.
    Then: It should return CommandResults and properly handle the description attribute.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.modify_image_attribute.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    args = {"image_id": "ami-1234567890abcdef0", "attribute": "description", "description": "Updated AMI description"}

    result = EC2.modify_image_attribute_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Image attribute successfully modified" in result.readable_output


def test_ec2_revoke_security_group_ingress_command_success(mocker):
    """
    Given: A mocked boto3 EC2 client and valid security group ingress arguments.
    When: revoke_security_group_ingress_command is called successfully.
    Then: It should return CommandResults with success message about rule revocation.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.revoke_security_group_ingress.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "Return": True,
    }

    args = {"group_id": "sg-1234567890abcdef0", "protocol": "tcp", "from_port": "80", "to_port": "80", "cidr": "0.0.0.0/0"}

    result = EC2.revoke_security_group_ingress_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Security Group ingress rule was revoked" in result.readable_output


def test_ec2_revoke_security_group_ingress_command_with_ip_permissions(mocker):
    """
    Given: A mocked boto3 EC2 client and security group arguments with ip_permissions JSON.
    When: revoke_security_group_ingress_command is called with complex ip_permissions.
    Then: It should return CommandResults and properly parse the JSON ip_permissions.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.revoke_security_group_ingress.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "Return": True,
    }

    ip_permissions = json.dumps([{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])

    args = {"group_id": "sg-1234567890abcdef0", "ip_permissions": ip_permissions}

    result = EC2.revoke_security_group_ingress_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Security Group ingress rule was revoked" in result.readable_output


def test_ec2_authorize_security_group_ingress_command_success(mocker):
    """
    Given: A mocked boto3 EC2 client and valid security group ingress arguments.
    When: authorize_security_group_ingress_command is called successfully.
    Then: It should return CommandResults with success message about rule authorization.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.authorize_security_group_ingress.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "Return": True,
    }

    args = {"group_id": "sg-1234567890abcdef0", "protocol": "tcp", "from_port": "00", "to_port": "00", "cidr": "10.0.0.0/8"}

    result = EC2.authorize_security_group_ingress_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Security Group ingress rule was authorized" in result.readable_output


def test_ec2_authorize_security_group_ingress_command_duplicate_rule(mocker):
    """
    Given: A mocked boto3 EC2 client that raises InvalidPermission.Duplicate error.
    When: authorize_security_group_ingress_command encounters duplicate rule error.
    Then: It should raise DemistoException with duplicate rule message.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.authorize_security_group_ingress.side_effect = Exception("InvalidPermission.Duplicate")

    args = {"group_id": "sg-1234567890abcdef0", "protocol": "tcp", "from_port": "00", "to_port": "00", "cidr": "0.0.0.0/0"}

    with pytest.raises(DemistoException, match="already exists"):
        EC2.authorize_security_group_ingress_command(mock_client, args)


def test_ec2_revoke_security_group_egress_command_success(mocker):
    """
    Given: A mocked boto3 EC2 client and valid security group egress arguments.
    When: revoke_security_group_egress_command is called successfully.
    Then: It should return CommandResults with success message about egress rule revocation.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.revoke_security_group_egress.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "Return": True,
    }

    args = {"group_id": "sg-1234567890abcdef0", "protocol": "tcp", "from_port": "40", "to_port": "443", "cidr": "0.0.0.0/0"}

    result = EC2.revoke_security_group_egress_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Egress rule revoked successfully" in result.readable_output


def test_ec2_revoke_security_group_egress_command_with_ip_permissions(mocker):
    """
    Given: A mocked boto3 EC2 client and egress arguments with ip_permissions JSON.
    When: revoke_security_group_egress_command is called with full mode ip_permissions.
    Then: It should return CommandResults and properly use the provided JSON permissions.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.revoke_security_group_egress.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "Return": True,
    }

    ip_permissions = json.dumps([{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])

    args = {"group_id": "sg-1234567890abcdef0", "ip_permissions": ip_permissions}

    result = EC2.revoke_security_group_egress_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Egress rule revoked successfully" in result.readable_output


def test_eks_update_cluster_config_command_success(mocker):
    """
    Given: A mocked boto3 EKS client and valid cluster configuration arguments.
    When: update_cluster_config_command is called successfully.
    Then: It should return CommandResults with update information and proper outputs.
    """
    from AWS import EKS

    mock_client = mocker.Mock()
    mock_client.update_cluster_config.return_value = {
        "update": {
            "id": "update-123",
            "status": "InProgress",
            "type": "ConfigUpdate",
            "createdAt": datetime(2023, 10, 15, 14, 30, 45),
        }
    }

    args = {"cluster_name": "test-cluster", "logging": '{"enable": ["api", "audit"]}'}

    result = EKS.update_cluster_config_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "AWS.EKS.UpdateCluster"


def test_eks_update_cluster_config_command_no_changes_needed(mocker):
    """
    Given: A mocked boto3 EKS client that raises "No changes needed" exception.
    When: update_cluster_config_command encounters no changes needed error.
    Then: It should return CommandResults with appropriate message about no changes.
    """
    from AWS import EKS

    mock_client = mocker.Mock()
    mock_client.update_cluster_config.side_effect = Exception("No changes needed")

    args = {"cluster_name": "test-cluster", "logging": '{"enable": ["api"]}'}

    result = EKS.update_cluster_config_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "No changes needed" in result.readable_output


def test_rds_modify_db_cluster_command_success(mocker):
    """
    Given: A mocked boto3 RDS client and valid DB cluster modification arguments.
    When: modify_db_cluster_command is called successfully.
    Then: It should return CommandResults with success message and cluster details.
    """
    from AWS import RDS

    mock_client = mocker.Mock()
    mock_client.modify_db_cluster.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "DBCluster": {"DBClusterIdentifier": "test-cluster", "DeletionProtection": True},
    }

    args = {"db_cluster_identifier": "test-cluster", "deletion_protection": "true"}

    result = RDS.modify_db_cluster_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Successfully modified DB cluster" in result.readable_output


def test_rds_modify_db_cluster_command_exception(mocker):
    """
    Given: A mocked boto3 RDS client that raises an exception.
    When: modify_db_cluster_command encounters an error during execution.
    Then: It should raise DemistoException with error message.
    """
    from AWS import RDS

    mock_client = mocker.Mock()
    mock_client.modify_db_cluster.side_effect = Exception("Cluster not found")

    args = {"db_cluster_identifier": "test-cluster", "deletion_protection": "true"}

    with pytest.raises(DemistoException, match="Error modifying DB cluster"):
        RDS.modify_db_cluster_command(mock_client, args)


def test_rds_modify_db_cluster_snapshot_attribute_command_success(mocker):
    """
    Given: A mocked boto3 RDS client and valid cluster snapshot attribute arguments.
    When: modify_db_cluster_snapshot_attribute_command is called successfully.
    Then: It should return CommandResults with success message and snapshot attributes.
    """
    from AWS import RDS

    mock_client = mocker.Mock()
    mock_client.modify_db_cluster_snapshot_attribute.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "DBClusterSnapshotAttributesResult": {"DBClusterSnapshotIdentifier": "test-snapshot", "DBClusterSnapshotAttributes": []},
    }

    args = {"db_cluster_snapshot_identifier": "test-snapshot", "attribute_name": "restore", "values_to_add": ["123456789012"]}

    result = RDS.modify_db_cluster_snapshot_attribute_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Successfully modified DB cluster snapshot attribute" in result.readable_output


def test_rds_modify_db_cluster_snapshot_attribute_command_failure(mocker):
    """
    Given: A mocked boto3 RDS client returning non-OK status code.
    When: modify_db_cluster_snapshot_attribute_command is called with failed response.
    Then: It should raise DemistoException with error message.
    """
    from AWS import RDS

    mock_client = mocker.Mock()
    mock_client.modify_db_cluster_snapshot_attribute.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.BAD_REQUEST}
    }

    args = {"db_cluster_snapshot_identifier": "test-snapshot", "attribute_name": "restore"}

    with pytest.raises(DemistoException, match="Error modifying DB cluster snapshot attribute"):
        RDS.modify_db_cluster_snapshot_attribute_command(mock_client, args)


def test_rds_modify_db_instance_command_success(mocker):
    """
    Given: A mocked boto3 RDS client and valid DB instance modification arguments.
    When: modify_db_instance_command is called successfully.
    Then: It should return CommandResults with success message and instance details.
    """
    from AWS import RDS

    mock_client = mocker.Mock()
    mock_client.modify_db_instance.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "DBInstance": {"DBInstanceIdentifier": "test-instance", "MultiAZ": True},
    }

    args = {"db_instance_identifier": "test-instance", "multi_az": "true", "apply_immediately": "true"}

    result = RDS.modify_db_instance_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Successfully modified DB instance" in result.readable_output


def test_rds_modify_db_instance_command_exception(mocker):
    """
    Given: A mocked boto3 RDS client that raises an exception.
    When: modify_db_instance_command encounters an error during execution.
    Then: It should raise DemistoException with error message.
    """
    from AWS import RDS

    mock_client = mocker.Mock()
    mock_client.modify_db_instance.side_effect = Exception("Instance not found")

    args = {"db_instance_identifier": "test-instance", "multi_az": "true"}

    with pytest.raises(DemistoException, match="Error modifying DB instance"):
        RDS.modify_db_instance_command(mock_client, args)


def test_rds_modify_db_snapshot_attribute_command_success(mocker):
    """
    Given: A mocked boto3 RDS client and valid DB snapshot attribute arguments.
    When: modify_db_snapshot_attribute_command is called successfully.
    Then: It should return CommandResults with success message about attribute modification.
    """
    from AWS import RDS

    mock_client = mocker.Mock()
    mock_client.modify_db_snapshot_attribute.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    args = {
        "db_snapshot_identifier": "test-snapshot",
        "attribute_name": "restore",
        "values_to_add": ["123456789012", "987654321098"],
    }

    result = RDS.modify_db_snapshot_attribute_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Successfully modified DB snapshot attribute" in result.readable_output


def test_rds_modify_db_snapshot_attribute_command_failure(mocker):
    """
    Given: A mocked boto3 RDS client returning non-OK status code.
    When: modify_db_snapshot_attribute_command is called with failed response.
    Then: It should raise DemistoException with error message.
    """
    from AWS import RDS

    mock_client = mocker.Mock()
    mock_client.modify_db_snapshot_attribute.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.BAD_REQUEST}}

    args = {"db_snapshot_identifier": "test-snapshot", "attribute_name": "restore", "values_to_remove": ["123456789012"]}

    with pytest.raises(DemistoException, match="Couldn't modify DB snapshot attribute for"):
        RDS.modify_db_snapshot_attribute_command(mock_client, args)


def test_cloudtrail_start_logging_command_success(mocker):
    """
    Given: A mocked boto3 CloudTrail client and valid trail name argument.
    When: start_logging_command is called successfully.
    Then: It should return CommandResults with success message about logging start.
    """
    from AWS import CloudTrail

    mock_client = mocker.Mock()
    mock_client.start_logging.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    args = {"name": "test-trail"}

    result = CloudTrail.start_logging_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Successfully started logging" in result.readable_output


def test_cloudtrail_start_logging_command_exception(mocker):
    """
    Given: A mocked boto3 CloudTrail client that raises an exception.
    When: start_logging_command encounters an error during execution.
    Then: It should return CommandResults with error entry type and error message.
    """
    from AWS import CloudTrail

    mock_client = mocker.Mock()
    mock_client.start_logging.side_effect = Exception("Trail not found")

    args = {"name": "test-trail"}

    with pytest.raises(DemistoException, match="Error starting logging for CloudTrail"):
        CloudTrail.start_logging_command(mock_client, args)


def test_cloudtrail_update_trail_command_success(mocker):
    """
    Given: A mocked boto3 CloudTrail client and valid trail update arguments.
    When: update_trail_command is called successfully.
    Then: It should return CommandResults with success message and trail details.
    """
    from AWS import CloudTrail

    mock_client = mocker.Mock()
    mock_client.update_trail.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "Trail": {
            "Name": "test-trail",
            "S3BucketName": "test-bucket",
            "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail",
        },
    }

    args = {"name": "test-trail", "s3_bucket_name": "test-bucket", "include_global_service_events": "true"}

    result = CloudTrail.update_trail_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Successfully updated CloudTrail" in result.readable_output
    assert result.outputs_prefix == "AWS.CloudTrail.Trail"


def test_cloudtrail_update_trail_command_exception(mocker):
    """
    Given: A mocked boto3 CloudTrail client that raises an exception.
    When: update_trail_command encounters an error during execution.
    Then: It should return CommandResults with error entry type and error message.
    """
    from AWS import CloudTrail

    mock_client = mocker.Mock()
    mock_client.update_trail.side_effect = Exception("Access denied")

    args = {"name": "test-trail", "s3_bucket_name": "test-bucket"}

    with pytest.raises(DemistoException, match="Error updating CloudTrail"):
        CloudTrail.update_trail_command(mock_client, args)


def test_register_proxydome_header(mocker):
    """
    Given: A mocked boto3 client and ProxyDome token.
    When: register_proxydome_header is called to configure ProxyDome authentication.
    Then: It should register an event handler to inject the ProxyDome header.
    """
    from AWS import register_proxydome_header

    mock_client = mocker.Mock()
    mock_event_system = mocker.Mock()
    mock_client.meta.events = mock_event_system

    mocker.patch("AWS.get_proxydome_token", return_value="test-token")

    register_proxydome_header(mock_client)

    mock_event_system.register_last.assert_called_once()
    assert mock_event_system.register_last.call_args[0][0] == "before-send.*.*"


def test_register_proxydome_header_adds_correct_header(mocker):
    """
    Given: A mocked boto3 client and the ProxyDome header injection function.
    When: register_proxydome_header sets up the header injection and a request is made.
    Then: It should add the correct x-caller-id header to the request.
    """
    from AWS import register_proxydome_header

    mock_client = mocker.Mock()
    mock_event_system = mocker.Mock()
    mock_client.meta.events = mock_event_system

    mocker.patch("AWS.get_proxydome_token", return_value="test-token-123")

    register_proxydome_header(mock_client)

    # Get the registered function
    header_function = mock_event_system.register_last.call_args[0][1]

    # Test the header injection
    mock_request = mocker.Mock()
    mock_request.headers = {}
    header_function(mock_request)

    assert mock_request.headers["x-caller-id"] == "test-token-123"


def test_ec2_create_security_group_command_success(mocker):
    """
    Given: A mocked boto3 EC2 client and valid security group creation arguments.
    When: create_security_group_command is called successfully.
    Then: It should return CommandResults with security group details and proper outputs.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.create_security_group.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "GroupId": "sg-1234567890abcdef0",
    }

    args = {"group_name": "test-security-group", "description": "Test security group", "vpc_id": "vpc-12345678"}

    result = EC2.create_security_group_command(mock_client, args)
    assert isinstance(result, CommandResults)


def test_ec2_create_security_group_command_without_vpc(mocker):
    """
    Given: A mocked boto3 EC2 client and security group arguments without VPC ID.
    When: create_security_group_command is called for EC2-Classic.
    Then: It should return CommandResults with security group created in EC2-Classic.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.create_security_group.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "GroupId": "sg-1234567890abcdef0",
    }

    args = {"group_name": "classic-security-group", "description": "EC2-Classic security group"}

    result = EC2.create_security_group_command(mock_client, args)
    assert isinstance(result, CommandResults)


def test_ec2_create_security_group_command_client_error(mocker):
    """
    Given: A mocked boto3 EC2 client that raises ClientError.
    When: create_security_group_command encounters a client error.
    Then: It should raise DemistoException with error details.
    """
    from AWS import EC2
    from botocore.exceptions import ClientError

    mock_client = mocker.Mock()
    mocker.patch.object(demisto, "error")
    error_response = {"Error": {"Code": "InvalidGroup.Duplicate", "Message": "The security group already exists"}}
    mock_client.create_security_group.side_effect = ClientError(error_response, "CreateSecurityGroup")

    args = {"group_name": "duplicate-group", "description": "Duplicate security group", "vpc_id": "vpc-12345678"}

    with pytest.raises(DemistoException, match=r".*AWS API Error occurred while executing*"):
        EC2.create_security_group_command(mock_client, args)


def test_ec2_create_security_group_command_unexpected_response(mocker):
    """
    Given: A mocked boto3 EC2 client returning unexpected response status.
    When: create_security_group_command receives non-200 status code.
    Then: It should raise DemistoException with unexpected response message.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mocker.patch.object(demisto, "error")
    mock_client.create_security_group.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.BAD_REQUEST},
        "GroupId": "sg-1234567890abcdef0",
    }

    args = {"group_name": "test-group", "description": "Test group", "vpc_id": "vpc-12345678"}

    with pytest.raises(DemistoException, match=r".*AWS API Error occurred*"):
        EC2.create_security_group_command(mock_client, args)


def test_ec2_create_security_group_command_missing_group_id(mocker):
    """
    Given: A mocked boto3 EC2 client returning response without GroupId.
    When: create_security_group_command receives response missing GroupId.
    Then: It should raise DemistoException with unexpected response message.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mocker.patch.object(demisto, "error")
    mock_client.create_security_group.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.PARTIAL_CONTENT}}

    args = {"group_name": "test-group", "description": "Test group", "vpc_id": "vpc-12345678"}

    with pytest.raises(DemistoException, match=r".*AWS API Error occurred*"):
        EC2.create_security_group_command(mock_client, args)


def test_ec2_create_security_group_command_output_format(mocker):
    """
    Given: A mocked boto3 EC2 client and valid security group creation arguments.
    When: create_security_group_command is called successfully.
    Then: It should return CommandResults with properly formatted outputs and table.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.create_security_group.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "GroupId": "sg-1234567890abcdef0",
    }

    args = {"group_name": "formatted-group", "description": "Formatted security group", "vpc_id": "vpc-12345678"}

    result = EC2.create_security_group_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert 'The security group "sg-1234567890abcdef0" was created successfully.' in result.readable_output


def test_ec2_delete_security_group_command_success_with_group_id(mocker):
    """
    Given: A mocked boto3 EC2 client and valid group_id argument.
    When: delete_security_group_command is called successfully with group_id.
    Then: It should return CommandResults with success message about group deletion.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.delete_security_group.return_value = {"GroupId": "sg-1234567890abcdef0"}

    args = {"group_id": "sg-1234567890abcdef0"}

    result = EC2.delete_security_group_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Successfully deleted security group: sg-1234567890abcdef0" in result.readable_output


def test_ec2_delete_security_group_command_success_with_group_name(mocker):
    """
    Given: A mocked boto3 EC2 client and valid group_name argument.
    When: delete_security_group_command is called successfully with group_name.
    Then: It should return CommandResults with success message about group deletion.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.delete_security_group.return_value = {"GroupId": "sg-1234567890abcdef0"}

    args = {"group_name": "test-security-group"}

    result = EC2.delete_security_group_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Successfully deleted security group: sg-1234567890abcdef0" in result.readable_output


def test_ec2_delete_security_group_command_no_parameters(mocker):
    """
    Given: A mocked boto3 EC2 client and no group identification arguments.
    When: delete_security_group_command is called without group_id or group_name.
    Then: It should raise DemistoException requiring one of the parameters.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    args = {}

    with pytest.raises(DemistoException, match="Either group_id or group_name must be provided"):
        EC2.delete_security_group_command(mock_client, args)


def test_ec2_delete_security_group_command_both_parameters(mocker):
    """
    Given: A mocked boto3 EC2 client and both group_id and group_name arguments.
    When: delete_security_group_command is called with both parameters.
    Then: It should raise DemistoException prohibiting both parameters.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    args = {"group_id": "sg-1234567890abcdef0", "group_name": "test-group"}

    with pytest.raises(DemistoException, match="Cannot specify both group_id and group_name. Please provide only one."):
        EC2.delete_security_group_command(mock_client, args)


def test_ec2_delete_security_group_command_group_not_found(mocker):
    """
    Given: A mocked boto3 EC2 client that raises InvalidGroup.NotFound error.
    When: delete_security_group_command encounters group not found error.
    Then: It should raise DemistoException with group not found message.
    """
    from AWS import EC2
    from botocore.exceptions import ClientError

    mock_client = mocker.Mock()
    mocker.patch.object(demisto, "error")
    error_response = {"Error": {"Code": "InvalidGroup.NotFound", "Message": "The security group does not exist"}}
    mock_client.delete_security_group.side_effect = ClientError(error_response, "DeleteSecurityGroup")

    args = {"group_id": "sg-nonexistent"}

    with pytest.raises(DemistoException, match=r".*AWS API Error occurred*"):
        EC2.delete_security_group_command(mock_client, args)


def test_ec2_delete_security_group_command_group_id_not_found(mocker):
    """
    Given: A mocked boto3 EC2 client that raises InvalidGroupId.NotFound error.
    When: delete_security_group_command encounters group ID not found error.
    Then: It should raise DemistoException with group not found message.
    """
    from AWS import EC2
    from botocore.exceptions import ClientError

    mock_client = mocker.Mock()
    mocker.patch.object(demisto, "error")
    error_response = {"Error": {"Code": "InvalidGroupId.NotFound", "Message": "The security group ID does not exist"}}
    mock_client.delete_security_group.side_effect = ClientError(error_response, "DeleteSecurityGroup")

    args = {"group_id": "sg-invalid"}

    with pytest.raises(DemistoException, match=r".*InvalidGroupId.NotFound*"):
        EC2.delete_security_group_command(mock_client, args)


def test_ec2_describe_security_groups_command_success_with_group_ids(mocker):
    """
    Given: A mocked boto3 EC2 client and valid group_ids argument.
    When: describe_security_groups_command is called with group IDs.
    Then: It should return CommandResults with security group details and proper outputs.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.describe_security_groups.return_value = {
        "NextToken": "NextToken",
        "SecurityGroups": [
            {
                "GroupId": "sg-1234567890abcdef0",
                "GroupName": "test-sg",
                "Description": "Test security group",
                "OwnerId": "123456789012",
                "VpcId": "vpc-12345678",
                "IpPermissions": [],
                "IpPermissionsEgress": [],
                "Tags": [{"Key": "Environment", "Value": "Test"}],
            }
        ],
    }

    args = {"group_ids": "sg-1234567890abcdef0"}

    result = EC2.describe_security_groups_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs == {
        "AWS.EC2.SecurityGroups(val.GroupId && val.GroupId == obj.GroupId)": [
            {
                "GroupId": "sg-1234567890abcdef0",
                "GroupName": "test-sg",
                "Description": "Test security group",
                "OwnerId": "123456789012",
                "VpcId": "vpc-12345678",
                "IpPermissions": [],
                "IpPermissionsEgress": [],
                "Tags": [{"Key": "Environment", "Value": "Test"}],
            }
        ],
        "AWS.EC2(true)": {"SecurityGroupsNextToken": "NextToken"},
    }
    assert "AWS EC2 SecurityGroups" in result.readable_output


def test_ec2_describe_security_groups_command_success_with_group_names(mocker):
    """
    Given: A mocked boto3 EC2 client and valid group_names argument.
    When: describe_security_groups_command is called with group names.
    Then: It should return CommandResults with security group details.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "ssg-1234567890abcdef0",
                "GroupName": "production-sg",
                "Description": "Production security group",
                "OwnerId": "123456789012",
                "VpcId": "vpc-12345678",
                "IpPermissions": [],
                "IpPermissionsEgress": [],
            }
        ]
    }

    args = {"group_names": "production-sg"}

    result = EC2.describe_security_groups_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs["AWS.EC2.SecurityGroups(val.GroupId && val.GroupId == obj.GroupId)"][0]["GroupName"] == "production-sg"
    assert "production-sg" in result.readable_output


def test_ec2_describe_security_groups_command_with_multiple_groups(mocker):
    """
    Given: A mocked boto3 EC2 client and multiple group IDs.
    When: describe_security_groups_command is called with comma-separated group IDs.
    Then: It should return CommandResults with all security groups.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-1111111111111111",
                "GroupName": "1sg",
                "Description": "Description",
                "OwnerId": "123456789012",
                "VpcId": "vpc-11111111",
                "IpPermissions": [],
                "IpPermissionsEgress": [],
            },
            {
                "GroupId": "sg-2222222222222222",
                "GroupName": "2sg",
                "Description": "Description",
                "OwnerId": "123456789012",
                "VpcId": "vpc-22222222",
                "IpPermissions": [],
                "IpPermissionsEgress": [],
            },
        ]
    }

    args = {"group_ids": "sg-1111111111111111, sg-2222222222222222"}

    result = EC2.describe_security_groups_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert len(result.outputs) == 2
    assert (
        result.outputs["AWS.EC2.SecurityGroups(val.GroupId && val.GroupId == obj.GroupId)"][0]["GroupId"] == "sg-1111111111111111"
    )
    assert (
        result.outputs["AWS.EC2.SecurityGroups(val.GroupId && val.GroupId == obj.GroupId)"][1]["GroupId"] == "sg-2222222222222222"
    )


def test_ec2_describe_security_groups_command_no_security_groups_found(mocker):
    """
    Given: A mocked boto3 EC2 client returning empty security groups list.
    When: describe_security_groups_command is called with non-existent group ID.
    Then: It should return CommandResults with no security groups message.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.describe_security_groups.return_value = {"SecurityGroups": []}

    args = {"group_ids": "sg-nonexistent123"}

    result = EC2.describe_security_groups_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.readable_output == "No security groups were found."
    assert result.outputs is None


def test_ec2_describe_security_groups_command_with_tags(mocker):
    """
    Given: A mocked boto3 EC2 client and security group with multiple tags.
    When: describe_security_groups_command is called successfully.
    Then: It should return CommandResults with tags included in the table data.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-1234567890abcdef0",
                "GroupName": "tagged-test-sg",
                "Description": "Security group with tags",
                "OwnerId": "123456789012",
                "VpcId": "vpc-12345678",
                "IpPermissions": [],
                "IpPermissionsEgress": [],
                "Tags": [
                    {"Key": "Environment", "Value": "Production"},
                    {"Key": "Team", "Value": "DevOps"},
                    {"Key": "Application", "Value": "WebApp"},
                ],
            }
        ]
    }

    args = {"group_ids": "sg-1234567890abcdef0"}

    result = EC2.describe_security_groups_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Environment" in result.readable_output
    assert "Production" in result.readable_output
    assert "Team" in result.readable_output


def test_ec2_authorize_security_group_egress_command_success(mocker):
    """
    Given: A mocked boto3 EC2 client and valid security group egress arguments.
    When: authorize_security_group_egress_command is called successfully.
    Then: It should return CommandResults with success message about egress rule authorization.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.authorize_security_group_egress.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "Return": True,
        "SecurityGroupRules": [{"SecurityGroupRuleId": "id"}],
    }

    args = {"group_id": "sg-1234567890abcdef0", "protocol": "tcp", "to_port": "000", "from_port": "000", "cidr": "cidr"}

    result = EC2.authorize_security_group_egress_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "The Security Group egress rule was authorized" in result.readable_output


def test_ec2_authorize_security_group_egress_command_with_port_range(mocker):
    """
    Given: A mocked boto3 EC2 client and egress arguments with port range.
    When: authorize_security_group_egress_command is called with port range format.
    Then: It should return CommandResults and properly parse the port range.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.authorize_security_group_egress.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "Return": True,
        "SecurityGroupRules": [{"SecurityGroupRuleId": "id"}],
    }

    args = {"group_id": "sg-1234567890abcdef0", "protocol": "tcp", "from_port": "0000", "to_port": "0000", "cidr": "cidr"}

    result = EC2.authorize_security_group_egress_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "The Security Group egress rule was authorized" in result.readable_output


def test_ec2_authorize_security_group_egress_command_with_ip_permissions_json(mocker):
    """
    Given: A mocked boto3 EC2 client and egress arguments with ip_permissions JSON.
    When: authorize_security_group_egress_command is called with complex ip_permissions.
    Then: It should return CommandResults and properly parse the JSON ip_permissions.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.authorize_security_group_egress.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "Return": True,
        "SecurityGroupRules": [{"SecurityGroupRuleId": "id"}],
    }

    ip_permissions = json.dumps([{"IpProtocol": "tcp", "FromPort": 000, "ToPort": 000, "IpRanges": [{"CidrIp": "CidrIp"}]}])

    args = {"group_id": "sg-1234567890abcdef0", "ip_permissions": ip_permissions}

    result = EC2.authorize_security_group_egress_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "The Security Group egress rule was authorized" in result.readable_output


def test_ec2_authorize_security_group_egress_command_invalid_json(mocker):
    """
    Given: A mocked boto3 EC2 client and egress arguments with invalid JSON in ip_permissions.
    When: authorize_security_group_egress_command is called with malformed JSON.
    Then: It should raise DemistoException with JSON decode error message.
    """
    from AWS import EC2

    mock_client = mocker.Mock()

    args = {"group_id": "sg-1234567890abcdef0", "ip_permissions": "invalid-json-string"}

    with pytest.raises(DemistoException, match="Received invalid `ip_permissions` JSON object"):
        EC2.authorize_security_group_egress_command(mock_client, args)


def test_ec2_authorize_security_group_egress_command_security_group_not_found(mocker):
    """
    Given: A mocked boto3 EC2 client that raises InvalidGroup.NotFound error.
    When: authorize_security_group_egress_command encounters security group not found error.
    Then: It should raise DemistoException with security group not found message.
    """
    from AWS import EC2
    from botocore.exceptions import ClientError

    mock_client = mocker.Mock()
    mocker.patch.object(demisto, "error")
    error_response = {"Error": {"Code": "InvalidGroup.NotFound", "Message": "InvalidGroup.NotFound"}}
    mock_client.authorize_security_group_egress.side_effect = ClientError(error_response, "AuthorizeSecurityGroupEgress")

    args = {"group_id": "sg-nonexistent", "protocol": "tcp", "from_port": "0000", "to_port": "0000", "cidr": "cidr"}

    with pytest.raises(DemistoException, match=r".*Error Code: InvalidGroup.NotFound*"):
        EC2.authorize_security_group_egress_command(mock_client, args)


def test_ec2_authorize_security_group_egress_command_invalid_group_id(mocker):
    """
    Given: A mocked boto3 EC2 client that raises InvalidGroupId.NotFound error.
    When: authorize_security_group_egress_command encounters invalid group ID error.
    Then: It should raise DemistoException with invalid group ID message.
    """
    from AWS import EC2
    from botocore.exceptions import ClientError

    mock_client = mocker.Mock()
    mocker.patch.object(demisto, "error")

    error_response = {"Error": {"Code": "InvalidGroup.NotFound", "Message": "InvalidGroup.NotFound"}}
    mock_client.authorize_security_group_egress.side_effect = ClientError(error_response, "AuthorizeSecurityGroupEgress")

    args = {"group_id": "sg-invalid", "protocol": "tcp", "from_port": "0000", "to_port": "0000", "cidr": "cidr"}

    with pytest.raises(DemistoException, match=r".*Error Code: InvalidGroup.NotFound*"):
        EC2.authorize_security_group_egress_command(mock_client, args)


def test_ec2_authorize_security_group_egress_command_duplicate_rule(mocker):
    """
    Given: A mocked boto3 EC2 client that raises InvalidPermission.Duplicate error.
    When: authorize_security_group_egress_command encounters duplicate rule error.
    Then: It should raise DemistoException with duplicate rule message.
    """
    from AWS import EC2
    from botocore.exceptions import ClientError

    mock_client = mocker.Mock()
    mocker.patch.object(demisto, "error")
    error_response = {"Error": {"Code": "InvalidPermission.Duplicate", "Message": "InvalidPermission.Duplicate"}}
    mock_client.authorize_security_group_egress.side_effect = ClientError(error_response, "AuthorizeSecurityGroupEgress")

    args = {"group_id": "sg-1234567890abcdef0", "protocol": "tcp", "from_port": "0000", "to_port": "0000", "cidr": "cidr"}

    with pytest.raises(DemistoException, match=r".*Error Code: InvalidPermission.Duplicate*"):
        EC2.authorize_security_group_egress_command(mock_client, args)


def test_ec2_authorize_security_group_egress_command_unexpected_response(mocker):
    """
    Given: A mocked boto3 EC2 client returning unexpected response format.
    When: authorize_security_group_egress_command receives unexpected response.
    Then: It should raise DemistoException with unexpected response message.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mocker.patch.object(demisto, "error")
    mock_client.authorize_security_group_egress.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.BAD_REQUEST},
        "Return": False,
        "SecurityGroupRules": [{"SecurityGroupRuleId": "id"}],
    }

    args = {"group_id": "sg-1234567890abcdef0", "protocol": "tcp", "from_port": "0000", "to_port": "0000", "cidr": "cidr"}

    with pytest.raises(DemistoException, match=r".*Status Code: 400*"):
        EC2.authorize_security_group_egress_command(mock_client, args)


def test_ec2_authorize_security_group_egress_command_without_port(mocker):
    """
    Given: A mocked boto3 EC2 client and egress arguments without port specification.
    When: authorize_security_group_egress_command is called without port parameter.
    Then: It should return CommandResults and handle None port values properly.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.authorize_security_group_egress.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "Return": True,
        "SecurityGroupRules": [{"SecurityGroupRuleId": "id"}],
    }

    args = {"group_id": "sg-1234567890abcdef0", "protocol": "protocol", "cidr": "cidr"}

    result = EC2.authorize_security_group_egress_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "The Security Group egress rule was authorized" in result.readable_output


def test_parse_filter_field_with_valid_single_filter():
    """
    Given: A single valid filter string with name and values.
    When: parse_filter_field function processes the input.
    Then: It should return a list with one filter dict containing Name and Values.
    """
    from AWS import parse_filter_field

    result = parse_filter_field("name=instance-state-name,values=running")
    assert len(result) == 1
    assert result[0]["Name"] == "instance-state-name"
    assert result[0]["Values"] == ["running"]


def test_parse_filter_field_with_multiple_filters():
    """
    Given: Multiple valid filter strings separated by semicolons.
    When: parse_filter_field function processes the input.
    Then: It should return a list with multiple filter dicts.
    """
    from AWS import parse_filter_field

    filter_string = "name=instance-state-name,values=running;name=tag:Environment,values=production,staging"
    result = parse_filter_field(filter_string)
    assert len(result) == 2
    assert result[0]["Name"] == "instance-state-name"
    assert result[0]["Values"] == ["running"]
    assert result[1]["Name"] == "tag:Environment"
    assert result[1]["Values"] == ["production", "staging"]


def test_parse_filter_field_with_multiple_values():
    """
    Given: A filter string with multiple comma-separated values.
    When: parse_filter_field function processes the input.
    Then: It should return a filter dict with Values as a list of multiple items.
    """
    from AWS import parse_filter_field

    result = parse_filter_field("name=instance-type,values=1,2,3")
    assert len(result) == 1
    assert result[0]["Name"] == "instance-type"
    assert result[0]["Values"] == ["1", "2", "3"]


def test_parse_filter_field_with_none_input():
    """
    Given: A None value passed to parse_filter_field function.
    When: The function attempts to process the None input.
    Then: It should return an empty list.
    """
    from AWS import parse_filter_field

    result = parse_filter_field(None)
    assert result == []


def test_parse_filter_field_with_empty_string():
    """
    Given: An empty string passed to parse_filter_field function.
    When: The function attempts to process the empty input.
    Then: It should return an empty list.
    """
    from AWS import parse_filter_field

    result = parse_filter_field("")
    assert result == []


def test_parse_filter_field_with_invalid_format():
    """
    Given: A filter string that doesn't match the expected regex pattern.
    When: parse_filter_field function processes the malformed input.
    Then: It should skip the invalid filter and return an empty list.
    """
    from AWS import parse_filter_field

    result = parse_filter_field("invalid-filter-format")
    assert result == []


def test_parse_filter_field_with_mixed_valid_invalid_filters():
    """
    Given: Multiple filter strings where some are valid and some are invalid.
    When: parse_filter_field function processes the mixed input.
    Then: It should return only the valid filters and skip invalid ones.
    """
    from AWS import parse_filter_field

    filter_string = "name=valid-filter,values=test;invalid-format;name=another-valid,values=value1,value2"
    result = parse_filter_field(filter_string)
    assert len(result) == 2
    assert result[0]["Name"] == "valid-filter"
    assert result[0]["Values"] == ["test"]
    assert result[1]["Name"] == "another-valid"
    assert result[1]["Values"] == ["value1", "value2"]


def test_parse_filter_field_with_spaces_in_values():
    """
    Given: A filter string with spaces in the values field.
    When: parse_filter_field function processes the input with spaces.
    Then: It should successfully parse the filter preserving spaces in values.
    """
    from AWS import parse_filter_field

    result = parse_filter_field("name=tag:Name,values=My App Server,Test Instance")
    assert len(result) == 1
    assert result[0]["Name"] == "tag:Name"
    assert result[0]["Values"] == ["My App Server", "Test Instance"]


def test_parse_filter_field_with_missing_values():
    """
    Given: A filter string with name but missing values part.
    When: parse_filter_field function processes the incomplete input.
    Then: It should skip the invalid filter and return an empty list.
    """
    from AWS import parse_filter_field

    result = parse_filter_field("name=instance-state-name")
    assert result == []


def test_parse_filter_field_with_missing_name():
    """
    Given: A filter string with values but missing name part.
    When: parse_filter_field function processes the incomplete input.
    Then: It should skip the invalid filter and return an empty list.
    """
    from AWS import parse_filter_field

    result = parse_filter_field("values=running,stopped")
    assert result == []


def test_parse_filter_field_with_colon_in_value():
    """
    Given: A filter string with values but missing name part.
    When: parse_filter_field function processes the incomplete input.
    Then: It should skip the invalid filter and return an empty list.
    """
    from AWS import parse_filter_field

    result = parse_filter_field("name=instance-state-name,values=running:active,stopped:inactive")
    expected = [{"Name": "instance-state-name", "Values": ["running:active", "stopped:inactive"]}]
    assert result == expected
