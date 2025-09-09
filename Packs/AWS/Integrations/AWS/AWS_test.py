import json
from datetime import datetime, date
from http import HTTPStatus

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
        "user_ids": "accountID, accountID",
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
        "launch_permission_add_user_id": "accountID",
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

    args = {"group_id": "sg-1234567890abcdef0", "protocol": "tcp", "port": "80", "cidr": "0.0.0.0/0"}

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

    args = {"group_id": "sg-1234567890abcdef0", "protocol": "tcp", "port": "443", "cidr": "10.0.0.0/8"}

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

    args = {"group_id": "sg-1234567890abcdef0", "protocol": "tcp", "port": "80", "cidr": "0.0.0.0/0"}

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

    args = {"group_id": "sg-1234567890abcdef0", "protocol": "tcp", "port": "80-443", "cidr": "0.0.0.0/0"}

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

    args = {"db_cluster_snapshot_identifier": "test-snapshot", "attribute_name": "restore", "values_to_add": ["accountID"]}

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
        "values_to_add": ["accountID", "accountID"],
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

    args = {"db_snapshot_identifier": "test-snapshot", "attribute_name": "restore", "values_to_remove": ["accountID"]}

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
            "TrailARN": "arn:aws:cloudtrail:us-east-1:accountID:trail/test-trail",
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


def test_aws_error_handler_handle_response_error_with_request_id(mocker):
    """
    Given: A response dict with ResponseMetadata including RequestId and HTTPStatusCode.
    When: handle_response_error is called with the response.
    Then: It should raise DemistoException with detailed error information including RequestId.
    """
    from AWS import AWSErrorHandler

    mocker.patch("AWS.demisto.command", return_value="test-command")
    mocker.patch("AWS.demisto.args", return_value={"arg1": "value1"})
    demisto_results = mocker.patch("AWS.demisto.results")

    response = {"ResponseMetadata": {"RequestId": "RequestId", "HTTPStatusCode": 400}}

    with pytest.raises(SystemExit):
        AWSErrorHandler.handle_response_error(response, "accountID")

    demisto_results.assert_called_once_with(
        {
            "Type": 4,
            "ContentsFormat": "text",
            "Contents": "AWS API Error occurred while executing:"
            " test-command with arguments: {'arg1': 'value1'}\nRequest Id: RequestId\nHTTP Status Code: 400",
            "EntryContext": None,
        }
    )


def test_aws_error_handler_handle_response_error_missing_metadata(mocker):
    """
    Given: A response dict without ResponseMetadata.
    When: handle_response_error is called with the response.
    Then: It should raise DemistoException with N/A values for missing metadata.
    """
    from AWS import AWSErrorHandler

    mocker.patch("AWS.demisto.command", return_value="test-command")
    mocker.patch("AWS.demisto.args", return_value={})
    demisto_results = mocker.patch("AWS.demisto.results")

    response = {}

    with pytest.raises(SystemExit):
        AWSErrorHandler.handle_response_error(response)

    demisto_results.assert_called_once_with(
        {
            "Type": 4,
            "ContentsFormat": "text",
            "Contents": "AWS API Error occurred while executing: test-command with arguments: {}"
            "\nRequest Id: N/A\nHTTP Status Code: N/A",
            "EntryContext": None,
        }
    )


def test_aws_error_handler_handle_client_error_access_denied(mocker):
    """
    Given: A ClientError with AccessDenied error code.
    When: handle_client_error is called with the error.
    Then: It should call _handle_permission_error and return_multiple_permissions_error.
    """
    from AWS import AWSErrorHandler
    from botocore.exceptions import ClientError

    mock_return_multiple_permissions_error = mocker.patch("AWS.return_multiple_permissions_error")
    mocker.patch("AWS.demisto.args", return_value={"account_id": "accountID"})
    mocker.patch("AWS.demisto.info")
    mocker.patch("AWS.demisto.debug")

    error_response = {
        "Error": {"Code": "AccessDenied", "Message": "User is not authorized to perform action"},
        "ResponseMetadata": {"HTTPStatusCode": 403},
    }
    client_error = ClientError(error_response, "test-operation")

    AWSErrorHandler.handle_client_error(client_error, "accountID")

    mock_return_multiple_permissions_error.assert_called_once()
    call_args = mock_return_multiple_permissions_error.call_args[0][0]
    assert len(call_args) == 1
    assert call_args[0]["account_id"] == "accountID"


def test_aws_error_handler_handle_client_error_unauthorized_operation(mocker):
    """
    Given: A ClientError with UnauthorizedOperation error code.
    When: handle_client_error is called with the error.
    Then: It should handle it as a permission error.
    """
    from AWS import AWSErrorHandler
    from botocore.exceptions import ClientError

    mock_return_multiple_permissions_error = mocker.patch("AWS.return_multiple_permissions_error")
    mocker.patch("AWS.demisto.args", return_value={"account_id": "accountID"})
    mocker.patch("AWS.demisto.info")
    mocker.patch("AWS.demisto.debug")

    error_response = {
        "Error": {"Code": "UnauthorizedOperation", "Message": "You are not authorized to perform this operation"},
        "ResponseMetadata": {"HTTPStatusCode": 401},
    }
    client_error = ClientError(error_response, "test-operation")

    AWSErrorHandler.handle_client_error(client_error)

    mock_return_multiple_permissions_error.assert_called_once()


def test_aws_error_handler_handle_client_error_http_401(mocker):
    """
    Given: A ClientError with HTTP status code 401 but different error code.
    When: handle_client_error is called with the error.
    Then: It should handle it as a permission error based on HTTP status.
    """
    from AWS import AWSErrorHandler
    from botocore.exceptions import ClientError

    mock_return_multiple_permissions_error = mocker.patch("AWS.return_multiple_permissions_error")
    mocker.patch("AWS.demisto.args", return_value={})
    mocker.patch("AWS.demisto.info")
    mocker.patch("AWS.demisto.debug")

    error_response = {
        "Error": {"Code": "CustomError", "Message": "Authentication failed"},
        "ResponseMetadata": {"HTTPStatusCode": 401},
    }
    client_error = ClientError(error_response, "test-operation")

    AWSErrorHandler.handle_client_error(client_error, "accountID")

    mock_return_multiple_permissions_error.assert_called_once()


def test_aws_error_handler_handle_client_error_general_error(mocker):
    """
    Given: A ClientError with non-permission error code.
    When: handle_client_error is called with the error.
    Then: It should raise DemistoException with detailed error information.
    """
    from AWS import AWSErrorHandler
    from botocore.exceptions import ClientError

    mocker.patch("AWS.demisto.command", return_value="test-command")
    mocker.patch("AWS.demisto.args", return_value={"param": "value"})
    mocker.patch("AWS.demisto.error")
    demisto_results = mocker.patch("AWS.demisto.results")

    error_response = {
        "Error": {"Code": "InvalidParameterValue", "Message": "The parameter value is invalid"},
        "ResponseMetadata": {"HTTPStatusCode": 400, "RequestId": "RequestId"},
    }
    client_error = ClientError(error_response, "test-operation")

    with pytest.raises(SystemExit):
        AWSErrorHandler.handle_client_error(client_error, "accountID")

    demisto_results.assert_called_once_with(
        {
            "Type": 4,
            "ContentsFormat": "text",
            "Contents": "AWS API Error occurred while executing:"
            " test-command with arguments: {'param': 'value'}\n"
            "Error Code: InvalidParameterValue\nError Message: "
            "The parameter value is invalid\nHTTP Status Code: 400\n"
            "Request ID: RequestId",
            "EntryContext": None,
        }
    )


def test_aws_error_handler_handle_permission_error_no_account_id(mocker):
    """
    Given: A permission error without account_id provided.
    When: _handle_permission_error is called.
    Then: It should get account_id from demisto.args() and use "unknown" if not found.
    """
    from AWS import AWSErrorHandler
    from botocore.exceptions import ClientError

    mock_return_multiple_permissions_error = mocker.patch("AWS.return_multiple_permissions_error")
    mocker.patch("AWS.demisto.args", return_value={})
    mocker.patch("AWS.demisto.info")
    mocker.patch("AWS.demisto.debug")

    error_response = {"Error": {"Code": "AccessDenied", "Message": "Access denied for operation"}}
    client_error = ClientError(error_response, "test-operation")

    AWSErrorHandler._handle_permission_error(client_error, "AccessDenied", "Access denied for operation", None)

    mock_return_multiple_permissions_error.assert_called_once()
    call_args = mock_return_multiple_permissions_error.call_args[0][0]
    assert call_args[0]["account_id"] == "unknown"


def test_aws_error_handler_remove_encoded_authorization_message_with_encoding(mocker):
    """
    Given: An error message containing encoded authorization failure message.
    When: remove_encoded_authorization_message is called.
    Then: It should return the message truncated before the encoded part.
    """
    from AWS import AWSErrorHandler

    message = "Access denied. User is not authorized. Encoded authorization failure message: <message>"
    result = AWSErrorHandler.remove_encoded_authorization_message(message)

    assert result == "Access denied. User is not authorized. "
    assert "Encoded authorization failure message:" not in result


def test_aws_error_handler_remove_encoded_authorization_message_case_insensitive(mocker):
    """
    Given: An error message with mixed case encoded authorization failure message.
    When: remove_encoded_authorization_message is called.
    Then: It should find and remove the encoded part case-insensitively.
    """
    from AWS import AWSErrorHandler

    message = "Access denied. ENCODED AUTHORIZATION FAILURE MESSAGE: <message>"
    result = AWSErrorHandler.remove_encoded_authorization_message(message)

    assert result == "Access denied. "


def test_aws_error_handler_remove_encoded_authorization_message_no_encoding():
    """
    Given: An error message without encoded authorization failure message.
    When: remove_encoded_authorization_message is called.
    Then: It should return the original message unchanged.
    """
    from AWS import AWSErrorHandler

    message = "Simple access denied error"
    result = AWSErrorHandler.remove_encoded_authorization_message(message)

    assert result == message


def test_aws_error_handler_handle_general_error_missing_metadata(mocker):
    """
    Given: A ClientError with missing ResponseMetadata fields.
    When: _handle_general_error is called.
    Then: It should handle missing fields gracefully with N/A values.
    """
    from AWS import AWSErrorHandler
    from botocore.exceptions import ClientError

    mocker.patch("AWS.demisto.command", return_value="test-command")
    mocker.patch("AWS.demisto.args", return_value={})
    demisto_results = mocker.patch("AWS.demisto.results")
    mocker.patch("AWS.demisto.error")

    error_response = {"Error": {"Code": "TestError", "Message": "Test message"}, "ResponseMetadata": {}}
    client_error = ClientError(error_response, "test-operation")

    with pytest.raises(SystemExit):
        AWSErrorHandler._handle_general_error(client_error, "TestError", "Test message")

    demisto_results.assert_called_once_with(
        {
            "Type": 4,
            "ContentsFormat": "text",
            "Contents": "AWS API Error occurred while executing:"
            " test-command with arguments: {}\n"
            "Error Code: TestError\n"
            "Error Message: Test message\nHTTP Status Code: N/A\nRequest ID: N/A",
            "EntryContext": None,
        }
    )


def test_aws_error_handler_extract_action_from_message_valid_action(mocker):
    """
    Given: An error message containing a valid AWS action from REQUIRED_ACTIONS.
    When: _extract_action_from_message is called.
    Then: It should return the matched action name.
    """
    from AWS import AWSErrorHandler

    mocker.patch("AWS.REQUIRED_ACTIONS", ["action_1", "action_2"])

    message = "User is not authorized to perform action_1 on resource"
    result = AWSErrorHandler._extract_action_from_message(message)

    assert result == "action_1"


def test_aws_error_handler_extract_action_from_message_case_insensitive(mocker):
    """
    Given: An error message with action in different case.
    When: _extract_action_from_message is called.
    Then: It should match case-insensitively and return the action.
    """
    from AWS import AWSErrorHandler

    mocker.patch("AWS.REQUIRED_ACTIONS", ["action_2"])

    message = "Permission denied for action_2"
    result = AWSErrorHandler._extract_action_from_message(message)

    assert result == "action_2"


def test_aws_error_handler_extract_action_from_message_no_match(mocker):
    """
    Given: An error message without any known AWS actions.
    When: _extract_action_from_message is called.
    Then: It should return "unknown".
    """
    from AWS import AWSErrorHandler

    mocker.patch("AWS.REQUIRED_ACTIONS", ["action_1"])

    message = "Generic access denied error"
    result = AWSErrorHandler._extract_action_from_message(message)

    assert result == "unknown"


def test_aws_error_handler_extract_action_from_message_empty_input():
    """
    Given: An empty or None error message.
    When: _extract_action_from_message is called.
    Then: It should return "unknown" safely.
    """
    from AWS import AWSErrorHandler

    assert AWSErrorHandler._extract_action_from_message(None) == "unknown"
    assert AWSErrorHandler._extract_action_from_message("") == "unknown"
    assert AWSErrorHandler._extract_action_from_message(123) == "unknown"


def test_s3_get_bucket_policy_command_success(mocker):
    """
    Given: A mocked boto3 S3 client and valid bucket name.
    When: get_bucket_policy_command is called successfully.
    Then: It should return CommandResults with policy data and outputs.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "Resource"}],
    }
    mock_client.get_bucket_policy.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "Policy": json.dumps(policy_document),
    }

    args = {"bucket": "test-bucket"}

    result = S3.get_bucket_policy_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "AWS.S3-Buckets"
    assert result.outputs_key_field == "BucketName"
    assert result.outputs["BucketName"] == "test-bucket"
    assert result.outputs["Policy"] == policy_document


def test_s3_get_bucket_policy_command_with_expected_bucket_owner(mocker):
    """
    Given: A mocked boto3 S3 client and bucket name with expected bucket owner.
    When: get_bucket_policy_command is called with expected_bucket_owner parameter.
    Then: It should return CommandResults and pass the expected_bucket_owner to the API call.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    policy_document = {"Version": "2012-10-17", "Statement": []}
    mock_client.get_bucket_policy.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "Policy": json.dumps(policy_document),
    }

    args = {"bucket": "test-bucket", "expected_bucket_owner": "expected_bucket_owner"}

    result = S3.get_bucket_policy_command(mock_client, args)
    mock_client.get_bucket_policy.assert_called_once_with(Bucket="test-bucket", ExpectedBucketOwner="expected_bucket_owner")
    assert isinstance(result, CommandResults)
    assert result.outputs["BucketName"] == "test-bucket"


def test_s3_get_bucket_policy_command_empty_policy(mocker):
    """
    Given: A mocked boto3 S3 client returning empty policy.
    When: get_bucket_policy_command is called with successful response but empty policy.
    Then: It should return CommandResults with empty policy object.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.get_bucket_policy.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}, "Policy": "{}"}

    args = {"bucket": "test-bucket"}

    result = S3.get_bucket_policy_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs["Policy"] == {}


def test_s3_get_bucket_policy_command_complex_policy(mocker):
    """
    Given: A mocked boto3 S3 client returning complex policy with multiple statements.
    When: get_bucket_policy_command is called successfully.
    Then: It should return CommandResults with properly parsed complex policy.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    complex_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "AllowPublicRead", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "Resource"},
            {
                "Sid": "DenyInsecureConnections",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": ["Resource_1", "Resource_2"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            },
        ],
    }
    mock_client.get_bucket_policy.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "Policy": json.dumps(complex_policy),
    }

    args = {"bucket": "test-bucket"}

    result = S3.get_bucket_policy_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs["Policy"] == complex_policy
    assert len(result.outputs["Policy"]["Statement"]) == 2


def test_s3_get_bucket_policy_command_failure_response(mocker):
    """
    Given: A mocked boto3 S3 client returning non-OK status code.
    When: get_bucket_policy_command is called with failed response.
    Then: It should call AWSErrorHandler.handle_response_error.
    """
    from AWS import S3, AWSErrorHandler

    mock_client = mocker.Mock()
    mock_client.get_bucket_policy.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.NOT_FOUND}}
    mock_handle_error = mocker.patch.object(AWSErrorHandler, "handle_response_error")

    args = {"bucket": "test-bucket"}

    S3.get_bucket_policy_command(mock_client, args)
    mock_handle_error.assert_called_once()


def test_s3_get_bucket_policy_command_malformed_json_policy(mocker):
    """
    Given: A mocked boto3 S3 client returning malformed JSON policy.
    When: get_bucket_policy_command is called with invalid JSON in policy.
    Then: It should raise a JSON decode error.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.get_bucket_policy.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "Policy": "invalid json content",
    }

    args = {"bucket": "test-bucket"}

    with pytest.raises(json.JSONDecodeError):
        S3.get_bucket_policy_command(mock_client, args)


def test_s3_get_bucket_policy_command_missing_policy_key(mocker):
    """
    Given: A mocked boto3 S3 client returning response without Policy key.
    When: get_bucket_policy_command is called with missing Policy in response.
    Then: It should handle the missing Policy key gracefully.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.get_bucket_policy.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    args = {"bucket": "test-bucket"}

    result = S3.get_bucket_policy_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs["Policy"] == {}


def test_s3_get_bucket_policy_command_null_expected_bucket_owner(mocker):
    """
    Given: A mocked boto3 S3 client and args with null expected_bucket_owner.
    When: get_bucket_policy_command is called with None expected_bucket_owner.
    Then: It should remove the null value and not include it in API call.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.get_bucket_policy.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}, "Policy": "{}"}

    args = {"bucket": "test-bucket", "expected_bucket_owner": None}

    S3.get_bucket_policy_command(mock_client, args)
    mock_client.get_bucket_policy.assert_called_once_with(Bucket="test-bucket")


def test_s3_get_bucket_policy_command_table_markdown_output(mocker):
    """
    Given: A mocked boto3 S3 client returning a policy.
    When: get_bucket_policy_command is called successfully.
    Then: It should generate readable_output with proper table markdown formatting.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    policy_document = {"Version": "2012-10-17", "Id": "ExamplePolicy"}
    mock_client.get_bucket_policy.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "Policy": json.dumps(policy_document),
    }

    args = {"bucket": "test-bucket"}

    result = S3.get_bucket_policy_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Bucket Policy" in result.readable_output
    assert "Version" in result.readable_output
    assert "2012-10-17" in result.readable_output


def test_s3_get_bucket_encryption_command_success(mocker):
    """
    Given: A mocked boto3 S3 client and valid bucket name.
    When: get_bucket_encryption_command is called successfully.
    Then: It should return CommandResults with encryption configuration and proper outputs.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.get_bucket_encryption.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "ServerSideEncryptionConfiguration": {
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "SSEAlgorithm"}}]
        },
    }

    args = {"bucket": "test-bucket"}

    result = S3.get_bucket_encryption_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "AWS.S3-Buckets"
    assert result.outputs_key_field == "BucketName"
    assert result.outputs["BucketName"] == "test-bucket"
    assert "ServerSideEncryptionConfiguration" in result.outputs


def test_s3_get_bucket_encryption_command_with_expected_bucket_owner(mocker):
    """
    Given: A mocked boto3 S3 client with bucket name and expected bucket owner.
    When: get_bucket_encryption_command is called with expected_bucket_owner parameter.
    Then: It should return CommandResults and include expected_bucket_owner in API call.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.get_bucket_encryption.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "ServerSideEncryptionConfiguration": {
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "SSEAlgorithm", "KMSMasterKeyID": "KMSMasterKeyID"}}
            ]
        },
    }

    args = {"bucket": "test-bucket", "expected_bucket_owner": "expected_bucket_owner"}

    result = S3.get_bucket_encryption_command(mock_client, args)
    assert isinstance(result, CommandResults)
    mock_client.get_bucket_encryption.assert_called_once_with(Bucket="test-bucket", ExpectedBucketOwner="expected_bucket_owner")
    assert result.outputs["BucketName"] == "test-bucket"


def test_s3_get_bucket_encryption_command_empty_encryption_config(mocker):
    """
    Given: A mocked boto3 S3 client returning empty encryption configuration.
    When: get_bucket_encryption_command is called with successful response but no encryption.
    Then: It should return CommandResults with empty ServerSideEncryptionConfiguration.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.get_bucket_encryption.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    args = {"bucket": "test-bucket"}

    result = S3.get_bucket_encryption_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs["ServerSideEncryptionConfiguration"] == {}
    assert "Server Side Encryption Configuration" in result.readable_output


def test_s3_get_bucket_encryption_command_failure(mocker):
    """
    Given: A mocked boto3 S3 client returning non-OK status code.
    When: get_bucket_encryption_command is called with failed response.
    Then: It should call AWSErrorHandler.handle_response_error.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.get_bucket_encryption.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.BAD_REQUEST}}

    mock_error_handler = mocker.patch("AWS.AWSErrorHandler.handle_response_error")

    args = {"bucket": "test-bucket"}

    S3.get_bucket_encryption_command(mock_client, args)
    mock_error_handler.assert_called_once()


def test_s3_get_bucket_encryption_command_none_expected_bucket_owner(mocker):
    """
    Given: A mocked boto3 S3 client with None expected_bucket_owner.
    When: get_bucket_encryption_command is called with None expected_bucket_owner.
    Then: It should remove None values and call API without expected_bucket_owner parameter.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.get_bucket_encryption.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "ServerSideEncryptionConfiguration": {"Rules": []},
    }

    args = {"bucket": "test-bucket", "expected_bucket_owner": None}

    result = S3.get_bucket_encryption_command(mock_client, args)
    assert isinstance(result, CommandResults)
    mock_client.get_bucket_encryption.assert_called_once_with(Bucket="test-bucket")


def test_s3_get_bucket_encryption_command_complex_encryption_config(mocker):
    """
    Given: A mocked boto3 S3 client returning complex encryption configuration with multiple rules.
    When: get_bucket_encryption_command is called successfully.
    Then: It should return CommandResults with complete encryption configuration in outputs.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    complex_config = {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "SSEAlgorithm", "KMSMasterKeyID": "KMSMasterKeyID"},
                "BucketKeyEnabled": True,
            },
            {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "SSEAlgorithm"}},
        ]
    }
    mock_client.get_bucket_encryption.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "ServerSideEncryptionConfiguration": complex_config,
    }

    args = {"bucket": "test-bucket"}

    result = S3.get_bucket_encryption_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs["ServerSideEncryptionConfiguration"] == complex_config
    assert len(result.outputs["ServerSideEncryptionConfiguration"]["Rules"]) == 2


def test_s3_get_bucket_encryption_command_missing_response_metadata(mocker):
    """
    Given: A mocked boto3 S3 client returning response without ResponseMetadata.
    When: get_bucket_encryption_command is called with malformed response.
    Then: It should call AWSErrorHandler.handle_response_error due to missing metadata.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.get_bucket_encryption.return_value = {"ServerSideEncryptionConfiguration": {"Rules": []}}

    mock_error_handler = mocker.patch("AWS.AWSErrorHandler.handle_response_error")

    args = {"bucket": "test-bucket"}

    S3.get_bucket_encryption_command(mock_client, args)
    mock_error_handler.assert_called_once()


def test_s3_get_public_access_block_command_success(mocker):
    """
    Given: A mocked boto3 S3 client and valid bucket name.
    When: get_public_access_block_command is called successfully.
    Then: It should return CommandResults with public access block configuration and outputs.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    public_access_block_config = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": False,
    }
    mock_client.get_public_access_block.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "PublicAccessBlockConfiguration": public_access_block_config,
    }

    args = {"bucket": "test-bucket"}

    result = S3.get_public_access_block_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "AWS.S3-Buckets"
    assert result.outputs_key_field == "BucketName"
    assert result.outputs["BucketName"] == "test-bucket"
    assert result.outputs["PublicAccessBlock"] == public_access_block_config


def test_s3_get_public_access_block_command_with_expected_bucket_owner(mocker):
    """
    Given: A mocked boto3 S3 client and bucket name with expected bucket owner.
    When: get_public_access_block_command is called with expected_bucket_owner parameter.
    Then: It should return CommandResults and pass the expected_bucket_owner to the API call.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    public_access_block_config = {
        "BlockPublicAcls": False,
        "IgnorePublicAcls": False,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
    mock_client.get_public_access_block.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "PublicAccessBlockConfiguration": public_access_block_config,
    }

    args = {"bucket": "test-bucket", "expected_bucket_owner": "expected_bucket_owner"}

    result = S3.get_public_access_block_command(mock_client, args)
    mock_client.get_public_access_block.assert_called_once_with(Bucket="test-bucket", ExpectedBucketOwner="expected_bucket_owner")
    assert isinstance(result, CommandResults)
    assert result.outputs["BucketName"] == "test-bucket"


def test_s3_get_public_access_block_command_empty_configuration(mocker):
    """
    Given: A mocked boto3 S3 client returning empty public access block configuration.
    When: get_public_access_block_command is called with successful response but empty configuration.
    Then: It should return CommandResults with empty public access block object.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.get_public_access_block.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "PublicAccessBlockConfiguration": {},
    }

    args = {"bucket": "test-bucket"}

    result = S3.get_public_access_block_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs["PublicAccessBlock"] == {}


def test_s3_get_public_access_block_command_partial_configuration(mocker):
    """
    Given: A mocked boto3 S3 client returning partial public access block configuration.
    When: get_public_access_block_command is called successfully.
    Then: It should return CommandResults with properly parsed partial configuration.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    partial_config = {"BlockPublicAcls": True, "IgnorePublicAcls": True}
    mock_client.get_public_access_block.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "PublicAccessBlockConfiguration": partial_config,
    }

    args = {"bucket": "test-bucket"}

    result = S3.get_public_access_block_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs["PublicAccessBlock"] == partial_config
    assert len(result.outputs["PublicAccessBlock"]) == 2


def test_s3_get_public_access_block_command_failure_response(mocker):
    """
    Given: A mocked boto3 S3 client returning non-OK status code.
    When: get_public_access_block_command is called with failed response.
    Then: It should call AWSErrorHandler.handle_response_error.
    """
    from AWS import S3, AWSErrorHandler

    mock_client = mocker.Mock()
    mock_client.get_public_access_block.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.NOT_FOUND}}
    mock_handle_error = mocker.patch.object(AWSErrorHandler, "handle_response_error")

    args = {"bucket": "test-bucket"}

    S3.get_public_access_block_command(mock_client, args)
    mock_handle_error.assert_called_once()


def test_s3_get_public_access_block_command_missing_configuration_key(mocker):
    """
    Given: A mocked boto3 S3 client returning response without PublicAccessBlockConfiguration key.
    When: get_public_access_block_command is called with missing configuration in response.
    Then: It should handle the missing configuration key gracefully.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.get_public_access_block.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    args = {"bucket": "test-bucket"}

    result = S3.get_public_access_block_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs["PublicAccessBlock"] == {}


def test_s3_get_public_access_block_command_null_expected_bucket_owner(mocker):
    """
    Given: A mocked boto3 S3 client and args with null expected_bucket_owner.
    When: get_public_access_block_command is called with None expected_bucket_owner.
    Then: It should remove the null value and not include it in API call.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.get_public_access_block.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "PublicAccessBlockConfiguration": {},
    }

    args = {"bucket": "test-bucket", "expected_bucket_owner": None}

    S3.get_public_access_block_command(mock_client, args)
    mock_client.get_public_access_block.assert_called_once_with(Bucket="test-bucket")


def test_s3_get_public_access_block_command_table_markdown_output(mocker):
    """
    Given: A mocked boto3 S3 client returning a public access block configuration.
    When: get_public_access_block_command is called successfully.
    Then: It should generate readable_output with proper table markdown formatting.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    public_access_block_config = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": False,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": False,
    }
    mock_client.get_public_access_block.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "PublicAccessBlockConfiguration": public_access_block_config,
    }

    args = {"bucket": "test-bucket"}

    result = S3.get_public_access_block_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Public Access Block configuration" in result.readable_output
    assert "Block Public Acls" in result.readable_output
    assert "true" in result.readable_output


def test_s3_get_public_access_block_command_all_settings_enabled(mocker):
    """
    Given: A mocked boto3 S3 client returning all public access block settings enabled.
    When: get_public_access_block_command is called successfully.
    Then: It should return CommandResults with all settings set to True.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    all_enabled_config = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
    mock_client.get_public_access_block.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "PublicAccessBlockConfiguration": all_enabled_config,
    }

    args = {"bucket": "test-bucket"}

    result = S3.get_public_access_block_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs["PublicAccessBlock"] == all_enabled_config
    assert all(result.outputs["PublicAccessBlock"].values())


def test_s3_get_public_access_block_command_all_settings_disabled(mocker):
    """
    Given: A mocked boto3 S3 client returning all public access block settings disabled.
    When: get_public_access_block_command is called successfully.
    Then: It should return CommandResults with all settings set to False.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    all_disabled_config = {
        "BlockPublicAcls": False,
        "IgnorePublicAcls": False,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": False,
    }
    mock_client.get_public_access_block.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "PublicAccessBlockConfiguration": all_disabled_config,
    }

    args = {"bucket": "test-bucket"}

    result = S3.get_public_access_block_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs["PublicAccessBlock"] == all_disabled_config
    assert not any(result.outputs["PublicAccessBlock"].values())


def test_s3_get_public_access_block_command_missing_response_metadata(mocker):
    """
    Given: A mocked boto3 S3 client returning response without ResponseMetadata.
    When: get_public_access_block_command is called with missing metadata.
    Then: It should handle the missing ResponseMetadata gracefully.
    """
    from AWS import S3, AWSErrorHandler

    mock_client = mocker.Mock()
    mock_client.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True}}
    mock_handle_error = mocker.patch.object(AWSErrorHandler, "handle_response_error")

    args = {"bucket": "test-bucket"}

    S3.get_public_access_block_command(mock_client, args)
    mock_handle_error.assert_called_once()


def test_s3_delete_bucket_policy_command_success(mocker):
    """
    Given: A mocked boto3 S3 client and valid bucket name.
    When: delete_bucket_policy_command is called successfully.
    Then: It should return CommandResults with success message about policy deletion.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.delete_bucket_policy.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.NO_CONTENT}}

    args = {"bucket": "test-bucket"}

    result = S3.delete_bucket_policy_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Successfully deleted bucket policy from bucket 'test-bucket'" in result.readable_output


def test_s3_delete_bucket_policy_command_failure_response(mocker):
    """
    Given: A mocked boto3 S3 client returning non-NO_CONTENT status code.
    When: delete_bucket_policy_command is called with failed response.
    Then: It should call AWSErrorHandler.handle_response_error.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.delete_bucket_policy.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.BAD_REQUEST}}

    mock_error_handler = mocker.patch("AWS.AWSErrorHandler.handle_response_error")

    args = {"bucket": "test-bucket"}

    S3.delete_bucket_policy_command(mock_client, args)
    mock_error_handler.assert_called_once()


def test_s3_delete_bucket_policy_command_ok_status_code(mocker):
    """
    Given: A mocked boto3 S3 client returning OK status instead of NO_CONTENT.
    When: delete_bucket_policy_command is called with OK response.
    Then: It should call AWSErrorHandler.handle_response_error.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.delete_bucket_policy.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    mock_error_handler = mocker.patch("AWS.AWSErrorHandler.handle_response_error")

    args = {"bucket": "test-bucket"}

    S3.delete_bucket_policy_command(mock_client, args)
    mock_error_handler.assert_called_once()


def test_s3_delete_bucket_policy_command_missing_response_metadata(mocker):
    """
    Given: A mocked boto3 S3 client returning response without ResponseMetadata.
    When: delete_bucket_policy_command is called with malformed response.
    Then: It should call AWSErrorHandler.handle_response_error.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.delete_bucket_policy.return_value = {}

    mock_error_handler = mocker.patch("AWS.AWSErrorHandler.handle_response_error")

    args = {"bucket": "test-bucket"}

    S3.delete_bucket_policy_command(mock_client, args)
    mock_error_handler.assert_called_once()


def test_s3_delete_bucket_policy_command_missing_http_status_code(mocker):
    """
    Given: A mocked boto3 S3 client returning ResponseMetadata without HTTPStatusCode.
    When: delete_bucket_policy_command is called with incomplete response metadata.
    Then: It should call AWSErrorHandler.handle_response_error.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.delete_bucket_policy.return_value = {"ResponseMetadata": {}}

    mock_error_handler = mocker.patch("AWS.AWSErrorHandler.handle_response_error")

    args = {"bucket": "test-bucket"}

    S3.delete_bucket_policy_command(mock_client, args)
    mock_error_handler.assert_called_once()


def test_s3_delete_bucket_policy_command_verify_api_call_parameters(mocker):
    """
    Given: A mocked boto3 S3 client and valid bucket name.
    When: delete_bucket_policy_command is called successfully.
    Then: It should call delete_bucket_policy with correct parameters.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.delete_bucket_policy.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.NO_CONTENT}}

    args = {"bucket": "my-test-bucket"}

    S3.delete_bucket_policy_command(mock_client, args)
    mock_client.delete_bucket_policy.assert_called_once_with(Bucket="my-test-bucket")


def test_s3_delete_bucket_policy_command_debug_logging(mocker):
    """
    Given: A mocked boto3 S3 client and valid bucket name.
    When: delete_bucket_policy_command is called successfully.
    Then: It should call print_debug_logs with appropriate message.
    """
    from AWS import S3

    mock_client = mocker.Mock()
    mock_client.delete_bucket_policy.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.NO_CONTENT}}

    mock_print_debug_logs = mocker.patch("AWS.print_debug_logs")

    args = {"bucket": "test-bucket"}

    S3.delete_bucket_policy_command(mock_client, args)
    mock_print_debug_logs.assert_called_once_with(mock_client, "Deleting bucket policy for bucket: test-bucket")
