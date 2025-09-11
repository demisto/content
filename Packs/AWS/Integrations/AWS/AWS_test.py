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

    args = {"instance_id": "InstanceID", "http_tokens": "required", "http_endpoint": "enabled"}

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

    args = {"instance_id": "InstanceID", "http_tokens": "required"}

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

    args = {"instance_id": "InstanceID", "attribute": "instanceType", "value": "t3.micro"}

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

    args = {"instance_id": "InstanceID", "groups": "sg-test, sg-test, sg-789"}

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
        "image_id": "amInstanceID",
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

    args = {"image_id": "amInstanceID", "attribute": "description", "description": "Updated AMI description"}

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

    args = {"group_id": "sg-test", "protocol": "tcp", "port": "80", "cidr": "0.0.0.0/0"}

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

    args = {"group_id": "sg-test", "ip_permissions": ip_permissions}

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

    args = {"group_id": "sg-test", "protocol": "tcp", "port": "443", "cidr": "10.0.0.0/8"}

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

    args = {"group_id": "sg-test", "protocol": "tcp", "port": "80", "cidr": "0.0.0.0/0"}

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

    args = {"group_id": "sg-test", "protocol": "tcp", "port": "80-443", "cidr": "0.0.0.0/0"}

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

    args = {"group_id": "sg-test", "ip_permissions": ip_permissions}

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


def test_cloudtrail_describe_trails_command_success(mocker):
    """
    Given: A mocked boto3 CloudTrail client and valid trail name arguments.
    When: describe_trails_command is called successfully.
    Then: It should return CommandResults with trail list data and proper outputs.
    """
    from AWS import CloudTrail

    mock_client = mocker.Mock()
    mock_client.describe_trails.return_value = {
        "trailList": [
            {
                "Name": "test-trail",
                "S3BucketName": "test-bucket",
                "IncludeGlobalServiceEvents": True,
                "IsMultiRegionTrail": True,
                "TrailARN": "TrailARN",
                "LogFileValidationEnabled": True,
                "HomeRegion": "us-east-1",
            }
        ]
    }

    args = {"trail_names": ["test-trail"], "include_shadow_trails": "true"}

    result = CloudTrail.describe_trails_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "AWS.CloudTrail.Trails"
    assert result.outputs_key_field == "TrailARN"
    assert "Trail List" in result.readable_output


def test_cloudtrail_describe_trails_command_with_multiple_trails(mocker):
    """
    Given: A mocked boto3 CloudTrail client and multiple trail names.
    When: describe_trails_command is called with multiple trail names.
    Then: It should return CommandResults with data for all specified trails.
    """
    from AWS import CloudTrail

    mock_client = mocker.Mock()
    mock_client.describe_trails.return_value = {
        "trailList": [
            {"Name": "trail-1", "S3BucketName": "bucket-1", "TrailARN": "TrailARN-1", "HomeRegion": "us-east-1"},
            {"Name": "trail-2", "S3BucketName": "bucket-2", "TrailARN": "TrailARN-2", "HomeRegion": "us-west-2"},
        ]
    }

    args = {"trail_names": ["trail-1", "trail-2"]}

    result = CloudTrail.describe_trails_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert len(result.outputs) == 2


def test_cloudtrail_describe_trails_command_no_trail_names(mocker):
    """
    Given: A mocked boto3 CloudTrail client without specific trail names.
    When: describe_trails_command is called without trail_names argument.
    Then: It should return CommandResults with all trails in the account.
    """
    from AWS import CloudTrail

    mock_client = mocker.Mock()
    mock_client.describe_trails.return_value = {
        "trailList": [
            {"Name": "default-trail", "S3BucketName": "default-bucket", "TrailARN": "TrailARN", "HomeRegion": "us-east-1"}
        ]
    }

    args = {}

    result = CloudTrail.describe_trails_command(mock_client, args)
    assert isinstance(result, CommandResults)
    mock_client.describe_trails.assert_called_once()
    call_kwargs = mock_client.describe_trails.call_args[1]
    assert "trailNameList" not in call_kwargs


def test_cloudtrail_describe_trails_command_include_shadow_trails_false(mocker):
    """
    Given: A mocked boto3 CloudTrail client with include_shadow_trails set to false.
    When: describe_trails_command is called with include_shadow_trails as false.
    Then: It should pass includeShadowTrails as False to the API call.
    """
    from AWS import CloudTrail

    mock_client = mocker.Mock()
    mock_client.describe_trails.return_value = {"trailList": []}

    args = {"include_shadow_trails": "false"}

    result = CloudTrail.describe_trails_command(mock_client, args)
    assert isinstance(result, CommandResults)
    mock_client.describe_trails.assert_called_once_with(includeShadowTrails=False)


def test_cloudtrail_describe_trails_command_empty_trail_list(mocker):
    """
    Given: A mocked boto3 CloudTrail client returning empty trail list.
    When: describe_trails_command is called and no trails are found.
    Then: It should return CommandResults with empty trail list and proper structure.
    """
    from AWS import CloudTrail

    mock_client = mocker.Mock()
    mock_client.describe_trails.return_value = {"trailList": []}

    args = {"trail_names": ["non-existent-trail"]}

    result = CloudTrail.describe_trails_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs == []
    assert "Trail List" in result.readable_output


def test_cloudtrail_describe_trails_command_missing_trail_list_key(mocker):
    """
    Given: A mocked boto3 CloudTrail client returning response without trailList key.
    When: describe_trails_command processes response missing trailList.
    Then: It should handle missing key gracefully and return empty list.
    """
    from AWS import CloudTrail

    mock_client = mocker.Mock()
    mock_client.describe_trails.return_value = {}

    args = {}

    result = CloudTrail.describe_trails_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs == []


def test_cloudtrail_describe_trails_command_with_all_trail_properties(mocker):
    """
    Given: A mocked boto3 CloudTrail client returning trail with all possible properties.
    When: describe_trails_command is called and receives comprehensive trail data.
    Then: It should return CommandResults with all trail properties properly displayed.
    """
    from AWS import CloudTrail

    mock_client = mocker.Mock()
    mock_client.describe_trails.return_value = {
        "trailList": [
            {
                "Name": "trail",
                "S3BucketName": "S3BucketName",
                "S3KeyPrefix": "logs/",
                "SnsTopicName": "SnsTopicName",
                "IncludeGlobalServiceEvents": True,
                "IsMultiRegionTrail": True,
                "TrailARN": "TrailARN",
                "LogFileValidationEnabled": True,
                "CloudWatchLogsLogGroupArn": "CloudWatchLogsLogGroupArn",
                "CloudWatchLogsRoleArn": "CloudWatchLogsRoleArn",
                "KMSKeyId": "KMSKeyId",
                "HomeRegion": "us-east-1",
                "HasCustomEventSelectors": True,
                "HasInsightSelectors": False,
                "IsOrganizationTrail": False,
            }
        ]
    }

    args = {"trail_names": ["trail"]}

    result = CloudTrail.describe_trails_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "trail" in result.readable_output
    assert result.outputs[0]["Name"] == "trail"


def test_cloudtrail_describe_trails_command_default_include_shadow_trails(mocker):
    """
    Given: A mocked boto3 CloudTrail client without include_shadow_trails argument.
    When: describe_trails_command is called with default include_shadow_trails behavior.
    Then: It should use the default value of True for includeShadowTrails.
    """
    from AWS import CloudTrail

    mock_client = mocker.Mock()
    mock_client.describe_trails.return_value = {"trailList": []}

    args = {"trail_names": ["test-trail"]}

    result = CloudTrail.describe_trails_command(mock_client, args)
    assert isinstance(result, CommandResults)
    mock_client.describe_trails.assert_called_once()
    call_kwargs = mock_client.describe_trails.call_args[1]
    assert call_kwargs["includeShadowTrails"] is True


def test_ec2_terminate_instances_command_success(mocker):
    """
    Given: A mocked boto3 EC2 client and valid instance IDs.
    When: terminate_instances_command is called successfully.
    Then: It should return CommandResults with success message about instance termination.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.terminate_instances.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "TerminatingInstances": [
            {"InstanceId": "InstanceID", "CurrentState": {"Name": "shutting-down"}},
            {"InstanceId": "InstanceID", "CurrentState": {"Name": "shutting-down"}},
        ],
    }

    args = {"instance_ids": "InstanceID,InstanceID"}

    result = EC2.terminate_instances_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "The instances have been terminated successfully" in result.readable_output


def test_ec2_terminate_instances_command_single_instance(mocker):
    """
    Given: A mocked boto3 EC2 client and a single instance ID.
    When: terminate_instances_command is called with one instance.
    Then: It should return CommandResults with success message.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.terminate_instances.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "TerminatingInstances": [{"InstanceId": "InstanceID", "CurrentState": {"Name": "shutting-down"}}],
    }

    args = {"instance_ids": "InstanceID"}

    result = EC2.terminate_instances_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "The instances have been terminated successfully" in result.readable_output


def test_ec2_terminate_instances_command_empty_instance_ids(mocker):
    """
    Given: A mocked boto3 EC2 client and empty list of instance IDs.
    When: terminate_instances_command is called with empty instance_ids list.
    Then: It should raise DemistoException indicating instance_ids is required.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    args = {"instance_ids": []}

    with pytest.raises(DemistoException, match="instance_ids parameter is required"):
        EC2.terminate_instances_command(mock_client, args)


def test_ec2_terminate_instances_command_http_error_response(mocker):
    """
    Given: A mocked boto3 EC2 client returning non-OK HTTP status.
    When: terminate_instances_command is called with failed HTTP response.
    Then: It should handle the error response appropriately.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.terminate_instances.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.BAD_REQUEST}}

    mock_error_handler = mocker.patch("AWS.AWSErrorHandler.handle_response_error")

    args = {"instance_ids": "InstanceID"}

    EC2.terminate_instances_command(mock_client, args)
    mock_error_handler.assert_called_once()


def test_ec2_terminate_instances_command_terminating_stopping_instances_response(mocker):
    """
    Given: A mocked boto3 EC2 client that doesn't raise exceptions but returns invalid response.
    When: terminate_instances_command completes without success or error.
    Then: It should return CommandResults with No instance message.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.terminate_instances.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}}

    args = {"instance_ids": "InstanceID"}

    result = EC2.terminate_instances_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "No instances were terminated." in result.readable_output


def test_ec2_start_instances_command_success(mocker):
    """
    Given: A mocked boto3 EC2 client and valid instance IDs.
    When: start_instances_command is called successfully.
    Then: It should return CommandResults with success message about instances starting.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.start_instances.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "StartingInstances": [
            {
                "InstanceId": "InstanceID",
                "CurrentState": {"Code": 0, "Name": "pending"},
                "PreviousState": {"Code": 80, "Name": "stopped"},
            }
        ],
    }

    args = {"instance_ids": ["InstanceID"]}

    result = EC2.start_instances_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "The instances have been started successfully" in result.readable_output


def test_ec2_start_instances_command_multiple_instances(mocker):
    """
    Given: A mocked boto3 EC2 client and multiple instance IDs.
    When: start_instances_command is called with multiple instances.
    Then: It should return CommandResults with success message and start all instances.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.start_instances.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "StartingInstances": [
            {
                "InstanceId": "InstanceID",
                "CurrentState": {"Code": 0, "Name": "pending"},
                "PreviousState": {"Code": 80, "Name": "stopped"},
            },
            {
                "InstanceId": "InstanceID",
                "CurrentState": {"Code": 0, "Name": "pending"},
                "PreviousState": {"Code": 80, "Name": "stopped"},
            },
        ],
    }

    args = {"instance_ids": ["InstanceID", "InstanceID"]}

    result = EC2.start_instances_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "The instances have been started successfully" in result.readable_output
    mock_client.start_instances.assert_called_once_with(InstanceIds=["InstanceID", "InstanceID"])


def test_ec2_start_instances_command_comma_separated_ids(mocker):
    """
    Given: A mocked boto3 EC2 client and comma-separated instance IDs string.
    When: start_instances_command is called with comma-separated instance IDs.
    Then: It should properly parse the string and start all instances.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.start_instances.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "StartingInstances": [
            {
                "InstanceId": "InstanceID",
                "CurrentState": {"Code": 0, "Name": "pending"},
                "PreviousState": {"Code": 80, "Name": "stopped"},
            }
        ],
    }

    args = {"instance_ids": "InstanceID,InstanceID"}

    result = EC2.start_instances_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "The instances have been started successfully" in result.readable_output


def test_ec2_start_instances_command_bad_request_status(mocker):
    """
    Given: A mocked boto3 EC2 client returning non-OK HTTP status.
    When: start_instances_command is called with failed HTTP response.
    Then: It should handle the response error appropriately.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.start_instances.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.BAD_REQUEST},
        "StartingInstances": [],
    }

    mock_error_handler = mocker.patch("AWS.AWSErrorHandler.handle_response_error")

    args = {"instance_ids": ["InstanceID"]}

    EC2.start_instances_command(mock_client, args)
    mock_error_handler.assert_called_once()


def test_ec2_start_instances_command_empty_instance_ids(mocker):
    """
    Given: A mocked boto3 EC2 client and args without instance_ids key.
    When: start_instances_command is called without instance_ids argument.
    Then: It should use empty list as default and call the client.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.start_instances.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}, "StartingInstances": []}

    args = {"instance_ids": "id"}

    result = EC2.start_instances_command(mock_client, args)
    mock_client.start_instances.assert_called_once_with(InstanceIds=["id"])
    assert isinstance(result, CommandResults)
    assert "No instances were started." in result.readable_output


def test_ec2_start_instances_command_raw_response_included(mocker):
    """
    Given: A mocked boto3 EC2 client with successful response.
    When: start_instances_command is called successfully.
    Then: It should return CommandResults with raw_response included.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    expected_response = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "StartingInstances": [
            {
                "InstanceId": "InstanceID",
                "CurrentState": {"Code": 0, "Name": "pending"},
                "PreviousState": {"Code": 80, "Name": "stopped"},
            }
        ],
    }
    mock_client.start_instances.return_value = expected_response

    args = {"instance_ids": ["InstanceID"]}

    result = EC2.start_instances_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.raw_response == expected_response


def test_ec2_stop_instances_command_success(mocker):
    """
    Given: A mocked boto3 EC2 client and valid instance IDs.
    When: stop_instances_command is called successfully.
    Then: It should return CommandResults with success message about instances stopping.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.stop_instances.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "StoppingInstances": [
            {
                "InstanceId": "InstanceID",
                "CurrentState": {"Code": 64, "Name": "stopping"},
                "PreviousState": {"Code": 16, "Name": "running"},
            }
        ],
    }

    args = {"instance_ids": ["InstanceID"]}

    result = EC2.stop_instances_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "The instances have been stopped successfully" in result.readable_output


def test_ec2_stop_instances_command_multiple_instances(mocker):
    """
    Given: A mocked boto3 EC2 client and multiple instance IDs.
    When: stop_instances_command is called with multiple instances.
    Then: It should return CommandResults with success message and stop all instances.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.stop_instances.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "StoppingInstances": [
            {
                "InstanceId": "InstanceID",
                "CurrentState": {"Code": 64, "Name": "stopping"},
                "PreviousState": {"Code": 16, "Name": "running"},
            },
            {
                "InstanceId": "InstanceID",
                "CurrentState": {"Code": 64, "Name": "stopping"},
                "PreviousState": {"Code": 16, "Name": "running"},
            },
        ],
    }

    args = {"instance_ids": ["InstanceID", "InstanceID"], "hibernate": "false", "force": "false"}

    result = EC2.stop_instances_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "The instances have been stopped successfully" in result.readable_output
    mock_client.stop_instances.assert_called_once_with(InstanceIds=["InstanceID", "InstanceID"], Force=False, Hibernate=False)


def test_ec2_stop_instances_command_with_force_flag(mocker):
    """
    Given: A mocked boto3 EC2 client and instance IDs with force flag enabled.
    When: stop_instances_command is called with force=true.
    Then: It should pass Force=True to the boto3 client call.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.stop_instances.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "StoppingInstances": [
            {
                "InstanceId": "InstanceID",
                "CurrentState": {"Code": 64, "Name": "stopping"},
                "PreviousState": {"Code": 16, "Name": "running"},
            }
        ],
    }

    args = {"instance_ids": ["InstanceID"], "hibernate": "false", "force": "true"}

    result = EC2.stop_instances_command(mock_client, args)
    assert isinstance(result, CommandResults)
    mock_client.stop_instances.assert_called_once_with(InstanceIds=["InstanceID"], Force=True, Hibernate=False)


def test_ec2_stop_instances_command_with_hibernate_flag(mocker):
    """
    Given: A mocked boto3 EC2 client and instance IDs with hibernate flag enabled.
    When: stop_instances_command is called with hibernate=true.
    Then: It should pass Hibernate=True to the boto3 client call.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.stop_instances.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "StoppingInstances": [
            {
                "InstanceId": "InstanceID",
                "CurrentState": {"Code": 64, "Name": "stopping"},
                "PreviousState": {"Code": 16, "Name": "running"},
            }
        ],
    }

    args = {"instance_ids": ["InstanceID"], "hibernate": "true", "force": "false"}

    result = EC2.stop_instances_command(mock_client, args)
    assert isinstance(result, CommandResults)
    mock_client.stop_instances.assert_called_once_with(InstanceIds=["InstanceID"], Force=False, Hibernate=True)


def test_ec2_stop_instances_command_with_both_flags(mocker):
    """
    Given: A mocked boto3 EC2 client and instance IDs with both force and hibernate flags.
    When: stop_instances_command is called with force=true and hibernate=true.
    Then: It should pass both Force=True and Hibernate=True to the boto3 client call.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.stop_instances.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "StoppingInstances": [
            {
                "InstanceId": "InstanceID",
                "CurrentState": {"Code": 64, "Name": "stopping"},
                "PreviousState": {"Code": 16, "Name": "running"},
            }
        ],
    }

    args = {"instance_ids": ["InstanceID"], "force": "true", "hibernate": "true"}

    result = EC2.stop_instances_command(mock_client, args)
    assert isinstance(result, CommandResults)
    mock_client.stop_instances.assert_called_once_with(InstanceIds=["InstanceID"], Force=True, Hibernate=True)


def test_ec2_stop_instances_command_comma_separated_ids(mocker):
    """
    Given: A mocked boto3 EC2 client and comma-separated instance IDs string.
    When: stop_instances_command is called with comma-separated instance IDs.
    Then: It should properly parse the string and stop all instances.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.stop_instances.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "StoppingInstances": [
            {
                "InstanceId": "InstanceID",
                "CurrentState": {"Code": 64, "Name": "stopping"},
                "PreviousState": {"Code": 16, "Name": "running"},
            },
            {
                "InstanceId": "InstanceID",
                "CurrentState": {"Code": 64, "Name": "stopping"},
                "PreviousState": {"Code": 16, "Name": "running"},
            },
        ],
    }

    args = {"instance_ids": "InstanceID,InstanceID"}

    result = EC2.stop_instances_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "The instances have been stopped successfully" in result.readable_output


def test_ec2_stop_instances_command_no_stopping_instances_response(mocker):
    """
    Given: A mocked boto3 EC2 client and empty instance IDs list.
    When: stop_instances_command is called with empty instance IDs list.
    Then: It should raise DemistoException indicating instance_ids is required.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    args = {"instance_ids": []}

    with pytest.raises(DemistoException, match="instance_ids parameter is required"):
        EC2.stop_instances_command(mock_client, args)


def test_ec2_stop_instances_command_bad_request_status(mocker):
    """
    Given: A mocked boto3 EC2 client returning non-OK HTTP status.
    When: stop_instances_command is called with failed HTTP response.
    Then: It should handle the response error appropriately.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.stop_instances.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.BAD_REQUEST},
        "StoppingInstances": [],
    }

    mock_error_handler = mocker.patch("AWS.AWSErrorHandler.handle_response_error")

    args = {"instance_ids": ["InstanceID"]}

    EC2.stop_instances_command(mock_client, args)
    mock_error_handler.assert_called_once()


def test_ec2_stop_instances_command_raw_response_included(mocker):
    """
    Given: A mocked boto3 EC2 client with successful response.
    When: stop_instances_command is called successfully.
    Then: It should return CommandResults with raw_response included.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    expected_response = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "StoppingInstances": [
            {
                "InstanceId": "InstanceID",
                "CurrentState": {"Code": 64, "Name": "stopping"},
                "PreviousState": {"Code": 16, "Name": "running"},
            }
        ],
    }
    mock_client.stop_instances.return_value = expected_response

    args = {"instance_ids": ["InstanceID"]}

    result = EC2.stop_instances_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.raw_response == expected_response


def test_ec2_stop_instances_command_with_spaces_in_ids(mocker):
    """
    Given: A mocked boto3 EC2 client and instance IDs with spaces.
    When: stop_instances_command is called with space-separated instance IDs.
    Then: It should properly parse the instance IDs and return success message.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.stop_instances.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "StoppingInstances": [
            {
                "InstanceId": "InstanceID",
                "CurrentState": {"Code": 64, "Name": "stopping"},
                "PreviousState": {"Code": 16, "Name": "running"},
            },
            {
                "InstanceId": "InstanceID",
                "CurrentState": {"Code": 64, "Name": "stopping"},
                "PreviousState": {"Code": 16, "Name": "running"},
            },
        ],
    }

    args = {"instance_ids": "InstanceID, InstanceID", "hibernate": "false", "force": "false"}

    result = EC2.stop_instances_command(mock_client, args)
    assert isinstance(result, CommandResults)
    mock_client.stop_instances.assert_called_once_with(InstanceIds=["InstanceID", "InstanceID"], Force=False, Hibernate=False)


def test_ec2_run_instances_command_success_basic(mocker):
    """
    Given: A mocked boto3 EC2 client and basic instance configuration.
    When: run_instances_command is called with minimal required parameters.
    Then: It should return CommandResults with success message and instance details.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.run_instances.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "Instances": [
            {
                "InstanceId": "InstanceID",
                "ImageId": "ImageID",
                "State": {"Name": "pending"},
                "InstanceType": "InstanceType",
                "LaunchTime": datetime(2023, 10, 15, 14, 30, 45),
            }
        ],
    }

    mocker.patch(
        "AWS.process_instance_data",
        return_value={"InstanceId": "InstanceID", "ImageId": "ImageID", "State": "pending", "Type": "InstanceType"},
    )

    args = {"image_id": "ImageID", "count": 1}

    result = EC2.run_instances_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Launched 1 EC2 Instance(s)" in result.readable_output
    assert result.outputs_prefix == "AWS.EC2.Instances"


def test_ec2_run_instances_command_with_launch_template_id(mocker):
    """
    Given: A mocked boto3 EC2 client and launch template ID configuration.
    When: run_instances_command is called with launch template ID.
    Then: It should use the launch template and return success.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.run_instances.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "Instances": [
            {
                "InstanceId": "InstanceID",
                "ImageId": "ImageID",
                "State": {"Name": "pending"},
                "InstanceType": "InstanceType",
                "LaunchTime": datetime(2023, 10, 15, 14, 30, 45),
            }
        ],
    }

    mocker.patch("AWS.process_instance_data", return_value={})

    args = {"launch_template_id": "LaunchTemplateId", "count": 1}

    result = EC2.run_instances_command(mock_client, args)
    assert isinstance(result, CommandResults)
    mock_client.run_instances.assert_called_once()
    call_args = mock_client.run_instances.call_args[1]
    assert call_args["LaunchTemplate"]["LaunchTemplateId"] == "LaunchTemplateId"


def test_ec2_run_instances_command_with_launch_template_name_and_version(mocker):
    """
    Given: A mocked boto3 EC2 client and launch template name with version.
    When: run_instances_command is called with launch template name and version.
    Then: It should use the named launch template with specified version.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.run_instances.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "Instances": [
            {
                "InstanceId": "InstanceID",
                "ImageId": "ImageID",
                "State": {"Name": "pending"},
                "InstanceType": "InstanceType",
                "LaunchTime": datetime(2023, 10, 15, 14, 30, 45),
            }
        ],
    }

    mocker.patch("AWS.process_instance_data", return_value={})

    args = {"launch_template_name": "my-template", "launch_template_version": "$Latest", "count": 1}

    result = EC2.run_instances_command(mock_client, args)
    assert isinstance(result, CommandResults)
    call_args = mock_client.run_instances.call_args[1]
    assert call_args["LaunchTemplate"]["LaunchTemplateName"] == "my-template"
    assert call_args["LaunchTemplate"]["Version"] == "$Latest"


def test_ec2_run_instances_command_with_security_groups(mocker):
    """
    Given: A mocked boto3 EC2 client and security group configuration.
    When: run_instances_command is called with security group IDs and names.
    Then: It should pass the security groups to the API call.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.run_instances.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "Instances": [
            {
                "InstanceId": "InstanceID",
                "ImageId": "ImageID",
                "State": {"Name": "pending"},
                "InstanceType": "InstanceType",
                "LaunchTime": datetime(2023, 10, 15, 14, 30, 45),
            }
        ],
    }

    mocker.patch("AWS.process_instance_data", return_value={})

    args = {"image_id": "ImageID", "security_group_ids": "sg-test,sg-test", "security_groups_names": "default,web-sg", "count": 1}

    result = EC2.run_instances_command(mock_client, args)
    assert isinstance(result, CommandResults)
    call_args = mock_client.run_instances.call_args[1]
    assert call_args["SecurityGroupIds"] == ["sg-test", "sg-test"]
    assert call_args["SecurityGroups"] == ["default", "web-sg"]


def test_ec2_run_instances_command_with_ebs_configuration(mocker):
    """
    Given: A mocked boto3 EC2 client and EBS block device configuration.
    When: run_instances_command is called with EBS parameters.
    Then: It should configure the block device mapping correctly.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.run_instances.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "Instances": [
            {
                "InstanceId": "InstanceID",
                "ImageId": "ImageID",
                "State": {"Name": "pending"},
                "InstanceType": "InstanceType",
                "LaunchTime": datetime(2023, 10, 15, 14, 30, 45),
            }
        ],
    }

    mocker.patch("AWS.process_instance_data", return_value={})

    args = {
        "image_id": "ImageID",
        "device_name": "DeviceName",
        "ebs_volume_size": "20",
        "ebs_volume_type": "VolumeType",
        "ebs_delete_on_termination": "true",
        "ebs_encrypted": "true",
        "count": 1,
    }

    result = EC2.run_instances_command(mock_client, args)
    assert isinstance(result, CommandResults)
    call_args = mock_client.run_instances.call_args[1]
    block_device = call_args["BlockDeviceMappings"][0]
    assert block_device["DeviceName"] == "DeviceName"
    assert block_device["Ebs"]["VolumeSize"] == 20
    assert block_device["Ebs"]["VolumeType"] == "VolumeType"
    assert block_device["Ebs"]["DeleteOnTermination"] is True
    assert block_device["Ebs"]["Encrypted"] is True


def test_ec2_run_instances_command_with_iam_instance_profile(mocker):
    """
    Given: A mocked boto3 EC2 client and IAM instance profile configuration.
    When: run_instances_command is called with IAM instance profile ARN and name.
    Then: It should configure the IAM instance profile correctly.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.run_instances.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "Instances": [
            {
                "InstanceId": "InstanceID",
                "ImageId": "ImageID",
                "State": {"Name": "pending"},
                "InstanceType": "InstanceType",
                "LaunchTime": datetime(2023, 10, 15, 14, 30, 45),
            }
        ],
    }

    mocker.patch("AWS.process_instance_data", return_value={})

    args = {
        "image_id": "ImageID",
        "iam_instance_profile_arn": "IamInstanceProfileARN",
        "iam_instance_profile_name": "MyProfile",
        "count": 1,
    }

    result = EC2.run_instances_command(mock_client, args)
    assert isinstance(result, CommandResults)
    call_args = mock_client.run_instances.call_args[1]
    assert call_args["IamInstanceProfile"]["Arn"] == "IamInstanceProfileARN"
    assert call_args["IamInstanceProfile"]["Name"] == "MyProfile"


def test_ec2_run_instances_command_with_tags(mocker):
    """
    Given: A mocked boto3 EC2 client and instance tags configuration.
    When: run_instances_command is called with tags parameter.
    Then: It should configure the tag specifications correctly.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.run_instances.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "Instances": [
            {
                "InstanceId": "InstanceID",
                "ImageId": "ImageID",
                "State": {"Name": "pending"},
                "InstanceType": "InstanceType",
                "LaunchTime": datetime(2023, 10, 15, 14, 30, 45),
            }
        ],
    }

    mocker.patch("AWS.process_instance_data", return_value={})
    mocker.patch("AWS.parse_tag_field", return_value=[{"Key": "Name", "Value": "TestInstance"}])

    args = {"image_id": "ImageID", "tags": "Name=TestInstance", "count": 1}

    result = EC2.run_instances_command(mock_client, args)
    assert isinstance(result, CommandResults)
    call_args = mock_client.run_instances.call_args[1]
    assert call_args["TagSpecifications"][0]["ResourceType"] == "instance"


def test_ec2_run_instances_command_with_multiple_instances(mocker):
    """
    Given: A mocked boto3 EC2 client and count parameter greater than 1.
    When: run_instances_command is called with count=3.
    Then: It should launch multiple instances and show correct count in output.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.run_instances.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
        "Instances": [
            {
                "InstanceId": "InstanceID",
                "ImageId": "ImageID",
                "State": {"Name": "pending"},
                "InstanceType": "InstanceType",
                "LaunchTime": datetime(2023, 10, 15, 14, 30, 45),
            },
            {
                "InstanceId": "InstanceID",
                "ImageId": "ImageID",
                "State": {"Name": "pending"},
                "InstanceType": "InstanceType",
                "LaunchTime": datetime(2023, 10, 15, 14, 30, 45),
            },
            {
                "InstanceId": "InstanceID",
                "ImageId": "ImageID",
                "State": {"Name": "pending"},
                "InstanceType": "InstanceType",
                "LaunchTime": datetime(2023, 10, 15, 14, 30, 45),
            },
        ],
    }

    mocker.patch("AWS.process_instance_data", return_value={})

    args = {"image_id": "ImageID", "count": 3}

    result = EC2.run_instances_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "Launched 3 EC2 Instance(s)" in result.readable_output
    call_args = mock_client.run_instances.call_args[1]
    assert call_args["MinCount"] == 3
    assert call_args["MaxCount"] == 3


def test_ec2_run_instances_command_invalid_count_zero(mocker):
    """
    Given: A mocked boto3 EC2 client and count parameter of 0.
    When: run_instances_command is called with count=0.
    Then: It should raise DemistoException for invalid count.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    args = {"image_id": "ImageID", "count": 0}

    with pytest.raises(DemistoException, match="count parameter must be a positive integer"):
        EC2.run_instances_command(mock_client, args)


def test_ec2_run_instances_command_invalid_count_negative(mocker):
    """
    Given: A mocked boto3 EC2 client and negative count parameter.
    When: run_instances_command is called with count=-1.
    Then: It should raise DemistoException for invalid count.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    args = {"image_id": "ImageID", "count": -1}

    with pytest.raises(DemistoException, match="count parameter must be a positive integer"):
        EC2.run_instances_command(mock_client, args)


def test_ec2_run_instances_command_no_instances_launched(mocker):
    """
    Given: A mocked boto3 EC2 client returning empty instances list.
    When: run_instances_command is called but no instances are returned.
    Then: It should return CommandResults with no instances message.
    """
    from AWS import EC2

    mock_client = mocker.Mock()
    mock_client.run_instances.return_value = {"ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK}, "Instances": []}

    args = {"image_id": "ImageID", "count": 1}

    result = EC2.run_instances_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert "No instances were launched" in result.readable_output


def test_parse_tag_field_with_valid_single_tag():
    """
    Given: A valid tag string with single key-value pair.
    When: parse_tag_field processes the input.
    Then: It should return a list with one properly formatted tag dictionary.
    """
    from AWS import parse_tag_field

    result = parse_tag_field("key=Key1,value=Value1")
    assert result == [{"Key": "Key1", "Value": "Value1"}]


def test_parse_tag_field_with_multiple_valid_tags():
    """
    Given: A valid tag string with multiple key-value pairs separated by semicolons.
    When: parse_tag_field processes the input.
    Then: It should return a list with multiple properly formatted tag dictionaries.
    """
    from AWS import parse_tag_field

    result = parse_tag_field("key=Key1,value=Value1;key=Key2,value=Value2")
    assert result == [{"Key": "Key1", "Value": "Value1"}, {"Key": "Key2", "Value": "Value2"}]


def test_parse_tag_field_with_none_input():
    """
    Given: A None value is passed to parse_tag_field function.
    When: The function attempts to process the None input.
    Then: It should return an empty list.
    """
    from AWS import parse_tag_field

    result = parse_tag_field(None)
    assert result == []


def test_parse_tag_field_with_empty_string():
    """
    Given: An empty string is passed to parse_tag_field function.
    When: The function attempts to process the empty string.
    Then: It should return an empty list.
    """
    from AWS import parse_tag_field

    result = parse_tag_field("")
    assert result == []


def test_parse_tag_field_with_invalid_format():
    """
    Given: A tag string with invalid format (missing value part).
    When: parse_tag_field processes the malformed input.
    Then: It should raise an error.
    """
    from AWS import parse_tag_field

    with pytest.raises(ValueError):
        parse_tag_field("key=Key1")


def test_parse_tag_field_with_mixed_valid_and_invalid_tags():
    """
    Given: A tag string with both valid and invalid formatted tags.
    When: parse_tag_field processes the mixed input.
    Then: It should raise an error.
    """
    from AWS import parse_tag_field

    with pytest.raises(ValueError):
        parse_tag_field("key=Key1,value=Value1;invalid-tag;key=Key2,value=Value2")


def test_parse_tag_field_with_empty_value(mocker):
    """
    Given: A tag string with empty value part.
    When: parse_tag_field processes the input with empty value.
    Then: It should return a tag with empty value string.
    """
    from AWS import parse_tag_field

    mocker.patch.object(demisto, "debug")
    result = parse_tag_field("key=Key1,value=")
    assert result == [{"Key": "Key1", "Value": ""}]


def test_parse_tag_field_with_special_characters_in_key():
    """
    Given: A tag string with special characters allowed in key.
    When: parse_tag_field processes the input with special characters.
    Then: It should return a properly formatted tag dictionary.
    """
    from AWS import parse_tag_field

    result = parse_tag_field("key=aws:ec2:test,value=test.test")
    assert result == [{"Key": "aws:ec2:test", "Value": "test.test"}]


def test_parse_tag_field_with_spaces_in_key():
    """
    Given: A tag string with spaces in the key name.
    When: parse_tag_field processes the input with spaces.
    Then: It should return a properly formatted tag dictionary.
    """
    from AWS import parse_tag_field

    result = parse_tag_field("key=My Tag Name,value=MyValue")
    assert result == [{"Key": "My Tag Name", "Value": "MyValue"}]


def test_parse_tag_field_with_maximum_key_length():
    """
    Given: A tag string with key at maximum allowed length (128 characters).
    When: parse_tag_field processes the input with maximum key length.
    Then: It should return a properly formatted tag dictionary.
    """
    from AWS import parse_tag_field

    max_key = "a" * 128
    result = parse_tag_field(f"key={max_key},value=test")
    assert result == [{"Key": max_key, "Value": "test"}]


def test_parse_tag_field_with_maximum_value_length():
    """
    Given: A tag string with value at maximum allowed length (256 characters).
    When: parse_tag_field processes the input with maximum value length.
    Then: It should return a properly formatted tag dictionary.
    """
    from AWS import parse_tag_field

    max_value = "a" * 256
    result = parse_tag_field(f"key=TestKey,value={max_value}")
    assert result == [{"Key": "TestKey", "Value": max_value}]


def test_parse_tag_field_with_key_exceeding_maximum_length():
    """
    Given: A tag string with key exceeding maximum allowed length (129 characters).
    When: parse_tag_field processes the input with oversized key.
    Then: It should raise an error.
    """
    from AWS import parse_tag_field

    oversized_key = "a" * 129
    with pytest.raises(ValueError):
        parse_tag_field(f"key={oversized_key},value=test")


def test_parse_tag_field_with_value_exceeding_maximum_length():
    """
    Given: A tag string with value exceeding maximum allowed length (257 characters).
    When: parse_tag_field processes the input with oversized value.
    Then: It should raise an error.
    """
    from AWS import parse_tag_field

    oversized_value = "a" * 257
    with pytest.raises(ValueError):
        parse_tag_field(f"key=TestKey,value={oversized_value}")


def test_parse_tag_field_with_exactly_fifty_tags(mocker):
    """
    Given: A tag string with exactly 50 tags (maximum allowed).
    When: parse_tag_field processes the input with 50 tags.
    Then: It should return all 50 tags without truncation.
    """
    from AWS import parse_tag_field

    mock_debug = mocker.patch.object(demisto, "debug")

    tags_string = ";".join([f"key=Key{i},value=Value{i}" for i in range(50)])
    result = parse_tag_field(tags_string)

    assert len(result) == 50
    assert result[0] == {"Key": "Key0", "Value": "Value0"}
    assert result[49] == {"Key": "Key49", "Value": "Value49"}
    mock_debug.assert_not_called()


def test_parse_tag_field_with_more_than_fifty_tags(mocker):
    """
    Given: A tag string with more than 50 tags (exceeds maximum).
    When: parse_tag_field processes the input with too many tags.
    Then: It should return only the first 50 tags and log a debug message.
    """
    from AWS import parse_tag_field

    mock_debug = mocker.patch.object(demisto, "debug")

    tags_string = ";".join([f"key=Key{i},value=Value{i}" for i in range(55)])
    result = parse_tag_field(tags_string)

    assert len(result) == 50
    assert result[0] == {"Key": "Key0", "Value": "Value0"}
    assert result[49] == {"Key": "Key49", "Value": "Value49"}
    mock_debug.assert_called_once_with("Number of tags is larger then 50, parsing only first 50 tags.")


def test_parse_tag_field_with_missing_comma_separator():
    """
    Given: A tag string missing comma separator between key and value.
    When: parse_tag_field processes the input without proper separator.
    Then: It should raise an error.
    """
    from AWS import parse_tag_field

    with pytest.raises(ValueError):
        parse_tag_field("key=Key1 value=Value1")


def test_parse_tag_field_with_extra_whitespace():
    """
    Given: A tag string with extra whitespace around the tag.
    When: parse_tag_field processes the input with whitespace.
    Then: It should handle the whitespace properly based on regex matching.
    """
    from AWS import parse_tag_field

    result = parse_tag_field("  key=Key1,value=Value1  ")
    assert result == [{"Key": "Key1", "Value": "Value1"}]


def test_parse_tag_field_with_numeric_keys_and_values():
    """
    Given: A tag string with numeric characters in keys and values.
    When: parse_tag_field processes the numeric input.
    Then: It should return properly formatted tag dictionaries.
    """
    from AWS import parse_tag_field

    result = parse_tag_field("key=123,value=456;key=Cost123,value=100.50")
    assert result == [{"Key": "123", "Value": "456"}, {"Key": "Cost123", "Value": "100.50"}]


def test_parse_tag_field_debug_logging_for_invalid_tag(mocker):
    """
    Given: A tag string with invalid format.
    When: parse_tag_field processes the invalid input.
    Then: It should log a debug message about the unparseable tag.
    """
    from AWS import parse_tag_field

    mocker.patch.object(demisto, "debug")

    invalid_tag = "invalid-format"
    with pytest.raises(ValueError):
        parse_tag_field(invalid_tag)


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
    Then: Raise an ValueError.
    """
    from AWS import parse_filter_field

    with pytest.raises(ValueError):
        parse_filter_field("invalid-filter-format")


def test_parse_filter_field_with_mixed_valid_invalid_filters():
    """
    Given: Multiple filter strings where some are valid and some are invalid.
    When: parse_filter_field function processes the mixed input.
    Then: Raise an ValueError.
    """
    from AWS import parse_filter_field

    filter_string = "name=valid-filter,values=test;invalid-format;name=another-valid,values=value1,value2"
    with pytest.raises(ValueError):
        parse_filter_field(filter_string)


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
    Then: Raises ValueError.
    """
    from AWS import parse_filter_field

    with pytest.raises(ValueError):
        parse_filter_field("name=instance-state-name")


def test_parse_filter_field_with_missing_name():
    """
    Given: A filter string with values but missing name part.
    When: parse_filter_field function processes the incomplete input.
    Then: Raises ValueError.
    """
    from AWS import parse_filter_field

    with pytest.raises(ValueError):
        parse_filter_field("values=running,stopped")


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


def test_parse_filter_more_then_200_values():
    """
    Given: A filter string with more than 200 values in a single filter.
    When: parse_filter_field function processes the input with excessive values.
    Then: It should raise DemistoException indicating too many values in filter.
    """
    from AWS import parse_filter_field

    # Create a filter with 51 values (exceeding the 50 value limit)
    values = ",".join([f"value{i}" for i in range(2011)])
    filter_string = f"name=test-filter,values={values}"
    result = parse_filter_field(filter_string)
    assert len(result) == 1
    assert result[0]["Name"] == "test-filter"
    assert len(result[0]["Values"]) == 200
    assert result[0]["Values"][0] == "value0"
    assert result[0]["Values"][199] == "value199"


def test_parse_filter_exactly_200_values():
    """
    Given: A filter string with exactly 50 values in a single filter.
    When: parse_filter_field function processes the input with 50 values.
    Then: It should successfully parse the filter without raising an exception.
    """
    from AWS import parse_filter_field

    # Create a filter with exactly 50 values (at the limit)
    values = ",".join([f"value{i}" for i in range(200)])
    filter_string = f"name=test-filter,values={values}"

    result = parse_filter_field(filter_string)
    assert len(result) == 1
    assert result[0]["Name"] == "test-filter"
    assert len(result[0]["Values"]) == 200
    assert result[0]["Values"][0] == "value0"
    assert result[0]["Values"][199] == "value199"


def test_build_pagination_kwargs_with_default_limit():
    """
    Given: No limit argument provided in args.
    When: build_pagination_kwargs is called without limit.
    Then: It should return kwargs with default limit value.
    """
    from AWS import build_pagination_kwargs

    args = {}
    result = build_pagination_kwargs(args)

    assert "MaxResults" in result
    assert result["MaxResults"] == 50  # DEFAULT_LIMIT_VALUE


def test_build_pagination_kwargs_with_valid_limit():
    """
    Given: A valid limit argument in args.
    When: build_pagination_kwargs is called with valid limit.
    Then: It should return kwargs with the specified limit.
    """
    from AWS import build_pagination_kwargs

    args = {"limit": "25"}
    result = build_pagination_kwargs(args)

    assert result["MaxResults"] == 25


def test_build_pagination_kwargs_with_valid_next_token():
    """
    Given: Valid limit and next_token arguments in args.
    When: build_pagination_kwargs is called with both parameters.
    Then: It should return kwargs with both MaxResults and NextToken.
    """
    from AWS import build_pagination_kwargs

    args = {"limit": "30", "next_token": "token123"}
    result = build_pagination_kwargs(args)

    assert result["MaxResults"] == 30
    assert result["NextToken"] == "token123"


def test_build_pagination_kwargs_with_next_token_whitespace():
    """
    Given: A next_token with leading and trailing whitespace.
    When: build_pagination_kwargs is called with whitespace token.
    Then: It should strip whitespace and return clean NextToken.
    """
    from AWS import build_pagination_kwargs

    args = {"limit": "10", "next_token": "  token_with_spaces  "}
    result = build_pagination_kwargs(args)

    assert result["NextToken"] == "token_with_spaces"


def test_build_pagination_kwargs_with_limit_exceeding_maximum():
    """
    Given: A limit argument exceeding the maximum allowed value.
    When: build_pagination_kwargs is called with oversized limit.
    Then: It should cap the limit at maximum value and log debug message.
    """
    from AWS import build_pagination_kwargs

    args = {"limit": "2000"}
    result = build_pagination_kwargs(args)

    assert result["MaxResults"] == 1000  # MAX_LIMIT_VALUE


def test_build_pagination_kwargs_with_zero_limit():
    """
    Given: A limit argument of zero.
    When: build_pagination_kwargs is called with zero limit.
    Then: It should raise ValueError indicating limit must be greater than 0.
    """
    from AWS import build_pagination_kwargs

    args = {"limit": "0"}

    with pytest.raises(ValueError, match="Limit must be greater than 0"):
        build_pagination_kwargs(args)


def test_build_pagination_kwargs_with_negative_limit():
    """
    Given: A negative limit argument.
    When: build_pagination_kwargs is called with negative limit.
    Then: It should raise ValueError indicating limit must be greater than 0.
    """
    from AWS import build_pagination_kwargs

    args = {"limit": "-5"}

    with pytest.raises(ValueError, match="Limit must be greater than 0"):
        build_pagination_kwargs(args)


def test_build_pagination_kwargs_with_invalid_limit_string():
    """
    Given: A non-numeric string limit argument.
    When: build_pagination_kwargs is called with invalid limit.
    Then: It should raise ValueError indicating invalid limit parameter.
    """
    from AWS import build_pagination_kwargs

    args = {"limit": "not_a_number"}

    with pytest.raises(ValueError, match="Invalid limit parameter"):
        build_pagination_kwargs(args)


def test_build_pagination_kwargs_with_whitespace_only_next_token():
    """
    Given: A next_token with only whitespace characters.
    When: build_pagination_kwargs is called with whitespace-only token.
    Then: It should raise ValueError indicating next_token must be non-empty.
    """
    from AWS import build_pagination_kwargs

    args = {"limit": "10", "next_token": "   "}

    with pytest.raises(ValueError, match="next_token must be a non-empty string"):
        build_pagination_kwargs(args)


def test_build_pagination_kwargs_with_none_limit():
    """
    Given: A None value for limit argument.
    When: build_pagination_kwargs is called with None limit.
    Then: It should use default limit value.
    """
    from AWS import build_pagination_kwargs

    args = {"limit": None}
    result = build_pagination_kwargs(args)

    assert result["MaxResults"] == 50  # DEFAULT_LIMIT_VALUE


def test_build_pagination_kwargs_with_limit_at_maximum():
    """
    Given: A limit argument exactly at the maximum allowed value.
    When: build_pagination_kwargs is called with maximum limit.
    Then: It should return kwargs with the maximum limit without capping.
    """
    from AWS import build_pagination_kwargs

    args = {"limit": "1000"}
    result = build_pagination_kwargs(args)

    assert result["MaxResults"] == 1000


def test_build_pagination_kwargs_with_numeric_limit():
    """
    Given: A numeric limit argument instead of string.
    When: build_pagination_kwargs is called with numeric limit.
    Then: It should handle the numeric type and return correct limit.
    """
    from AWS import build_pagination_kwargs

    args = {"limit": 75}
    result = build_pagination_kwargs(args)

    assert result["MaxResults"] == 75


def test_build_pagination_kwargs_with_non_string_next_token():
    """
    Given: A non-string next_token argument.
    When: build_pagination_kwargs is called with non-string token.
    Then: It should raise ValueError indicating next_token must be a string.
    """
    from AWS import build_pagination_kwargs

    args = {"limit": "10", "next_token": 12345}

    with pytest.raises(ValueError, match="next_token must be a non-empty string"):
        build_pagination_kwargs(args)


def test_build_pagination_kwargs_no_pagination_arguments():
    """
    Given: Args dictionary with no pagination-related arguments.
    When: build_pagination_kwargs is called with non-pagination args.
    Then: It should return kwargs with default limit only.
    """
    from AWS import build_pagination_kwargs

    args = {"other_param": "value", "unrelated_arg": "test"}
    result = build_pagination_kwargs(args)

    assert result["MaxResults"] == 50
    assert "NextToken" not in result


def test_aws_error_handler_handle_client_error_missing_error_code(mocker):
    """
    Given: A ClientError with missing error code in response.
    When: handle_client_error is called with incomplete error response.
    Then: It should raise DemistoException with the original error.
    """
    from AWS import AWSErrorHandler
    from botocore.exceptions import ClientError

    mocker.patch("AWS.demisto.debug")

    error_response = {"Error": {"Message": "Some error message"}, "ResponseMetadata": {"HTTPStatusCode": 400}}
    client_error = ClientError(error_response, "test-operation")

    with pytest.raises(SystemExit):
        AWSErrorHandler.handle_client_error(client_error, "accountID")


def test_aws_error_handler_handle_client_error_missing_error_message(mocker):
    """
    Given: A ClientError with missing error message in response.
    When: handle_client_error is called with incomplete error response.
    Then: It should raise DemistoException with the original error.
    """
    from AWS import AWSErrorHandler
    from botocore.exceptions import ClientError

    mocker.patch("AWS.demisto.debug")

    error_response = {"Error": {"Code": "TestError"}, "ResponseMetadata": {"HTTPStatusCode": 400}}
    client_error = ClientError(error_response, "test-operation")

    with pytest.raises(SystemExit):
        AWSErrorHandler.handle_client_error(client_error, "accountID")


def test_aws_error_handler_handle_client_error_missing_http_status_code(mocker):
    """
    Given: A ClientError with missing HTTP status code in response metadata.
    When: handle_client_error is called with incomplete response metadata.
    Then: It should raise DemistoException with the original error.
    """
    from AWS import AWSErrorHandler
    from botocore.exceptions import ClientError

    mocker.patch("AWS.demisto.debug")

    error_response = {"Error": {"Code": "TestError", "Message": "Test message"}, "ResponseMetadata": {}}
    client_error = ClientError(error_response, "test-operation")

    with pytest.raises(SystemExit):
        AWSErrorHandler.handle_client_error(client_error, "accountID")


def test_aws_error_handler_handle_client_error_missing_response_metadata(mocker):
    """
    Given: A ClientError with missing ResponseMetadata entirely.
    When: handle_client_error is called with incomplete response structure.
    Then: It should raise DemistoException with the original error.
    """
    from AWS import AWSErrorHandler
    from botocore.exceptions import ClientError

    mocker.patch("AWS.demisto.debug")

    error_response = {"Error": {"Code": "TestError", "Message": "Test message"}}
    client_error = ClientError(error_response, "test-operation")

    with pytest.raises(SystemExit):
        AWSErrorHandler.handle_client_error(client_error, "accountID")


def test_aws_error_handler_handle_client_error_missing_error_section(mocker):
    """
    Given: A ClientError with missing Error section entirely.
    When: handle_client_error is called with incomplete response structure.
    Then: It should raise DemistoException with the original error.
    """
    from AWS import AWSErrorHandler
    from botocore.exceptions import ClientError

    mocker.patch("AWS.demisto.debug")

    error_response = {"ResponseMetadata": {"HTTPStatusCode": 400}}
    client_error = ClientError(error_response, "test-operation")

    with pytest.raises(SystemExit):
        AWSErrorHandler.handle_client_error(client_error, "accountID")


def test_aws_error_handler_handle_client_error_unhandled_exception_debug_logging(mocker):
    """
    Given: A ClientError that causes an unhandled exception during processing.
    When: handle_client_error encounters the unhandled exception.
    Then: It should log debug message about the unhandled error and raise DemistoException.
    """
    from AWS import AWSErrorHandler
    from botocore.exceptions import ClientError

    mock_debug = mocker.patch("AWS.demisto.debug")
    mocker.patch("AWS.AWSErrorHandler._handle_permission_error", side_effect=ValueError("Unexpected error"))

    error_response = {
        "Error": {"Code": "AccessDenied", "Message": "Access denied"},
        "ResponseMetadata": {"HTTPStatusCode": 403},
    }
    client_error = ClientError(error_response, "test-operation")

    with pytest.raises(SystemExit):
        AWSErrorHandler.handle_client_error(client_error, "accountID")

    mock_debug.assert_any_call("[AWSErrorHandler] Unhandled error: Unexpected error")
