import pytest
import AWS

class AWSClient:
    def aws_session(self, **kwargs):
        return Boto3Client()

class Boto3Client:
    def get_public_access_block(self, **kwargs):
        pass

    def put_public_access_block(self, **kwargs):
        pass

    def get_account_password_policy(self, **kwargs):
        pass

    def update_account_password_policy(self, **kwargs):
        pass
    
    def modify_instance_metadata_options(self, **kwargs):
        pass


@pytest.fixture()
def aws_client():
    return AWSClient()


@pytest.mark.parametrize(
    "bucket, get_command_return, put_command_return, expected_result",
    [
        (
            "bucket-pass-1",
            {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                }
            },
            {'ResponseMetadata':{'HTTPStatusCode':200}},
            "Successfully applied public access block to the bucket-pass-1 bucket"
        ),
        (
            "bucket-fail-1",
            {},
            {'ResponseMetadata':{'HTTPStatusCode':200}},
            "Couldn't check current public access block to the bucket-fail-1 bucket"
        ),
        (
            "bucket-fail-2",
            {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                }
            },
            {'ResponseMetadata':{'HTTPStatusCode':500}},
            "Couldn't apply public access block to the bucket-fail-2 bucket"
        )
    ]
)
def test_put_public_access_block(aws_client, mocker, bucket, get_command_return, put_command_return, expected_result):
    mocker.patch.object(Boto3Client, "get_public_access_block", return_value=get_command_return)
    mocker.patch.object(Boto3Client, "put_public_access_block", return_value=put_command_return)

    args = {
        'bucket': bucket,
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        }
    }

    result = AWS.put_public_access_block(aws_client, args)
    assert result.readable_output == expected_result


def test_get_account_password_policy(aws_client, mocker):

    get_account_password_policy_return = {
        'account_id': 1234567890,
        'PasswordPolicy': {
            'MinimumPasswordLength': 12,
            'RequireSymbols': True,
            'RequireNumbers': True,
            'RequireUppercaseCharacters': True,
            'RequireLowercaseCharacters': True,
            'AllowUsersToChangePassword': True,
            'ExpirePasswords': True,
            'MaxPasswordAge': 12,
            'PasswordReusePrevention': 12,
            'HardExpiry': True,
        }
    }
    mocker.patch.object(Boto3Client, "get_account_password_policy", return_value=get_account_password_policy_return)

    result = AWS.get_account_password_policy(aws_client, {})
    assert result.outputs == get_account_password_policy_return.get('PasswordPolicy')


@pytest.mark.parametrize(
    "command_args, command_return, expected_result",
    [
        (
            {
                "account_id": 1234567890,
                "minimum_password_length": 16
            },
            {'ResponseMetadata':{'HTTPStatusCode':200}},
            "Successfully updated account password policy for account: 1234567890"
        ),
        (
            {
                "account_id": 1234567890,
                "require_lowercase_characters": True
            },
            {'ResponseMetadata':{'HTTPStatusCode':200}},
            "Successfully updated account password policy for account: 1234567890"
        ),
        (
            {
                "account_id": 1234567890,
                "minimum_password_length": 16
            },
            {'ResponseMetadata':{'HTTPStatusCode':500}},
            "Couldn't updated account password policy for account: 1234567890"
        )
    ]
)
def test_update_account_password_policy(aws_client, mocker, command_args, command_return, expected_result):

    get_account_password_policy_return = {
        'PasswordPolicy': {
            'MinimumPasswordLength': 12,
            'RequireSymbols': False,
            'RequireNumbers': False,
            'RequireUppercaseCharacters': False,
            'RequireLowercaseCharacters': False,
            'AllowUsersToChangePassword': False,
            'ExpirePasswords': False,
            'MaxPasswordAge': 12,
            'PasswordReusePrevention': 12,
            'HardExpiry': False,
        }
    }
    mocker.patch.object(Boto3Client, "get_account_password_policy", return_value=get_account_password_policy_return)
    mocker.patch.object(Boto3Client, "update_account_password_policy", return_value=command_return)

    result = AWS.update_account_password_policy(aws_client, command_args)
    assert result.readable_output == expected_result


@pytest.mark.parametrize(
    "command_args, command_return, expected_result",
    [
        (
            {
                "instance_id": "i-1234567890",
                "http_tokens": "required"
            },
            {'ResponseMetadata':{'HTTPStatusCode':200}},
            "Successfully updated EC2 instance metadata for i-1234567890"
        ),
        (
            {
                "instance_id": "i-1234567890",
                "http_endpoint": "enabled"
            },
            {'ResponseMetadata':{'HTTPStatusCode':200}},
            "Successfully updated EC2 instance metadata for i-1234567890"
        ),
        (
            {
                "instance_id": "i-1234567890"
            },
            {'ResponseMetadata':{'HTTPStatusCode':500}},
            "Couldn't updated public EC2 instance metadata for i-1234567890"
        )
    ]
)
def test_aws_ec2_instance_metadata_options_modify(aws_client, mocker, command_args, command_return, expected_result):

    mocker.patch.object(Boto3Client, "modify_instance_metadata_options", return_value=command_return)

    result = AWS.ec2_instance_metadata_options_modify(aws_client, command_args)
    assert result.readable_output == expected_result
