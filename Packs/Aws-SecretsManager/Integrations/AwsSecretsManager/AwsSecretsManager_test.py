
from AWSApiModule import *
import importlib
import pytest

AWS_SECRETSMANAGER = importlib.import_module("AWS-SECRETSMANAGER")

def create_client():
    aws_client_args = {
        'aws_default_region': 'us-east-1',
        'aws_role_arn': None,
        'aws_role_session_name': None,
        'aws_role_session_duration': None,
        'aws_role_policy': None,
        'aws_access_key_id': 'test_access_key',
        'aws_secret_access_key': 'test_secret_key',
        'aws_session_token': 'test_sts_token',
        'verify_certificate': False,
        'timeout': 60,
        'retries': 3
    }

    client = AWSClient(**aws_client_args)
    return client

class Boto3Client:
    def list_secrets(self, **kwargs):
        pass

    def get_secret_value(self, **kwargs):
        pass

    def delete_secret(self, **kwargs):
        pass

    def restore_secret(self, **kwargs):
        pass

    def get_resource_policy(self, **kwargs):
        pass

def test_aws_secrets_manager_secret_list_command(mocker):
    aws_client = create_client()
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, 'list_secrets', return_value={'SecretList': [{'ARN': 'arn:aws:secretsmanager:eu-central-1:654338056632:secret:test_for_moishy-fVYXb6', 'Name': 'test_for_moishy', 'Description': 'new description', 'LastChangedDate': datetime.datetime(2022, 9, 5, 11, 54, 16, 838000, tzinfo=tzlocal()), 'LastAccessedDate': datetime.datetime(2022, 8, 31, 3, 0, tzinfo=tzlocal()), 'Tags': [], 'SecretVersionsToStages': {'01cba660-28be-45d7-8597-d1ab295b0f35': ['AWSCURRENT'], 'ac32e535-79e7-4188-a732-7f02dbe399f0': ['AWSPREVIOUS']}, 'CreatedDate': datetime.datetime(2022, 8, 21, 16, 54, 5, 25000, tzinfo=tzlocal())}, {'ARN': 'arn:aws:secretsmanager:eu-central-1:654338056632:secret:DB_credentials-3ic9K7', 'Name': 'DB_credentials', 'LastChangedDate': datetime.datetime(2022, 8, 31, 12, 45, 33, 569000, tzinfo=tzlocal()), 'LastAccessedDate': datetime.datetime(2022, 8, 31, 3, 0, tzinfo=tzlocal()), 'Tags': [], 'SecretVersionsToStages': {'f2a389e8-3860-47a0-b4a0-16424ad63a24': ['AWSCURRENT']}, 'CreatedDate': datetime.datetime(2022, 8, 31, 12, 45, 33, 532000, tzinfo=tzlocal())}, {'ARN': 'arn:aws:secretsmanager:eu-central-1:654338056632:secret:gmail-oF08mg', 'Name': 'gmail', 'LastChangedDate': datetime.datetime(2022, 8, 31, 12, 47, 24, 47000, tzinfo=tzlocal()), 'LastAccessedDate': datetime.datetime(2022, 8, 31, 3, 0, tzinfo=tzlocal()), 'Tags': [], 'SecretVersionsToStages': {'5889c662-13a6-4318-bec3-b234fcae3826': ['AWSCURRENT']}, 'CreatedDate': datetime.datetime(2022, 8, 31, 12, 47, 24, 11000, tzinfo=tzlocal())}, {'ARN': 'arn:aws:secretsmanager:eu-central-1:654338056632:secret:fdff-vnNyyc', 'Name': 'fdff', 'LastChangedDate': datetime.datetime(2022, 9, 4, 12, 10, 13, 14000, tzinfo=tzlocal()), 'LastAccessedDate': datetime.datetime(2022, 9, 4, 3, 0, tzinfo=tzlocal()), 'Tags': [], 'SecretVersionsToStages': {'c88e2176-aca4-4776-a422-c3a0616079bc': ['AWSCURRENT']}, 'CreatedDate': datetime.datetime(2022, 9, 4, 12, 10, 12, 964000, tzinfo=tzlocal())}], 'ResponseMetadata': {'RequestId': '98d36af0-71cd-46d9-9291-0bed912a4dfe', 'HTTPStatusCode': 200, 'HTTPHeaders': {'x-amzn-requestid': '98d36af0-71cd-46d9-9291-0bed912a4dfe', 'content-type': 'application/x-amz-json-1.1', 'content-length': '1264', 'date': 'Mon, 05 Sep 2022 09:04:03 GMT'}, 'RetryAttempts': 0}})
    mocker.patch.object(demisto, 'results')

    AWS_SECRETSMANAGER.aws_secrets_manager_secret_list_command(aws_client)

    results = demisto.results.call_args[0][0]

    assert list(results.keys()).sort() == ['Name', 'ARN', 'Description', 'LastAccessedDate'].sort()

def validate_kwargs(*args, **kwargs):
    if kwargs == {"secret_id": "123"}:
        return {'ResponseMetadata': {'HTTPStatusCode': 200}, 'Return': "some_return_value"}
    else:
        return {'ResponseMetadata': {'HTTPStatusCode': 200}, 'Return': "some_return_value"}

@pytest.mark.parametrize('args, expected_results', [
    ({"secret_id": "123"}, None),
    ({"secret_id": None}, 'Get command cannot be executed without "secret_id" param')
])
def test_aws_secrets_manager_secret_value_get_command(mocker, args, expected_results):
    aws_client = create_client()
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, 'get_secret_value', side_effect=validate_kwargs)
    mocker.patch.object(demisto, 'results')

    AWS_SECRETSMANAGER.aws_secrets_manager_secret_value_get_command(aws_client, args)

    if not expected_results:
        assert not demisto.results.call_args
    else:
        results = demisto.results.call_args[0][0]
        assert results == expected_results


def test_aws_secrets_manager_secret_delete_command(mocker):
    aws_client = create_client()
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())


def test_aws_secrets_manager_secret_restore_command(mocker):
    aws_client = create_client()
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())


def test_aws_secrets_manager_secret_policy_get_command(mocker):
    aws_client = create_client()
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())


def test_fetch_credentials(mocker):
    aws_client = create_client()
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())

