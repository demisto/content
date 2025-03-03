from CommonServerPython import *

from AWSApiModule import *
import demistomock as demisto

import pytest

import AwsSecretsManager as AWS_SECRETSMANAGER


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
    mocker.patch.object(Boto3Client, 'list_secrets',
                        return_value={'SecretList': [{'ARN': 'arn:aws:secretsmanager:eu-central-1:123456789012:secret:'
                                                             'test_account', 'Name': 'test_for_moishy',
                                                      'Description': 'new description', 'LastChangedDate': None,
                                                      'Tags': [], 'SecretVersionsToStages':
                                                          {'01cba660-28be-45d7-8597-d1ab295b0f35': ['AWSCURRENT'],
                                                           'ac32e535-79e7-4188-a732-7f02dbe399f0': ['AWSPREVIOUS']},
                                                      'CreatedDate': None}]})
    mocker.patch.object(demisto, 'results')

    AWS_SECRETSMANAGER.aws_secrets_manager_secret_list_command(aws_client, {})

    results = demisto.results.call_args[0][0]

    assert list(results.keys()).sort() == ['Name', 'ARN', 'Description', 'LastAccessedDate'].sort()


@pytest.mark.parametrize('args, expected_results', [
    ({"secret_id": "123"}, {'ResponseMetadata': {'HTTPStatusCode': 200}, 'Return': "some_return_value"}),
    ({"secret_id": None}, 'Get command cannot be executed without "secret_id" param')
])
def test_aws_secrets_manager_secret_value_get_command(mocker, args, expected_results):
    aws_client = create_client()
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, 'get_secret_value', return_value={'ResponseMetadata': {'HTTPStatusCode': 200},
                                                                       'Return': "some_return_value"})
    mocker.patch.object(demisto, 'results')
    return_error_method = mocker.patch.object(AWS_SECRETSMANAGER, 'return_error', return_value=expected_results)

    AWS_SECRETSMANAGER.aws_secrets_manager_secret_value_get_command(aws_client, args)

    if args['secret_id']:
        results = demisto.results.call_args[0][0]['Contents']
        assert results == expected_results
    else:
        return_error_method.assert_called_with(expected_results)


@pytest.mark.parametrize('args, expected_results', [
    ({"secret_id": "123", "days_of_recovery": 121}, 'The Secret was Deleted'),
    ({"secret_id": "123", "days_of_recovery": 121, "delete_immediately": False}, "Delete command cannot be executed "
                                                                                 "with both args: delete_immediately "
                                                                                 "and days_of_recovery")
])
def test_aws_secrets_manager_secret_delete_command(mocker, args, expected_results):
    aws_client = create_client()
    mocker.patch.object(sys, 'exit')
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, 'delete_secret',
                        return_value={'ResponseMetadata': {'HTTPStatusCode': 200}, 'Name': "dwdw", 'ARN': "arnarn"})
    mocker.patch.object(demisto, 'results')

    if len(args) < 3:
        AWS_SECRETSMANAGER.aws_secrets_manager_secret_delete_command(aws_client, args)
        results = demisto.results.call_args[0][0]
        assert results == expected_results
    else:
        try:
            AWS_SECRETSMANAGER.aws_secrets_manager_secret_delete_command(aws_client, args)
        except Exception as e:
            assert expected_results == e.args[0]


@pytest.mark.parametrize('args, expected_results', [
    ({"secret_id": "123"}, 'the secret was restored successfully'),
    ({"secret_id": None}, 'secret_id is mandatory inorder to run this command!')
])
def test_aws_secrets_manager_secret_restore_command(mocker, args, expected_results):
    aws_client = create_client()
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, 'restore_secret',
                        return_value={'ResponseMetadata': {'HTTPStatusCode': 200}, 'Name': "dwdw", 'ARN': "arnarn"})
    mocker.patch.object(demisto, 'results')

    if args['secret_id']:
        AWS_SECRETSMANAGER.aws_secrets_manager_secret_restore_command(aws_client, args)
        results = demisto.results.call_args[0][0]
        assert results == expected_results
    else:
        try:
            AWS_SECRETSMANAGER.aws_secrets_manager_secret_restore_command(aws_client, args)
        except Exception as e:
            assert expected_results == e.args[0]


@pytest.mark.parametrize('args, expected_results', [
    ({"secret_id": "123"}, {'ARN': 'arn', 'Name': 'd', 'ResourcePolicy': 'dw',
                            'ResponseMetadata': {'HTTPStatusCode': 200}}),
    ({"secret_id": None}, 'secret_id is mandatory inorder to run this command!')
])
def test_aws_secrets_manager_secret_policy_get_command(mocker, args, expected_results):
    aws_client = create_client()
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, 'get_resource_policy',
                        return_value={'ARN': 'arn', 'Name': 'd', 'ResourcePolicy': 'dw',
                                      'ResponseMetadata': {'HTTPStatusCode': 200}})
    mocker.patch.object(demisto, 'results')
    return_error_method = mocker.patch.object(AWS_SECRETSMANAGER, 'return_error', return_value=expected_results)

    AWS_SECRETSMANAGER.aws_secrets_manager_secret_policy_get_command(aws_client, args)

    if args['secret_id']:
        results = demisto.results.call_args[0][0]['Contents']
        assert results == expected_results
    else:
        return_error_method.assert_called_with(expected_results)


@pytest.mark.parametrize('secret, should_create', [
    ({}, False),
    ({'username', "somevalue"}, True),
    ({'randomvalue', "somevalue"}, False),
    ({'username': "somevalue", "password": 'somevalue'}, True)
])
def test_should_create_credential(secret, should_create):
    assert AWS_SECRETSMANAGER.should_create_credential(secret) == should_create
