from AWSApiModule import *
import pytest
from pytest import raises

VALIDATE_CASES = \
    [{
     'aws_default_region': 'test',
     'aws_role_arn': 'test',
     'aws_role_session_name': 'test',
     'aws_access_key_id': 'test',
     'aws_secret_access_key': 'test'
     },
     {
     'aws_default_region': 'region test',
     'aws_role_arn': None,
     'aws_role_session_name': None,
     'aws_access_key_id': None,
     'aws_secret_access_key': None
     },
     {
     'aws_default_region': 'region test',
     'aws_role_arn': None,
     'aws_role_session_name': None,
     'aws_access_key_id': 'test',
     'aws_secret_access_key': 'test'
     }]


VALIDATE_CASES_MISSING_PARAMS = [
    ({
     'aws_default_region': 'region test',
     'aws_role_arn': None,
     'aws_role_session_name': None,
     'aws_access_key_id': None,
     'aws_secret_access_key': 'secret key test'
     },
     'You must provide Access Key id and Secret key id to configure the instance with credentials.'),
    ({
     'aws_default_region': None,
     'aws_role_arn': None,
     'aws_role_session_name': None,
     'aws_access_key_id': 'access key test',
     'aws_secret_access_key': None
     },
     'You must specify AWS default region.'),
    ({
     'aws_default_region': 'region test',
     'aws_role_arn': 'example',
     'aws_role_session_name': None,
     'aws_access_key_id': None,
     'aws_secret_access_key': None
     },
     'Role session name is required when using role ARN.')]


@pytest.mark.parametrize('params, raised_message', VALIDATE_CASES_MISSING_PARAMS)
def test_validate_params_with_missing_values(mocker, params, raised_message):
    """
    Given
    - Different missing configuration parameters
    When
    - Before creating AWSClient object
    Then
    - Validates that exception is thrown properly with each missing parameter
    """

    with raises(DemistoException) as exception:
        validate_params(**params)

    assert raised_message == str(exception.value)


@pytest.mark.parametrize('params', VALIDATE_CASES)
def test_validate_params(mocker, params):
    """
    Given
    - Different valid configuration parameters
    When
    - Before creating AWSClient object
    Then
    - Validates that all parameters are given for each authentication method
    """
    validate_params(**params)


def test_get_timeout():
    """
    Given
    - Different valid values for timeout and retries parameters
    When
    - before setting aws config instance
    Then
    - validates the logic of setting read_timeout and connect_timeout values
    """
    (read, connect) = AWSClient.get_timeout(None)
    assert read == 60 and connect == 10
    (read, connect) = AWSClient.get_timeout("100")
    assert read == 100 and connect == 10
    (read, connect) = AWSClient.get_timeout("200,2")
    assert read == 200 and connect == 2
    (read, connect) = AWSClient.get_timeout(60)
    assert read == 60 and connect == 10
    (read, connect) = AWSClient.get_timeout(u"60, 10")  # testing for unicode variable
    assert read == 60 and connect == 10


def test_AWSClient_with_session_token():
    """
    Given
        - Creates new class instance object with aws session token
    When
        - After creating the client instance
    Then
        - Checks if class object contains aws_session_token argument and creates a session
    """

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

    if client:
        assert client.aws_session_token
        assert client.aws_access_key_id
        assert client.aws_secret_access_key

        try:
            session = client.aws_session('s3')
            assert session
        except Exception:
            print('failed to create session:' + Exception)


def test_AWSClient_without_session_token():
    """
    Given
        - Creates new class instance object with aws session token
    When
        - After creating the client instance
    Then
        - Checks if class object contains aws_session_token argument and creates a session
    """
    # Purposfully leaving out aws_session_token to test optional argument in class instance
    aws_client_args = {
        'aws_default_region': 'us-east-1',
        'aws_role_arn': None,
        'aws_role_session_name': None,
        'aws_role_session_duration': None,
        'aws_role_policy': None,
        'aws_access_key_id': 'test_access_key',
        'aws_secret_access_key': 'test_secret_key',
        'verify_certificate': False,
        'timeout': 60,
        'retries': 3
    }

    client = AWSClient(**aws_client_args)

    if client and client.aws_session_token is None:
        assert client.aws_access_key_id
        assert client.aws_secret_access_key

        try:
            session = client.aws_session('s3')
            assert session
        except Exception:
            print('failed to create session:' + Exception)


@pytest.mark.parametrize('secret_key, session_token, expected',
                         [
                             ('secret_key@@@session_token', None, ('secret_key', 'session_token')),
                             ('test1', None, ('test1', None)),
                             ('test1', 'test2', ('test1', 'test2')),
                             ('test1@@@test2', 'test3', ('test1@@@test2', 'test3')),
                             ('', None, ('', None)),
                             (None, '', (None, '')),
                             (None, None, (None, None))
                         ])
def test_extract_session_from_secret(secret_key, session_token, expected):
    """
    Given
    - Secret key and session token

    When
    - Calling the extract_session_from_secret function

    Then
    - Check that the function returns the expected secret key and session token
    """
    result = extract_session_from_secret(secret_key, session_token)

    assert result == expected


@pytest.mark.parametrize(
    'params, args, expected_assume_roles_args', [
        (
            {
                'aws_default_region': 'us-east-1',
                'aws_role_arn': None,
                'aws_role_session_name': None,
                'aws_access_key_id': 'test_access_key',
                'aws_role_session_duration': None

            },
            {
                'role_arn': 'role_arn_arg',
                'role_session_name': 'role_session_name_arg'
            },
            {
                'RoleArn': 'role_arn_arg',
                'RoleSessionName': 'role_session_name_arg'
            }
        ),
        (
            {
                'aws_default_region': 'us-east-1',
                'aws_role_arn': 'role_arn_param',
                'aws_role_session_name': 'role_session_name_param',
                'aws_access_key_id': 'test_access_key',
                'aws_role_session_duration': None
            },
            {},
            {
                'RoleArn': 'role_arn_param',
                'RoleSessionName': 'role_session_name_param'
            }
        ),
        (
            {
                'aws_default_region': 'us-east-1',
                'aws_role_arn': 'role_arn_param',
                'aws_role_session_name': 'role_session_name_param',
                'aws_access_key_id': 'test_access_key',
                'aws_role_session_duration': None
            },
            {
                'role_arn': 'role_arn_arg',
                'role_session_name': 'role_session_name_arg'
            },
            {
                'RoleArn': 'role_arn_arg',
                'RoleSessionName': 'role_session_name_arg'
            }
        ),
        (
            {
                'aws_default_region': 'us-east-1',
                'aws_role_arn': 'role_arn_param',
                'aws_role_session_name': 'role_session_name_param',
                'aws_access_key_id': 'test_access_key',
                'aws_role_session_duration': ''
            },
            {
                'role_arn': 'role_arn_arg',
                'role_session_name': 'role_session_name_arg'
            },
            {
                'RoleArn': 'role_arn_arg',
                'RoleSessionName': 'role_session_name_arg'
            }
        )
    ]
)
def test_aws_session(mocker, params, args, expected_assume_roles_args):
    """
    Given
    - Case A: role arn and role session name provided only from demisto.args()
    - Case B: role arn and role session name provided only from demisto.params()
    - Case C: role arn and role session name provided from both demisto.params() and demisto.args()
    - Case D: role arn, role session name and aws role session duration which is empty
              provided from both demisto.params() and demisto.args()

    When
    - Calling the aws_session method

    Then
    - Case A: make sure the role arn and role session name are taken from command arguments
    - Case B: make sure the role arn and role session name are taken from integration parameters
    - Case C: make sure the role arn and role session name are taken from command arguments
    - Case D: make sure the role arn and role session name are taken from command arguments and no exception is raised
              when sending empty aws role session
    """
    params.update(
        {
            'aws_role_policy': None,
            'aws_secret_access_key': 'test_secret_key',
            'verify_certificate': False,
            'timeout': 60,
            'retries': 3
        }
    )

    sts_client_mock = boto3.client('sts', region_name=params['aws_default_region'])
    assume_client_mock = mocker.patch.object(
        sts_client_mock,
        'assume_role', return_value={
            'Credentials': {
                'AccessKeyId': '1',
                'SecretAccessKey': '2',
                'SessionToken': '3'
            }
        }
    )

    mocker.patch(
        'AWSApiModule.boto3.client',
        side_effect=[sts_client_mock, boto3.client('ec2', region_name=params['aws_default_region'])]
    )
    aws_client = AWSClient(**params)
    aws_client.aws_session(service='ec2', **args)

    assert assume_client_mock.call_args_list[0].kwargs == expected_assume_roles_args
