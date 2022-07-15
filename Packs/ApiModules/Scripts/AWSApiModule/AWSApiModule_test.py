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
