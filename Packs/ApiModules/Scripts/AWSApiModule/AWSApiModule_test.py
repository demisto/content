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
     'When using role ARN you must provide role session name.')]


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
