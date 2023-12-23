from AWSApiModule import *
from CommonServerPython import *  # noqa: F401
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import demistomock as demisto  # noqa: F401
import importlib
import pytest


AWS_EC2 = importlib.import_module("AWS-EC2")

VALID_ARGS = {"groupId": "sg-0566450bb5ae17c7d",
              "IpPermissionsfromPort": 23,
              "IpPermissionsToPort": 23,
              "IpPermissionsIpProtocol": "TCP",
              "region": "reg",
              "roleArn": "role",
              "roleSessionName": "role_Name",
              "roleSessionDuration": 200}

IPPERMISSIONSFULL_ARGS = {"groupId": "sg-0566450bb5ae17c7d",
                          "IpPermissionsFull": """[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                          "Ipv6Ranges": [], "PrefixListIds": [], "UserIdGroupPairs": []}]"""}

IPPERMISSIONSFULL_ARGS = {"groupId": "sg-0566450bb5ae17c7d",
                          "IpPermissionsFull": """[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                          "Ipv6Ranges": [], "PrefixListIds": [], "UserIdGroupPairs": []}]"""}

INVALID_ARGS = {"groupId": "sg-0566450bb5ae17c7d",
                "region": "reg",
                "roleArn": "role",
                "roleSessionName": "role_Name",
                "roleSessionDuration": 200}


class Boto3Client:
    def authorize_security_group_egress(self, **kwargs):
        pass

    def authorize_security_group_ingress(self, **kwargs):
        pass

    def authorize_security_group_ingress(self, **kwargs):
        pass


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


AWS_EC2.build_client = lambda x: create_client().aws_session(**x)


def validate_kwargs(*args, **kwargs):
    normal_kwargs = {'IpPermissions': [{'ToPort': 23, 'FromPort': 23, 'UserIdGroupPairs': [{}], 'IpProtocol': 'TCP'}],
                     'GroupId': 'sg-0566450bb5ae17c7d'}
    ippermsfull_kwargs = {'GroupId': 'sg-0566450bb5ae17c7d', 'IpPermissions':
                          [{'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
                           'Ipv6Ranges': [], 'PrefixListIds': [], 'UserIdGroupPairs': []}]}
    if kwargs in (normal_kwargs, ippermsfull_kwargs):
    normal_kwargs = {'IpPermissions': [{'ToPort': 23, 'FromPort': 23, 'UserIdGroupPairs': [{}], 'IpProtocol': 'TCP'}],
                     'GroupId': 'sg-0566450bb5ae17c7d'}
    ippermsfull_kwargs = {'GroupId': 'sg-0566450bb5ae17c7d', 'IpPermissions':
                          [{'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
                           'Ipv6Ranges': [], 'PrefixListIds': [], 'UserIdGroupPairs': []}]}
    if kwargs in (normal_kwargs, ippermsfull_kwargs):
        return {'ResponseMetadata': {'HTTPStatusCode': 200}, 'Return': "some_return_value"}
    else:
        return {'ResponseMetadata': {'HTTPStatusCode': 404}, 'Return': "some_return_value"}


def test_aws_ec2_authorize_security_group_ingress_rule(mocker):
    """
    Given
    - authorize-security-group-ingress-command arguments and aws client
    - Case 1: Valid arguments.
    - Case 2: Invalid arguments.
    When
    - running authorize-security-group-ingress-command.
    Then
    - Ensure that the information was parsed correctly
    - Case 1: Should ensure that the right message was resulted return true.
    - Case 2: Should ensure that no message was resulted return true.
    """
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, 'authorize_security_group_ingress', side_effect=validate_kwargs)
    mocker.patch.object(AWS_EC2, 'return_results')

    # Case 1
    with pytest.raises(DemistoException, match='Unexpected response from AWS - EC2:'):
        AWS_EC2.authorize_security_group_ingress_command(INVALID_ARGS)

    # Case 2
    result = AWS_EC2.authorize_security_group_ingress_command(IPPERMISSIONSFULL_ARGS)
    assert result.readable_output == "The Security Group ingress rule was created"


def test_create_policy_kwargs_dict():
    """
    Given
    - empty policy kwargs

    When
    - running create_policy_kwargs_dict function

    Then
    - make sure that create_policy_kwargs_dict does not fail on any exception

    """
    assert AWS_EC2.create_policy_kwargs_dict({}) == {}


def test_aws_ec2_authorize_security_group_egress_rule(mocker):
    """
    Given
    - authorize-security-group-egress-command arguments and aws client
    - Case 1: Valid arguments.
    - Case 2: Invalid arguments.
    When
    - running authorize-security-group-egress-command.
    Then
    - Ensure that the information was parsed correctly
    - Case 1: Should ensure that the right message was resulted return true.
    - Case 2: Should ensure that no message was resulted return true.
    """
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, 'authorize_security_group_egress', side_effect=validate_kwargs)
    mocker.patch.object(AWS_EC2, 'return_results')

    # Case 1
    with pytest.raises(DemistoException, match='Unexpected response from AWS - EC2:'):
        AWS_EC2.authorize_security_group_egress_command(INVALID_ARGS)

    # Case 2
    result = AWS_EC2.authorize_security_group_egress_command(VALID_ARGS)
    assert result.readable_output == "The Security Group egress rule was created"


@pytest.mark.parametrize('filter, expected_results', [
    ("Name=iam-instance-profile.arn,Values=arn:aws:iam::664798938958:instance-profile/AmazonEKSNodeRole",
     [{'Name': 'iam-instance-profile.arn', 'Values': ['arn:aws:iam::664798938958:instance-profile/AmazonEKSNodeRole']}])
])
def test_parse_filter_field(filter, expected_results):
    """
    Given
    - A filter string.
    - Case 1: a filter string including ':' in the value.
    When
    - Running parse_filter_field method.
    Then
    - Ensure that the filter was parsed correctly.
    - Case 1: Should ensure that the filter value include the whole value (including the part after the ':').
    """
    res = AWS_EC2.parse_filter_field(filter)
    assert res == expected_results


def mock_command_func(_):
    return CommandResults(
        outputs=[{}],
        readable_output='readable_output',
        outputs_prefix='prefix',
    )


def test_run_on_all_accounts(mocker):
    """
    Given:
        - The accounts_to_access and access_role_name params are provided.

    When:
        - Calling a command function that is decorated with test_account_runner.

    Then:
        - Ensure account_runner runs the command function for each of the accounts provided.
    """
    AWS_EC2.ROLE_NAME = 'name'
    AWS_EC2.PARAMS = {'accounts_to_access': '1,2'}
    mocker.patch.object(demisto, 'getArg', return_value=None)

    # list as output
    result_func = AWS_EC2.run_on_all_accounts(mock_command_func)
    results: list[CommandResults] = result_func({})

    assert results[0].readable_output == '#### Result for account `1`:\nreadable_output'
    assert results[0].outputs == [{'AccountId': '1'}]
    assert results[1].readable_output == '#### Result for account `2`:\nreadable_output'
    assert results[1].outputs == [{'AccountId': '2'}]
    
    # dict as output
    result_func = AWS_EC2.run_on_all_accounts(lambda _: CommandResults(
        outputs={},
        readable_output='readable_output',
        outputs_prefix='prefix',
    ))
    results: list[CommandResults] = result_func({})
    
    assert results[0].readable_output == '#### Result for account `1`:\nreadable_output'
    assert results[0].outputs == {'AccountId': '1'}
    assert results[1].readable_output == '#### Result for account `2`:\nreadable_output'
    assert results[1].outputs == {'AccountId': '2'}


@pytest.mark.parametrize('role_name, roleArn', [
    (None, None), ('name', 'role'),
])
def test_run_on_all_accounts_no_new_func(mocker, role_name, roleArn):
    """
    Given:
        - 1. The access_role_name param is not provided.
        - 2. The roleArn arg is provided.

    When:
        - Calling a command function that is decorated with test_account_runner.

    Then:
        - Ensure account_runner returns the command function unchanged.
    """
    AWS_EC2.ROLE_NAME = role_name
    mocker.patch.object(demisto, 'getArg', return_value=roleArn)

    result_func = AWS_EC2.run_on_all_accounts(mock_command_func)
    result: CommandResults = result_func({})

    assert result.readable_output == 'readable_output'
    assert result.outputs == [{}]
