import datetime

import pytest
import importlib
import demistomock as demisto

AWS_IAM = importlib.import_module("AWS-IAM")

ATTACHED_POLICIES = [
    {
        'PolicyName': 'AdministratorAccess',
        'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'
    }
]

ATTACHED_RESPONSE = {
    'AttachedPolicies': ATTACHED_POLICIES,
    'IsTruncated': True,
    'Marker': '111'
}

PAGINATION_CHECK = [
    (
        {'userName': 'test'},
        ['AllAccessPolicy', 'KeyPolicy']),
    (
        {
            'userName': 'test',
            'page': 2,
            'page_size': 1,
            'marker': '111'
        },
        ['KeyPolicy'])
]

ARG_LIST = [({'limit': '2', 'page_size': '3'}, 2, False, 3),
            ({'page_size': '3', 'page': '4'}, 12, True, 3),
            ({}, 50, False, None)]


class AWSClient:
    def aws_session(self):
        pass


class Boto3Client:
    def list_user_policies(self):
        pass

    def list_attached_user_policies(self):
        pass

    def list_attached_group_policies(self):
        pass

    def get_login_profile(self):
        pass


@pytest.mark.parametrize('args, res', PAGINATION_CHECK)
def test_list_user_policies(mocker, args, res):
    """

    Given:
    - user_name - user name to retrieve policies for.
    - pagination args - combination of marker, limit, page and page_size args in order to control pagination.

    When:
    - After running a list_user_policies command

    Then:
    - Ensure that the returned list includes only the policies the user posses.
    """

    response = {
        'PolicyNames': [
            'AllAccessPolicy',
            'KeyPolicy'
        ],
        'IsTruncated': True,
        'Marker': '111'
    }

    policy_data = []
    for policy in res:
        policy_data.append({
            'UserName': 'test',
            'PolicyName': policy,
        })

    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, "list_user_policies", return_value=response)
    mocker.patch.object(demisto, 'results')

    client = AWSClient()
    AWS_IAM.list_user_policies(args, client)
    contents = demisto.results.call_args[0][0]

    assert 'AWS IAM Policies for user test' in contents.get('HumanReadable')
    assert policy_data in contents.get('EntryContext').values()
    assert response.get('Marker') in contents.get('EntryContext').values()


def test_list_attached_user_polices(mocker):
    """

    Given:
    - user_name - user name to retrieve policies for.
    - pagination args - combination of marker, limit, page and page_size args in order to control pagination.

    When:
    - After running a list_user_attached_policies command

    Then:
    - Ensure that the returned list includes only the attached policies the user posses.
    """
    args = {
        'userName': 'test'
    }

    policy_name = ATTACHED_POLICIES[0].get('PolicyName')
    policy_arn = ATTACHED_POLICIES[0].get('PolicyArn')

    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, "list_attached_user_policies", return_value=ATTACHED_RESPONSE)
    mocker.patch.object(demisto, 'results')

    client = AWSClient()
    AWS_IAM.list_attached_user_policies(args, client)
    contents = demisto.results.call_args[0][0]

    assert 'AWS IAM Attached Policies for user test' in contents.get('HumanReadable')
    assert [{'UserName': 'test', 'PolicyName': policy_name, 'PolicyArn': policy_arn}] in contents.get(
        'EntryContext').values()
    assert '111' in contents.get('EntryContext').values()


def test_list_attached_group_polices(mocker):
    """

     Given:
    - group_name - group name to retrieve policies for.
    - pagination args - combination of marker, limit, page and page_size args in order to control pagination.

    When:
    - After running a list_group_attached_policies command

    Then:
    - Ensure that the returned list includes only the attached policies the group posses.
    """
    args = {
        'groupName': 'test'
    }

    policy_name = ATTACHED_POLICIES[0].get('PolicyName')
    policy_arn = ATTACHED_POLICIES[0].get('PolicyArn')

    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, "list_attached_group_policies", return_value=ATTACHED_RESPONSE)
    mocker.patch.object(demisto, 'results')

    client = AWSClient()
    AWS_IAM.list_attached_group_policies(args, client)
    contents = demisto.results.call_args[0][0]

    assert 'AWS IAM Attached Policies for group test' in contents.get('HumanReadable')
    assert [{'GroupName': 'test', 'PolicyName': policy_name, 'PolicyArn': policy_arn}] in contents.get(
        'EntryContext').values()
    assert '111' in contents.get('EntryContext').values()


def test_get_user_login_profile(mocker):
    """
        Given:
       - user_name - user name to retrieve login profile for.

       When:
       - After running a get_user_login_profile command

       Then:
       - Ensure that the returned profile set correctly.
       """
    res = {
        'LoginProfile': {
            'UserName': 'test',
            'CreateDate': datetime.datetime(2021, 11, 7, 15, 55, 3),
            'PasswordResetRequired': False
        }
    }
    args = {
        'userName': 'test'
    }

    data = ({
        'UserName': 'test',
        'LoginProfile': {
            'CreateDate': '2021-11-07 15:55:03',
            'PasswordResetRequired': False
        }
    })

    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, "get_login_profile", return_value=res)
    mocker.patch.object(demisto, 'results')

    client = AWSClient()
    AWS_IAM.get_user_login_profile(args, client)
    contents = demisto.results.call_args[0][0]

    assert 'AWS IAM Login Profile for user test' in contents.get('HumanReadable')
    assert data in contents.get('EntryContext').values()


@pytest.mark.parametrize('args, limit, is_manual, page_size', ARG_LIST)
def test_get_limit(args, limit, is_manual, page_size):
    res_limit, res_is_manual, res_page_size = AWS_IAM.get_limit(args)

    assert res_limit == limit
    assert res_is_manual == is_manual
    assert res_page_size == page_size
