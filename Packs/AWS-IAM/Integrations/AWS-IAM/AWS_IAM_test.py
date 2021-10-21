import copy

import pytest

from CommonServerPython import tableToMarkdown, pascalToSpace, date_to_timestamp
import demistomock as demisto
import importlib

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


PAGINATION_CHECK = [
    ({
         'userName': 'test'
     },
     ['AllAccessPolicy', 'KeyPolicy'])
    ,
    (
        {
            'userName': 'test',
            'page': 2,
            'page_size': 1,
            'marker': '111'
        },
        ['KeyPolicy'])
]


@pytest.mark.parametrize('args, res', PAGINATION_CHECK)
def test_list_user_policies(mocker, args, res):
    response = {
        'PolicyNames': [
            'AllAccessPolicy',
            'KeyPolicy'
        ],
        'IsTruncated': True,
        'Marker': '111'
    }

    ec = {'AWS.IAM.Users(val.UserName && val.UserName === obj.UserName)': {'UserName': 'test',
                                                                           'Policies': res,
                                                                           'InlinePoliciesMarker': '111'}}

    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, "list_user_policies", return_value=response)
    mocker.patch.object(demisto, 'results')

    client = AWSClient()
    AWS_IAM.list_user_policies(args, client)
    contents = demisto.results.call_args[0][0]
    human_readable = tableToMarkdown('AWS IAM Policies for user {}'.format('test'),
                                     headers=["PolicyNames"],
                                     headerTransform=pascalToSpace,
                                     t=res)
    assert contents.get('HumanReadable') == human_readable
    assert contents.get('EntryContext') == ec


def test_list_attached_user_polices(mocker):
    args = {
        'userName': 'test'
    }

    ec = {'AWS.IAM.Users(val.UserName && val.UserName === obj.UserName)': {'UserName': 'test',
                                                                           'AttachedPolicies': ATTACHED_POLICIES,
                                                                           'AttachedPoliciesMarker': '111'}}

    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, "list_attached_user_policies", return_value=ATTACHED_RESPONSE)
    mocker.patch.object(demisto, 'results')

    client = AWSClient()
    AWS_IAM.list_attached_user_policies(args, client)
    contents = demisto.results.call_args[0][0]
    human_readable = tableToMarkdown('AWS IAM Attached Policies for user {}'.format('test'),
                                     headers=['PolicyName', 'PolicyArn'],
                                     headerTransform=pascalToSpace,
                                     t=ATTACHED_POLICIES)
    assert contents.get('HumanReadable') == human_readable
    assert contents.get('EntryContext') == ec


def test_list_attached_group_polices(mocker):
    args = {
        'groupName': 'test'
    }

    ec = {'AWS.IAM.Groups(val.GroupName && val.GroupName === obj.GroupName)': {'GroupName': 'test',
                                                                               'AttachedPolicies': ATTACHED_POLICIES,
                                                                               'AttachedPoliciesMarker': '111'}}

    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, "list_attached_group_policies", return_value=ATTACHED_RESPONSE)
    mocker.patch.object(demisto, 'results')

    client = AWSClient()
    AWS_IAM.list_attached_group_policies(args, client)
    contents = demisto.results.call_args[0][0]
    human_readable = tableToMarkdown('AWS IAM Attached Policies for group {}'.format('test'),
                                     headers=['PolicyName', 'PolicyArn'],
                                     headerTransform=pascalToSpace,
                                     t=ATTACHED_POLICIES)
    assert contents.get('HumanReadable') == human_readable
    assert contents.get('EntryContext') == ec


def test_get_user_login_profile(mocker):
    res = {
        'LoginProfile': {
            'UserName': 'test',
            'CreateDate': '2011-09-19T23:00:56Z',
            'PasswordResetRequired': False
        }
    }
    args = {
        'userName': 'test'
    }

    data = ({
        'UserName': 'test',
        'LoginProfile': {
            'CreateDate': '2011-09-19T23:00:56Z',
            'PasswordResetRequired': False
        }
    })

    ec = {'AWS.IAM.Users(val.UserName && val.UserName === obj.UserName)': data}

    human_readable = tableToMarkdown('AWS IAM Login Profile for user {}'.format('test'),
                                     t=data.get('LoginProfile'),
                                     headers=['CreateDate', 'PasswordResetRequired'],
                                     removeNull=True,
                                     headerTransform=pascalToSpace)

    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, "get_login_profile", return_value=res)
    mocker.patch.object(demisto, 'results')

    client = AWSClient()
    AWS_IAM.get_user_login_profile(args, client)
    contents = demisto.results.call_args[0][0]

    assert contents.get('HumanReadable') == human_readable
    assert contents.get('EntryContext') == ec
