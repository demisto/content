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


class Boto3Client:
    def list_user_policies(self):
        pass

    def list_attached_user_policies(self):
        pass

    def list_attached_group_policies(self):
        pass

    def get_login_profile(self):
        pass

    def put_group_policy(self):
        pass

    def put_user_policy(self):
        pass

    def put_role_policy(self):
        pass

    def tag_role(self):
        pass

    def tag_user(self):
        pass

    def untag_role(self):
        pass

    def untag_user(self):
        pass

    def get_access_key_last_used(self):
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

    mocker.patch.object(Boto3Client, "list_user_policies", return_value=response)
    mocker.patch.object(demisto, 'results')

    client = Boto3Client()
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

    mocker.patch.object(Boto3Client, "list_attached_user_policies", return_value=ATTACHED_RESPONSE)
    mocker.patch.object(demisto, 'results')

    client = Boto3Client()
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

    mocker.patch.object(Boto3Client, "list_attached_group_policies", return_value=ATTACHED_RESPONSE)
    mocker.patch.object(demisto, 'results')

    client = Boto3Client()
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

    mocker.patch.object(Boto3Client, "get_login_profile", return_value=res)
    mocker.patch.object(demisto, 'results')

    client = Boto3Client()
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


@pytest.mark.parametrize('args, mocked_res, expected_hr', [
    ({'policyDocument': "policy_doc", "policyName": "policy_name", "roleName": "role_name"},
     {'ResponseMetadata': {'HTTPStatusCode': 200}}, 'Policy policy_name was added to role role_name')])
def test_put_role_policy_command(args, mocked_res, expected_hr, mocker):
    """
        Given:
       - args with policyDocument,  policyName, and roleName.

       When:
       - Calling put_role_policy_command.

       Then:
       - Ensure that the right header appears in the human readable results.
       """
    mocker.patch.object(Boto3Client, "put_role_policy", return_value=mocked_res)

    client = Boto3Client()
    cr_obj = AWS_IAM.put_role_policy_command(args, client)
    assert expected_hr in cr_obj.readable_output


@pytest.mark.parametrize('args, mocked_res, expected_hr', [
    ({'policyDocument': "policy_doc", "policyName": "policy_name", "userName": "user_name"},
     {'ResponseMetadata': {'HTTPStatusCode': 200}}, 'Policy policy_name was added to user user_name')])
def test_put_user_policy_command(args, mocked_res, expected_hr, mocker):
    """
        Given:
       - args with policyDocument,  policyName, and userName.

       When:
       - Calling _put_user_policy_command.

       Then:
       - Ensure that the right header appears in the human readable results.
       """
    mocker.patch.object(Boto3Client, "put_user_policy", return_value=mocked_res)

    client = Boto3Client()
    cr_obj = AWS_IAM.put_user_policy_command(args, client)
    assert expected_hr in cr_obj.readable_output


@pytest.mark.parametrize('args, mocked_res, expected_hr', [
    ({'policyDocument': "policy_doc", "policyName": "policy_name", "groupName": "group_name"},
     {'ResponseMetadata': {'HTTPStatusCode': 200}}, 'Policy policy_name was added to group group_name')])
def test_put_group_policy_command(args, mocked_res, expected_hr, mocker):
    """
        Given:
       - args with policyDocument,  policyName, and groupName.

       When:
       - Calling put_group_policy_command.

       Then:
       - Ensure that the right header appears in the human readable results.
       """
    mocker.patch.object(Boto3Client, "put_group_policy", return_value=mocked_res)

    client = Boto3Client()
    cr_obj = AWS_IAM.put_group_policy_command(args, client)
    assert expected_hr in cr_obj.readable_output


@pytest.mark.parametrize('args, mocked_res, expected_hr', [
    ({"roleName": "role_name", "tags": "Key:Value"}, {'ResponseMetadata': {'HTTPStatusCode': 200}},
     '### Added the following tags to role role_name\n|Key|Value|\n|---|---|\n| Key | Value |\n')])
def test_tag_role_command(args, mocked_res, expected_hr, mocker):
    """
        Given:
       - args with roleName and tags.

       When:
       - Calling tag_role_command.

       Then:
       - Ensure that the results were parsed correctly into a 2 columns table with all the keys and values.
       """
    mocker.patch.object(Boto3Client, "tag_role", return_value=mocked_res)

    client = Boto3Client()
    cr_obj = AWS_IAM.tag_role_command(args, client)
    assert expected_hr == cr_obj.readable_output


@pytest.mark.parametrize('args, mocked_res, expected_hr', [
    ({"userName": "user_name", "tags": "Key:Value, Key1:Value1"}, {'ResponseMetadata': {'HTTPStatusCode': 200}},
     '### Added the following tags to user user_name\n|Key|Value|\n|---|---|\n| Key | Value |\n| Key1 | Value1 |\n')])
def test_tag_user_command(args, mocked_res, expected_hr, mocker):
    """
        Given:
       - args with userName and tags.

       When:
       - Calling tag_user_command.

       Then:
       - Ensure that the results were parsed correctly into a 2 columns table with all the keys and values.
       """
    mocker.patch.object(Boto3Client, "tag_user", return_value=mocked_res)

    client = Boto3Client()
    cr_obj = AWS_IAM.tag_user_command(args, client)
    assert expected_hr == cr_obj.readable_output


@pytest.mark.parametrize('args, mocked_res, expected_hr', [
    ({"roleName": "role_name", "tagKeys": "Key1"}, {'ResponseMetadata': {'HTTPStatusCode': 200}},
     '### Untagged the following tags from role role_name\n|Removed keys|\n|---|\n| Key1 |\n')])
def test_untag_role_command(args, mocked_res, expected_hr, mocker):
    """
        Given:
       - args with roleName and tagKeys.

       When:
       - Calling untag_role_command.

       Then:
       - Ensure that the results were parsed correctly into a 1 column table with all the keys.
       """
    mocker.patch.object(Boto3Client, "untag_role", return_value=mocked_res)

    client = Boto3Client()
    cr_obj = AWS_IAM.untag_role_command(args, client)
    assert expected_hr == cr_obj.readable_output


@pytest.mark.parametrize('args, mocked_res, expected_hr', [
    ({"userName": "user_name", "tagKeys": "Key1,Key2"},
     {'ResponseMetadata': {'HTTPStatusCode': 200}},
     "### Untagged the following tags from user user_name\n|Removed keys|\n|---|\n| Key1 |\n| Key2 |\n")])
def test_untag_user_command(args, mocked_res, expected_hr, mocker):
    """
        Given:
       - args with userName and tagKeys.

       When:
       - Calling untag_user_command.

       Then:
       - Ensure that the results were parsed correctly into a 1 column table with all the keys.
       """
    mocker.patch.object(Boto3Client, "untag_user", return_value=mocked_res)

    client = Boto3Client()
    cr_obj = AWS_IAM.untag_user_command(args, client)
    assert expected_hr == cr_obj.readable_output


@pytest.mark.parametrize('args, mocked_res, expected_hr, expected_ec', [
    ({"accessKeyId": "access_Key_Id"},
     {'UserName': 'user_name', 'AccessKeyLastUsed': {'LastUsedDate': datetime.datetime(2023, 6, 6, 14, 32),
                                                     'ServiceName': 'test', 'Region': 'Here'},
      'ResponseMetadata': {'HTTPStatusCode': 200, 'RetryAttempts': 0}},
     '### Found the following information about access key access_Key_Id\n|ID|UserName|LastUsedDate|LastUsedServiceName|'
     'LastUsedRegion|\n|---|---|---|---|---|\n| access_Key_Id | user_name | 2023-06-06T14:32:00 | test | Here |\n',
     {'ID': 'access_Key_Id', 'UserName': 'user_name', 'LastUsedServiceName': 'test', 'LastUsedRegion': 'Here',
      'LastUsedDate': '2023-06-06T14:32:00'}
     )])
def test_get_access_key_last_used_command(args, mocked_res, expected_hr, expected_ec, mocker):
    """
        Given:
       - args with accessKeyId, and mocked_response with all fields that should be in the outputs.

       When:
       - Calling get_access_key_last_used_command.

       Then:
       - Ensure that the returned CR object contain the right data - all fields are included in the HR and EC,
       and that the LastUsedDate field in the response was converted to str.
       """
    mocker.patch.object(Boto3Client, "get_access_key_last_used", return_value=mocked_res)

    client = Boto3Client()
    cr_obj = AWS_IAM.get_access_key_last_used_command(args, client)
    assert expected_hr == cr_obj.readable_output
    assert expected_ec == cr_obj.outputs
    assert type(cr_obj.raw_response.get("AccessKeyLastUsed", {}).get("LastUsedDate")) == str


@pytest.mark.parametrize('tags_ls, expected_output', [
    (["Key1:Value1", "Key2:Value2"], [{"Key": "Key1", "Value": "Value1"}, {"Key": "Key2", "Value": "Value2"}])])
def test_create_tag_dicts_list(tags_ls, expected_output):
    """
        Given:
       - tags_ls - a list of Key:Value tags.

       When:
       - running create_tag_dicts_list.

       Then:
       - Ensure that the list was parsed into a list of dicts,
       where each Key:Value in the input is {"Key": "Key1", "Value": "Value1"}.
       """
    tags_dicts_ls = AWS_IAM.create_tag_dicts_list(tags_ls)
    assert expected_output == tags_dicts_ls
