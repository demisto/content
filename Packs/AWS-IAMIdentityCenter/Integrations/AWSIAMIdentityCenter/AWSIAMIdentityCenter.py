import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401



import botocore.exceptions

from datetime import datetime, date
import urllib3.util

# Disable insecure warnings
urllib3.disable_warnings()

param = demisto.params()

SERVICE = 'identitystore'
IDENTITYSTOREID = param.get('IdentityStoreId')

class DatetimeEncoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def create_user(args, client):  # pragma: no cover
    username = demisto.getArg('userName')
    familyName = demisto.getArg('familyName')
    givenName = demisto.getArg('givenName')
    userEmail = demisto.getArg('userEmailAddress')
    userDisplayName = demisto.getArg('displayName')

    response = client.create_user(
        IdentityStoreId=f'{IDENTITYSTOREID}',
        UserName=f'{username}',
        Name={
            'FamilyName': f'{familyName}',
            'GivenName': f'{givenName}'
        },
        Emails=[
            {
                'Value': f'{userEmail}',
                'Primary': True
            },
        ],
        DisplayName=f'{userDisplayName}'
    )
    print(response)
    ec = {'AWS.IAMIdentityCenter.Users': response}
    human_readable = tableToMarkdown('AWS IAM Identity Center Users', response)
    return_outputs(human_readable, ec)


def get_user(args, client):  # pragma: no cover
    data = []
    userName = demisto.getArg('userName')
    response = client.list_users(
        IdentityStoreId=f'{IDENTITYSTOREID}',
        Filters=[
            {
                'AttributePath': 'UserName',
                'AttributeValue': f'{userName}'
            },
        ]
    )
    rep = json.dumps(response)
    repJSON = json.loads(rep)
    datas = repJSON.get('Users', [])
    for da in datas:
        for user in response['Users']:
            user_details = {
                'UserName': user['UserName'],
                'UserId': user['UserId']
            }
            userID = user['UserId']
            data.append(user_details)
    ec = {'AWS.IAM.IdentityCenter.Users': data}
    human_readable = tableToMarkdown('AWS IAM Users', data, removeNull=True)
    return_outputs(human_readable, ec)
    return userID


def list_users(args, client):  # pragma: no cover
    data = []
    response = client.list_users(
        IdentityStoreId=f'{IDENTITYSTOREID}',
    )
    rep = json.dumps(response)
    repJSON = json.loads(rep)
    datas = repJSON.get('Users', [])
    for da in datas:
        for user in response['Users']:
            user_details = {
                'UserName': user['UserName'],
                'UserId': user['UserId']
            }
            data.append(user_details)
    ec = {'AWS.IAM.IdentityCenter.Users': data}
    human_readable = tableToMarkdown('AWS IAM Identity Center Users', data, removeNull=True)
    return_outputs(human_readable, ec)


def list_groups(args, client):  # pragma: no cover
    data = []
    response = client.list_groups(
        IdentityStoreId=f'{IDENTITYSTOREID}',
    )
    rep = json.dumps(response)
    repJSON = json.loads(rep)
    datas = repJSON.get('Groups', [])
    for da in datas:
        for group in response['Groups']:
            group_details = {
                'DisplayName': group['DisplayName'],
                'GroupId': group['GroupId']
            }
            data.append(group_details)
    ec = {'AWS.IAM.IdentityCenter.Groups': data}
    human_readable = tableToMarkdown('AWS IAM Identity Center Groups', data)
    return_outputs(human_readable, ec)


def get_group(args, client):  # pragma: no cover
    data = []
    groupName = demisto.getArg('groupName')
    response = client.list_groups(
        IdentityStoreId=f'{IDENTITYSTOREID}',
        Filters=[
            {
                'AttributePath': 'DisplayName',
                'AttributeValue': f'{groupName}'
            },
        ]
    )
    rep = json.dumps(response)
    repJSON = json.loads(rep)
    datas = repJSON.get('Groups', [])
    for da in datas:
        for group in response['Groups']:
            group_details = {
                'DisplayName': group['DisplayName'],
                'GroupId': group['GroupId']
            }
            groupID = group['GroupId']
            data.append(group_details)
    ec = {'AWS.IAM.IdentityCenter.Groups': data}
    human_readable = tableToMarkdown('AWS IAM Identity Center Groups', data)
    return_outputs(human_readable, ec)
    return groupID


def list_groups_for_user(args, client):  # pragma: no cover
    data = []
    userName = demisto.getArg('userName')
    userID = get_user(args,client)
    response = client.list_group_memberships_for_member(
        IdentityStoreId=f'{IDENTITYSTOREID}',
        MemberId={
            'UserId': f'{userID}'
        }
    )
    rep = json.dumps(response)
    repJSON = json.loads(rep)
    datas = repJSON.get('GroupMemberships', [])
    for da in datas:
        for group in response['GroupMemberships']:
            group_details = {
                'GroupId': group['GroupId'],
                'MembershipId': group['MembershipId']
            }
            membershipID = group['MembershipId']
            data.append(group_details)
    ec = {'AWS.IAM.IdentityCenter.Users.GroupMemeberships': data}
    human_readable = tableToMarkdown(f'AWS IAM Identity Center Group for user {userName} ', data)
    return_outputs(human_readable, ec)
    return membershipID


def add_user_to_group(args, client):  # pragma: no cover
    userID = get_user(args,client)
    GroupID = get_group(args,client)
    response = client.create_group_membership(
        IdentityStoreId=f'{IDENTITYSTOREID}',
        GroupId=f'{GroupID}',
        MemberId={
            'UserId': f'{userID}'
        }
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The user {0} was added to the IAM group: {1}".format(args.get('userName'),
                                                                              args.get(
                                                                                  'groupName')))


def remove_user_from_groups(args, client):  # pragma: no cover
    membershipID = list_groups_for_user(args, client)
    response = client.delete_group_membership(
        IdentityStoreId=f'{IDENTITYSTOREID}',
        MembershipId=f'{membershipID}'
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results(
            "The User {0} has been removed from the group {1}".format(args.get('userName'),
                                                                      args.get('groupName')))


def test_function(client):
    response = client.list_users()
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results('ok')


def main():     # pragma: no cover
    params = demisto.params()
    aws_default_region = params.get('defaultRegion')
    aws_role_arn = params.get('roleArn')
    aws_role_session_name = params.get('roleSessionName')
    aws_role_session_duration = params.get('sessionDuration')
    aws_role_policy = None
    aws_access_key_id = params.get('credentials', {}).get('identifier') or params.get('access_key')
    aws_secret_access_key = params.get('credentials', {}).get('password') or params.get('secret_key')
    verify_certificate = not params.get('insecure', True)
    timeout = params.get('timeout')
    retries = params.get('retries') or 5

    validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id,
                    aws_secret_access_key)

    aws_client = AWSClient(aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                           aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate, timeout,
                           retries)
    command = demisto.command()
    args = demisto.args()
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )

    try:
        LOG('Command being called is {command}'.format(command=command))
        if command == 'test-module':
            test_function(client)
        elif command == 'aws-iam-identitycenter-create-user':
            create_user(args, client)
        elif command == 'aws-iam-identitycenter-get-user':
            get_user(args, client)
        elif command == 'aws-iam-identitycenter-list-users':
            list_users(args, client)
        elif command == 'aws-iam-identitycenter-list-groups':
            list_groups(args, client)
        elif command == 'aws-iam-identitycenter-get-group':
            get_user(args, client)
        elif command == 'aws-iam-identitycenter-list-groups-for-user':
            list_groups_for_user(args, client)
        elif command == 'aws-iam-identitycenter-add-user-to-group':
            add_user_to_group(args, client)
        elif command == 'aws-iam-identitycenter-remove-user-from-all-groups':
            remove_user_from_groups(args, client)

    except Exception as e:
        LOG(str(e))
        return_error('Error has occurred in the AWS IAM Integration: {code}\n {message}'.format(
            code=type(e), message=str(e)))



from AWSApiModule import *  # noqa: E402

if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()

register_module_line('AWS - IAM Identity Cetner', 'end', __line__())
