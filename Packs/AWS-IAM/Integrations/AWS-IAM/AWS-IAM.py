from datetime import date, datetime

import boto3
import botocore.exceptions
import demistomock as demisto  # noqa: F401
import urllib3.util
from botocore.config import Config
from CommonServerPython import *  # noqa: F401

register_module_line('AWS - IAM', 'start', __line__())


# Disable insecure warnings
urllib3.disable_warnings()

SERVICE = 'iam'


class DatetimeEncoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)

# editing only integration


def get_limit(args):
    """
    Args:
        args: Args input for command, this function uses limit, page and page_size

    Returns:
        - limit - how many items to request from AWS - IAM API.
        - is_manual - whether manual pagination is active (using page and page_size)
        - page_size - used when manual pagination is active, to bring the relevant number of results from the data.

    """
    limit = arg_to_number(str(args.get("limit"))) if "limit" in args else None
    page = arg_to_number(str(args.get("page"))) if "page" in args else None
    page_size = arg_to_number(str(args.get("page_size"))) if "page_size" in args else None

    if limit is None:
        if page is not None and page_size is not None:
            if page <= 0:
                raise Exception('Chosen page number must be greater than 0')
            limit = page_size * page
            return limit, True, page_size
        else:
            limit = 50
    return limit, False, page_size


def create_user(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    kwargs = {'UserName': args.get('userName')}
    if args.get('path'):
        kwargs.update({'Path': args.get('path')})

    response = client.create_user(**kwargs)
    user = response['User']
    data = ({
        'UserName': user['UserName'],
        'UserId': user['UserId'],
        'Arn': user['Arn'],
        'CreateDate': datetime.strftime(user['CreateDate'], '%Y-%m-%dT%H:%M:%S'),
        'Path': user['Path'],
    })
    ec = {'AWS.IAM.Users': data}
    human_readable = tableToMarkdown('AWS IAM Users', data)
    return_outputs(human_readable, ec)


def create_login_profile(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    kwargs = {
        'UserName': args.get('userName'),
        'Password': args.get('password')
    }
    if args.get('passwordResetRequired'):
        kwargs.update({'PasswordResetRequired': True if args.get(
            'passwordResetRequired') == 'True' else False})

    response = client.create_login_profile(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("Login Profile Was Created For user {0} ".format(args.get('userName')))


def get_user(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    response = client.get_user(UserName=args.get('userName'))
    user = response['User']
    data = ({
        'UserName': user['UserName'],
        'UserId': user['UserId'],
        'Arn': user['Arn'],
        'CreateDate': datetime.strftime(user['CreateDate'], '%Y-%m-%dT%H:%M:%S'),
        'Path': user['Path'],
    })
    ec = {'AWS.IAM.Users': data}
    human_readable = tableToMarkdown('AWS IAM Users', data)
    return_outputs(human_readable, ec)


def list_users(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    data = []
    paginator = client.get_paginator('list_users')
    for response in paginator.paginate():
        for user in response['Users']:
            data.append({
                'UserName': user['UserName'],
                'UserId': user['UserId'],
                'Arn': user['Arn'],
                'CreateDate': datetime.strftime(user['CreateDate'], '%Y-%m-%d %H:%M:%S'),
                'Path': user['Path'],
            })
    ec = {'AWS.IAM.Users': data}
    human_readable = tableToMarkdown('AWS IAM Users', data)
    return_outputs(human_readable, ec)


def update_user(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    kwargs = {'UserName': args.get('oldUserName')}
    if args.get('newUserName'):
        kwargs.update({'NewUserName': args.get('newUserName')})
    if args.get('newPath'):
        kwargs.update({'NewPath': args.get('newPath')})

    response = client.update_user(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results(
            "Changed UserName {0} To: {1}".format(args.get('oldUserName'), args.get('newUserName')))


def delete_user(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    response = client.delete_user(UserName=args.get('userName'))
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results('The User {0} has been deleted'.format(args.get('userName')))


def update_login_profile(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    response = client.update_login_profile(
        Password=args.get('newPassword'),
        UserName=args.get('userName'),
        PasswordResetRequired=True if args.get('passwordResetRequired') == 'True' else False
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The user {0} Password was changed".format(args.get('userName')))


def create_group(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    kwargs = {'GroupName': args.get('groupName')}
    if args.get('path') is not None:
        kwargs.update({'Path': args.get('path')})

    response = client.create_group(**kwargs)
    group = response['Group']
    data = ({
        'GroupName': group['GroupName'],
        'GroupId': group['GroupId'],
        'Arn': group['Arn'],
        'CreateDate': datetime.strftime(group['CreateDate'], '%Y-%m-%dT%H:%M:%S'),
        'Path': group['Path'],
    })
    ec = {'AWS.IAM.Groups': data}
    human_readable = tableToMarkdown('AWS IAM Groups', data)
    return_outputs(human_readable, ec)


def list_groups(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    data = []
    paginator = client.get_paginator('list_groups')
    for response in paginator.paginate():
        for group in response['Groups']:
            data.append({
                'GroupName': group['GroupName'],
                'GroupId': group['GroupId'],
                'Arn': group['Arn'],
                'CreateDate': datetime.strftime(group['CreateDate'], '%Y-%m-%dT%H:%M:%S'),
                'Path': group['Path'],
            })
    ec = {'AWS.IAM.Groups': data}
    human_readable = tableToMarkdown('AWS IAM Groups', data)
    return_outputs(human_readable, ec)


def list_groups_for_user(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    data = []
    response = client.list_groups_for_user(UserName=args.get('userName'))
    for group in response['Groups']:
        data.append({
            'UserName': args.get('userName'),
            'GroupName': group['GroupName'],
            'GroupId': group['GroupId'],
            'Arn': group['Arn'],
            'CreateDate': datetime.strftime(group['CreateDate'], '%Y-%m-%dT%H:%M:%S'),
            'Path': group['Path'],
        })

    ec = {'AWS.IAM.Users(val.UserName === obj.UserName).Groups': data}
    human_readable = tableToMarkdown('AWS IAM User Groups', data)
    return_outputs(human_readable, ec)


def add_user_to_group(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    response = client.add_user_to_group(
        GroupName=args.get('groupName'),
        UserName=args.get('userName')
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The user {0} was added to the IAM group: {1}".format(args.get('userName'),
                                                                              args.get(
                                                                                  'groupName')))


def create_access_key(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    response = client.create_access_key(UserName=args.get('userName'))
    AccessKey = response['AccessKey']
    data = ({
        'UserName': AccessKey['UserName'],
        'AccessKeyId': AccessKey['AccessKeyId'],
        'SecretAccessKey': AccessKey['SecretAccessKey'],
        'Status': AccessKey['Status'],
        'CreateDate': datetime.strftime(AccessKey['CreateDate'], '%Y-%m-%dT%H:%M:%S')
    })

    ec = {'AWS.IAM.Users(val.UserName === obj.UserName).AccessKeys': data}
    human_readable = tableToMarkdown('AWS IAM Users', data)
    return_outputs(human_readable, ec)


def update_access_key(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    response = client.update_access_key(
        UserName=args.get('userName'),
        AccessKeyId=args.get('accessKeyId'),
        Status=args.get('status')
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results(
            "Access Key with ID {0} was set to status: {1}".format(args.get('accessKeyId'),
                                                                   args.get('status')))


def list_access_key_for_user(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    data = []
    response = client.list_access_keys(UserName=args.get('userName'))
    for accesskey in response['AccessKeyMetadata']:
        data.append({
            'UserName': accesskey['UserName'],
            'AccessKeyId': accesskey['AccessKeyId'],
            'Status': accesskey['Status'],
            'CreateDate': datetime.strftime(accesskey['CreateDate'], '%Y-%m-%dT%H:%M:%S')
        })

    ec = {'AWS.IAM.Users(val.UserName === obj.UserName).AccessKeys': data}
    human_readable = tableToMarkdown('AWS IAM Users Access Keys', data)
    return_outputs(human_readable, ec)


def list_policies(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    data = []
    response = client.list_policies(
        Scope=args.get('scope'),
        OnlyAttached=True if args.get('onlyAttached') == 'True' else False
    )
    for policy in response['Policies']:
        data.append({
            'PolicyName': policy['PolicyName'],
            'PolicyId': policy['PolicyId'],
            'Arn': policy['Arn'],
            'Path': policy['Path'],
            'DefaultVersionId': policy['DefaultVersionId'],
            'IsAttachable': policy['IsAttachable'],
            'AttachmentCount': policy['AttachmentCount'],
            'CreateDate': datetime.strftime(policy['CreateDate'], '%Y-%m-%dT%H:%M:%S'),
            'UpdateDate': datetime.strftime(policy['UpdateDate'], '%Y-%m-%dT%H:%M:%S'),
        })
    ec = {'AWS.IAM.Policies': data}
    human_readable = tableToMarkdown('AWS IAM Policies', data)
    return_outputs(human_readable, ec)


def list_roles(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    data = []
    output = []
    paginator = client.get_paginator('list_roles')
    for response in paginator.paginate():
        for role in response['Roles']:
            data.append({
                'RoleName': role['RoleName'],
                'RoleId': role['RoleId'],
                'Arn': role['Arn'],
                'CreateDate': datetime.strftime(role['CreateDate'], '%Y-%m-%dT%H:%M:%S'),
                'Path': role['Path'],
            })
            output.append(role)

    raw = json.loads(json.dumps(output, cls=DatetimeEncoder))
    ec = {'AWS.IAM.Roles': raw}
    human_readable = tableToMarkdown('AWS IAM Roles', data)
    return_outputs(human_readable, ec)


def attach_policy(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    if args.get('type') == 'User':
        response = client.attach_user_policy(
            UserName=args.get('entityName'),
            PolicyArn=args.get('policyArn')
        )
    if args.get('type') == 'Group':
        response = client.attach_group_policy(
            GroupName=args.get('entityName'),
            PolicyArn=args.get('policyArn')
        )
    if args.get('type') == 'Role':
        response = client.attach_role_policy(
            RoleName=args.get('entityName'),
            PolicyArn=args.get('policyArn')
        )

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results(
            "Policy was attached to {0}: {1} ".format(args.get('type'), args.get('entityName')))


def detach_policy(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    if args.get('type') == 'User':
        response = client.detach_user_policy(
            UserName=args.get('entityName'),
            PolicyArn=args.get('policyArn')
        )
    if args.get('type') == 'Group':
        response = client.detach_group_policy(
            GroupName=args.get('entityName'),
            PolicyArn=args.get('policyArn')
        )
    if args.get('type') == 'Role':
        response = client.detach_role_policy(
            RoleName=args.get('entityName'),
            PolicyArn=args.get('policyArn')
        )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results(
            "Policy was detached from {0}: {1} ".format(args.get('type'), args.get('entityName')))


def delete_login_profile(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    response = client.delete_login_profile(UserName=args.get('userName'))
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The user {0} login profile has been deleted".format(args.get('userName')))


def delete_group(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    response = client.delete_group(GroupName=args.get('groupName'))
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Group {0} has been deleted".format(args.get('groupName')))


def remove_user_from_group(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    response = client.remove_user_from_group(
        GroupName=args.get('groupName'),
        UserName=args.get('userName')
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results(
            "The User {0} has been removed from the group {1}".format(args.get('userName'),
                                                                      args.get('groupName')))


def delete_access_key(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    kwargs = {
        'UserName': args.get('userName'),
        'AccessKeyId': args.get('AccessKeyId')
    }

    response = client.delete_access_key(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Access Key was deleted")


def create_instance_profile(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    kwargs = {'InstanceProfileName': args.get('instanceProfileName')}
    if args.get('path') is not None:
        kwargs.update({'Path': args.get('path')})

    response = client.create_instance_profile(**kwargs)
    instanceProfile = response['InstanceProfile']
    data = ({
        'Path': instanceProfile['Path'],
        'InstanceProfileName': instanceProfile['InstanceProfileName'],
        'InstanceProfileId': instanceProfile['Path'],
        'Arn': instanceProfile['Arn'],
        'CreateDate': datetime.strftime(instanceProfile['CreateDate'], '%Y-%m-%dT%H:%M:%S'),
    })

    ec = {'AWS.IAM.InstanceProfiles': data}
    human_readable = tableToMarkdown('AWS IAM InstanceProfile', data)
    return_outputs(human_readable, ec)


def delete_instance_profile(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    response = client.delete_instance_profile(InstanceProfileName=args.get('instanceProfileName'))
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results(
            "The InstanceProfile: {0} was deleted".format(args.get('instanceProfileName')))


def list_instance_profiles(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    output = []
    data = []
    paginator = client.get_paginator('list_instance_profiles')
    for response in paginator.paginate():
        for instanceProfile in response['InstanceProfiles']:
            data.append({
                'Path': instanceProfile['Path'],
                'InstanceProfileName': instanceProfile['InstanceProfileName'],
                'InstanceProfileId': instanceProfile['InstanceProfileId'],
                'CreateDate': datetime.strftime(instanceProfile['CreateDate'], '%Y-%m-%dT%H:%M:%S'),
            })
            output.append(instanceProfile)

    raw = json.loads(json.dumps(output, cls=DatetimeEncoder))
    ec = {'AWS.IAM.InstanceProfiles': raw}
    human_readable = tableToMarkdown('AWS IAM Instance Profiles', data)
    return_outputs(human_readable, ec)


def add_role_to_instance_profile(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    kwargs = {
        'InstanceProfileName': args.get('instanceProfileName'),
        'RoleName': args.get('roleName')
    }

    response = client.add_role_to_instance_profile(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results(
            "The Role: {0} was added to the Instance Profile: {1}".format(args.get('roleName'),
                                                                          args.get('instanceProfileName'))
        )


def remove_role_from_instance_profile(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    kwargs = {
        'InstanceProfileName': args.get('instanceProfileName'),
        'RoleName': args.get('roleName')
    }

    response = client.remove_role_from_instance_profile(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results(
            "The Role: {0} was removed from the Instance Profile: {1}".format(args.get('roleName'),
                                                                              args.get(
                                                                                  'instanceProfileName')))


def list_instance_profiles_for_role(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    output = []
    data = []
    paginator = client.get_paginator('list_instance_profiles_for_role')
    for response in paginator.paginate(RoleName=args.get('roleName')):
        for instanceProfile in response['InstanceProfiles']:
            data.append({
                'Path': instanceProfile['Path'],
                'InstanceProfileName': instanceProfile['InstanceProfileName'],
                'InstanceProfileId': instanceProfile['InstanceProfileId'],
                'CreateDate': datetime.strftime(instanceProfile['CreateDate'], '%Y-%m-%dT%H:%M:%S'),
                'Arn': instanceProfile['Arn'],
            })
            output.append(instanceProfile)

    raw = json.loads(json.dumps(instanceProfile, cls=DatetimeEncoder))
    ec = {'AWS.IAM.InstanceProfiles': raw}
    human_readable = tableToMarkdown('AWS IAM Instance Profiles', data)
    return_outputs(human_readable, ec)


def get_instance_profile(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    response = client.get_instance_profile(InstanceProfileName=args.get('instanceProfileName'))
    instanceProfile = response['InstanceProfile']
    data = ({
        'Path': instanceProfile['Path'],
        'InstanceProfileName': instanceProfile['InstanceProfileName'],
        'InstanceProfileId': instanceProfile['InstanceProfileId'],
        'CreateDate': datetime.strftime(instanceProfile['CreateDate'], '%Y-%m-%dT%H:%M:%S'),
    })

    raw = json.loads(json.dumps(instanceProfile, cls=DatetimeEncoder))
    ec = {'AWS.IAM.InstanceProfiles': raw}
    human_readable = tableToMarkdown('AWS IAM Instance Profiles', data)
    return_outputs(human_readable, ec)


def get_role(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    response = client.get_role(RoleName=args.get('roleName'))
    role = response['Role']
    data = ({
        'RoleName': role['RoleName'],
        'RoleId': role['RoleId'],
        'Arn': role['Arn'],
        'CreateDate': datetime.strftime(role['CreateDate'], '%Y-%m-%dT%H:%M:%S'),
        'Path': role['Path'],
    })

    raw = json.loads(json.dumps(response['Role'], cls=DatetimeEncoder))
    ec = {'AWS.IAM.Roles': raw}
    human_readable = tableToMarkdown('AWS IAM Roles', data)
    return_outputs(human_readable, ec)


def delete_role(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    response = client.delete_role(RoleName=args.get('roleName'))

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Role: {0} was deleted".format(args.get('roleName')))


def create_role(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )

    kwargs = {
        'RoleName': args.get('roleName'),
        'AssumeRolePolicyDocument': json.dumps(json.loads(args.get('assumeRolePolicyDocument')))
    }
    if args.get('path') is not None:
        kwargs.update({'Path': args.get('path')})
    if args.get('description') is not None:
        kwargs.update({'Description': args.get('description')})
    if args.get('maxSessionDuration') is not None:
        kwargs.update({'MaxSessionDuration': int(args.get('maxSessionDuration'))})
    # return kwargs
    response = client.create_role(**kwargs)
    role = response['Role']
    data = ({
        'RoleName': role['RoleName'],
        'RoleId': role['RoleId'],
        'Arn': role['Arn'],
        'Path': role['Path'],
    })

    raw = json.loads(json.dumps(response['Role'], cls=DatetimeEncoder))
    ec = {'AWS.IAM.Roles': raw}
    human_readable = tableToMarkdown('AWS IAM Roles', data)
    return_outputs(human_readable, ec)


def create_policy(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )

    kwargs = {
        'PolicyName': args.get('policyName'),
        'PolicyDocument': json.dumps(json.loads(args.get('policyDocument')))
    }
    if args.get('path') is not None:
        kwargs.update({'Path': args.get('path')})
    if args.get('description') is not None:
        kwargs.update({'Description': args.get('description')})

    response = client.create_policy(**kwargs)
    policy = response['Policy']
    data = ({
        'PolicyName': policy['PolicyName'],
        'PolicyId': policy['PolicyId'],
        'Arn': policy['Arn'],
        'Path': policy['Path'],
        'CreateDate': datetime.strftime(policy['CreateDate'], '%Y-%m-%dT%H:%M:%S'),
    })

    raw = json.loads(json.dumps(response['Policy'], cls=DatetimeEncoder))
    ec = {'AWS.IAM.Policies': raw}
    human_readable = tableToMarkdown('AWS IAM Policies', data)
    return_outputs(human_readable, ec)


def delete_policy(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    response = client.delete_policy(PolicyArn=args.get('policyArn'))

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Policy: {0} was deleted".format(args.get('policyArn')))


def create_policy_version(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )

    kwargs = {
        'PolicyArn': args.get('policyArn'),
        'PolicyDocument': json.dumps(json.loads(args.get('policyDocument')))
    }
    if args.get('setAsDefault') is not None:
        kwargs.update({'SetAsDefault': True if args.get('setAsDefault') == 'True' else False})

    response = client.create_policy_version(**kwargs)
    policy = response['PolicyVersion']
    data = ({
        'PolicyArn': args.get('policyArn'),
        'VersionId': policy['VersionId'],
        'IsDefaultVersion': policy['IsDefaultVersion'],
        'CreateDate': datetime.strftime(policy['CreateDate'], '%Y-%m-%dT%H:%M:%S'),
    })

    ec = {'AWS.IAM.Policies(val.PolicyArn === obj.PolicyArn).Versions': data}
    human_readable = tableToMarkdown('New AWS IAM Policy Version', data)
    return_outputs(human_readable, ec)


def delete_policy_version(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    kwargs = {
        'PolicyArn': args.get('policyArn'),
        'VersionId': args.get('versionId')
    }
    response = client.delete_policy_version(**kwargs)

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Policy Version was deleted")


def list_policy_versions(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    data = []
    response = client.list_policy_versions(PolicyArn=args.get('policyArn'))
    for version in response['Versions']:
        data.append({
            'PolicyArn': args.get('policyArn'),
            'VersionId': version['VersionId'],
            'IsDefaultVersion': version['IsDefaultVersion'],
            'CreateDate': datetime.strftime(version['CreateDate'], '%Y-%m-%dT%H:%M:%S'),
        })
    ec = {'AWS.IAM.Policies(val.PolicyArn === obj.PolicyArn).Versions': data}
    human_readable = tableToMarkdown('AWS IAM Policy Versions', data)
    return_outputs(human_readable, ec)


def get_policy_version(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    data = []
    kwargs = {
        'PolicyArn': args.get('policyArn'),
        'VersionId': args.get('versionId')
    }
    response = client.get_policy_version(**kwargs)
    version = response['PolicyVersion']
    data.append({
        'PolicyArn': args.get('policyArn'),
        'Document': version['Document'],
        'VersionId': version['VersionId'],
        'IsDefaultVersion': version['IsDefaultVersion'],
        'CreateDate': datetime.strftime(version['CreateDate'], '%Y-%m-%dT%H:%M:%S'),
    })
    ec = {'AWS.IAM.Policies(val.PolicyArn === obj.PolicyArn).Versions': data}
    human_readable = tableToMarkdown('AWS IAM Policy Version', data)
    return_outputs(human_readable, ec)


def set_default_policy_version(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    kwargs = {
        'PolicyArn': args.get('policyArn'),
        'VersionId': args.get('versionId')
    }
    response = client.set_default_policy_version(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Default Policy Version was set to {0}".format(args.get('versionId')))


def create_account_alias(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    kwargs = {'AccountAlias': args.get('accountAlias')}
    response = client.create_account_alias(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Account Alias was created")


def delete_account_alias(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    kwargs = {'AccountAlias': args.get('accountAlias')}
    response = client.delete_account_alias(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Account Alias was deleted")


def get_account_password_policy(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    response = client.get_account_password_policy()
    data = response['PasswordPolicy']
    raw = json.loads(json.dumps(response['PasswordPolicy'], cls=DatetimeEncoder))
    ec = {'AWS.IAM.PasswordPolicy': raw}
    human_readable = tableToMarkdown('AWS IAM Account Password Policy', data)
    return_outputs(human_readable, ec)


def update_account_password_policy(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    try:
        response = client.get_account_password_policy()
        kwargs = response['PasswordPolicy']
    except client.exceptions.NoSuchEntityException:
        kwargs = {}
    # ExpirePasswords is part of the response but cannot be included
    # in the request
    if 'ExpirePasswords' in kwargs:
        kwargs.pop('ExpirePasswords')
    if args.get('minimumPasswordLength'):
        kwargs.update({'MinimumPasswordLength': int(args.get('minimumPasswordLength'))})
    if args.get('requireSymbols'):
        kwargs.update({'RequireSymbols': True if args.get('requireSymbols') == 'True' else False})
    if args.get('requireNumbers'):
        kwargs.update({'RequireNumbers': True if args.get('requireNumbers') == 'True' else False})
    if args.get('requireUppercaseCharacters'):
        kwargs.update(
            {'RequireUppercaseCharacters': True if args.get('requireUppercaseCharacters') == 'True' else False})
    if args.get('requireLowercaseCharacters'):
        kwargs.update(
            {'RequireLowercaseCharacters': True if args.get('requireLowercaseCharacters') == 'True' else False})
    if args.get('allowUsersToChangePassword'):
        kwargs.update(
            {'AllowUsersToChangePassword': True if args.get('allowUsersToChangePassword') == 'True' else False})
    if args.get('maxPasswordAge'):
        kwargs.update({'MaxPasswordAge': int(args.get('maxPasswordAge'))})
    if args.get('passwordReusePrevention'):
        kwargs.update({'PasswordReusePrevention': int(args.get('passwordReusePrevention'))})
    if args.get('hardExpiry'):
        kwargs.update({'HardExpiry': True if args.get('hardExpiry') == 'True' else False})
    response = client.update_account_password_policy(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Account Password Policy was updated")


def list_role_policies(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    kwargs = {'RoleName': args.get('roleName')}
    response = client.list_role_policies(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {
        'AWS.IAM.Roles(val.RoleName && val.RoleName === obj.RoleName).Policies':
            response.get('PolicyNames')}
    del response['ResponseMetadata']
    table_header = 'AWS IAM Role Policies for {}'.format(args.get('roleName'))
    human_readable = aws_table_to_markdown(response, table_header)
    return_outputs(human_readable, outputs, response)


def get_role_policy(args, aws_client):  # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    kwargs = {
        'RoleName': args.get('roleName'),
        'PolicyName': args.get('policyName')
    }
    response = client.get_role_policy(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {
        'AWS.IAM.Roles(val.RoleName && val.RoleName === obj.RoleName)':
            response}
    del response['ResponseMetadata']
    table_header = 'AWS IAM Role Policy for {}'.format(args.get('roleName'))
    human_readable = aws_table_to_markdown(response, table_header)
    return_outputs(human_readable, outputs, response)


def get_policy(args, aws_client):   # pragma: no cover
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    kwargs = {
        'PolicyArn': args.get('policyArn')
    }
    response = client.get_policy(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {
        'AWS.IAM.Policy(val.PolicyName && val.PolicyName === obj.PolicyName)':
            response.get('Policy')}
    del response['ResponseMetadata']
    table_header = 'AWS IAM Policy for {}'.format(args.get('policyArn'))
    human_readable = aws_table_to_markdown(response, table_header)
    return_outputs(human_readable, outputs, response)


def list_user_policies(args, aws_client):
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    user_name = args.get('userName', "")
    marker = args.get('marker', None)
    limit, is_manual, page_size = get_limit(args)

    kwargs = {
        'UserName': user_name,
        'MaxItems': limit
    }
    if marker:
        kwargs.update({'Marker': marker})

    response = client.list_user_policies(**kwargs)
    data = response.get('PolicyNames', [])
    marker = response.get('Marker', None)

    if is_manual and page_size and len(data) > page_size:
        data = data[-1 * page_size:]

    policy_data = [{
        'UserName': user_name,
        'PolicyName': policy,
    } for policy in data]

    ec = {}
    if policy_data:
        ec = {'AWS.IAM.UserPolicies(val.PolicyName && val.UserName && val.PolicyName === obj.PolicyName && '
              'val.UserName === obj.UserName)': policy_data,
              'AWS.IAM.Users(val.UserName === \'{}\').InlinePoliciesMarker'.format(user_name): marker}

    human_readable = tableToMarkdown('AWS IAM Policies for user {}'.format(user_name),
                                     headers=["PolicyNames"],
                                     headerTransform=pascalToSpace,
                                     t=data)
    return_outputs(human_readable, ec, response)


def list_attached_user_policies(args, aws_client):
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )

    user_name = args.get('userName')
    marker = args.get('marker')
    limit, is_manual, page_size = get_limit(args)

    kwargs = {
        'UserName': user_name,
        'MaxItems': limit
    }
    if marker:
        kwargs.update({'Marker': marker})

    response = client.list_attached_user_policies(**kwargs)
    data = response.get('AttachedPolicies', [])
    marker = response.get('Marker', None)

    if is_manual and page_size is not None and len(data) > page_size:
        data = data[-1 * page_size:]

    policy_data = [{
        'UserName': user_name,
        'PolicyArn': policy.get('PolicyArn'),
        'PolicyName': policy.get('PolicyName')
    } for policy in data]

    ec = {}
    if policy_data:
        ec = {'AWS.IAM.AttachedUserPolicies(val.PolicyArn && val.UserName && val.PolicyArn === obj.PolicyArn && '
              'val.UserName === obj.UserName)': policy_data,
              'AWS.IAM.Users(val.UserName === \'{}\').AttachedPoliciesMarker'.format(user_name): marker}

    human_readable = tableToMarkdown('AWS IAM Attached Policies for user {}'.format(user_name),
                                     headers=['PolicyName', 'PolicyArn'],
                                     headerTransform=pascalToSpace,
                                     t=data)

    return_outputs(human_readable, ec, response)


def list_attached_group_policies(args, aws_client):
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )

    group_name = args.get('groupName')
    marker = args.get('marker')
    limit, is_manual, page_size = get_limit(args)

    kwargs = {
        'GroupName': group_name,
        'MaxItems': limit
    }
    if marker:
        kwargs.update({'Marker': marker})

    response = client.list_attached_group_policies(**kwargs)
    data = response.get('AttachedPolicies', [])
    marker = response.get('Marker')

    if is_manual and page_size and len(data) > page_size:
        data = data[-1 * args.get('page_size'):]

    policy_data = [{
        'GroupName': group_name,
        'PolicyArn': policy.get('PolicyArn'),
        'PolicyName': policy.get('PolicyName')
    } for policy in data]

    ec = {}
    if policy_data:
        ec = {'AWS.IAM.AttachedGroupPolicies(val.PolicyArn && val.GroupName && val.PolicyArn === obj.PolicyArn && '
              'val.GroupName === obj.GroupName)': policy_data,
              'AWS.IAM.Groups(val.GroupName === \'{}\').AttachedPoliciesMarker'.format(group_name): marker}

    human_readable = tableToMarkdown('AWS IAM Attached Policies for group {}'.format(group_name),
                                     headers=['PolicyName', 'PolicyArn'],
                                     headerTransform=pascalToSpace,
                                     t=data)

    return_outputs(human_readable, ec, response)


def get_user_login_profile(args, aws_client):
    client = aws_client.aws_session(
        service=SERVICE,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    user_name = args.get('userName')
    kwargs = {
        'UserName': user_name
    }

    try:
        response = client.get_login_profile(**kwargs)
        user_profile = response['LoginProfile']
        create_date = datetime_to_string(user_profile.get('CreateDate')) or user_profile.get('CreateDate')
        data = {
            'UserName': user_profile.get('UserName'),
            'LoginProfile': {
                'CreateDate': create_date,
                'PasswordResetRequired': user_profile.get('PasswordResetRequired')
            }
        }

        ec = {'AWS.IAM.Users(val.UserName && val.UserName === obj.UserName)': data}

        human_readable = tableToMarkdown('AWS IAM Login Profile for user {}'.format(user_name),
                                         t=data.get('LoginProfile'),
                                         headers=['CreateDate', 'PasswordResetRequired'],
                                         removeNull=True,
                                         headerTransform=pascalToSpace)

        response['LoginProfile'].update({'CreateDate': create_date})
        return_outputs(human_readable, ec, response)
    except botocore.exceptions.ClientError as error:
        if error.response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 404:
            return_outputs(tableToMarkdown('AWS IAM Login Profile for user {}'.format(user_name), t={}))
        else:
            raise error


def test_function(aws_client):
    client = aws_client.aws_session(service=SERVICE)
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
    aws_access_key_id = params.get('access_key')
    aws_secret_access_key = params.get('secret_key')
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

    try:
        LOG('Command being called is {command}'.format(command=command))
        if command == 'test-module':
            test_function(aws_client)
        elif command == 'aws-iam-create-user':
            create_user(args, aws_client)
        elif command == 'aws-iam-create-login-profile':
            create_login_profile(args, aws_client)
        elif command == 'aws-iam-get-user':
            get_user(args, aws_client)
        elif command == 'aws-iam-list-users':
            list_users(args, aws_client)
        elif command == 'aws-iam-update-user':
            update_user(args, aws_client)
        elif command == 'aws-iam-delete-user':
            delete_user(args, aws_client)
        elif command == 'aws-iam-update-login-profile':
            update_login_profile(args, aws_client)
        elif command == 'aws-iam-create-group':
            create_group(args, aws_client)
        elif command == 'aws-iam-list-groups':
            list_groups(args, aws_client)
        elif command == 'aws-iam-list-groups-for-user':
            list_groups_for_user(args, aws_client)
        elif command == 'aws-iam-create-access-key':
            create_access_key(args, aws_client)
        elif command == 'aws-iam-update-access-key':
            update_access_key(args, aws_client)
        elif command == 'aws-iam-list-access-keys-for-user':
            list_access_key_for_user(args, aws_client)
        elif command == 'aws-iam-list-policies':
            list_policies(args, aws_client)
        elif command == 'aws-iam-list-roles':
            list_roles(args, aws_client)
        elif command == 'aws-iam-attach-policy':
            attach_policy(args, aws_client)
        elif command == 'aws-iam-detach-policy':
            detach_policy(args, aws_client)
        elif command == 'aws-iam-delete-login-profile':
            delete_login_profile(args, aws_client)
        elif command == 'aws-iam-add-user-to-group':
            add_user_to_group(args, aws_client)
        elif command == 'aws-iam-delete-group':
            delete_group(args, aws_client)
        elif command == 'aws-iam-remove-user-from-group':
            remove_user_from_group(args, aws_client)
        elif command == 'aws-iam-delete-access-key':
            delete_access_key(args, aws_client)
        elif command == 'aws-iam-create-instance-profile':
            create_instance_profile(args, aws_client)
        elif command == 'aws-iam-delete-instance-profile':
            delete_instance_profile(args, aws_client)
        elif command == 'aws-iam-list-instance-profiles':
            list_instance_profiles(args, aws_client)
        elif command == 'aws-iam-add-role-to-instance-profile':
            add_role_to_instance_profile(args, aws_client)
        elif command == 'aws-iam-remove-role-from-instance-profile':
            remove_role_from_instance_profile(args, aws_client)
        elif command == 'aws-iam-list-instance-profiles-for-role':
            list_instance_profiles_for_role(args, aws_client)
        elif command == 'aws-iam-get-instance-profile':
            get_instance_profile(args, aws_client)
        elif command == 'aws-iam-get-role':
            get_role(args, aws_client)
        elif command == 'aws-iam-delete-role':
            delete_role(args, aws_client)
        elif command == 'aws-iam-create-role':
            create_role(args, aws_client)
        elif command == 'aws-iam-create-policy':
            create_policy(args, aws_client)
        elif command == 'aws-iam-delete-policy':
            delete_policy(args, aws_client)
        elif command == 'aws-iam-create-policy-version':
            create_policy_version(args, aws_client)
        elif command == 'aws-iam-delete-policy-version':
            delete_policy_version(args, aws_client)
        elif command == 'aws-iam-list-policy-versions':
            list_policy_versions(args, aws_client)
        elif command == 'aws-iam-get-policy-version':
            get_policy_version(args, aws_client)
        elif command == 'aws-iam-set-default-policy-version':
            set_default_policy_version(args, aws_client)
        elif command == 'aws-iam-create-account-alias':
            create_account_alias(args, aws_client)
        elif command == 'aws-iam-delete-account-alias':
            delete_account_alias(args, aws_client)
        elif command == 'aws-iam-get-account-password-policy':
            get_account_password_policy(args, aws_client)
        elif command == 'aws-iam-update-account-password-policy':
            update_account_password_policy(args, aws_client)
        elif command == 'aws-iam-list-role-policies':
            list_role_policies(args, aws_client)
        elif command == 'aws-iam-get-role-policy':
            get_role_policy(args, aws_client)
        elif command == 'aws-iam-get-policy':
            get_policy(args, aws_client)
        elif command == 'aws-iam-list-user-policies':
            list_user_policies(args, aws_client)
        elif command == 'aws-iam-list-attached-user-policies':
            list_attached_user_policies(args, aws_client)
        elif command == 'aws-iam-list-attached-group-policies':
            list_attached_group_policies(args, aws_client)
        elif command == 'aws-iam-get-user-login-profile':
            get_user_login_profile(args, aws_client)

    except Exception as e:
        LOG(str(e))
        return_error('Error has occurred in the AWS IAM Integration: {code}\n {message}'.format(
            code=type(e), message=str(e)))


### GENERATED CODE ###: from AWSApiModule import *  # noqa: E402
# This code was inserted in place of an API module.
register_module_line('AWSApiModule', 'start', __line__(), wrapper=-3)


def validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id, aws_secret_access_key):
    """
    Validates that the provided parameters are compatible with the appropriate authentication method.
    """
    if not aws_default_region:
        raise DemistoException('You must specify AWS default region.')

    if bool(aws_access_key_id) != bool(aws_secret_access_key):
        raise DemistoException('You must provide Access Key id and Secret key id to configure the instance with '
                               'credentials.')
    if bool(aws_role_arn) != bool(aws_role_session_name):
        raise DemistoException('Role session name is required when using role ARN.')


class AWSClient:

    def __init__(self, aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                 aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate, timeout, retries,
                 aws_session_token=None):

        self.aws_default_region = aws_default_region
        self.aws_role_arn = aws_role_arn
        self.aws_role_session_name = aws_role_session_name
        self.aws_role_session_duration = aws_role_session_duration
        self.aws_role_policy = aws_role_policy
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.aws_session_token = aws_session_token
        self.verify_certificate = verify_certificate

        proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)
        (read_timeout, connect_timeout) = AWSClient.get_timeout(timeout)
        if int(retries) > 10:
            retries = 10
        self.config = Config(
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            retries=dict(
                max_attempts=int(retries)
            ),
            proxies=proxies
        )

    def update_config(self):
        command_config = {}
        retries = demisto.getArg('retries')  # Supports retries and timeout parameters on the command execution level
        if retries is not None:
            command_config['retries'] = dict(max_attempts=int(retries))
        timeout = demisto.getArg('timeout')
        if timeout is not None:
            (read_timeout, connect_timeout) = AWSClient.get_timeout(timeout)
            command_config['read_timeout'] = read_timeout
            command_config['connect_timeout'] = connect_timeout
        if retries or timeout:
            demisto.debug('Merging client config settings: {}'.format(command_config))
            self.config = self.config.merge(Config(**command_config))

    def aws_session(self, service, region=None, role_arn=None, role_session_name=None, role_session_duration=None,
                    role_policy=None):
        kwargs = {}

        self.update_config()

        if role_arn and role_session_name is not None:
            kwargs.update({
                'RoleArn': role_arn,
                'RoleSessionName': role_session_name,
            })
        elif self.aws_role_arn and self.aws_role_session_name is not None:
            kwargs.update({
                'RoleArn': self.aws_role_arn,
                'RoleSessionName': self.aws_role_session_name,
            })

        if role_session_duration is not None:
            kwargs.update({'DurationSeconds': int(role_session_duration)})
        elif self.aws_role_session_duration is not None:
            kwargs.update({'DurationSeconds': int(self.aws_role_session_duration)})

        if role_policy is not None:
            kwargs.update({'Policy': role_policy})
        elif self.aws_role_policy is not None:
            kwargs.update({'Policy': self.aws_role_policy})

        if kwargs and not self.aws_access_key_id:  # login with Role ARN

            if not self.aws_access_key_id:
                sts_client = boto3.client('sts', config=self.config, verify=self.verify_certificate,
                                          region_name=self.aws_default_region)
                sts_response = sts_client.assume_role(**kwargs)
                client = boto3.client(
                    service_name=service,
                    region_name=region if region else self.aws_default_region,
                    aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                    aws_session_token=sts_response['Credentials']['SessionToken'],
                    verify=self.verify_certificate,
                    config=self.config
                )
        elif self.aws_access_key_id and self.aws_role_arn:  # login with Access Key ID and Role ARN
            sts_client = boto3.client(
                service_name='sts',
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                verify=self.verify_certificate,
                config=self.config
            )
            kwargs.update({
                'RoleArn': self.aws_role_arn,
                'RoleSessionName': self.aws_role_session_name,
            })
            sts_response = sts_client.assume_role(**kwargs)
            client = boto3.client(
                service_name=service,
                region_name=self.aws_default_region,
                aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                aws_session_token=sts_response['Credentials']['SessionToken'],
                verify=self.verify_certificate,
                config=self.config
            )
        elif self.aws_access_key_id and not self.aws_role_arn:  # login with access key id
            client = boto3.client(
                service_name=service,
                region_name=region if region else self.aws_default_region,
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                verify=self.verify_certificate,
                config=self.config
            )
        elif self.aws_session_token and not self.aws_role_arn:  # login with session token
            client = boto3.client(
                service_name=service,
                region_name=region if region else self.aws_default_region,
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                aws_session_token=self.aws_session_token,
                verify=self.verify_certificate,
                config=self.config
            )
        else:  # login with default permissions, permissions pulled from the ec2 metadata
            client = boto3.client(service_name=service,
                                  region_name=region if region else self.aws_default_region)

        return client

    @staticmethod
    def get_timeout(timeout):
        if not timeout:
            timeout = "60,10"  # default values
        try:

            if isinstance(timeout, int):
                read_timeout = timeout
                connect_timeout = 10

            else:
                timeout_vals = timeout.split(',')
                read_timeout = int(timeout_vals[0])
                # the default connect timeout is 10
                connect_timeout = 10 if len(timeout_vals) == 1 else int(timeout_vals[1])

        except ValueError:
            raise DemistoException("You can specify just the read timeout (for example 60) or also the connect "
                                   "timeout followed after a comma (for example 60,10). If a connect timeout is not "
                                   "specified, a default of 10 second will be used.")
        return read_timeout, connect_timeout


register_module_line('AWSApiModule', 'end', __line__(), wrapper=1)
### END GENERATED CODE ###

if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()

register_module_line('AWS - IAM', 'end', __line__())
