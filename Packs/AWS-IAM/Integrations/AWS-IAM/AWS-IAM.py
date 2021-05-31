import demistomock as demisto
from CommonServerPython import *
from datetime import datetime, date
import boto3
from botocore.config import Config
from botocore.parsers import ResponseParserError
import urllib3.util

# Disable insecure warnings
urllib3.disable_warnings()

# Initiating params object for efficiency
params = demisto.params()

AWS_DEFAULT_REGION = None
AWS_ROLE_ARN = params.get('roleArn')
AWS_ROLE_SESSION_NAME = params.get('roleSessionName')
AWS_ROLE_SESSION_DURATION = params.get('sessionDuration')
AWS_ROLE_POLICY = None
AWS_ACCESS_KEY_ID = params.get('access_key')
AWS_SECRET_ACCESS_KEY = params.get('secret_key')
VERIFY_CERTIFICATE = not params.get('insecure', True)
proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)
config = Config(
    connect_timeout=1,
    retries=dict(
        max_attempts=5
    ),
    proxies=proxies
)


def aws_session(service='iam', region=None, roleArn=None, roleSessionName=None,
                roleSessionDuration=None,
                rolePolicy=None):
    kwargs = {}
    if roleArn and roleSessionName is not None:
        kwargs.update({
            'RoleArn': roleArn,
            'RoleSessionName': roleSessionName,
        })
    elif AWS_ROLE_ARN and AWS_ROLE_SESSION_NAME is not None:
        kwargs.update({
            'RoleArn': AWS_ROLE_ARN,
            'RoleSessionName': AWS_ROLE_SESSION_NAME,
        })

    if roleSessionDuration is not None:
        kwargs.update({'DurationSeconds': int(roleSessionDuration)})
    elif AWS_ROLE_SESSION_DURATION is not None:
        kwargs.update({'DurationSeconds': int(AWS_ROLE_SESSION_DURATION)})

    if rolePolicy is not None:
        kwargs.update({'Policy': rolePolicy})
    elif AWS_ROLE_POLICY is not None:
        kwargs.update({'Policy': AWS_ROLE_POLICY})
    if kwargs and not AWS_ACCESS_KEY_ID:

        if not AWS_ACCESS_KEY_ID:
            sts_client = boto3.client('sts', config=config, verify=VERIFY_CERTIFICATE)
            sts_response = sts_client.assume_role(**kwargs)
            if region is not None:
                client = boto3.client(
                    service_name=service,
                    region_name=region,
                    aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                    aws_session_token=sts_response['Credentials']['SessionToken'],
                    verify=VERIFY_CERTIFICATE,
                    config=config
                )
            else:
                client = boto3.client(
                    service_name=service,
                    region_name=AWS_DEFAULT_REGION,
                    aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                    aws_session_token=sts_response['Credentials']['SessionToken'],
                    verify=VERIFY_CERTIFICATE,
                    config=config
                )
    elif AWS_ACCESS_KEY_ID and AWS_ROLE_ARN:
        sts_client = boto3.client(
            service_name='sts',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            verify=VERIFY_CERTIFICATE,
            config=config
        )
        kwargs.update({
            'RoleArn': AWS_ROLE_ARN,
            'RoleSessionName': AWS_ROLE_SESSION_NAME,
        })
        sts_response = sts_client.assume_role(**kwargs)
        client = boto3.client(
            service_name=service,
            region_name=AWS_DEFAULT_REGION,
            aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
            aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
            aws_session_token=sts_response['Credentials']['SessionToken'],
            verify=VERIFY_CERTIFICATE,
            config=config
        )
    else:
        if region is not None:
            client = boto3.client(
                service_name=service,
                region_name=region,
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                verify=VERIFY_CERTIFICATE,
                config=config
            )
        else:
            client = boto3.client(
                service_name=service,
                region_name=AWS_DEFAULT_REGION,
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                verify=VERIFY_CERTIFICATE,
                config=config
            )

    return client


class DatetimeEncoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def create_user(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def create_login_profile(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def get_user(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def list_users(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def update_user(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def delete_user(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    response = client.delete_user(UserName=args.get('userName'))
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results('The User {0} has been deleted'.format(args.get('userName')))


def update_login_profile(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    response = client.update_login_profile(
        Password=args.get('newPassword'),
        UserName=args.get('userName'),
        PasswordResetRequired=True if args.get('passwordResetRequired') == 'True' else False
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The user {0} Password was changed".format(args.get('userName')))


def create_group(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def list_groups(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def list_groups_for_user(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def add_user_to_group(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    response = client.add_user_to_group(
        GroupName=args.get('groupName'),
        UserName=args.get('userName')
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The user {0} was added to the IAM group: {1}".format(args.get('userName'),
                                                                              args.get(
                                                                                  'groupName')))


def create_access_key(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def update_access_key(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def list_access_key_for_user(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def list_policies(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def list_roles(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def attach_policy(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def detach_policy(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def delete_login_profile(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    response = client.delete_login_profile(UserName=args.get('userName'))
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The user {0} login profile has been deleted".format(args.get('userName')))


def delete_group(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    response = client.delete_group(GroupName=args.get('groupName'))
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Group {0} has been deleted".format(args.get('groupName')))


def remove_user_from_group(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    response = client.remove_user_from_group(
        GroupName=args.get('groupName'),
        UserName=args.get('userName')
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results(
            "The User {0} has been removed from the group {1}".format(args.get('userName'),
                                                                      args.get('groupName')))


def delete_access_key(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        'UserName': args.get('userName'),
        'AccessKeyId': args.get('AccessKeyId')
    }

    response = client.delete_access_key(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Access Key was deleted")


def create_instance_profile(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def delete_instance_profile(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    response = client.delete_instance_profile(InstanceProfileName=args.get('instanceProfileName'))
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results(
            "The InstanceProfile: {0} was deleted".format(args.get('instanceProfileName')))


def list_instance_profiles(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def add_role_to_instance_profile(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def remove_role_from_instance_profile(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def list_instance_profiles_for_role(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def get_instance_profile(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def get_role(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def delete_role(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    response = client.delete_role(RoleName=args.get('roleName'))

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Role: {0} was deleted".format(args.get('roleName')))


def create_role(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def create_policy(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def delete_policy(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    response = client.delete_policy(PolicyArn=args.get('policyArn'))

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Policy: {0} was deleted".format(args.get('policyArn')))


def create_policy_version(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def delete_policy_version(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        'PolicyArn': args.get('policyArn'),
        'VersionId': args.get('versionId')
    }
    response = client.delete_policy_version(**kwargs)

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Policy Version was deleted")


def list_policy_versions(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def get_policy_version(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def set_default_policy_version(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        'PolicyArn': args.get('policyArn'),
        'VersionId': args.get('versionId')
    }
    response = client.set_default_policy_version(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Default Policy Version was set to {0}".format(args.get('versionId')))


def create_account_alias(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {'AccountAlias': args.get('accountAlias')}
    response = client.create_account_alias(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Account Alias was created")


def delete_account_alias(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {'AccountAlias': args.get('accountAlias')}
    response = client.delete_account_alias(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Account Alias was deleted")


def get_account_password_policy(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    response = client.get_account_password_policy()
    data = response['PasswordPolicy']
    raw = json.loads(json.dumps(response['PasswordPolicy'], cls=DatetimeEncoder))
    ec = {'AWS.IAM.PasswordPolicy': raw}
    human_readable = tableToMarkdown('AWS IAM Account Password Policy', data)
    return_outputs(human_readable, ec)


def update_account_password_policy(args):
    client = aws_session(
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
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


def test_function():
    client = aws_session()
    response = client.list_users()
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results('ok')


'''EXECUTION BLOCK'''
try:
    LOG('Command being called is {command}'.format(command=demisto.command()))
    if demisto.command() == 'test-module':
        test_function()
    elif demisto.command() == 'aws-iam-create-user':
        create_user(demisto.args())
    elif demisto.command() == 'aws-iam-create-login-profile':
        create_login_profile(demisto.args())
    elif demisto.command() == 'aws-iam-get-user':
        get_user(demisto.args())
    elif demisto.command() == 'aws-iam-list-users':
        list_users(demisto.args())
    elif demisto.command() == 'aws-iam-update-user':
        update_user(demisto.args())
    elif demisto.command() == 'aws-iam-delete-user':
        delete_user(demisto.args())
    elif demisto.command() == 'aws-iam-update-login-profile':
        update_login_profile(demisto.args())
    elif demisto.command() == 'aws-iam-create-group':
        create_group(demisto.args())
    elif demisto.command() == 'aws-iam-list-groups':
        list_groups(demisto.args())
    elif demisto.command() == 'aws-iam-list-groups-for-user':
        list_groups_for_user(demisto.args())
    elif demisto.command() == 'aws-iam-create-access-key':
        create_access_key(demisto.args())
    elif demisto.command() == 'aws-iam-update-access-key':
        update_access_key(demisto.args())
    elif demisto.command() == 'aws-iam-list-access-keys-for-user':
        list_access_key_for_user(demisto.args())
    elif demisto.command() == 'aws-iam-list-policies':
        list_policies(demisto.args())
    elif demisto.command() == 'aws-iam-list-roles':
        list_roles(demisto.args())
    elif demisto.command() == 'aws-iam-attach-policy':
        attach_policy(demisto.args())
    elif demisto.command() == 'aws-iam-detach-policy':
        detach_policy(demisto.args())
    elif demisto.command() == 'aws-iam-delete-login-profile':
        delete_login_profile(demisto.args())
    elif demisto.command() == 'aws-iam-add-user-to-group':
        add_user_to_group(demisto.args())
    elif demisto.command() == 'aws-iam-delete-group':
        delete_group(demisto.args())
    elif demisto.command() == 'aws-iam-remove-user-from-group':
        remove_user_from_group(demisto.args())
    elif demisto.command() == 'aws-iam-delete-access-key':
        delete_access_key(demisto.args())
    elif demisto.command() == 'aws-iam-create-instance-profile':
        create_instance_profile(demisto.args())
    elif demisto.command() == 'aws-iam-delete-instance-profile':
        delete_instance_profile(demisto.args())
    elif demisto.command() == 'aws-iam-list-instance-profiles':
        list_instance_profiles(demisto.args())
    elif demisto.command() == 'aws-iam-add-role-to-instance-profile':
        add_role_to_instance_profile(demisto.args())
    elif demisto.command() == 'aws-iam-remove-role-from-instance-profile':
        remove_role_from_instance_profile(demisto.args())
    elif demisto.command() == 'aws-iam-list-instance-profiles-for-role':
        list_instance_profiles_for_role(demisto.args())
    elif demisto.command() == 'aws-iam-get-instance-profile':
        get_instance_profile(demisto.args())
    elif demisto.command() == 'aws-iam-get-role':
        get_role(demisto.args())
    elif demisto.command() == 'aws-iam-delete-role':
        delete_role(demisto.args())
    elif demisto.command() == 'aws-iam-create-role':
        create_role(demisto.args())
    elif demisto.command() == 'aws-iam-create-policy':
        create_policy(demisto.args())
    elif demisto.command() == 'aws-iam-delete-policy':
        delete_policy(demisto.args())
    elif demisto.command() == 'aws-iam-create-policy-version':
        create_policy_version(demisto.args())
    elif demisto.command() == 'aws-iam-delete-policy-version':
        delete_policy_version(demisto.args())
    elif demisto.command() == 'aws-iam-list-policy-versions':
        list_policy_versions(demisto.args())
    elif demisto.command() == 'aws-iam-get-policy-version':
        get_policy_version(demisto.args())
    elif demisto.command() == 'aws-iam-set-default-policy-version':
        set_default_policy_version(demisto.args())
    elif demisto.command() == 'aws-iam-create-account-alias':
        create_account_alias(demisto.args())
    elif demisto.command() == 'aws-iam-delete-account-alias':
        delete_account_alias(demisto.args())
    elif demisto.command() == 'aws-iam-get-account-password-policy':
        get_account_password_policy(demisto.args())
    elif demisto.command() == 'aws-iam-update-account-password-policy':
        update_account_password_policy(demisto.args())

except ResponseParserError as e:
    return_error(
        'Could not connect to the AWS endpoint. Please check that the region is valid.\n {error}'.format(
            error=type(e)))
    LOG(str(e))

except Exception as e:
    LOG(str(e))
    return_error('Error has occurred in the AWS IAM Integration: {code}\n {message}'.format(
        code=type(e), message=str(e)))
