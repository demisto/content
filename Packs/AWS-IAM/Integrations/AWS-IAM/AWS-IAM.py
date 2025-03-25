
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import botocore.exceptions
from datetime import datetime, date


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


def create_user(args, client):  # pragma: no cover
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


def create_login_profile(args, client):  # pragma: no cover
    kwargs = {
        'UserName': args.get('userName'),
        'Password': args.get('password')
    }
    if args.get('passwordResetRequired'):
        kwargs.update({'PasswordResetRequired': args.get('passwordResetRequired') == 'True'})

    response = client.create_login_profile(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("Login Profile Was Created For user {} ".format(args.get('userName')))


def get_user(args, client):  # pragma: no cover
    try:
        response = client.get_user(UserName=args.get('userName'))
    except Exception as e:
        if 'NoSuchEntity' in str(e):
            return_outputs(f'User {args.get("userName")} was not found.')
            return
        else:
            raise e

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


def list_users(args, client):  # pragma: no cover
    data = []
    paginator = client.get_paginator('list_users')
    for response in paginator.paginate():
        for user in response['Users']:
            user_details = {
                'UserName': user['UserName'],
                'UserId': user['UserId'],
                'Arn': user['Arn'],
                'CreateDate': datetime.strftime(user['CreateDate'], '%Y-%m-%d %H:%M:%S'),
                'Path': user['Path'],
            }
            if user.get('PasswordLastUsed'):
                user_details['PasswordLastUsed'] = datetime.strftime(user['PasswordLastUsed'], '%Y-%m-%d %H:%M:%S')
            data.append(user_details)
    ec = {'AWS.IAM.Users': data}
    human_readable = tableToMarkdown('AWS IAM Users', data, removeNull=True)
    return_outputs(human_readable, ec)


def update_user(args, client):  # pragma: no cover
    kwargs = {'UserName': args.get('oldUserName')}
    if args.get('newUserName'):
        kwargs.update({'NewUserName': args.get('newUserName')})
    if args.get('newPath'):
        kwargs.update({'NewPath': args.get('newPath')})

    response = client.update_user(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results(
            "Changed UserName {} To: {}".format(args.get('oldUserName'), args.get('newUserName')))


def delete_user(args, client):  # pragma: no cover
    response = client.delete_user(UserName=args.get('userName'))
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results('The User {} has been deleted'.format(args.get('userName')))


def update_login_profile(args, client):  # pragma: no cover
    response = client.update_login_profile(
        Password=args.get('newPassword'),
        UserName=args.get('userName'),
        PasswordResetRequired=args.get('passwordResetRequired') == 'True'
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The user {} Password was changed".format(args.get('userName')))


def create_group(args, client):  # pragma: no cover
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


def list_groups(args, client):  # pragma: no cover
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


def list_groups_for_user(args, client):  # pragma: no cover
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


def add_user_to_group(args, client):  # pragma: no cover
    response = client.add_user_to_group(
        GroupName=args.get('groupName'),
        UserName=args.get('userName')
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The user {} was added to the IAM group: {}".format(args.get('userName'),
                                                                            args.get(
            'groupName')))


def create_access_key(args, client):  # pragma: no cover
    kwargs = {}
    if user_name := args.get('userName'):
        kwargs["UserName"] = user_name
    response = client.create_access_key(**kwargs)
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


def update_access_key(args, client):  # pragma: no cover
    kwargs = {
        "AccessKeyId": args.get('accessKeyId'),
        "Status": args.get('status')
    }
    if user_name := args.get('userName'):
        kwargs["UserName"] = user_name

    response = client.update_access_key(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results(
            "Access Key with ID {} was set to status: {}".format(args.get('accessKeyId'),
                                                                 args.get('status')))


def list_access_key_for_user(args, client):  # pragma: no cover
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


def list_policies(args, client):  # pragma: no cover
    data = []
    response = client.list_policies(
        Scope=args.get('scope'),
        OnlyAttached=args.get('onlyAttached') == 'True'
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


def list_roles(args, client):  # pragma: no cover
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


def attach_policy(args, client):  # pragma: no cover
    response = {}
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
            "Policy was attached to {}: {} ".format(args.get('type'), args.get('entityName')))


def detach_policy(args, client):  # pragma: no cover
    response = {}
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
            "Policy was detached from {}: {} ".format(args.get('type'), args.get('entityName')))


def delete_login_profile(args, client):  # pragma: no cover
    response = client.delete_login_profile(UserName=args.get('userName'))
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The user {} login profile has been deleted".format(args.get('userName')))


def delete_group(args, client):  # pragma: no cover
    response = client.delete_group(GroupName=args.get('groupName'))
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Group {} has been deleted".format(args.get('groupName')))


def remove_user_from_group(args, client):  # pragma: no cover
    response = client.remove_user_from_group(
        GroupName=args.get('groupName'),
        UserName=args.get('userName')
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results(
            "The User {} has been removed from the group {}".format(args.get('userName'),
                                                                    args.get('groupName')))


def delete_access_key(args, client):  # pragma: no cover
    kwargs = {
        'AccessKeyId': args.get('AccessKeyId')
    }
    if user_name := args.get('userName'):
        kwargs['UserName'] = user_name

    response = client.delete_access_key(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Access Key was deleted")


def list_mfa_devices(args, client):
    user_name = args.get('userName', "")
    marker = args.get('marker', None)
    limit, is_manual, page_size = get_limit(args)

    kwargs = {
        'UserName': user_name,
        'MaxItems': limit
    }
    if marker:
        kwargs.update({'Marker': marker})
    response = client.list_mfa_devices(**kwargs)

    mfa_devices = response['MFADevices']
    data = []

    for mfa_device in mfa_devices:
        data.append({
            'UserName': mfa_device['UserName'],
            'SerialNumber': mfa_device['SerialNumber'],
            'EnableDate': datetime.strftime(mfa_device['EnableDate'], '%Y-%m-%d %H:%M:%S'),
        })
    if is_manual and page_size and len(data) > page_size:
        data = data[-1 * page_size:]
    human_readable = tableToMarkdown('AWS IAM Users MFA Devices', data)
    return CommandResults(
        readable_output=human_readable,
        outputs_key_field="UserName",
        outputs_prefix="AWS.IAM.MFADevices",
        outputs={"Devices": data, "Marker": response["Marker"]},
    )


def deactivate_mfa_device(args, client):
    response = client.deactivate_mfa_device(
        UserName=args['userName'],
        SerialNumber=args['serialNumber']
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results('The User {} mfa device has been deactivated'.format(args.get('userName')))


def delete_virtual_mfa_device(args, client):
    response = client.delete_virtual_mfa_device(
        SerialNumber=args['serialNumber']
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results('The User {} mfa device has been deleted'.format(args.get('serialNumber')))


def create_instance_profile(args, client):  # pragma: no cover
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


def delete_instance_profile(args, client):  # pragma: no cover
    response = client.delete_instance_profile(InstanceProfileName=args.get('instanceProfileName'))
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results(
            "The InstanceProfile: {} was deleted".format(args.get('instanceProfileName')))


def list_instance_profiles(args, client):  # pragma: no cover
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


def add_role_to_instance_profile(args, client):  # pragma: no cover
    kwargs = {
        'InstanceProfileName': args.get('instanceProfileName'),
        'RoleName': args.get('roleName')
    }

    response = client.add_role_to_instance_profile(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results(
            "The Role: {} was added to the Instance Profile: {}".format(args.get('roleName'),
                                                                        args.get('instanceProfileName'))
        )


def remove_role_from_instance_profile(args, client):  # pragma: no cover
    kwargs = {
        'InstanceProfileName': args.get('instanceProfileName'),
        'RoleName': args.get('roleName')
    }

    response = client.remove_role_from_instance_profile(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results(
            "The Role: {} was removed from the Instance Profile: {}".format(args.get('roleName'),
                                                                            args.get(
                'instanceProfileName')))


def list_instance_profiles_for_role(args, client):  # pragma: no cover
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


def get_instance_profile(args, client):  # pragma: no cover
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


def get_role(args, client):  # pragma: no cover
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
    raw["Tags"] = raw.get("Tags", [])
    human_readable = tableToMarkdown('AWS IAM Roles', data)
    return CommandResults(
        outputs=createContext(raw),
        outputs_prefix='AWS.IAM.Roles',
        outputs_key_field='RoleName',
        readable_output=human_readable
    )


def delete_role(args, client):  # pragma: no cover
    response = client.delete_role(RoleName=args.get('roleName'))

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Role: {} was deleted".format(args.get('roleName')))


def create_role(args, client):  # pragma: no cover
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


def create_policy(args, client):  # pragma: no cover
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


def delete_policy(args, client):  # pragma: no cover
    response = client.delete_policy(PolicyArn=args.get('policyArn'))

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Policy: {} was deleted".format(args.get('policyArn')))


def create_policy_version(args, client):  # pragma: no cover
    kwargs = {
        'PolicyArn': args.get('policyArn'),
        'PolicyDocument': json.dumps(json.loads(args.get('policyDocument')))
    }
    if args.get('setAsDefault') is not None:
        kwargs.update({'SetAsDefault': args.get('setAsDefault') == 'True'})

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


def delete_policy_version(args, client):  # pragma: no cover
    kwargs = {
        'PolicyArn': args.get('policyArn'),
        'VersionId': args.get('versionId')
    }
    response = client.delete_policy_version(**kwargs)

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Policy Version was deleted")


def list_policy_versions(args, client):  # pragma: no cover
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


def get_policy_version(args, client):  # pragma: no cover
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


def set_default_policy_version(args, client):  # pragma: no cover
    kwargs = {
        'PolicyArn': args.get('policyArn'),
        'VersionId': args.get('versionId')
    }
    response = client.set_default_policy_version(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Default Policy Version was set to {}".format(args.get('versionId')))


def create_account_alias(args, client):  # pragma: no cover
    kwargs = {'AccountAlias': args.get('accountAlias')}
    response = client.create_account_alias(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Account Alias was created")


def delete_account_alias(args, client):  # pragma: no cover
    kwargs = {'AccountAlias': args.get('accountAlias')}
    response = client.delete_account_alias(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Account Alias was deleted")


def get_account_password_policy(args, client):  # pragma: no cover
    response = client.get_account_password_policy()
    data = response['PasswordPolicy']
    raw = json.loads(json.dumps(response['PasswordPolicy'], cls=DatetimeEncoder))
    ec = {'AWS.IAM.PasswordPolicy': raw}
    human_readable = tableToMarkdown('AWS IAM Account Password Policy', data)
    return_outputs(human_readable, ec)


def update_account_password_policy(args, client):  # pragma: no cover
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
        kwargs.update({'RequireSymbols': args.get('requireSymbols') == 'True'})
    if args.get('requireNumbers'):
        kwargs.update({'RequireNumbers': args.get('requireNumbers') == 'True'})
    if args.get('requireUppercaseCharacters'):
        kwargs.update(
            {'RequireUppercaseCharacters': args.get('requireUppercaseCharacters') == 'True'})
    if args.get('requireLowercaseCharacters'):
        kwargs.update(
            {'RequireLowercaseCharacters': args.get('requireLowercaseCharacters') == 'True'})
    if args.get('allowUsersToChangePassword'):
        kwargs.update(
            {'AllowUsersToChangePassword': args.get('allowUsersToChangePassword') == 'True'})
    if args.get('maxPasswordAge'):
        kwargs.update({'MaxPasswordAge': int(args.get('maxPasswordAge'))})
    if args.get('passwordReusePrevention'):
        kwargs.update({'PasswordReusePrevention': int(args.get('passwordReusePrevention'))})
    if args.get('hardExpiry'):
        kwargs.update({'HardExpiry': args.get('hardExpiry') == 'True'})
    response = client.update_account_password_policy(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Account Password Policy was updated")


def list_role_policies(args, client):  # pragma: no cover
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


def get_role_policy(args, client):  # pragma: no cover
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


def get_policy(args, client):   # pragma: no cover
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


def list_user_policies(args, client):
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
              f'AWS.IAM.Users(val.UserName === \'{user_name}\').InlinePoliciesMarker': marker}

    human_readable = tableToMarkdown(f'AWS IAM Policies for user {user_name}',
                                     headers=["PolicyNames"],
                                     headerTransform=pascalToSpace,
                                     t=data)
    return_outputs(human_readable, ec, response)


def list_attached_user_policies(args, client):
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
              f'AWS.IAM.Users(val.UserName === \'{user_name}\').AttachedPoliciesMarker': marker}

    human_readable = tableToMarkdown(f'AWS IAM Attached Policies for user {user_name}',
                                     headers=['PolicyName', 'PolicyArn'],
                                     headerTransform=pascalToSpace,
                                     t=data)

    return_outputs(human_readable, ec, response)


def list_attached_group_policies(args, client):
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
              f'AWS.IAM.Groups(val.GroupName === \'{group_name}\').AttachedPoliciesMarker': marker}

    human_readable = tableToMarkdown(f'AWS IAM Attached Policies for group {group_name}',
                                     headers=['PolicyName', 'PolicyArn'],
                                     headerTransform=pascalToSpace,
                                     t=data)

    return_outputs(human_readable, ec, response)


def get_user_login_profile(args, client):
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

        human_readable = tableToMarkdown(f'AWS IAM Login Profile for user {user_name}',
                                         t=data.get('LoginProfile'),
                                         headers=['CreateDate', 'PasswordResetRequired'],
                                         removeNull=True,
                                         headerTransform=pascalToSpace)

        response['LoginProfile'].update({'CreateDate': create_date})
        return_outputs(human_readable, ec, response)
    except botocore.exceptions.ClientError as error:
        if error.response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 404:
            return_outputs(tableToMarkdown(f'AWS IAM Login Profile for user {user_name}', t={}))
        else:
            raise error


def put_role_policy_command(args, client):
    """
    Add or change a policy entry for a given role.
    Args:
        client (boto3.client): The boto3.client client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, and the human readable section.
    """
    policy_document = args.get('policyDocument')
    policy_name = args.get('policyName')
    role_name = args.get('roleName')

    kwargs = {
        'PolicyDocument': policy_document,
        'PolicyName': policy_name,
        'RoleName': role_name
    }

    try:
        response = client.put_role_policy(**kwargs)
        human_readable = f"Policy {policy_name} was added to role {role_name}"
        return CommandResults(
            raw_response=response,
            readable_output=human_readable
        )
    except Exception as e:
        raise DemistoException(f"Couldn't add policy {policy_name} to role {role_name}"
                               f"\nencountered the following exception: {str(e)}")


def put_user_policy_command(args, client):
    """
    Add or change a policy entry for a given user.
    Args:
        client (boto3.client): The boto3.client client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, and the human readable section.
    """
    policy_document = args.get('policyDocument')
    policy_name = args.get('policyName')
    user_name = args.get('userName')

    kwargs = {
        'PolicyDocument': policy_document,
        'PolicyName': policy_name,
        'UserName': user_name
    }

    try:
        response = client.put_user_policy(**kwargs)
        human_readable = f"Policy {policy_name} was added to user {user_name}"
        return CommandResults(
            raw_response=response,
            readable_output=human_readable
        )
    except Exception as e:
        raise DemistoException(f"Couldn't add policy {policy_name} to user {user_name}"
                               f"\nencountered the following exception: {str(e)}")


def put_group_policy_command(args, client):
    """
    Add or change a policy entry for a given group.
    Args:
        client (boto3.client): The boto3.client client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, and the human readable section.
    """
    policy_document = args.get('policyDocument')
    policy_name = args.get('policyName')
    group_name = args.get('groupName')

    kwargs = {
        'PolicyDocument': policy_document,
        'PolicyName': policy_name,
        'GroupName': group_name
    }

    try:
        response = client.put_group_policy(**kwargs)
        human_readable = f"Policy {policy_name} was added to group {group_name}"
        return CommandResults(
            raw_response=response,
            readable_output=human_readable
        )
    except Exception as e:
        raise DemistoException(f"Couldn't add policy {policy_name} to group {group_name}"
                               f"\nencountered the following exception: {str(e)}")


def tag_role_command(args, client):
    """
    Add the given tags to the given role.
    Args:
        client (boto3.client): The boto3.client client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, and the human readable section.
    """
    tags = create_tag_dicts_list(argToList(args.get('tags')))
    role_name = args.get('roleName')

    kwargs = {
        'RoleName': role_name,
        'Tags': tags
    }

    try:
        response = client.tag_role(**kwargs)
        human_readable = tableToMarkdown(f"Added the following tags to role {role_name}", tags)
        return CommandResults(
            raw_response=response,
            readable_output=human_readable
        )
    except Exception as e:
        raise DemistoException(f"Couldn't add the following tags {tags} to role {role_name}"
                               f"\nencountered the following exception: {str(e)}")


def list_attached_role_policies_command(args: dict, client) -> list[CommandResults]:
    aws_args = {"RoleName": (role_name := args["roleName"])}

    for demisto_key, aws_key in (
        ("pathPrefix", "PathPrefix"),
        ("marker", "Marker"),
        ("maxItems", "MaxItems")
    ):  # optional keys, renaming to match AWS API
        if (value := args.get(demisto_key)) is not None:
            aws_args[aws_key] = value

    if (max_itmes := aws_args.get("MaxItems")) is not None:
        aws_args["MaxItems"] = int(max_itmes)
    try:
        raw_response = client.list_attached_role_policies(**aws_args)
    except Exception as e:
        raise DemistoException(f"Couldn't list role policies with {args}\n"
                               f"encountered the following exception: {str(e)}") from e

    policies = [
        policy | {"RoleName": role_name}
        for policy in raw_response["AttachedPolicies"]
    ]

    query_outputs = {k: v for k, v in raw_response.items() if k in ("IsTruncated", "Marker")}
    return [
        CommandResults(
            # Main result - here be policies
            raw_response=raw_response,
            outputs=policies,
            outputs_prefix='AWS.IAM.Roles.AttachedPolicies.Policies',
            readable_output=tableToMarkdown(
                name=f"Attached Policies for Role {role_name}",
                t=policies,
            )),
        CommandResults(
            # Secondary result object, for querying the next ones (if necessary)
            raw_response=raw_response,
            outputs=query_outputs,
            outputs_prefix="AWS.IAM.Roles.AttachedPolicies.Query",
            readable_output=f"Listed {len(policies)} attached policies for role {role_name}"
            if not raw_response.get("IsTruncated")
            else (f"Listed {len(policies)} role policies but more are available. "
                  "Either increase the `maxItems` argument, or use `marker` argument with the value from context.")
        )
    ]


def tag_user_command(args, client):
    """
    Add the given tags to the given user.
    Args:
        client (boto3.client): The boto3.client client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, and the human readable section.
    """
    tags = create_tag_dicts_list(argToList(args.get('tags')))
    user_name = args.get('userName')

    kwargs = {
        'UserName': user_name,
        'Tags': tags
    }

    try:
        response = client.tag_user(**kwargs)
        human_readable = tableToMarkdown(f"Added the following tags to user {user_name}", tags)
        return CommandResults(
            raw_response=response,
            readable_output=human_readable
        )
    except Exception as e:
        raise DemistoException(f"Couldn't add the following tags {tags} to role {user_name}"
                               f"\nencountered the following exception: {str(e)}")


def untag_user_command(args, client):
    """
    Remove the given tags from the given user.
    Args:
        client (boto3.client): The boto3.client client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, and the human readable section.
    """
    tags = argToList(args.get('tagKeys'))
    user_name = args.get('userName')

    kwargs = {
        'UserName': user_name,
        'TagKeys': tags
    }

    try:
        response = client.untag_user(**kwargs)
        human_readable = tableToMarkdown(f"Untagged the following tags from user {user_name}", tags, headers=["Removed keys"])
        return CommandResults(
            raw_response=response,
            readable_output=human_readable
        )
    except Exception as e:
        raise DemistoException(f"Couldn't untag the following tags {', '.join(tags)} from user {user_name}"
                               f"\nencountered the following exception: {str(e)}")


def untag_role_command(args, client):
    """
    Remove the given tags from the given role.
    Args:
        client (boto3.client): The boto3.client client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, and the human readable section.
    """
    tags = argToList(args.get('tagKeys'))
    role_name = args.get('roleName')

    kwargs = {
        'RoleName': role_name,
        'TagKeys': tags
    }

    try:
        response = client.untag_role(**kwargs)
        human_readable = tableToMarkdown(f"Untagged the following tags from role {role_name}", tags, headers=["Removed keys"])
        return CommandResults(
            raw_response=response,
            readable_output=human_readable
        )
    except Exception as e:
        raise DemistoException(f"Couldn't untag the following tags {', '.join(tags)} from role {role_name}"
                               f"\nencountered the following exception: {str(e)}")


def create_tag_dicts_list(tags):
    """
    Transform the given tags list to a list of dicts.
    Args:
        tags (list): The tags list where each entry is in the form of Key:value
    Returns:
        list: The transformed list.
    """
    try:
        dict_tags = []
        for tag in tags:
            temp = tag.split(':')
            dict_tags.append({"Key": temp[0], "Value": temp[1]})
        return dict_tags
    except Exception as e:
        demisto.debug(f"encountered the following error in create_tag_dicts_list: {str(e)}")
        raise DemistoException("Please make sure the tags argument is in the form of Key1:Value1,Key2:Value2.")


def get_access_key_last_used_command(args, client):
    """
    Retrieve information about the last used occasion of the given access key.
    Args:
        client (boto3.client): The boto3.client client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, the ec, and the human readable section.
    """
    access_key_id = args.get('accessKeyId')
    kwargs = {
        'AccessKeyId': access_key_id
    }

    try:
        response = client.get_access_key_last_used(**kwargs)
        access_key_last_used = response.get("AccessKeyLastUsed", {})
        last_used = ""
        if last_used := access_key_last_used.get("LastUsedDate", ""):
            last_used = datetime.strftime(last_used, '%Y-%m-%dT%H:%M:%S')
            response["AccessKeyLastUsed"]["LastUsedDate"] = last_used
        data = {
            "ID": access_key_id,
            "UserName": response.get("UserName", ""),
            "LastUsedServiceName": access_key_last_used.get("ServiceName", ""),
            "LastUsedRegion": access_key_last_used.get("Region", ""),
            "LastUsedDate": last_used
        }
        headers = ["ID", "UserName", "LastUsedDate", "LastUsedServiceName", "LastUsedRegion"]
        human_readable = tableToMarkdown(f"Found the following information about access key {access_key_id}", data,
                                         headers, removeNull=True)
        return CommandResults(
            outputs=createContext(data, removeNull=True),
            outputs_prefix='AWS.IAM.AccessKey',
            raw_response=response,
            outputs_key_field='ID',
            readable_output=human_readable
        )
    except Exception as e:
        raise DemistoException(f"Couldn't get information about access key {access_key_id}"
                               f"\nencountered the following exception: {str(e)}")


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
        LOG(f'Command being called is {command}')
        if command == 'test-module':
            test_function(client)
        elif command == 'aws-iam-create-user':
            create_user(args, client)
        elif command == 'aws-iam-create-login-profile':
            create_login_profile(args, client)
        elif command == 'aws-iam-get-user':
            get_user(args, client)
        elif command == 'aws-iam-list-users':
            list_users(args, client)
        elif command == 'aws-iam-update-user':
            update_user(args, client)
        elif command == 'aws-iam-delete-user':
            delete_user(args, client)
        elif command == 'aws-iam-update-login-profile':
            update_login_profile(args, client)
        elif command == 'aws-iam-create-group':
            create_group(args, client)
        elif command == 'aws-iam-list-groups':
            list_groups(args, client)
        elif command == 'aws-iam-list-groups-for-user':
            list_groups_for_user(args, client)
        elif command == 'aws-iam-create-access-key':
            create_access_key(args, client)
        elif command == 'aws-iam-update-access-key':
            update_access_key(args, client)
        elif command == 'aws-iam-list-access-keys-for-user':
            list_access_key_for_user(args, client)
        elif command == 'aws-iam-list-policies':
            list_policies(args, client)
        elif command == 'aws-iam-list-roles':
            list_roles(args, client)
        elif command == 'aws-iam-attach-policy':
            attach_policy(args, client)
        elif command == 'aws-iam-detach-policy':
            detach_policy(args, client)
        elif command == 'aws-iam-delete-login-profile':
            delete_login_profile(args, client)
        elif command == 'aws-iam-add-user-to-group':
            add_user_to_group(args, client)
        elif command == 'aws-iam-delete-group':
            delete_group(args, client)
        elif command == 'aws-iam-remove-user-from-group':
            remove_user_from_group(args, client)
        elif command == 'aws-iam-delete-access-key':
            delete_access_key(args, client)
        elif command == 'aws-iam-list-mfa-devices':
            list_mfa_devices(args, client)
        elif command == 'aws-iam-deactivate-mfa-devices':
            deactivate_mfa_device(args, client)
        elif command == 'aws-iam-delete-mfa-devices':
            delete_virtual_mfa_device(args, client)
        elif command == 'aws-iam-create-instance-profile':
            create_instance_profile(args, client)
        elif command == 'aws-iam-delete-instance-profile':
            delete_instance_profile(args, client)
        elif command == 'aws-iam-list-instance-profiles':
            list_instance_profiles(args, client)
        elif command == 'aws-iam-add-role-to-instance-profile':
            add_role_to_instance_profile(args, client)
        elif command == 'aws-iam-remove-role-from-instance-profile':
            remove_role_from_instance_profile(args, client)
        elif command == 'aws-iam-list-instance-profiles-for-role':
            list_instance_profiles_for_role(args, client)
        elif command == 'aws-iam-get-instance-profile':
            get_instance_profile(args, client)
        elif command == 'aws-iam-get-role':
            return_results(get_role(args, client))
        elif command == 'aws-iam-delete-role':
            delete_role(args, client)
        elif command == 'aws-iam-create-role':
            create_role(args, client)
        elif command == 'aws-iam-create-policy':
            create_policy(args, client)
        elif command == 'aws-iam-delete-policy':
            delete_policy(args, client)
        elif command == 'aws-iam-create-policy-version':
            create_policy_version(args, client)
        elif command == 'aws-iam-delete-policy-version':
            delete_policy_version(args, client)
        elif command == 'aws-iam-list-policy-versions':
            list_policy_versions(args, client)
        elif command == 'aws-iam-get-policy-version':
            get_policy_version(args, client)
        elif command == 'aws-iam-set-default-policy-version':
            set_default_policy_version(args, client)
        elif command == 'aws-iam-create-account-alias':
            create_account_alias(args, client)
        elif command == 'aws-iam-delete-account-alias':
            delete_account_alias(args, client)
        elif command == 'aws-iam-get-account-password-policy':
            get_account_password_policy(args, client)
        elif command == 'aws-iam-update-account-password-policy':
            update_account_password_policy(args, client)
        elif command == 'aws-iam-list-role-policies':
            list_role_policies(args, client)
        elif command == 'aws-iam-get-role-policy':
            get_role_policy(args, client)
        elif command == 'aws-iam-get-policy':
            get_policy(args, client)
        elif command == 'aws-iam-list-user-policies':
            list_user_policies(args, client)
        elif command == 'aws-iam-list-attached-user-policies':
            list_attached_user_policies(args, client)
        elif command == 'aws-iam-list-attached-group-policies':
            list_attached_group_policies(args, client)
        elif command == 'aws-iam-get-user-login-profile':
            get_user_login_profile(args, client)
        elif command == 'aws-iam-put-role-policy':
            return_results(put_role_policy_command(args, client))
        elif command == 'aws-iam-put-user-policy':
            return_results(put_user_policy_command(args, client))
        elif command == 'aws-iam-put-group-policy':
            return_results(put_group_policy_command(args, client))
        elif command == 'aws-iam-tag-role':
            return_results(tag_role_command(args, client))
        elif command == 'aws-iam-tag-user':
            return_results(tag_user_command(args, client))
        elif command == 'aws-iam-untag-user':
            return_results(untag_user_command(args, client))
        elif command == 'aws-iam-untag-role':
            return_results(untag_role_command(args, client))
        elif command == 'aws-iam-get-access-key-last-used':
            return_results(get_access_key_last_used_command(args, client))
        elif command == 'aws-iam-list-attached-role-policies':
            return_results(list_attached_role_policies_command(args, client))
    except Exception as e:
        LOG(str(e))
        return_error('Error has occurred in the AWS IAM Integration: {code}\n {message}'.format(
            code=type(e), message=str(e)))


from AWSApiModule import *  # noqa: E402

if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
