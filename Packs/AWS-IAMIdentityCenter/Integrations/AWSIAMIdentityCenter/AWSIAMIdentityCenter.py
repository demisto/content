import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from AWSApiModule import *


params = demisto.params()
args = demisto.args()

SERVICE = 'identitystore'
PREFIX = 'AWS.IAMIdentityCenter'
PREFIXUSER = 'AWS.IAMIdentityCenter.User'
PREFIXGROUP = 'AWS.IAMIdentityCenter.Group'


def create_user(args, client, IdentityStoreId):
    user_name = args.get('userName')
    family_name = args.get('familyName')
    given_name = args.get('givenName')
    user_email = args.get('userEmailAddress')
    user_display_name = args.get('displayName')
    user_type = args.get('userType')
    profile_url = args.get('profileUrl')
    title = args.get('title')
    region = args.get('region')
    primary_email = args.get('userEmailAddressPrimary')
    if primary_email and not user_email:
        return_error('Error: When specifying userEmailAddressPrimary, userEmailAddress must also be provided.')
    if primary_email:
        primary_email = argToBoolean(primary_email)

    kwargs = {
        'IdentityStoreId': IdentityStoreId,
        'UserName': user_name,
        'Name': {
            'FamilyName': family_name,
            'GivenName': given_name
        },
        'Emails': [
            {
                'Value': user_email,
                'Primary': primary_email
            }
        ],
        'DisplayName': user_display_name,
        'UserType': user_type,
        'ProfileUrl': profile_url,
        'Title': title,
        'Addresses': [
            {
                'Region': region,
            }
        ]
    }
    kwargs = remove_empty_elements(kwargs)
    response = client.create_user(**kwargs)
    user_id = response.get('UserId')
    response.pop('ResponseMetadata', None)
    response = remove_empty_elements(response)
    human_readable = tableToMarkdown(f'User {user_name} has been successfully created with user id {user_id}', response)
    result = CommandResults(
        outputs_prefix=PREFIXUSER,
        readable_output=human_readable,
        outputs=response
    )
    return_results(result)


def get_userId_by_username(args, client, IdentityStoreId):
    user_name = args.get('userName')
    response_id = client.get_user_id(
        IdentityStoreId=IdentityStoreId,
        AlternateIdentifier={
            'UniqueAttribute': {
                'AttributePath': "userName",
                'AttributeValue': user_name
            }
        }
    )
    return response_id.get('UserId')


def get_user_operations_list(args):
    primary = args.get('userEmailAddressPrimary')
    if primary and not args.get('userEmailAddress'):
        return_error('Error: When specifying userEmailAddressPrimary, userEmailAddress must also be provided.')
    if primary:
        primary = argToBoolean(primary)
    path_and_value = {
        'name.familyName': args.get('familyName'),
        'name.givenName': args.get('givenName'),
        'emails': [{
            'value': args.get('userEmailAddress'),
            'primary': primary
        }],
        'displayName': args.get('displayName'),
        'userType': args.get('userType'),
        'profileUrl': args.get('profileUrl'),
        'title': args.get('title'),
        'addresses': [{
            'region': args.get('region')
        }]
    }
    path_and_value = remove_empty_elements(path_and_value)
    to_update = []
    for var in path_and_value:
        to_update.append({
            'AttributePath': var,
            'AttributeValue': path_and_value[var]
        })

    return to_update


def update_user(args, client, IdentityStoreId):
    user_name = args.get('userName')
    user_id = get_userId_by_username(args, client, IdentityStoreId)
    operations = get_user_operations_list(args)
    kwargs = {
        "IdentityStoreId": IdentityStoreId,
        "UserId": user_id,
        "Operations": operations
    }
    client.update_user(**kwargs)
    hr_data = f'User {user_name} has been successfully updated'
    result = CommandResults(
        readable_output=hr_data
    )
    return_results(result)


def delete_user(args, client, IdentityStoreId):
    user_id = get_userId_by_username(args, client, IdentityStoreId)
    client.delete_user(
        IdentityStoreId=IdentityStoreId,
        UserId=user_id
    )
    demisto.debug(f'The User {user_id} has been removed.')
    hr_data = f'The User {user_id} has been removed.'
    result = CommandResults(
        readable_output=hr_data
    )
    return_results(result)


def get_user(args, client, IdentityStoreId):
    response_id = get_userId_by_username(args, client, IdentityStoreId)
    response = client.describe_user(
        IdentityStoreId=IdentityStoreId,
        UserId=response_id
    )
    response.pop('ResponseMetadata', None)
    hr_data = {
        'UserId': response.get('UserId'),
        'UserName': response.get('UserName'),
        'DisplayName': response.get('DisplayName'),
    }
    if response.get('Emails'):
        emails = []
        for email in response.get('Emails'):
            emails.append(email.get('Value'))
        hr_data['Emails'] = emails

    human_readable = tableToMarkdown('AWS IAM Identity Center Users', hr_data, removeNull=True)
    result = CommandResults(
        outputs_prefix=PREFIXUSER,
        readable_output=human_readable,
        outputs_key_field='UserId',
        outputs=response
    )
    return_results(result)


def get_user_by_email(args, client, IdentityStoreId):
    email_arg = args.get('emailAddress')
    response = client.list_users(
        IdentityStoreId=IdentityStoreId,
    )
    for user in response.get('Users'):
        user_emails = user.get('Emails')
        if user_emails:
            for email in user_emails:
                if email.get('Value') == email_arg:
                    emails = []
                    for appendEmail in user_emails:
                        emails.append(appendEmail.get('Value'))
                    user_details = {
                        'UserName': user.get('UserName'),
                        'UserId': user.get('UserId'),
                        'Emails': emails,
                        'DisplayName': user.get('DisplayName')
                    }
                    hr_data = user_details
                    context_data = user

    human_readable = tableToMarkdown('AWS IAM Identity Center Users ', hr_data, removeNull=True)
    result = CommandResults(
        outputs_prefix=PREFIXUSER,
        readable_output=human_readable,
        outputs_key_field='UserId',
        outputs=context_data
    )
    return_results(result)


def get_limit(args):
    limit_arg = args.get('limit')
    if limit_arg:
        limit = arg_to_number(args.get('limit'))
        if limit and limit < 50:
            return limit

    return 50


def list_users(args, client, IdentityStoreId):
    context_data = []
    hr_data = []
    kwargs = {
        'IdentityStoreId': IdentityStoreId,
        'MaxResults': get_limit(args),
        'NextToken': args.get('nextToken')
    }
    kwargs = remove_empty_elements(kwargs)
    response = client.list_users(**kwargs)
    for user in response.get('Users', []):
        context_data.append(user)
        user_details = {
            'UserId': user.get('UserId'),
            'UserName': user.get('UserName'),
            'DisplayName': user.get('DisplayName'),
        }
        if user.get('Emails'):
            emails = []
            for email in user.get('Emails'):
                emails.append(email.get('Value'))
            user_details['Emails'] = emails
        hr_data.append(user_details)
    outputs = {f'{PREFIXUSER}(val.UserId === obj.UserId)': context_data,
               f'{PREFIX}(true)': {'UserNextToken': response.get('NextToken')}}
    human_readable = tableToMarkdown('AWS IAM Identity Center Users', hr_data, removeNull=True)
    result = CommandResults(
        readable_output=human_readable,
        outputs_key_field='UserId',
        outputs=outputs
    )
    return_results(result)


def list_groups(args, client, IdentityStoreId):
    context_data = []
    hr_data = []
    kwargs = {
        'IdentityStoreId': IdentityStoreId,
        'MaxResults': get_limit(args),
        'NextToken': args.get('nextToken')
    }
    kwargs = remove_empty_elements(kwargs)
    response = client.list_groups(**kwargs)
    for group in response.get('Groups', []):
        group_details = {
            'DisplayName': group.get('DisplayName'),
            'GroupId': group.get('GroupId'),
            'Description': group.get('Description')
        }
        hr_data.append(group_details)
        context_data.append(group)

    outputs = {f'{PREFIXGROUP}(val.GroupId === obj.GroupId)': context_data,
               f'{PREFIX}(true)': {'GroupNextToken': response.get('NextToken')}}
    human_readable = tableToMarkdown('AWS IAM Identity Center Groups', hr_data, removeNull=True)
    result = CommandResults(
        readable_output=human_readable,
        outputs_key_field='GroupId',
        outputs=outputs
    )
    return_results(result)


def create_group(args, client, IdentityStoreId):
    display_name = args.get('displayName')
    kwargs = {
        'IdentityStoreId': IdentityStoreId,
        'DisplayName': display_name,
        'Description': args.get('description')
    }
    kwargs = remove_empty_elements(kwargs)
    response = client.create_group(**kwargs)
    group_id = response.get('GroupId')
    response.pop('ResponseMetadata', None)
    human_readable = tableToMarkdown(f'Group {display_name} has been successfully created with id {group_id}', response)
    result = CommandResults(
        outputs_prefix=PREFIXGROUP,
        readable_output=human_readable,
        outputs=response
    )
    return_results(result)


def delete_group(args, client, IdentityStoreId):
    group_id = get_groupId_by_displayName(args, client, IdentityStoreId)
    client.delete_group(
        IdentityStoreId=IdentityStoreId,
        GroupId=group_id
    )
    demisto.debug(f'The Group {group_id} has been removed.')
    hr_data = f'The Group {group_id} has been removed.'
    result = CommandResults(
        readable_output=hr_data
    )
    return_results(result)


def get_groupId_by_displayName(args, client, IdentityStoreId):
    group_name = args.get('displayName') or args.get('groupName')
    response_id = client.get_group_id(
        IdentityStoreId=IdentityStoreId,
        AlternateIdentifier={
            'UniqueAttribute': {
                'AttributePath': "displayName",
                'AttributeValue': group_name
            }
        }
    )
    return response_id.get('GroupId')


def update_group(args, client, IdentityStoreId):
    display_name = args.get('displayName')
    group_id = get_groupId_by_displayName(args, client, IdentityStoreId)
    kwargs = {
        "IdentityStoreId": IdentityStoreId,
        "GroupId": group_id,
        "Operations": [{
            'AttributePath': "description",
            'AttributeValue': args.get('description')
        }]
    }
    client.update_group(**kwargs)
    hr_data = f'Group {display_name} has been successfully updated'
    result = CommandResults(
        readable_output=hr_data
    )
    return_results(result)


def get_group(args, client, IdentityStoreId):
    response_id = get_groupId_by_displayName(args, client, IdentityStoreId)
    response = client.describe_group(
        IdentityStoreId=IdentityStoreId,
        GroupId=response_id
    )
    hr_data = {
        'DisplayName': response.get('DisplayName'),
        'GroupId': response.get('GroupId')
    }
    response.pop('ResponseMetadata', None)
    human_readable = tableToMarkdown('AWS IAM Identity Center Groups', hr_data, removeNull=True)
    result = CommandResults(
        outputs_prefix=PREFIXGROUP,
        readable_output=human_readable,
        outputs_key_field='GroupId',
        outputs=response
    )
    return_results(result)


def list_groups_for_user(args, client, IdentityStoreId):
    hr_data = []
    context_data = {}
    user_id = get_userId_by_username(args, client, IdentityStoreId)
    kwargs = {
        'IdentityStoreId': IdentityStoreId,
        'MemberId': {
            'UserId': user_id
        },
        'MaxResults': get_limit(args),
        'NextToken': args.get('nextToken')
    }
    kwargs = remove_empty_elements(kwargs)
    response = client.list_group_memberships_for_member(**kwargs)
    groups = []
    for group in response.get('GroupMemberships', []):
        hr_data.append({
            'UserID': user_id,
            'GroupID': group.get('GroupId'),
            'MembershipID': group.get('MembershipId')
        })
        groups.append({
            'GroupId': group.get('GroupId'),
            'MembershipId': group.get('MembershipId')
        })

    context_data['UserId'] = user_id
    context_data['GroupsUserNextToken'] = response.get('NextToken')
    last_context = demisto.context()
    last_users = last_context.get('AWS', {}).get('IAMIdentityCenter', {}).get('User', {})
    last_group_memberships = None
    if isinstance(last_users, list):
        for user_data in last_users:
            if user_data.get('UserId') == user_id:
                last_group_memberships = user_data.get('GroupMemberships')
                break
    else:
        if last_users.get('UserId') == user_id:
            last_group_memberships = last_users.get('GroupMemberships')

    if last_group_memberships:
        combined_groups = last_group_memberships + [g for g in groups if g not in last_group_memberships]
        context_data['GroupMemberships'] = combined_groups
    else:
        context_data['GroupMemberships'] = groups

    human_readable = tableToMarkdown('AWS IAM Identity Center Groups', hr_data, removeNull=True)
    result = CommandResults(
        outputs_prefix=PREFIXUSER,
        readable_output=human_readable,
        outputs_key_field='UserId',
        outputs=context_data
    )
    return_results(result)


def add_user_to_group(args, client, IdentityStoreId):
    user_id = get_userId_by_username(args, client, IdentityStoreId)
    Group_id = get_groupId_by_displayName(args, client, IdentityStoreId)
    response = client.create_group_membership(
        IdentityStoreId=IdentityStoreId,
        GroupId=Group_id,
        MemberId={
            'UserId': user_id
        }
    )
    membership_id = response.get('MembershipId')
    hr_data = f'The membership id {membership_id} has been successfully created.'
    result = CommandResults(
        readable_output=hr_data
    )
    return_results(result)


def get_group_memberships_for_member(args, client, IdentityStoreId):
    memberships_of_member = []
    user_id = get_userId_by_username(args, client, IdentityStoreId)
    kwargs = {
        'IdentityStoreId': IdentityStoreId,
        'MemberId': {
            'UserId': user_id
        }
    }
    kwargs = remove_empty_elements(kwargs)
    groups_response = client.list_group_memberships_for_member(**kwargs)
    for group in groups_response.get('GroupMemberships', []):
        memberships_of_member.append(group.get('MembershipId'))

    return memberships_of_member


def delete_group_membership(args, client, IdentityStoreId):
    memberships_to_delete = []
    if args.get('membershipId') and args.get('userName'):
        return_error("Please provide one of userName or membershipId.")
    elif args.get('membershipId'):
        memberships_to_delete = argToList(args.get('membershipId'))
    elif args.get('userName'):
        memberships_to_delete = get_group_memberships_for_member(args, client, IdentityStoreId)
        if memberships_to_delete == []:
            return_error('User is not member of any group.')
    else:
        return_error("userName or membershipId must be provided.")
    for member in memberships_to_delete:
        client.delete_group_membership(
            IdentityStoreId=IdentityStoreId,
            MembershipId=member
        )

    demisto.debug(f'The membership with ids {memberships_to_delete} have been deleted.')
    hr_data = f'The membership with ids {memberships_to_delete} have been deleted.'
    result = CommandResults(
        readable_output=hr_data
    )
    return_results(result)


def list_group_memberships(args, client, IdentityStoreId):
    hr_data = []
    context_data = {}
    group_id = get_groupId_by_displayName(args, client, IdentityStoreId)
    kwargs = {
        'IdentityStoreId': IdentityStoreId,
        'GroupId': group_id,
        'MaxResults': get_limit(args),
        'NextToken': args.get('nextToken')
    }
    kwargs = remove_empty_elements(kwargs)
    response = client.list_group_memberships(**kwargs)
    memberships = []
    for membership in response.get('GroupMemberships', []):
        member_details = {
            'MembershipId': membership.get('MembershipId'),
            'GroupId': group_id,
            'UserId': membership.get('MemberId', {}).get('UserId')
        }
        hr_data.append(member_details)
        memberships.append({
            'MembershipId': membership.get('MembershipId'),
            'UserId': membership.get('MemberId', {}).get('UserId')
        })

    context_data['GroupId'] = group_id
    context_data['GroupMembershipNextToken'] = response.get('NextToken')

    last_context = demisto.context()
    last_groups = last_context.get('AWS', {}).get('IAMIdentityCenter', {}).get('Group', {})
    last_group_memberships = None
    if isinstance(last_groups, list):
        for user_data in last_groups:
            if user_data.get('GroupId') == group_id:
                last_group_memberships = user_data.get('GroupMemberships')
                break
    else:
        if last_groups.get('GroupId') == group_id:
            last_group_memberships = last_groups.get('GroupMemberships')

    if last_group_memberships:
        combined_memberships = last_group_memberships + [g for g in memberships if g not in last_group_memberships]
        context_data['GroupMemberships'] = combined_memberships
    else:
        context_data['GroupMemberships'] = memberships

    human_readable = tableToMarkdown('AWS IAM Identity Center Groups', hr_data, removeNull=True)
    result = CommandResults(
        outputs_prefix=PREFIXGROUP,
        readable_output=human_readable,
        outputs_key_field='GroupId',
        outputs=context_data
    )
    return_results(result)


def test_module(args, client, IdentityStoreId):    # pragma: no cover
    if not IdentityStoreId:
        return_error("Identity Store ID was not specified - Test failure. The `Identity Store ID` parameter can be left empty and\
                     included as an argument in every command.")

    client.list_users(
        IdentityStoreId=IdentityStoreId,
    )
    demisto.results('ok')


def main():     # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    IdentityStoreId = args.get('IdentityStoreId') or params.get('IdentityStoreId')
    aws_default_region = params.get('defaultRegion')
    aws_role_arn = params.get('roleArn')
    aws_role_session_name = params.get('roleSessionName')
    aws_role_session_duration = params.get('sessionDuration')
    aws_access_key_id = params.get('credentials', {}).get('identifier') or params.get('access_key')
    aws_secret_access_key = params.get('credentials', {}).get('password') or params.get('secret_key')
    verify_certificate = not params.get('insecure', True)
    timeout = params.get('timeout')
    retries = params.get('retries') or 5
    command = demisto.command()

    try:
        validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id,
                        aws_secret_access_key)

        aws_client = AWSClient(aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                               None, aws_access_key_id, aws_secret_access_key, verify_certificate, timeout,
                               retries)

        client = aws_client.aws_session(
            service=SERVICE,
            region=args.get('region'),
            role_arn=args.get('roleArn'),
            role_session_name=args.get('roleSessionName'),
            role_session_duration=args.get('roleSessionDuration'),
        )

        demisto.debug(f'Command being called is {command}')
        if command == 'test-module':
            test_module(args, client, IdentityStoreId)
        elif command == 'aws-iam-identitycenter-create-user':
            create_user(args, client, IdentityStoreId)
        elif command == 'aws-iam-identitycenter-get-user':
            get_user(args, client, IdentityStoreId)
        elif command == 'aws-iam-identitycenter-get-user-by-email':
            get_user_by_email(args, client, IdentityStoreId)
        elif command == 'aws-iam-identitycenter-list-users':
            list_users(args, client, IdentityStoreId)
        elif command == 'aws-iam-identitycenter-list-groups':
            list_groups(args, client, IdentityStoreId)
        elif command == 'aws-iam-identitycenter-get-group':
            get_group(args, client, IdentityStoreId)
        elif command == 'aws-iam-identitycenter-list-groups-for-user':
            list_groups_for_user(args, client, IdentityStoreId)
        elif command == 'aws-iam-identitycenter-add-user-to-group':
            add_user_to_group(args, client, IdentityStoreId)
        elif command == 'aws-iam-identitycenter-delete-user':
            delete_user(args, client, IdentityStoreId)
        elif command == 'aws-iam-identitycenter-create-group':
            create_group(args, client, IdentityStoreId)
        elif command == 'aws-iam-identitycenter-delete-group':
            delete_group(args, client, IdentityStoreId)
        elif command == 'aws-iam-identitycenter-delete-group-membership':
            delete_group_membership(args, client, IdentityStoreId)
        elif command == 'aws-iam-identitycenter-list-memberships':
            list_group_memberships(args, client, IdentityStoreId)
        elif command == 'aws-iam-identitycenter-update-user':
            update_user(args, client, IdentityStoreId)
        elif command == 'aws-iam-identitycenter-update-group':
            update_group(args, client, IdentityStoreId)
        else:
            raise NotImplementedError(f'Command {command} is not implemented in AWS - IAM Identity Center integration.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.info(str(e))
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
