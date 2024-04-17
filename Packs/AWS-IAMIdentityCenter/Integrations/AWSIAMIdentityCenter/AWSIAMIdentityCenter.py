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
    username = args.get('userName')
    familyName = args.get('familyName')
    givenName = args.get('givenName')
    userEmail = args.get('userEmailAddress')
    userDisplayName = args.get('displayName')
    userType = args.get('userType')
    profileUrl = args.get('profileUrl')
    title = args.get('title')
    region = args.get('region')
    primaryEmail = args.get('userEmailAddressPrimary')
    if primaryEmail and not userEmail:
        return_error('Error: When specifying userEmailAddressPrimary, userEmailAddress must also be provided.')
    if primaryEmail:
        primaryEmail = argToBoolean(primaryEmail)

    kwargs = {
        'IdentityStoreId': IdentityStoreId,
        'UserName': username,
        'Name': {
            'FamilyName': familyName,
            'GivenName': givenName
        },
        'Emails': [
            {
                'Value': userEmail,
                'Primary': primaryEmail
            }
        ],
        'DisplayName': userDisplayName,
        'UserType': userType,
        'ProfileUrl': profileUrl,
        'Title': title,
        'Addresses': [
            {
                'Region': region,
            }
        ]
    }
    kwargs = remove_empty_elements(kwargs)
    response = client.create_user(**kwargs)
    userId = response.get('UserId')
    response.pop('ResponseMetadata', None)
    response = remove_empty_elements(response)
    human_readable = tableToMarkdown(f'User {username} has been successfully created with user id {userId}', response)
    result = CommandResults(
        outputs_prefix=PREFIXUSER,
        readable_output=human_readable,
        outputs=response
    )
    return_results(result)


def get_userId_by_username(args, client, IdentityStoreId):
    userName = args.get('userName')
    response_id = client.get_user_id(
        IdentityStoreId=IdentityStoreId,
        AlternateIdentifier={
            'UniqueAttribute': {
                'AttributePath': "userName",
                'AttributeValue': userName
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
    userName = args.get('userName')
    user_id = get_userId_by_username(args, client, IdentityStoreId)
    operations = get_user_operations_list(args)
    kwargs = {
        "IdentityStoreId": IdentityStoreId,
        "UserId": user_id,
        "Operations": operations
    }
    client.update_user(**kwargs)
    hr_data = f'User {userName} has been successfully updated'
    result = CommandResults(
        readable_output=hr_data
    )
    return_results(result)


def delete_user(args, client, IdentityStoreId):
    userId = get_userId_by_username(args, client, IdentityStoreId)
    response = client.delete_user(
        IdentityStoreId=IdentityStoreId,
        UserId=userId
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.debug(f'The User {userId} has been removed.')
        hr_data = f'The User {userId} has been removed.'
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
    emailArg = args.get('emailAddress')
    response = client.list_users(
        IdentityStoreId=IdentityStoreId,
    )
    for user in response.get('Users'):
        userEmails = user.get('Emails')
        if userEmails:
            for email in userEmails:
                if email.get('Value') == emailArg:
                    emails = []
                    for appendEmail in userEmails:
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
    limitArg = args.get('limit')
    if limitArg:
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
    displayName = args.get('displayName')
    kwargs = {
        'IdentityStoreId': IdentityStoreId,
        'DisplayName': displayName,
        'Description': args.get('description')
    }
    kwargs = remove_empty_elements(kwargs)
    response = client.create_group(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        group_id = response.get('GroupId')
        response.pop('ResponseMetadata', None)
        human_readable = tableToMarkdown(f'Group {displayName} has been successfully created with id {group_id}', response)
        result = CommandResults(
            outputs_prefix=PREFIXGROUP,
            readable_output=human_readable,
            outputs=response
        )
        return_results(result)


def delete_group(args, client, IdentityStoreId):
    groupId = get_groupId_by_displayName(args, client, IdentityStoreId)
    response = client.delete_group(
        IdentityStoreId=IdentityStoreId,
        GroupId=groupId
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.debug(f'The Group {groupId} has been removed.')
        hr_data = f'The Group {groupId} has been removed.'
        result = CommandResults(
            readable_output=hr_data
        )
        return_results(result)


def get_groupId_by_displayName(args, client, IdentityStoreId):
    groupName = args.get('displayName') or args.get('groupName')
    response_id = client.get_group_id(
        IdentityStoreId=IdentityStoreId,
        AlternateIdentifier={
            'UniqueAttribute': {
                'AttributePath': "displayName",
                'AttributeValue': groupName
            }
        }
    )
    return response_id.get('GroupId')


def update_group(args, client, IdentityStoreId):
    displayName = args.get('displayName')
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
    hr_data = f'Group {displayName} has been successfully updated'
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
    userID = get_userId_by_username(args, client, IdentityStoreId)
    kwargs = {
        'IdentityStoreId': IdentityStoreId,
        'MemberId': {
            'UserId': userID
        },
        'MaxResults': get_limit(args),
        'NextToken': args.get('nextToken')
    }
    kwargs = remove_empty_elements(kwargs)
    response = client.list_group_memberships_for_member(**kwargs)
    groups = []
    for group in response.get('GroupMemberships', []):
        hr_data.append({
            'UserID': userID,
            'GroupID': group.get('GroupId'),
            'MembershipID': group.get('MembershipId')
        })
        groups.append({
            'GroupId': group.get('GroupId'),
            'MembershipId': group.get('MembershipId')
        })

    context_data['UserId'] = userID
    context_data['GroupMemberships'] = groups
    context_data['GroupsUserNextToken'] = response.get('NextToken')
    human_readable = tableToMarkdown('AWS IAM Identity Center Groups', hr_data, removeNull=True)
    result = CommandResults(
        outputs_prefix=PREFIXUSER,
        readable_output=human_readable,
        outputs_key_field='UserId',
        outputs=context_data
    )
    return_results(result)


def add_user_to_group(args, client, IdentityStoreId):
    userID = get_userId_by_username(args, client, IdentityStoreId)
    GroupID = get_groupId_by_displayName(args, client, IdentityStoreId)
    response = client.create_group_membership(
        IdentityStoreId=IdentityStoreId,
        GroupId=GroupID,
        MemberId={
            'UserId': userID
        }
    )
    membershipId = response.get('MembershipId')
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        hr_data = f'The membership id {membershipId} has been successfully created.'
        result = CommandResults(
            readable_output=hr_data
        )
        return_results(result)


def get_group_memberships_for_member(args, client, IdentityStoreId):
    membershipsOfMember = []
    userID = get_userId_by_username(args, client, IdentityStoreId)
    kwargs = {
        'IdentityStoreId': IdentityStoreId,
        'MemberId': {
            'UserId': userID
        }
    }
    kwargs = remove_empty_elements(kwargs)
    groups_response = client.list_group_memberships_for_member(**kwargs)
    for group in groups_response.get('GroupMemberships', []):
        membershipsOfMember.append(group.get('MembershipId'))

    return membershipsOfMember


def delete_group_membership(args, client, IdentityStoreId):
    membershipsToDelete = []
    if args.get('membershipId') and args.get('userName'):
        return_error("Please provide one of userName or membershipId.")
    elif args.get('membershipId'):
        membershipsToDelete = argToList(args.get('membershipId'))
    elif args.get('userName'):
        membershipsToDelete = get_group_memberships_for_member(args, client, IdentityStoreId)
        if membershipsToDelete == []:
            return_error('User is not member of any group.')
    else:
        return_error("userName or membershipId must be provided.")
    if membershipsToDelete != []:
        for member in membershipsToDelete:
            response = client.delete_group_membership(
                IdentityStoreId=IdentityStoreId,
                MembershipId=member
            )

        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            demisto.debug(f'The membership with ids {membershipsToDelete} have been deleted.')
            hr_data = f'The membership with ids {membershipsToDelete} have been deleted.'
            result = CommandResults(
                readable_output=hr_data
            )
            return_results(result)


def list_group_memberships(args, client, IdentityStoreId):
    hr_data = []
    context_data = {}
    groupId = get_groupId_by_displayName(args, client, IdentityStoreId)
    kwargs = {
        'IdentityStoreId': IdentityStoreId,
        'GroupId': groupId,
        'MaxResults': get_limit(args),
        'NextToken': args.get('nextToken')
    }
    kwargs = remove_empty_elements(kwargs)
    response = client.list_group_memberships(**kwargs)
    memberships = []
    for membership in response.get('GroupMemberships', []):
        member_details = {
            'MembershipId': membership.get('MembershipId'),
            'GroupId': groupId,
            'UserId': membership.get('MemberId', {}).get('UserId')
        }
        hr_data.append(member_details)
        memberships.append({
            'MembershipId': membership.get('MembershipId'),
            'UserId': membership.get('MemberId', {}).get('UserId')
        })

    context_data['GroupId'] = groupId
    context_data['GroupMemberships'] = memberships
    context_data['GroupMembershipNextToken'] = response.get('NextToken')
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
        return_error("Identity Store ID was not specified - Test failuer. The `Identity Store ID` parameter can be left empty and\
                     included as an argument in every command. For testing the integration instance without specifiend `Identity\
                     Store ID` as a parameter you can execute `list_users` command specifieng\
                     `Identity Store ID` argument in xsoar cli.")

    response = client.list_users(
        IdentityStoreId=IdentityStoreId,
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
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
        demisto.info(e)
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
