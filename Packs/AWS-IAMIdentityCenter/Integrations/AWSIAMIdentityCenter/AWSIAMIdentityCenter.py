import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from AWSApiModule import *


params = demisto.params()
args = demisto.args()

SERVICE = 'identitystore'
IDENTITYSTOREID = args.get('IdentityStoreId') or params.get('IdentityStoreId')


    
def create_user(args, client):  # pragma: no cover
    username = args.get('userName')
    familyName = args.get('familyName')
    givenName = args.get('givenName')
    userEmail = args.get('userEmailAddress')
    userDisplayName = args.get('displayName')
    userType=args.get('userType')
    profileUrl= args.get('profileUrl')
    title= args.get('title')
    region = args.get('region')
    
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
                'Type': 'work',
                'Primary': True
            }
        ],
        DisplayName=f'{userDisplayName}',
        UserType=f'{userType}',
        ProfileUrl= f'{profileUrl}',
        Title= f'{title}',
        Addresses=[
            {
                'Region': f'{region}',
            }
        ]
    )
    del response['ResponseMetadata']
    response = remove_empty_elements(response)
    ec = {'AWS.IAMIdentityCenter.Users': response}
    human_readable = tableToMarkdown('AWS IAM Identity Center Users', response)
    return_outputs(human_readable, ec)


def get_userId_by_username(args, client):
    userName = args.get('userName')
    response_id = client.get_user_id(
        IdentityStoreId=f'{IDENTITYSTOREID}',
        AlternateIdentifier={
            'UniqueAttribute': {
                'AttributePath': "userName",
                'AttributeValue': f'{userName}'
            }
        }
    )
    return response_id


def delete_user(args, client):
    userId = get_userId_by_username(args, client)['UserId']
    response = client.delete_user(
        IdentityStoreId=f'{IDENTITYSTOREID}',
        UserId=f'{userId}'
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results(f'The User {userId} has been removed')
    
    

def get_user(args, client):  # pragma: no cover
    response_id = get_userId_by_username(args, client)
    response = client.describe_user(
        IdentityStoreId=f'{IDENTITYSTOREID}',
        UserId=response_id.get('UserId')
    )
    del response['ResponseMetadata']
    hr_data = {
        'UserId': response.get('UserId'),
        'UserName': response.get('UserName'),
        'DisplayName': response.get('DisplayName'),
        'Emails': response.get('Emails')
    }
    ec = {'AWS.IAMIdentityCenter.Users(val.UserId === obj.UserId)': response}
    human_readable = tableToMarkdown('AWS IAM Users', hr_data, removeNull=True)
    result = CommandResults(
        readable_output=human_readable,
        outputs_key_field='UserId',
        outputs=ec
    )
    return_results(result)


def get_user_by_email(args, client):  # pragma: no cover
    emailArg = args.get('emailAddress')
    response = client.list_users(
        IdentityStoreId=f'{IDENTITYSTOREID}',
    )
    for user in response.get('Users'):
        userEmail = user.get('Emails')
        if len(userEmail) > 0 and userEmail[0]['Value'] == emailArg:
            user_details = {
                'UserName': user['UserName'],
                'UserId': user['UserId'],
                'Emails': user['Emails'][0]['Value'],
                'DisplayName': user['DisplayName']
            }
            hr_data = user_details
            context_data = user
    ec = {'AWS.IAMIdentityCenter.Users(val.UserId === obj.UserId)': context_data}
    human_readable = tableToMarkdown('AWS IAM Users ', hr_data, removeNull=True)
    result = CommandResults(
        readable_output=human_readable,
        outputs_key_field='UserId',
        outputs=ec
    )
    return_results(result)


def list_users(args, client):  # pragma: no cover
    context_data = []
    hr_data = []
    kwargs = {
        'IdentityStoreId': IDENTITYSTOREID,
        'MaxResults': arg_to_number(args.get('limit') or params.get('limit')),
        'NextToken': args.get('nextToken')
    }
    kwargs = remove_empty_elements(kwargs)
    response = client.list_users(**kwargs)
    for user in response.get('Users'):
        context_data.append(user)
        user_details = {
            'UserId': user['UserId'],
            'UserName': user['UserName'],
            'DisplayName': user['DisplayName'],
            'Emails': user['Emails']
        }
        hr_data.append(user_details)
    outputs = {'AWS.IAMIdentityCenter.Users(val.UserId === obj.UserId)': context_data,
          'AWS.IAMIdentityCenter(true)': {'UserNextToken': response.get('NextToken')}}
    human_readable = tableToMarkdown('AWS IAM Identity Center Users', hr_data, removeNull=True)
    result = CommandResults(
        readable_output=human_readable,
        outputs_key_field='UserId',
        outputs=outputs
    )
    return_results(result)
  

def list_groups(args, client):  # pragma: no cover
    context_data = []
    hr_data = []
    kwargs = {
        'IdentityStoreId': IDENTITYSTOREID,
        'MaxResults': arg_to_number(args.get('limit') or params.get('limit')),
        'NextToken': args.get('nextToken')
    }
    kwargs = remove_empty_elements(kwargs)
    response = client.list_groups(**kwargs)
    for group in response.get('Groups'):
        group_details = {
            'DisplayName': group.get('DisplayName'),
            'GroupId': group['GroupId'],
            'Description': group.get('Description')
        }
        hr_data.append(group_details)
        context_data.append(group)
    outputs = {'AWS.IAMIdentityCenter.Groups(val.GroupId === obj.GroupId)': context_data,
               'AWS.IAMIdentityCenter(true)': {'GroupNextToken': response.get('NextToken')}}
    human_readable = tableToMarkdown('AWS IAM Identity Center Groups', hr_data, removeNull=True)
    result = CommandResults(
        readable_output=human_readable,
        outputs_key_field='GroupId',
        outputs=outputs
    )
    return_results(result)


def get_groupId_by_displayName(args, client):
    groupName = args.get('displayName') or args.get('groupName')
    response_id = client.get_group_id(
        IdentityStoreId=f'{IDENTITYSTOREID}',
        AlternateIdentifier={
            'UniqueAttribute': {
                'AttributePath': "displayName",
                'AttributeValue': f'{groupName}'
            }
        }
    )
    return response_id
    

def get_group(args, client):  # pragma: no cover
    response_id = get_groupId_by_displayName(args, client)
    response = client.describe_group(
        IdentityStoreId=f'{IDENTITYSTOREID}',
        GroupId=response_id.get('GroupId')
    )
    hr_data = {
        'DisplayName': response.get('DisplayName'),
        'GroupId': response['GroupId']
    }
    del response['ResponseMetadata']
    ec = {'AWS.IAMIdentityCenter.Groups(val.GroupId == obj.GroupId)': response}
    human_readable = tableToMarkdown('AWS IAM Identity Center Groups', hr_data, removeNull=True)
    result = CommandResults(
        readable_output=human_readable,
        outputs_key_field='GroupId',
        outputs=ec
    )
    return_results(result)



def list_groups_for_user(args, client):  # pragma: no cover
    context_data = []
    hr_data = []
    userID = get_userId_by_username(args, client)['UserId']
    kwargs = {
        'IdentityStoreId':f'{IDENTITYSTOREID}',
        'MemberId':{
            'UserId': f'{userID}'
        },
        'MaxResults': arg_to_number(args.get('limit') or params.get('limit')),
        'NextToken': args.get('nextToken')
    }
    kwargs = remove_empty_elements(kwargs)
    response = client.list_group_memberships_for_member(**kwargs)
    for group in response.get('GroupMemberships'):
        group_details = {
            'UserID': group['MemberId']['UserId'],
            'GroupID': group['GroupId'],
            'MembershipID': group['MembershipId']
        }
        context_data.append(group)
        hr_data.append(group_details)
        
    outputs = {'AWS.IAMIdentityCenter.User(val.UserName === obj.UserName).Groups': context_data,
               'AWS.IAMIdentityCenter(true)': {'GroupsUserNextToken': response.get('NextToken')}}
    human_readable = tableToMarkdown('AWS IAM Identity Center Groups', hr_data, removeNull=True)
    result = CommandResults(
        readable_output=human_readable,
        outputs_key_field='UserId',
        outputs=outputs
    )
    return_results(result)


def add_user_to_group(args, client):  # pragma: no cover
    userID = get_userId_by_username(args, client)['UserId']
    GroupID = get_groupId_by_displayName(args, client)['GroupId']
    response = client.create_group_membership(
        IdentityStoreId=f'{IDENTITYSTOREID}',
        GroupId=f'{GroupID}',
        MemberId={
            'UserId': f'{userID}'
        }
    )
    membershipId = response.get('MembershipId')
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results(f'The membership id {membershipId} has been successfully created.')


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


def test_function(args, client):
    if not IDENTITYSTOREID:
        return_error("The parameter Identity Store ID can be empty and added as an argument to each command, but Test button will fail.")
    response = client.list_users(
        IdentityStoreId=f'{IDENTITYSTOREID}',
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results('ok')


def main():     # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    aws_default_region = params.get('defaultRegion')
    aws_role_arn = params.get('roleArn')
    aws_role_session_name = params.get('roleSessionName')
    aws_role_session_duration = params.get('sessionDuration') ##### check if changing because IAM does work this way!
    # aws_default_region = args.get('region') or params.get('defaultRegion')
    # aws_role_arn = args.get('roleArn') or params.get('roleArn')
    # aws_role_session_name = args.get('roleSessionName') or params.get('roleSessionName')
    # aws_role_session_duration = args.get('roleSessionDuration') or params.get('sessionDuration')
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
    
    
    client = aws_client.aws_session(
        service=SERVICE,
        #region=args.get('region'), ### should i add it? it appears in AWS-Athena
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )

    try:
        demisto.debug('Command being called is {command}'.format(command=command))
        if command == 'test-module':
            test_function(args, client)
        elif command == 'aws-iam-identitycenter-create-user':
            create_user(args, client)
        elif command == 'aws-iam-identitycenter-get-user':
            get_user(args, client)
        elif command == 'aws-iam-identitycenter-get-user-by-email':
            get_user_by_email(args, client)
        elif command == 'aws-iam-identitycenter-list-users':
            list_users(args, client)
        elif command == 'aws-iam-identitycenter-list-groups':
            list_groups(args, client)
        elif command == 'aws-iam-identitycenter-get-group':
            get_group(args, client)
        elif command == 'aws-iam-identitycenter-list-groups-for-user':
            list_groups_for_user(args, client)
        elif command == 'aws-iam-identitycenter-add-user-to-group':
            add_user_to_group(args, client)
        elif command == 'aws-iam-identitycenter-remove-user-from-all-groups':
            remove_user_from_groups(args, client)
        elif command == 'aws-iam-identitycenter-delete-user':
            delete_user(args, client)

    except Exception as e:
        return_error('Error has occurred in the AWS IAM Integration: {code}\n {message}'.format(
            code=type(e), message=str(e)))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
