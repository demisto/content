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
                'Type':'work',
                'Primary': True
            },
        ],
        DisplayName=f'{userDisplayName}'
    )
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
                'UserId': user['UserId'],
                'Email': user['Emails'][0]['Value'],
                'DisplayName': user['DisplayName']
            }
            userID = user['UserId']
            data.append(user_details)
    ec = {'AWS.IAM.IdentityCenter.Users': data}
    human_readable = tableToMarkdown('AWS IAM Users', data, removeNull=True)
    return_outputs(human_readable, ec)
    return userID

def get_user_by_email(args, client):  # pragma: no cover
    data = []
    emailArg = demisto.getArg('emailAddress')
    response = client.list_users(
        IdentityStoreId=f'{IDENTITYSTOREID}',
    )
    rep = json.dumps(response)
    repJSON = json.loads(rep)
    datas = repJSON.get('Users', [])
    for da in datas:
        for user in response['Users']:
            userEmail = user['Emails'][0]['Value']
            if userEmail == emailArg:
                user_details = {
                    'UserName': user['UserName'],
                    'UserId': user['UserId'],
                    'Email': user['Emails'][0]['Value'],
                    'DisplayName': user['DisplayName']
                }
                userID = user['UserId']
                data.append(user_details)
    ec = {'AWS.IAM.IdentityCenter.Users': data}
    human_readable = tableToMarkdown('AWS IAM Users ', data, removeNull=True)
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

#def update_user(args, client):  # pragma: no cover
#    kwargs = {'UserName': args.get('oldUserName')}
#    if args.get('newUserName'):
#        kwargs.update({'NewUserName': args.get('newUserName')})
#    if args.get('newPath'):
#        kwargs.update({'NewPath': args.get('newPath')})
#
#    response = client.update_user(**kwargs)
#    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
#        demisto.results(
#            "Changed UserName {0} To: {1}".format(args.get('oldUserName'), args.get('newUserName')))


#def delete_user(args, client):  # pragma: no cover
#    response = client.delete_user(UserName=args.get('userName'))
#    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
#        demisto.results('The User {0} has been deleted'.format(args.get('userName')))


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
        elif command == 'aws-iam-identitycenter-get-user-by-email':
            get_user_by_email(args, client)
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
        return_error('Error has occurred in the AWS IAM Integration: {code}\n {message}'.format(
            code=type(e), message=str(e)))



### GENERATED CODE ###: from AWSApiModule import *  # noqa: E402
# This code was inserted in place of an API module.
register_module_line('AWSApiModule', 'start', __line__(), wrapper=-3)


import boto3
from botocore.config import Config


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


def extract_session_from_secret(secret_key, session_token):
    """
    Extract the session token from the secret_key field.
    """
    if secret_key and '@@@' in secret_key and not session_token:
        return secret_key.split('@@@')[0], secret_key.split('@@@')[1]
    else:
        return secret_key, session_token


class AWSClient:

    def __init__(self, aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                 aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate, timeout, retries,
                 aws_session_token=None, sts_endpoint_url=None, endpoint_url=None):

        self.sts_endpoint_url = sts_endpoint_url
        self.endpoint_url = endpoint_url
        self.aws_default_region = aws_default_region
        self.aws_role_arn = aws_role_arn
        self.aws_role_session_name = aws_role_session_name
        # handle cases where aws_role_session_duration can be also empty string
        self.aws_role_session_duration = aws_role_session_duration if aws_role_session_duration else None
        self.aws_role_policy = aws_role_policy
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key, self.aws_session_token = extract_session_from_secret(aws_secret_access_key, aws_session_token)
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

        demisto.debug('{kwargs}='.format(kwargs=kwargs))

        if kwargs and not self.aws_access_key_id:  # login with Role ARN
            if not self.aws_access_key_id:
                sts_client = boto3.client('sts', config=self.config, verify=self.verify_certificate,
                                          region_name=region if region else self.aws_default_region,
                                          endpoint_url=self.sts_endpoint_url)
                sts_response = sts_client.assume_role(**kwargs)
                client = boto3.client(
                    service_name=service,
                    region_name=region if region else self.aws_default_region,
                    aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                    aws_session_token=sts_response['Credentials']['SessionToken'],
                    verify=self.verify_certificate,
                    config=self.config,
                    endpoint_url=self.endpoint_url
                )
        elif self.aws_access_key_id and (role_arn or self.aws_role_arn):  # login with Access Key ID and Role ARN
            sts_client = boto3.client(
                service_name='sts',
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                verify=self.verify_certificate,
                config=self.config,
                endpoint_url=self.sts_endpoint_url
            )
            kwargs.update({
                'RoleArn': role_arn or self.aws_role_arn,
                'RoleSessionName': role_session_name or self.aws_role_session_name,
            })
            sts_response = sts_client.assume_role(**kwargs)
            client = boto3.client(
                service_name=service,
                region_name=region if region else self.aws_default_region,
                aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                aws_session_token=sts_response['Credentials']['SessionToken'],
                verify=self.verify_certificate,
                config=self.config,
                endpoint_url=self.endpoint_url
            )
        elif self.aws_session_token and not self.aws_role_arn:  # login with session token
            client = boto3.client(
                service_name=service,
                region_name=region if region else self.aws_default_region,
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                aws_session_token=self.aws_session_token,
                verify=self.verify_certificate,
                config=self.config,
                endpoint_url=self.endpoint_url
            )
        elif self.aws_access_key_id and not self.aws_role_arn:  # login with access key id
            client = boto3.client(
                service_name=service,
                region_name=region if region else self.aws_default_region,
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                verify=self.verify_certificate,
                config=self.config,
                endpoint_url=self.endpoint_url
            )
        else:  # login with default permissions, permissions pulled from the ec2 metadata
            client = boto3.client(service_name=service,
                                  region_name=region if region else self.aws_default_region,
                                  endpoint_url=self.endpoint_url)

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
