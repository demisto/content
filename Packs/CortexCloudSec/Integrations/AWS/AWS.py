import demistomock as demisto
from AWSApiModule import *  # noqa: E402
from CommonServerPython import *
from http import HTTPStatus
from datetime import date

def test_module(aws_client: AWSClient) -> str:
    aws_client.aws_session(service=SERVICE)
    return "ok"

# =================== #
# Helpers
# =================== #
class DatetimeEncoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)

def get_client(params, command_args):
    aws_role_name = params.get('role_name')
    account_id = command_args.get('account_id')
    aws_role_arn = f'arn:aws:iam::{account_id}:role/{aws_role_name}'
    
    aws_role_session_name = params.get('role_session_name')
    aws_role_session_duration = params.get('session_duration')
    verify_certificate = not argToBoolean(params.get('insecure') or True)
    timeout = params.get('timeout')
    retries = params.get('retries') or 5
    sts_endpoint_url = params.get('sts_endpoint_url')
    endpoint_url = params.get('endpoint_url')
    
    aws_default_region = aws_role_policy = aws_access_key_id = aws_secret_access_key = aws_session_token = None
  
    return AWSClient(
            aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
            aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate, timeout,
            retries, aws_session_token, sts_endpoint_url, endpoint_url
        )

# =================== #
# S3 commands
# =================== #

def put_public_access_block(aws_client: AWSClient, args: Dict[str, Any]) -> CommandResults:
    client_session = aws_client.aws_session(service='s3', region=args.get('region'))
    try:
        response = client_session.get_public_access_block(Bucket=args.get('bucket'))
        public_access_block_configuration = response.get('PublicAccessBlockConfiguration')
        kwargs = {
            'BlockPublicAcls': public_access_block_configuration.get('BlockPublicAcls'),
            'IgnorePublicAcls': public_access_block_configuration.get('IgnorePublicAcls'),
            'BlockPublicPolicy': public_access_block_configuration.get('BlockPublicPolicy'),
            'RestrictPublicBuckets': public_access_block_configuration.get('RestrictPublicBuckets')
        }
    except client_session.exceptions.NoSuchEntityException:
        kwargs = {}
        
    if args.get('block_public_acls'):
        kwargs.update({ 'BlockPublicAcls': argToBoolean(args.get('block_public_acls')) })
    if args.get('ignore_public_acls'):
        kwargs.update({ 'IgnorePublicAcls': argToBoolean(args.get('ignore_public_acls')) })
    if args.get('block_public_policy'):
        kwargs.update({ 'BlockPublicPolicy': argToBoolean(args.get('block_public_policy')) })
    if args.get('restrict_public_buckets'):
        kwargs.update({ 'RestrictPublicBuckets': argToBoolean(args.get('restrict_public_buckets')) })


    response = client_session.put_public_access_block(Bucket=args.get('bucket'),
                                                      PublicAccessBlockConfiguration=kwargs)

    if response['ResponseMetadata']['HTTPStatusCode'] == HTTPStatus.OK:
        return CommandResults(
            readable_output=f"Successfully applied public access block to the {args.get('bucket')} bucket")
    return CommandResults(readable_output=f"Couldn't apply public access block to the {args.get('bucket')} bucket")

# =================== #
# IAM commands
# =================== #

def get_account_password_policy(aws_client: AWSClient, args: Dict[str, Any]) -> CommandResults:
    client_session = aws_client.aws_session(service='iam', region=args.get('region'))
    response = client_session.get_account_password_policy()
    data = json.loads(json.dumps(response['PasswordPolicy'], cls=DatetimeEncoder))
    data.update({'AccountId': args.get('account_id')})
    
    human_readable = tableToMarkdown('AWS IAM Account Password Policy', data)
    
    return CommandResults(outputs=data, readable_output=human_readable, outputs_prefix='AWS.IAM.PasswordPolicy',
                          outputs_key_field='AccountId')
    
def update_account_password_policy(aws_client: AWSClient, args: Dict[str, Any]) -> CommandResults:
    client_session = aws_client.aws_session(service='iam', region=args.get('region'))
    try:
        response = client_session.get_account_password_policy()
        kwargs = response['PasswordPolicy']
    except client_session.exceptions.NoSuchEntityException:
        kwargs = {}
    # ExpirePasswords is part of the response but cannot be included
    # in the request
    if 'ExpirePasswords' in kwargs:
        kwargs.pop('ExpirePasswords')
    if args.get('minimum_password_length'):
        kwargs.update({'MinimumPasswordLength': arg_to_number(args.get('minimum_password_length'))})
    if args.get('require_symbols'):
        kwargs.update({'RequireSymbols': args.get('require_symbols') == 'True'})
    if args.get('require_numbers'):
        kwargs.update({'RequireNumbers': args.get('require_numbers') == 'True'})
    if args.get('require_uppercase_characters'):
        kwargs.update(
            {'RequireUppercaseCharacters': args.get('require_uppercase_characters') == 'True'})
    if args.get('require_lowercase_characters'):
        kwargs.update(
            {'RequireLowercaseCharacters': args.get('require_lowercase_characters') == 'True'})
    if args.get('allow_users_to_change_password'):
        kwargs.update(
            {'AllowUsersToChangePassword': args.get('allow_users_to_change_password') == 'True'})
    if args.get('max_password_age'):
        kwargs.update({'MaxPasswordAge': int(args.get('max_password_age'))})
    if args.get('password_reuse_prevention'):
        kwargs.update({'PasswordReusePrevention': int(args.get('password_reuse_prevention'))})
    if args.get('hard_expiry'):
        kwargs.update({'HardExpiry': args.get('hard_expiry') == 'True'})
    response = client_session.update_account_password_policy(**kwargs)
    
    if response['ResponseMetadata']['HTTPStatusCode'] == HTTPStatus.OK:
        return CommandResults(readable_output=f"Successfully updated account password policy for account: {args.get('account_id')}")
    else:
        return CommandResults(readable_output=f"Couldn't updated account password policy for account: {args.get('account_id')}")
        
# =================== #
# EC2 commands
# =================== #
def aws_ec2_instance_metadata_options_modify(aws_client: AWSClient, args: Dict[str, Any]) -> CommandResults:
    client_session = aws_client.aws_session(service='ec2', region=args.get('region'))
    
    kwargs = {'InstanceId': args.get('instance_id')}
    
    if args.get('http_tokens'):
        kwargs.update({'HttpTokens': args.get('http_tokens')})
    if args.get('http_endpoint'):
        kwargs.update({'HttpEndpoint': args.get('http_endpoint')})

    response = client_session.modify_instance_metadata_options(**kwargs)
    
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The EC2 instance metadata was updated")
        
    if response['ResponseMetadata']['HTTPStatusCode'] == HTTPStatus.OK:
        return CommandResults(readable_output=f"Successfully updated EC2 instance metadata for {args.get('instance_id')}")
    else:
        return CommandResults(readable_output=f"Couldn't updated public EC2 instance metadata for {args.get('instance_id')}")
    

# =================== #
# MAIN
# =================== #
def main():

    params = demisto.params()
    demisto.debug(f"Params: {params}")

    command = demisto.command()
    command_args = demisto.args()
    demisto.debug(f"Command: {command}")
    demisto.debug(f"Args: {command_args}")
    
    aws_client = get_client(params, command_args)

    result = ''
    try:
        match command:
            case "aws-s3-public-access-block-update":
                result = put_public_access_block(aws_client, command_args)
            case 'aws-iam-account-password-policy-get':
                result = get_account_password_policy(aws_client, command_args)
            case 'aws-iam-account-password-policy-update':
                result = update_account_password_policy(aws_client, command_args)
            case 'aws-ec2-instance-metadata-options-modify':
                result = aws_ec2_instance_metadata_options_modify(aws_client, command_args)
                
            case 'test-module':
                result = test_module(aws_client)
            case _:
                raise NotImplementedError(f"Command {command} is not implemented")

        
        
        return_results(result)
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
