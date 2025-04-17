import demistomock as demisto
from AWSApiModule import *  # noqa: E402
from CommonServerPython import *
from http import HTTPStatus
from datetime import date
from collections.abc import Callable

def test_module(aws_client: AWSClient) -> str:
    # aws_client.aws_session(service='sts')
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
    
    aws_role_session_name = params.get('role_session_name') or 'cortex-session'
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
    except Exception:
        return CommandResults(readable_output=f"Couldn't check current public access block to the {args.get('bucket')} bucket")

    command_args: Dict[str, tuple[str, Callable[[Any], Any]]] = {
        'block_public_acls': ('BlockPublicAcls', argToBoolean),
        'ignore_public_acls': ('IgnorePublicAcls', argToBoolean),
        'block_public_policy': ('BlockPublicPolicy', argToBoolean),
        'restrict_public_buckets': ('RestrictPublicBuckets', argToBoolean)
    }
    
    remove_nulls_from_dictionary(args)
    for arg_key, (kwarg_key, converter_func) in command_args.items():
        if arg_key in args:
            kwargs[kwarg_key] = converter_func(args[arg_key])


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

    human_readable = tableToMarkdown('AWS IAM Account Password Policy', data)
    
    return CommandResults(outputs=data, readable_output=human_readable, outputs_prefix='AWS.IAM.PasswordPolicy',
                          outputs_key_field='AccountId')
    
def update_account_password_policy(aws_client: AWSClient, args: Dict[str, Any]) -> CommandResults:
    client_session = aws_client.aws_session(service='iam')
    try:
        response = client_session.get_account_password_policy()
        kwargs = response['PasswordPolicy']
    except Exception:
        return CommandResults(
            readable_output=f"Couldn't check current account password policy for account: {args.get('account_id')}"
        )
        
    # ExpirePasswords is part of the response but cannot be included in the request
    if 'ExpirePasswords' in kwargs:
        kwargs.pop('ExpirePasswords')
    
    command_args: Dict[str, tuple[str, Callable[[Any], Any]]] = {
        'minimum_password_length': ('MinimumPasswordLength', arg_to_number),
        'require_symbols': ('RequireSymbols', argToBoolean),
        'require_numbers': ('RequireNumbers', argToBoolean),
        'require_uppercase_characters': ('RequireUppercaseCharacters', argToBoolean),
        'require_lowercase_characters': ('RequireLowercaseCharacters', argToBoolean),
        'allow_users_to_change_password': ('AllowUsersToChangePassword', argToBoolean),
        'max_password_age': ('MaxPasswordAge', arg_to_number),
        'password_reuse_prevention': ('PasswordReusePrevention', arg_to_number),
        'hard_expiry': ('HardExpiry', argToBoolean),
    }
    
    remove_nulls_from_dictionary(args)
    for arg_key, (kwarg_key, converter_func) in command_args.items():
        if arg_key in args:
            kwargs[kwarg_key] = converter_func(args[arg_key])
        
    response = client_session.update_account_password_policy(**kwargs)
    
    if response['ResponseMetadata']['HTTPStatusCode'] == HTTPStatus.OK:
        return CommandResults(
            readable_output=f"Successfully updated account password policy for account: {args.get('account_id')}"
        )
    else:
        return CommandResults(readable_output=f"Couldn't updated account password policy for account: {args.get('account_id')}")
        
# =================== #
# EC2 commands
# =================== #
def ec2_instance_metadata_options_modify(aws_client: AWSClient, args: Dict[str, Any]) -> CommandResults:
    client_session = aws_client.aws_session(service='ec2', region=args.get('region'))
    
    kwargs = {
        'InstanceId': args.get('instance_id'),
        'HttpTokens': args.get('http_tokens'),
        'HttpEndpoint': args.get('http_endpoint')
    }
    remove_nulls_from_dictionary(kwargs)
    
    response = client_session.modify_instance_metadata_options(**kwargs)
        
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

    try:
        match command:
            case "aws-s3-public-access-block-update":
                return_results(put_public_access_block(aws_client, command_args))
            case 'aws-iam-account-password-policy-get':
                return_results(get_account_password_policy(aws_client, command_args))
            case 'aws-iam-account-password-policy-update':
                return_results(update_account_password_policy(aws_client, command_args))
            case 'aws-ec2-instance-metadata-options-modify':
                return_results(ec2_instance_metadata_options_modify(aws_client, command_args))
                
            case 'test-module':
                return_results(test_module(aws_client))
            case _:
                raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
