from typing import Callable
import demistomock as demisto
from AWSApiModule import *  # noqa: E402
from CommonServerPython import *
from http import HTTPStatus
from datetime import date
from enum import Enum
from abc import ABC, abstractmethod


class DatetimeEncoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)

class AWSServices(Enum):
    S3 = "s3"
    EC2 = "ec2"
    IAM = "iam"
    # LAMBDA = "lambda"
    # SAGEMAKER = "sagemaker"

class AWSService(ABC):
    COMMANDS = []
    def __init__(self, service_id: str, aws_client: AWSClient):
        self.service_id = service_id
        self.service_client = aws_client.aws_session(service=service_id, region=)
    @abstractmethod
    def test_module():
        pass
    
class S3(AWSService):
    OUTPUT_PREFIX = 'AWS.S3'
    COMMANDS = [...]
    def test_module(self, ):
        
        pass
    
    def put_public_access_block_command(self, s3_client, args: Dict[str, Any]) -> CommandResults:
        """_summary_

        Args:
            s3_client (_type_): _description_
            args (Dict[str, Any]): _description_

        Returns:
            CommandResults: _description_
        """
        try:
            response = s3_client.get_public_access_block(Bucket=args.get('bucket'))
            public_access_block_configuration = response.get('PublicAccessBlockConfiguration')
            kwargs = {
                'BlockPublicAcls': public_access_block_configuration.get('BlockPublicAcls'),
                'IgnorePublicAcls': public_access_block_configuration.get('IgnorePublicAcls'),
                'BlockPublicPolicy': public_access_block_configuration.get('BlockPublicPolicy'),
                'RestrictPublicBuckets': public_access_block_configuration.get('RestrictPublicBuckets')
            }
        except s3_client.exceptions.NoSuchEntityException:
            kwargs = {}
            
        if 'block_public_acls' in args:
            kwargs['BlockPublicAcls'] = argToBoolean(args['block_public_acls'])
        if 'ignore_public_acls' in args:
            kwargs['IgnorePublicAcls'] = argToBoolean(args['ignore_public_acls'])
        if 'block_public_policy' in args:
            kwargs['BlockPublicPolicy'] = argToBoolean(args['block_public_policy'])
        if 'restrict_public_buckets' in args:
            kwargs['RestrictPublicBuckets'] = argToBoolean(args['restrict_public_buckets'])


        response = s3_client.put_public_access_block(
            Bucket=args.get('bucket'), PublicAccessBlockConfiguration=kwargs
            )

        if response['ResponseMetadata']['HTTPStatusCode'] == HTTPStatus.OK:
            return CommandResults(
                readable_output=f"Successfully applied public access block to the {args.get('bucket')} bucket")
        
        demisto.error(json.dumps(response))
        return CommandResults(readable_output=f"Couldn't apply public access block to the {args.get('bucket')} bucket")

class EC2(AWSService):
    OUTPUT_PREFIX = 'AWS.EC2'
    def instance_metadata_options_modify_command(self, ec2_client, args: Dict[str, Any]) -> CommandResults:    
        kwargs = {
            'InstanceId': args['instance_id'],
            'RequireSymbols': argToBoolean(args['require_symbols']) if 'require_symbols' in args else None,
            'HttpTokens': args.get('http_tokens'),
            'HttpEndpoint': args.get('http_endpoint')
        }
        remove_nulls_from_dictionary(kwargs)
        
        response = ec2_client.modify_instance_metadata_options(**kwargs)
        
        if response['ResponseMetadata']['HTTPStatusCode'] == HTTPStatus.OK:
            return CommandResults(readable_output=f"Successfully updated EC2 instance metadata for {args.get('instance_id')}")
        else:
            return CommandResults(readable_output=f"Couldn't updated public EC2 instance metadata for {args.get('instance_id')}")

class IAM(AWSService):
    OUTPUT_PREFIX = 'AWS.IAM'
    def get_account_password_policy_command(self, iam_client, args: Dict[str, Any]) -> CommandResults:
        """
        
        """
        response = iam_client.get_account_password_policy()
        data = json.loads(DatetimeEncoder().encode(response['PasswordPolicy']))
        data['AccountId'] = args.get('account_id')
    
        human_readable = tableToMarkdown('AWS IAM Account Password Policy', data)
        
        return CommandResults(
            outputs=data,
            readable_output=human_readable,
            outputs_prefix=f'{self.OUTPUT_PREFIX}.PasswordPolicy',
            outputs_key_field='AccountId'
            )
    
    def update_account_password_policy_command(self, iam_client, args: Dict[str, Any]) -> CommandResults:
        """_summary_

        Args:
            iam_client (_type_): _description_
            args (Dict[str, Any]): _description_

        Returns:
            CommandResults: _description_
        """
        try:
            response = iam_client.get_account_password_policy()
            kwargs = response['PasswordPolicy']
        except iam_client.exceptions.NoSuchEntityException:
            kwargs = {}
            
        # ExpirePasswords is part of the response but cannot be included
        # in the request
        del kwargs['ExpirePasswords']
        
        kwargs['MinimumPasswordLength'] = args.get('minimum_password_length')
        kwargs['MaxPasswordAge'] = args.get('max_password_age')
        kwargs['PasswordReusePrevention'] = args.get('password_reuse_prevention')
        remove_nulls_from_dictionary(kwargs)
        
        if 'require_symbols' in args:
            kwargs['RequireSymbols'] = argToBoolean(args['require_symbols'])
        if 'require_numbers' in args:
            kwargs['RequireNumbers'] = argToBoolean(args['require_numbers'])
        if 'require_uppercase_characters' in args:
            kwargs['RequireUppercaseCharacters'] = argToBoolean(args['require_uppercase_characters'])
        if 'require_lowercase_characters' in args:
            kwargs['RequireLowercaseCharacters'] = argToBoolean(args['require_lowercase_characters'])
        if 'allow_users_to_change_password' in args:
            kwargs['AllowUsersToChangePassword'] = argToBoolean(args['allow_users_to_change_password'])
        if 'hard_expiry' in args:
            kwargs['HardExpiry'] = argToBoolean(args['hard_expiry'])
        
        
        response = iam_client.update_account_password_policy(**kwargs)
        
        if response['ResponseMetadata']['HTTPStatusCode'] == HTTPStatus.OK:
            return CommandResults(readable_output=f"Successfully updated account password policy for account: {args.get('account_id')}")
        else:
            return CommandResults(readable_output=f"Couldn't updated account password policy for account: {args.get('account_id')}")
            
AWS_SERVICES_TO_CLASS_MAPPING = {
    AWSServices.S3: S3,
    AWSServices.EC2: EC2,
    AWSServices.IAM: IAM,
}    

def get_client(params: dict, command: str, args: dict) -> AWSClient:
    try:
        accountId = args.get('account_id')
        aws_role_name = params.get('role_name')
        aws_default_region = aws_role_policy = aws_access_key_id = aws_secret_access_key = aws_session_token = None
        return AWSClient(
            aws_default_region=aws_default_region,
            aws_role_arn=f'arn:aws:iam::{accountId}:role/{aws_role_name}',
            aws_role_session_name=params.get('role_session_name'),
            aws_role_session_duration=params.get('session_duration'),
            aws_role_policy=aws_role_policy,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            verify_certificate = not params.get('insecure', True),
            timeout = params.get('timeout'),
            retries = params.get('retries', 5),
            aws_session_token=aws_session_token,
            sts_endpoint_url = params.get('sts_endpoint_url', None),
            endpoint_url = params.get('endpoint_url', None)
        )  
    
    except KeyError:
        raise NotImplementedError(f"The command '{command}' is not implemented.")

def test_modules(aws_client: AWSClient, params: dict):
    """
    Tests AWS Services connection.
    """
    test_results = []
    for service in AWSServices:
        aws_client.aws_session(service=service.value, region=params.get("default_region"))
        test_results.append(AWS_SERVICES_TO_CLASS_MAPPING[service].test_module())
    
    errors = [result for result in test_results if result != "ok"]
    return "ok" if not errors else errors

COMMANDS: dict[str, Callable] = {
    'aws-ec2-instance-metadata-options-modify': EC2.instance_metadata_options_modify_command,
    'aws-iam-get-account-password-policy': IAM.get_account_password_policy_command,
    'aws-iam-update-account-password-policy': IAM.update_account_password_policy_command,
    'aws-s3-apply-public-access-block': S3.put_public_access_block_command
}


def main():
     
    params, command, args = demisto.params(), demisto.command(), demisto.args()
    demisto.debug(f"{params=} | {command=} | {args=}")
    
    aws_client: AWSClient = get_client(params, command, args)
    try:
        if command == "test-module":
            return_results(test_modules(aws_client, params))
        elif command in COMMANDS:
            service_name: AWSServices = AWSServices(command.split('-')[1])   # Validating the service name through the AWSServices Enum.

            aws_service_client = aws_client.aws_session(service=service, region=args.get('region'))
            
            # Execute command.
            command_results: CommandResults = COMMANDS[command](aws_service_client, args)
            return_results(command_results)
        else:
            raise NotImplementedError
    except NotImplementedError:
        return_error(f"Command {command} is not implemented.")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
