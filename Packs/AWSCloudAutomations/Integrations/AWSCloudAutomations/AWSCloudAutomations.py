import demistomock as demisto
from AWSApiModule import *  # noqa: E402
from CommonServerPython import *
from http import HTTPStatus
from datetime import date
from collections.abc import Callable
from botocore.client import BaseClient as BotoBaseClient
DEFAULT_MAX_RETRIES: int  = 5

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
    
    verify_certificate = not argToBoolean(params.get('insecure', 'True'))
    timeout = params.get('timeout')
    retries = params.get('retries') or DEFAULT_MAX_RETRIES
    
    sts_endpoint_url = params.get('sts_endpoint_url')
    endpoint_url = params.get('endpoint_url')
    
    aws_default_region = aws_role_policy = aws_access_key_id = aws_secret_access_key = aws_session_token = None
  
    return AWSClient(
            aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
            aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate, timeout,
            retries, aws_session_token, sts_endpoint_url, endpoint_url
        )

def get_client_session(aws_client: AWSClient, service: str, args: dict) ->  BotoBaseClient:
    return aws_client.aws_session(service=service, region=args.get('region'))

# class AWSService:
#     def __init__(self, aws_client: AWSClient, args: Dict[str, Any], service=''):
            
#         self.client_session: BotoBaseClient = aws_client.aws_session(
#             service=service, region=args.get('region')
#             )
class S3:
    
    def __init__(self, aws_client: AWSClient, args: Dict[str, Any]):
        self.client_session: BotoBaseClient = get_client_session(aws_client, 's3', args)
        
    def put_public_access_block_command(self, args: Dict[str, Any]) -> CommandResults:
        try:
            response = self.client_session.get_public_access_block(Bucket=args.get('bucket'))
            public_access_block_configuration = response.get('PublicAccessBlockConfiguration')
            kwargs = {
                'BlockPublicAcls': public_access_block_configuration.get('BlockPublicAcls'),
                'IgnorePublicAcls': public_access_block_configuration.get('IgnorePublicAcls'),
                'BlockPublicPolicy': public_access_block_configuration.get('BlockPublicPolicy'),
                'RestrictPublicBuckets': public_access_block_configuration.get('RestrictPublicBuckets')
            }
        except Exception:
            return CommandResults(readable_output=f"Couldn't check current public access block to the {args.get('bucket')} bucket")
                
        command_args: dict[str, Union[bool, None]] = {
            'BlockPublicAcls': 
                argToBoolean(args.get('block_public_acls')) if 'block_public_acls' in args else None ,
            'IgnorePublicAcls': 
                argToBoolean(args.get('ignore_public_acls')) if 'ignore_public_acls' in args else None,
            'BlockPublicPolicy': 
                argToBoolean(args.get('block_public_policy')) if 'block_public_policy' in args else None,
            'RestrictPublicBuckets':
                argToBoolean(args.get('restrict_public_buckets')) if 'restrict_public_buckets' in args else None
        }
        
        remove_nulls_from_dictionary(command_args)
        for arg_key, arg_value in command_args.items():
            kwargs[arg_key] = arg_value

        response = self.client_session.put_public_access_block(Bucket=args.get('bucket'),
                                                        PublicAccessBlockConfiguration=kwargs)

        if response['ResponseMetadata']['HTTPStatusCode'] == HTTPStatus.OK:
            return CommandResults(
                readable_output=f"Successfully applied public access block to the {args.get('bucket')} bucket")
        return CommandResults(readable_output=f"Request completed but received unexpected status code: {response['ResponseMetadata']['HTTPStatusCode']}")

    def put_bucket_acl_command(self, args: Dict[str, Any]) -> CommandResults:
        acl, bucket = args.get('acl'), args.get('bucket')
        response = self.client_session.put_bucket_acl(Bucket=bucket, ACL=acl)
        if response['ResponseMetadata']['HTTPStatusCode'] == HTTPStatus.OK:
            return CommandResults(f"Successfully updated ACL for bucket {bucket} to '{acl}'")
        return CommandResults(
            f"Request completed but received unexpected status code: {response['ResponseMetadata']['HTTPStatusCode']}"
            )
        
    def put_bucket_logging_command(self, args: Dict[str, Any]) -> CommandResults:
        # TODO - Implement
        return CommandResults(
        )
    
    def put_bucket_versioning_command(self, args: Dict[str, Any]) -> CommandResults:
        # TODO - Implement
        raise NotImplementedError("put_bucket_versioning_command")
        return CommandResults(
            
        )

class IAM:
    def __init__(self, aws_client: AWSClient, args: Dict[str, Any]):
        self.client_session: BotoBaseClient = get_client_session(aws_client, 'iam', args)
        
    def get_account_password_policy_command(self, args: Dict[str, Any]) -> CommandResults:
        response = self.client_session.get_account_password_policy()
        data = json.loads(json.dumps(response['PasswordPolicy'], cls=DatetimeEncoder))

        human_readable = tableToMarkdown('AWS IAM Account Password Policy', data)
        
        return CommandResults(outputs=data, readable_output=human_readable, outputs_prefix='AWS.IAM.PasswordPolicy',
                            outputs_key_field='AccountId')
        
    def update_account_password_policy_command(self, args: Dict[str, Any]) -> CommandResults:

        try:
            response = self.client_session.get_account_password_policy()
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
            
        response = self.client_session.update_account_password_policy(**kwargs)
        
        if response['ResponseMetadata']['HTTPStatusCode'] == HTTPStatus.OK:
            return CommandResults(
                readable_output=f"Successfully updated account password policy for account: {args.get('account_id')}"
            )
        else:
            return CommandResults(readable_output=f"Couldn't updated account password policy for account: {args.get('account_id')}")
        
class EC2:
    def __init__(self, aws_client: AWSClient, args: Dict[str, Any]):
        self.client_session: BotoBaseClient = get_client_session(aws_client, 'ec2', args)
        
    def ec2_instance_metadata_options_modify_command(self, args: Dict[str, Any]) -> CommandResults:
        
        kwargs = {
            'InstanceId': args.get('instance_id'),
            'HttpTokens': args.get('http_tokens'),
            'HttpEndpoint': args.get('http_endpoint')
        }
        remove_nulls_from_dictionary(kwargs)
        
        response = self.client_session.modify_instance_metadata_options(**kwargs)
            
        if response['ResponseMetadata']['HTTPStatusCode'] == HTTPStatus.OK:
            return CommandResults(readable_output=f"Successfully updated EC2 instance metadata for {args.get('instance_id')}")
        else:
            return CommandResults(readable_output=f"Couldn't updated public EC2 instance metadata for {args.get('instance_id')}")
        
class RDS:
    def __init__(self, aws_client: AWSClient, args: Dict[str, Any]):
        self.client_session: BotoBaseClient = get_client_session(aws_client, 'rds', args)

    def modify_db_cluster_command(self, args: Dict[str, Any]) -> CommandResults:
        # TODO - Implmement
        raise NotImplementedError("modify_db_cluster_command")
        return CommandResults(
            
        )
        
    def modify_db_cluster_snapshot_attribute_command(self, args: Dict[str, Any]) -> CommandResults:
        # TODO - Implement
        raise NotImplementedError("modify_db_cluster_snapshot_attribute_command")        
        return CommandResults(
            
        )
        
    def modify_db_instance_command(self, args: Dict[str, Any]) -> CommandResults:





        try:
            kwargs = {
                'DBInstanceIdentifier': args.get('db-instance-identifier'),
            }

            # Optional parameters
            optional_params = {
                'PubliclyAccessible': 'publicly-accessible',
                'CopyTagsToSnapshot': 'copy-tags-to-snapshot',
                'BackupRetentionPeriod': 'backup-retention-period',
                'EnableIAMDatabaseAuthentication': 'enable-iam-database-authentication',
                'DeletionProtection': 'deletion-protection',
                'AutoMinorVersionUpgrade': 'auto-minor-version-upgrade',
                'MultiAZ': 'multi-az',
                'ApplyImmediately': 'apply-immediately'
            }

            for param, arg_name in optional_params.items():
                if arg_name in args:
                    kwargs[param] = argToBoolean(args[arg_name]) if param in ['PubliclyAccessible', 'CopyTagsToSnapshot', 'EnableIAMDatabaseAuthentication', 'DeletionProtection', 'AutoMinorVersionUpgrade', 'MultiAZ', 'ApplyImmediately'] else args[arg_name]

            response = self.client_session.modify_db_instance(**kwargs)

            if response['ResponseMetadata']['HTTPStatusCode'] == HTTPStatus.OK:
                db_instance = response.get('DBInstance', {})
                readable_output = f"Successfully modified DB instance {args.get('db-instance-identifier')}"
                
                if db_instance:
                    readable_output += "\n\nUpdated DB Instance details:"
                    readable_output += tableToMarkdown("", db_instance)

                return CommandResults(
                    readable_output=readable_output,
                    outputs_prefix='AWS.RDS.DBInstance',
                    outputs=db_instance,
                    outputs_key_field='DBInstanceIdentifier'
                )
            else:
                return CommandResults(
                    readable_output=f"Failed to modify DB instance. Status code: {response['ResponseMetadata']['HTTPStatusCode']}"
                )

        except Exception as e:
            return CommandResults(
                readable_output=f"Error modifying DB instance: {str(e)}"
            )
        
    def modify_db_snapshot_attribute_command(self, args: Dict[str, Any]) -> CommandResults:
        kwargs = {
            'DBSnapshotIdentifier': args.get('db_snapshot_identifier'),
            'AttributeName': args.get('attribute_name'),
            'ValuesToAdd': argToList(args.get('values_to_add')) if 'values_to_add' in args else None,
            'ValuesToRemove': argToList(args.get('values_to_remove')) if 'values_to_remove' in args else None
        }
        remove_nulls_from_dictionary(kwargs)
        
        response = self.client_session.modify_db_snapshot_attribute(**kwargs)
            
        if response['ResponseMetadata']['HTTPStatusCode'] == HTTPStatus.OK:
            # Return the changed fields in the command results:
            return CommandResults(
                readable_output=f"Successfully modified DB snapshot attribute for {args.get('db_snapshot_identifier')}:\n{tableToMarkdown('Modified', kwargs)}"
            )
            
        else:
            return CommandResults(
                readable_output=f"Couldn't modify DB snapshot attribute for {args.get('db_snapshot_identifier')}"
            )
        
def test_module(params, command_args) -> str:
    if test_account_id := params.get('test_account_id'):
        command_args['account_id'] = test_account_id
    else:
        return "Please provide Test AWS Account ID for the Integration instance to run test"
    
    aws_client = get_client(params, command_args)
    client_session = aws_client.aws_session(service='sts')
    if client_session:
        return "ok"
    else:
        return "fail"

COMMANDS: dict[str, Callable] = {
    "aws-s3-public-access-block-update": 
        lambda aws_client, args: S3(aws_client, args).put_public_access_block_command(args),
    "aws-s3-bucket-acl-put":
        lambda aws_client, args: S3(aws_client, args).put_bucket_acl_command(args),
    "aws-s3-bucket-logging-put":
        lambda aws_client, args: S3(aws_client, args).put_bucket_logging_command(args),
    "aws-s3-bucket-versioning-put":
        lambda aws_client, args: S3(aws_client, args).put_bucket_versioning_command(args),
        
    "aws-iam-account-password-policy-get": 
        lambda aws_client, args: IAM(aws_client, args).get_account_password_policy_command(args),
    "aws-iam-account-password-policy-update": 
        lambda aws_client, args: IAM(aws_client, args).update_account_password_policy_command(args),
        
    "aws-ec2-instance-metadata-options-modify": 
        lambda aws_client, args: EC2(aws_client, args).ec2_instance_metadata_options_modify_command(args),
        
    "aws-rds-db-cluster-modify":
        lambda aws_client, args: RDS(aws_client, args).modify_db_cluster_command(args),
    "aws-rds-db-cluster-snapshot-attribute-modify":
        lambda aws_client, args: RDS(aws_client, args).modify_db_cluster_snapshot_attribute_command(args),
    "aws-rds-db-instance-modify":
        lambda aws_client, args: RDS(aws_client, args).modify_db_instance_command(args),
    "aws-rds-db-snapshot-attribute-modify":
        lambda aws_client, args: RDS(aws_client, args).modify_db_snapshot_attribute_command(args),
    
}

# =================== #
# MAIN
# =================== #
def main():

    params = demisto.params()
    command = demisto.command()
    command_args = demisto.args()
    
    demisto.debug(f"Params: {params}")
    demisto.debug(f"Command: {command}")
    demisto.debug(f"Args: {command_args}")
        
    aws_client = get_client(params, command_args)
    try:
        if command == "test-module":
            return_results(test_module(params, command_args))
        elif command_function := COMMANDS.get(command):
            return_results(command_function(aws_client, command_args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
