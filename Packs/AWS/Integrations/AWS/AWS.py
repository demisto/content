import demistomock as demisto  # noqa: F401
from AWSApiModule import *  # noqa: E402
from COOCApiModule import *  # noqa: E402
from CommonServerPython import *  # noqa: F401
from http import HTTPStatus
from datetime import date
from typing import Callable
from enum import StrEnum
from botocore.client import BaseClient as BotoClient
from boto3 import Session

DEFAULT_MAX_RETRIES: int = 5
DEFAULT_SESSION_NAME = "cortex-session"

def arg_to_bool_or_none(value):
    """
    Converts a value to a boolean or None.
    
    Args:
        value: The value to convert to boolean or None.
    
    Returns:
        bool or None: Returns None if the input is None, otherwise returns the boolean representation of the value
        using the argToBoolean function.
    """
    if value is None:
        return None
    else:
        return argToBoolean(value)
  

class AWSServices(StrEnum):
    S3 = 's3'
    IAM = 'iam'
    EC2 = 'ec2'
    RDS = 'rds'
    EKS = 'eks'
    LAMBDA = 'lambda'


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


class S3:
    service = AWSServices.S3

    @staticmethod
    def put_public_access_block_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Create or Modify the PublicAccessBlock configuration for an Amazon S3 bucket.
        
        Args:
            client (BotoClient): The boto3 client for S3 service
            args (Dict[str, Any]): Command arguments including bucket name and access block settings
            
        Returns:
            CommandResults: Results of the operation with success/failure message
        """
        try:
            response = client.get_public_access_block(Bucket=args.get('bucket'))
            public_access_block_configuration = response.get('PublicAccessBlockConfiguration')
            kwargs = {
                'BlockPublicAcls': public_access_block_configuration.get('BlockPublicAcls'),
                'IgnorePublicAcls': public_access_block_configuration.get('IgnorePublicAcls'),
                'BlockPublicPolicy': public_access_block_configuration.get('BlockPublicPolicy'),
                'RestrictPublicBuckets': public_access_block_configuration.get('RestrictPublicBuckets')
            }
        except Exception:
            return CommandResults(
                readable_output=f"Couldn't check current public access block to the {args.get('bucket')} bucket")

        command_args: dict[str, Union[bool, None]] = {
            'BlockPublicAcls': argToBoolean(args.get('block_public_acls')) if args.get('block_public_acls') else None,
            'IgnorePublicAcls': argToBoolean(args.get('ignore_public_acls')) if args.get('ignore_public_acls') else None,
            'BlockPublicPolicy': argToBoolean(args.get('block_public_policy')) if args.get('block_public_policy') else None,
            'RestrictPublicBuckets':
                argToBoolean(args.get('restrict_public_buckets')) if args.get('restrict_public_buckets') else None
        }

        remove_nulls_from_dictionary(command_args)
        for arg_key, arg_value in command_args.items():
            kwargs[arg_key] = arg_value

        response = client.put_public_access_block(Bucket=args.get('bucket'),
                                                  PublicAccessBlockConfiguration=kwargs)

        if response['ResponseMetadata']['HTTPStatusCode'] == HTTPStatus.OK:
            return CommandResults(
                readable_output=f"Successfully applied public access block to the {args.get('bucket')} bucket")
        return CommandResults(readable_output=f"Couldn't apply public access block to the {args.get('bucket')} bucket")

class IAM:
    service = AWSServices.IAM

    @staticmethod
    def get_account_password_policy_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Get AWS account password policy.
        
        Args:
            client (BotoClient): The boto3 client for IAM service
            args (Dict[str, Any]): Command arguments including account ID
            
        Returns:
            CommandResults: Results containing the current password policy configuration
        """
        response = client.get_account_password_policy()
        data = json.loads(json.dumps(response['PasswordPolicy'], cls=DatetimeEncoder))

        human_readable = tableToMarkdown('AWS IAM Account Password Policy', data)

        return CommandResults(outputs=data, readable_output=human_readable, outputs_prefix='AWS.IAM.PasswordPolicy',
                              outputs_key_field='AccountId')

    @staticmethod
    def update_account_password_policy_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Create or Update AWS account password policy.
        
        Args:
            client (BotoClient): The boto3 client for IAM service
            args (Dict[str, Any]): Command arguments including password policy parameters
            
        Returns:
            CommandResults: Results of the operation with success/failure message
        """
        try:
            response = client.get_account_password_policy()
            kwargs = response['PasswordPolicy']
        except Exception:
            return CommandResults(
                readable_output=f"Couldn't check current account password policy for account: {args.get('account_id')}"
            )

        # ExpirePasswords is part of the response but cannot be included in the request
        if 'ExpirePasswords' in kwargs:
            kwargs.pop('ExpirePasswords')

        command_args: dict[str, Union[int, bool, None]] = {
            'MinimumPasswordLength': arg_to_number(args.get('minimum_password_length')),
            'RequireSymbols': argToBoolean(args.get('require_symbols')) if args.get('require_symbols') else None,
            'RequireNumbers': argToBoolean(args.get('require_numbers')) if args.get('require_numbers') else None,
            'RequireUppercaseCharacters':
                argToBoolean(args.get('require_uppercase_characters')) if args.get('require_uppercase_characters') else None,
            'RequireLowercaseCharacters':
                argToBoolean(args.get('require_lowercase_characters')) if args.get('require_lowercase_characters') else None,
            'AllowUsersToChangePassword':
                argToBoolean(args.get('allow_users_to_change_password')) if args.get('allow_users_to_change_password') else None,
            'MaxPasswordAge': arg_to_number(args.get('max_password_age')),
            'PasswordReusePrevention': arg_to_number(args.get('password_reuse_prevention')),
            'HardExpiry': argToBoolean(args.get('hard_expiry')) if args.get('hard_expiry') else None,
        }

        remove_nulls_from_dictionary(command_args)
        for arg_key, arg_value in command_args.items():
            kwargs[arg_key] = arg_value

        response = client.update_account_password_policy(**kwargs)

        if response['ResponseMetadata']['HTTPStatusCode'] == HTTPStatus.OK:
            return CommandResults(
                readable_output=f"Successfully updated account password policy for account: {args.get('account_id')}"
            )
        else:
            return CommandResults(
                readable_output=f"Couldn't updated account password policy for account: {args.get('account_id')}")

class EC2:
    service = AWSServices.EC2

    @staticmethod
    def modify_instance_metadata_options_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Modify the EC2 instance metadata parameters on a running or stopped instance.
        
        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including instance ID and metadata options
            
        Returns:
            CommandResults: Results of the operation with success/failure message
        """
        kwargs = {
            'InstanceId': args.get('instance_id'),
            'HttpTokens': args.get('http_tokens'),
            'HttpEndpoint': args.get('http_endpoint')
        }
        remove_nulls_from_dictionary(kwargs)

        response = client.modify_instance_metadata_options(**kwargs)

        if response['ResponseMetadata']['HTTPStatusCode'] == HTTPStatus.OK:
            return CommandResults(readable_output=f"Successfully updated EC2 instance metadata for {args.get('instance_id')}")
        else:
            return CommandResults(
                entry_type=EntryType.ERROR,
                readable_output=f"Couldn't updated public EC2 instance metadata for {args.get('instance_id')}"
            )

    @staticmethod
    def modify_instance_attribute_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """ 
        Modify an EC2 instance attribute.
        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including instance attribute modifications

        Returns
            CommandResults: Results of the operation with success/failure message
        """
        def parse_security_groups(csv_list):
            if csv_list is None:
                return None
            
            security_groups_str = csv_list.replace(" ", "")
            security_groups_list = security_groups_str.split(",")
            return security_groups_list
          
        kwargs = {
            'InstanceId': args.get('instance_id'),
            'Attribute': args.get('attribute'),
            'Value': args.get('value'),
            'DisableApiStop': arg_to_bool_or_none(args.get('disable_api_stop')),
            'Groups':  parse_security_groups(args.get('groups')),
        }
        remove_nulls_from_dictionary(kwargs)
        response = client.modify_instance_attribute(**kwargs)
        
        if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
            return CommandResults(readable_output=f"Successfully modified EC2 instance `{args.get('instance_id')}` attribute `{kwargs.popitem}")    
        raise DemistoException(f"Unexpected response from AWS - \n{response}")
    
    @staticmethod
    def modify_image_attribute_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        
        Args:
            client (BotoClient): _description_
            args (Dict[str, Any]): _description_

        Returns:
            CommandResults: _description_
        """
        
        
class EKS:
    service = AWSServices.EKS
    
    @staticmethod
    def update_cluster_config_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Updates an Amazon EKS cluster configuration. Only a single type of update (logging / resources_vpc_config) is allowed per call.
        
        Args:
            client (BotoClient): The boto3 client for EKS service
            args (Dict[str, Any]): Command arguments including cluster name and configuration options
            
        Returns:
            CommandResults: Results of the operation with update information
        """
        
        def validate_args(args: Dict[str, Any]) -> dict:
            """
            Check that exactly one argument is passed, and if not raises a value error
            """
            validated_args = {"name": args.get("cluster_name")}
            if resources_vpc_config := args.get('resources_vpc_config'):
                resources_vpc_config = json.loads(resources_vpc_config) if isinstance(resources_vpc_config, str) else resources_vpc_config
                validated_args["resourcesVpcConfig"] = resources_vpc_config
                # Convert specific string boolean values to actual boolean values
                if isinstance(resources_vpc_config, dict):
                    if 'endpointPublicAccess' in resources_vpc_config and isinstance(resources_vpc_config['endpointPublicAccess'], str):
                        resources_vpc_config['endpointPublicAccess'] = resources_vpc_config['endpointPublicAccess'].lower() == 'true'
                    if 'endpointPrivateAccess' in resources_vpc_config and isinstance(resources_vpc_config['endpointPrivateAccess'], str):
                        resources_vpc_config['endpointPrivateAccess'] = resources_vpc_config['endpointPrivateAccess'].lower() == 'true'
            
            if logging_arg := args.get('logging'):
                logging_arg = json.loads(logging_arg) if isinstance(logging_arg, str) else logging_arg
                validated_args["logging"] = logging_arg
                
            if logging_arg and resources_vpc_config:
                raise ValueError
            
            result = remove_empty_elements(validated_args)
            if isinstance(result, dict):
                return result
            else:
                raise ValueError("No valid configuration argument provided")
                                  
        validated_args: dict = validate_args(args)
        try:
            response = client.update_cluster_config(**validated_args)
            response_data = response.get("update", {})
            response_data["clusterName"] = validated_args["name"]
            response_data["createdAt"] = datetime_to_string(response_data.get("createdAt"))

            headers = ["clusterName", "id", "status", "type", "params"]
            readable_output = tableToMarkdown(
                name="Updated Cluster Config Information",
                t=response_data,
                removeNull=True,
                headers=headers,
                headerTransform=pascalToSpace,
            )
            return CommandResults(
                readable_output=readable_output,
                outputs_prefix="AWS.EKS.UpdateCluster",
                outputs=response_data,
                raw_response=response_data,
                outputs_key_field="id",
            )
        except Exception as e:
            if "No changes needed" in str(e):
                return CommandResults(readable_output="No changes needed for the required update.")
            else:
                raise e

class RDS:
    service = AWSServices.RDS
    
    @staticmethod
    def modify_db_cluster_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Modifies an Amazon RDS DB Cluster configuration.

        Args:
            client (BotoClient): The boto3 client for RDS service
            args (Dict[str, Any]): Command arguments including cluster configuration options

        Returns:
            CommandResults: Results of the operation with update information
        """
        try:
            kwargs = {
                "DBClusterIdentifier": args.get("db-cluster-identifier"),
            }

            # Optional parameters
            optional_params = {
                "DeletionProtection": "deletion-protection",
                "EnableIAMDatabaseAuthentication": "enable-iam-database-authentication",
            }

            for param, arg_name in optional_params.items():
                if arg_name in args:
                    kwargs[param] = argToBoolean(args[arg_name])

            response = client.modify_db_cluster(**kwargs)

            if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
                db_cluster = response.get("DBCluster", {})
                readable_output = f"Successfully modified DB cluster {args.get('db-cluster-identifier')}"

                if db_cluster:
                    readable_output += "\n\nUpdated DB Cluster details:"
                    readable_output += tableToMarkdown("", db_cluster)

                return CommandResults(
                    readable_output=readable_output,
                    outputs_prefix="AWS.RDS.DBCluster",
                    outputs=db_cluster,
                    outputs_key_field="DBClusterIdentifier",
                )
            else:
                return CommandResults(
                    readable_output=f"Failed to modify DB cluster. Status code: {response['ResponseMetadata']['HTTPStatusCode']}"
                )

        except Exception as e:
            return CommandResults(readable_output=f"Error modifying DB cluster: {str(e)}")
    
    @staticmethod
    def modify_db_cluster_snapshot_attribute_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Modifies attributes of an Amazon RDS DB Cluster snapshot.
        Args:
            client (BotoClient): The boto3 client for RDS service
            args (Dict[str, Any]): Command arguments for snapshot attribute modification

        Returns:
            CommandResults: Results of the snapshot attribute modification operation
        """
        try:
            kwargs = {
                "DBClusterSnapshotIdentifier": args.get("db_cluster_snapshot_identifier"),
                "AttributeName": args.get("attribute_name"),
            }

            # Optional parameters
            if "values_to_add" in args:
                kwargs["ValuesToAdd"] = argToList(args.get("values_to_add"))

            if "values-to-remove" in args:
                kwargs["ValuesToRemove"] = argToList(args.get("values_to_remove"))

            remove_nulls_from_dictionary(kwargs)

            response = client.modify_db_cluster_snapshot_attribute(**kwargs)

            if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
                attributes = response.get("DBClusterSnapshotAttributesResult", {})

                if attributes:
                    readable_output = (
                        f"Successfully modified DB cluster snapshot attribute for {args.get('db_cluster_snapshot_identifier')}"
                    )
                    readable_output += "\n\nUpdated DB Cluster Snapshot Attributes:"
                    readable_output += tableToMarkdown("", attributes)
                    
                return CommandResults(
                    readable_output=readable_output,
                    outputs_prefix="AWS.RDS.DBClusterSnapshotAttributes",
                    outputs=attributes,
                    outputs_key_field="DBClusterSnapshotIdentifier",
                )
            else:
                return CommandResults(
                    entry_type=EntryType.ERROR,
                    readable_output=f"Failed to modify DB cluster snapshot attribute. Status code: {response['ResponseMetadata']['HTTPStatusCode']}"
                )

        except Exception as e:
            return CommandResults(
                entry_type=EntryType.ERROR,
                readable_output=f"Error modifying DB cluster snapshot attribute: {str(e)}"
                )

    @staticmethod
    def modify_db_instance_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Modifies an Amazon RDS DB Instance configuration.

        Args:
            client (BotoClient): The boto3 client for RDS service
            args (Dict[str, Any]): Command arguments including instance identifier and configuration options
            
        Returns:
            CommandResults: Results of the operation with update information
        """
        try:
            kwargs = {
                "DBInstanceIdentifier": args.get("db_instance_identifier"),
                "MultiAZ": arg_to_bool_or_none(args.get("multi_az")),
                "ApplyImmediately": arg_to_bool_or_none(args.get('apply_immediately')),
                "AutoMinorVersionUpgrade": arg_to_bool_or_none(args.get('auto_minor_version_upgrade')),
                "DeletionProtection": arg_to_bool_or_none(args.get('deletion_protection')),
                "EnableIAMDatabaseAuthentication": arg_to_bool_or_none(args.get('enable_iam_database_authentication')),
                "PubliclyAccessible": arg_to_bool_or_none(args.get('publicly_accessible')),
                "CopyTagsToSnapshot": arg_to_bool_or_none(args.get('copy_tags_to_snapshot')),
                "BackupRetentionPeriod": arg_to_bool_or_none(args.get('backup_retention_period')),
                
            }
            remove_nulls_from_dictionary(kwargs)
            response = client.modify_db_instance(**kwargs)
   
            if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
                db_instance = response.get("DBInstance", {})
                readable_output = f"Successfully modified DB instance {args.get('db-instance-identifier')}"

                if db_instance:
                    readable_output += "\n\nUpdated DB Instance details:"
                    readable_output += tableToMarkdown("", db_instance)

                return CommandResults(
                    readable_output=readable_output,
                    outputs_prefix="AWS.RDS.DBInstance",
                    outputs=db_instance,
                    outputs_key_field="DBInstanceIdentifier",
                )
            else:
                return CommandResults(
                    entry_type=EntryType.ERROR,
                    readable_output=f"Failed to modify DB instance. Status code: {response['ResponseMetadata']['HTTPStatusCode']}"
                )

        except Exception as e:
            return CommandResults(
                entry_type=EntryType.ERROR,
                readable_output=f"Error modifying DB instance: {str(e)}"
                )
    
    @staticmethod
    def modify_db_snapshot_attribute_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Adds or removes permission for the specified AWS account IDs to restore the specified DB snapshot.
        
        Args:
            client (BotoClient): The boto3 client for RDS service
            args (Dict[str, Any]): Command arguments including snapshot identifier and attribute settings
            
        Returns:
            CommandResults: Results of the operation with success/failure message
        """
        kwargs = {
            "DBSnapshotIdentifier": args.get("db_snapshot_identifier"),
            "AttributeName": args.get("attribute_name"),
            "ValuesToAdd": argToList(args.get("values_to_add")) if "values_to_add" in args else None,
            "ValuesToRemove": argToList(args.get("values_to_remove")) if "values_to_remove" in args else None,
        }
        remove_nulls_from_dictionary(kwargs)

        response = client.modify_db_snapshot_attribute(**kwargs)

        if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
            # Return the changed fields in the command results:
            return CommandResults(
                readable_output=f"Successfully modified DB snapshot attribute for {args.get('db_snapshot_identifier')}:\n{tableToMarkdown('Modified', kwargs)}"
            )

        else:
            return CommandResults(
                entry_type=EntryType.ERROR,
                readable_output=f"Couldn't modify DB snapshot attribute for {args.get('db_snapshot_identifier')}"
            )
        
        
COMMANDS_MAPPING: dict[str, Callable[[BotoClient, Dict[str, Any]], CommandResults]] = {
    "aws-s3-public-access-block-put": S3.put_public_access_block_command,
    "aws-iam-account-password-policy-get": IAM.get_account_password_policy_command,
    "aws-iam-account-password-policy-update": IAM.update_account_password_policy_command,
    "aws-ec2-instance-metadata-options-modify": EC2.modify_instance_metadata_options_command,
    "aws-ec2-instance-attribute-modify": EC2.modify_instance_attribute_command,
    "aws-ec2-image-attribute-modify": EC2.modify_image_attribute_command,
    
    "aws-eks-cluster-config-update": EKS.update_cluster_config_command,
    "aws-rds-db-cluster-modify": RDS.modify_db_cluster_command,   
    "aws-rds-db-cluster-snapshot-attribute-modify": RDS.modify_db_cluster_command,   
    "aws-rds-db-instance-modify": RDS.modify_db_instance_command,   
    "aws-rds-db-snapshot-attribute-modify": RDS.modify_db_snapshot_attribute_command,   
}

def main():  # pragma: no cover
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f"Params: {params}")
    demisto.debug(f"Command: {command}")
    demisto.debug(f"Args: {args}")

    # TODO - credentials = get_cloud_credentials(CloudTypes.GCP)
    credentials = {}
    
    aws_session: Session = Session(
        aws_access_key_id=credentials.get('key') or params.get('access_key_id'),
        aws_secret_access_key=credentials.get('access_token') or params.get('secret_access_key').get('password'),
        aws_session_token=credentials.get('session_token'),
        region_name=args.get('region') or params.get('region', '')
    )
    
    try:
        if command == "test-module":
            # TODO - Check permissions 
            return_results(HealthCheckResult.ok())         
        elif command in COMMANDS_MAPPING:
            service = AWSServices(command.split('-')[1])
            service_client: BotoClient = aws_session.client(service)
            return_results(
                COMMANDS_MAPPING[command](service_client, args)
            )
        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
