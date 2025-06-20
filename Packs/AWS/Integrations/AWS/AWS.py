import demistomock as demisto  # noqa: F401
from AWSApiModule import *  # noqa: E402
from COOCApiModule import *  # noqa: E402
from CommonServerPython import *  # noqa: F401
from http import HTTPStatus
from datetime import date
from collections.abc import Callable
from enum import StrEnum
from botocore.client import BaseClient as BotoClient
from boto3 import Session
import botocore

DEFAULT_MAX_RETRIES: int = 5
DEFAULT_SESSION_NAME = "cortex-session"
DEFAULT_PROXYDOME_CERTFICATE_PATH = "/etc/certs/egress.crt"
DEFAULT_PROXYDOME = "10.181.0.100:11117"

# TODO - Remove >>
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


# <<


def parse_resource_ids(resource_id: str | None) -> list[str]:
    if resource_id is None:
        raise ValueError("Resource ID cannot be empty")
    id_list = resource_id.replace(" ", "")
    resource_ids = id_list.split(",")
    return resource_ids


class AWSServices(StrEnum):
    S3 = "s3"
    IAM = "iam"
    EC2 = "ec2"
    RDS = "rds"
    EKS = "eks"
    LAMBDA = "lambda"


# =================== #
# Helpers
# =================== #
class DatetimeEncoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime("%Y-%m-%dT%H:%M:%S")
        elif isinstance(obj, date):
            return obj.strftime("%Y-%m-%d")
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

        kwargs: dict[str, Union[bool, None]] = {
            "BlockPublicAcls": argToBoolean(args.get("block_public_acls")) if args.get("block_public_acls") else None,
            "IgnorePublicAcls": argToBoolean(args.get("ignore_public_acls")) if args.get("ignore_public_acls") else None,
            "BlockPublicPolicy": argToBoolean(args.get("block_public_policy")) if args.get("block_public_policy") else None,
            "RestrictPublicBuckets": argToBoolean(args.get("restrict_public_buckets"))
            if args.get("restrict_public_buckets")
            else None,
        }

        remove_nulls_from_dictionary(kwargs)
        response = client.put_public_access_block(Bucket=args.get("bucket"), PublicAccessBlockConfiguration=kwargs)

        if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
            return CommandResults(readable_output=f"Successfully applied public access block to the {args.get('bucket')} bucket")

        return CommandResults(
            entry_type=EntryType.ERROR, readable_output=f"Couldn't apply public access block to the {args.get('bucket')} bucket"
        )

    @staticmethod
    def put_bucket_versioning_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Set the versioning state of an Amazon S3 bucket.

        Args:
            client (BotoClient): The boto3 client for S3 service
            args (Dict[str, Any]): Command arguments including:
                - bucket (str): The name of the bucket
                - status (str): The versioning state of the bucket (Enabled or Suspended)
                - mfa_delete (str): Specifies whether MFA delete is enabled (Enabled or Disabled)

        Returns:
            CommandResults: Results of the command execution
        """
        bucket: str = args.get("bucket", "")
        status: str = args.get("status", "")
        mfa_delete: str = args.get("mfa_delete", "")

        versioning_configuration = {"Status": status, "MFADelete": mfa_delete}
        remove_nulls_from_dictionary(versioning_configuration)
        try:
            response = client.put_bucket_versioning(Bucket=bucket, VersioningConfiguration=versioning_configuration)
            if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
                return CommandResults(
                    readable_output=f"Successfully {status.lower()} versioning configuration for bucket `{bucket}`"
                )
            return CommandResults(
                entry_type=EntryType.WARNING,
                readable_output=f"Request completed but received unexpected status code: {response['ResponseMetadata']['HTTPStatusCode']}",
            )
        except Exception as e:
            return CommandResults(
                entry_type=EntryType.ERROR,
                readable_output=f"Failed to update versioning configuration for bucket {bucket}. Error: {str(e)}",
            )


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
        data = json.loads(json.dumps(response["PasswordPolicy"], cls=DatetimeEncoder))

        human_readable = tableToMarkdown("AWS IAM Account Password Policy", data)

        return CommandResults(
            outputs=data, readable_output=human_readable, outputs_prefix="AWS.IAM.PasswordPolicy", outputs_key_field="AccountId"
        )

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
            kwargs = response["PasswordPolicy"]
        except Exception:
            return CommandResults(
                entry_type=EntryType.ERROR,
                readable_output=f"Couldn't check current account password policy for account: {args.get('account_id')}",
            )

        # ExpirePasswords is part of the response but cannot be included in the request
        if "ExpirePasswords" in kwargs:
            kwargs.pop("ExpirePasswords")

        command_args: dict[str, Union[int, bool, None]] = {
            "MinimumPasswordLength": arg_to_number(args.get("minimum_password_length")),
            "RequireSymbols": argToBoolean(args.get("require_symbols")) if args.get("require_symbols") else None,
            "RequireNumbers": argToBoolean(args.get("require_numbers")) if args.get("require_numbers") else None,
            "RequireUppercaseCharacters": argToBoolean(args.get("require_uppercase_characters"))
            if args.get("require_uppercase_characters")
            else None,
            "RequireLowercaseCharacters": argToBoolean(args.get("require_lowercase_characters"))
            if args.get("require_lowercase_characters")
            else None,
            "AllowUsersToChangePassword": argToBoolean(args.get("allow_users_to_change_password"))
            if args.get("allow_users_to_change_password")
            else None,
            "MaxPasswordAge": arg_to_number(args.get("max_password_age")),
            "PasswordReusePrevention": arg_to_number(args.get("password_reuse_prevention")),
            "HardExpiry": argToBoolean(args.get("hard_expiry")) if args.get("hard_expiry") else None,
        }

        remove_nulls_from_dictionary(command_args)
        for arg_key, arg_value in command_args.items():
            kwargs[arg_key] = arg_value

        response = client.update_account_password_policy(**kwargs)

        if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
            return CommandResults(
                readable_output=f"Successfully updated account password policy for account: {args.get('account_id')}"
            )
        else:
            return CommandResults(
                readable_output=f"Couldn't updated account password policy for account: {args.get('account_id')}"
            )
    
    @staticmethod
    def put_role_policy_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Adds or updates an inline policy document that is embedded in the specified IAM role.
    
        Args:
            client (BotoClient): The boto3 client for IAM service
            args (Dict[str, Any]): Command arguments including policy_document, policy_name, and role_name
            
        Returns:
            CommandResults: Results of the operation with success/failure message
        """
        policy_document: str = args.get('policy_document', '')
        policy_name: str = args.get('policy_name', '')
        role_name: str = args.get('role_name', '')
        kwargs = {
            "PolicyDocument": policy_document,
            "PolicyName": policy_name,
            "RoleName": role_name
        }

        try:
            response = client.put_user_policy(**kwargs)
            human_readable = f"Policy '{policy_name}' was successfully added to role '{role_name}'"
            return CommandResults(raw_response=response, readable_output=human_readable)
        except Exception as e:
            raise DemistoException(
                f"Failed to add policy '{policy_name}' to role '{role_name}'. Error: {str(e)}"
            )

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
            "InstanceId": args.get("instance_id"),
            "HttpTokens": args.get("http_tokens"),
            "HttpEndpoint": args.get("http_endpoint"),
        }
        remove_nulls_from_dictionary(kwargs)

        response = client.modify_instance_metadata_options(**kwargs)

        if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
            return CommandResults(readable_output=f"Successfully updated EC2 instance metadata for {args.get('instance_id')}")
        else:
            return CommandResults(
                entry_type=EntryType.ERROR,
                readable_output=f"Couldn't updated public EC2 instance metadata for {args.get('instance_id')}",
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
            "InstanceId": args.get("instance_id"),
            "Attribute": args.get("attribute"),
            "Value": args.get("value"),
            "DisableApiStop": arg_to_bool_or_none(args.get("disable_api_stop")),
            "Groups": parse_security_groups(args.get("groups")),
        }
        remove_nulls_from_dictionary(kwargs)
        response = client.modify_instance_attribute(**kwargs)

        if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
            return CommandResults(
                readable_output=f"Successfully modified EC2 instance `{args.get('instance_id')}` attribute `{kwargs.popitem()}"
            )
        raise DemistoException(f"Unexpected response from AWS - \n{response}")

    @staticmethod
    def modify_snapshot_permission_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Modifies permission for the specified snapshot
        """
        group_names = argToList(args.get("groupNames"))
        user_ids = argToList(args.get("userIds"))
        if (group_names and user_ids) or not (group_names or user_ids):
            raise DemistoException('Please provide either "groupNames" or "userIds"')

        accounts = assign_params(GroupNames=group_names, UserIds=user_ids)
        operation_type = args.get("operationType")
        response = client.modify_snapshot_attribute(
            Attribute="createVolumePermission",
            SnapshotId=args.get("snapshotId"),
            OperationType=operation_type,
            **accounts,
        )
        if response["ResponseMetadata"]["HTTPStatusCode"] != HTTPStatus.OK:
            raise DemistoException(f"Unexpected response from AWS - EC2:\n{response}")
        return CommandResults(readable_output=f"Snapshot {args.get('snapshotId')} permissions was successfully updated.")

    @staticmethod
    def modify_image_attribute_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Modify the specified attribute of an Amazon Machine Image (AMI).
        """
        # Build the base kwargs dictionary
        kwargs = {
            "Attribute": args.get("Attribute"),
            "ImageId": args.get("ImageId"),
            "Value": args.get("Value"),
            "OperationType": args.get("OperationType"),
        }

        # Add description if provided
        if args.get("Description"):
            kwargs["Description"] = {"Value": args.get("Description")}

        # Parse resource IDs
        for resource_type in ["UserIds", "UserGroups", "ProductCodes"]:
            if args.get(resource_type):
                kwargs[resource_type] = parse_resource_ids(args.get(resource_type))

        # Handle LaunchPermission configuration
        launch_permission = {"Add": [], "Remove": []}

        # Process Add permissions
        for permission_type in ["Group", "UserId"]:
            if value := args.get(f"LaunchPermission-Add-{permission_type}"):
                launch_permission["Add"].append({permission_type: value})

        # Process Remove permissions
        for permission_type in ["Group", "UserId"]:
            if value := args.get(f"LaunchPermission-Remove-{permission_type}"):
                launch_permission["Remove"].append({permission_type: value})

        # Only add LaunchPermission if any values were added
        if launch_permission["Add"] or launch_permission["Remove"]:
            kwargs["LaunchPermission"] = launch_permission

        remove_nulls_from_dictionary(kwargs)

        response = client.modify_image_attribute(**kwargs)
        if response["ResponseMetadata"]["HTTPStatusCode"] != HTTPStatus.OK:
            raise DemistoException(f"Unexpected response from AWS - EC2:\n{response}")
        return CommandResults(readable_output="Image attribute successfully modified")

    @staticmethod
    def revoke_security_group_ingress_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Revokes an ingress rule from a security group.

        The command supports two modes:
        1. Simple mode: using protocol, port, and cidr arguments
        2. Full mode: using ip_permissions for complex configurations
        """

        def parse_port_range(port: str) -> tuple[Optional[int], Optional[int]]:
            """Parse port argument which can be a single port or range (min-max)."""
            if not port:
                return None, None

            if "-" in port:
                from_port, to_port = port.split("-", 1)
                return int(from_port.strip()), int(to_port.strip())
            else:
                _port: int = int(port.strip())
                return _port, _port

        kwargs = {"GroupId": args.get("group_id"), "IpProtocol": args.get("protocol"), "CidrIp": args.get("cidr")}
        kwargs["FromPort"], kwargs["ToPort"] = parse_port_range(args.get("port", ""))

        if ip_permissions := args.get("ip_permissions"):
            try:
                kwargs["IpPermissions"] = json.loads(ip_permissions)
            except json.JSONDecodeError as e:
                raise DemistoException(f"Received invalid `ip_permissions` JSON object: {e}")

        remove_nulls_from_dictionary(kwargs)
        try:
            response = client.revoke_security_group_ingress(**kwargs)

            if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK and response["Return"]:
                if "UnknownIpPermissions" in response:
                    raise DemistoException("Security Group ingress rule not found.")
                return CommandResults(readable_output="The Security Group ingress rule was revoked")
            else:
                raise DemistoException(f"Unexpected response from AWS - EC2:\n{response}")

        except Exception as e:
            if "InvalidGroup.NotFound" in str(e):
                raise DemistoException(f"Security group {kwargs['GroupId']} not found")
            elif "InvalidGroupId.NotFound" in str(e):
                raise DemistoException(f"Invalid security group ID: {kwargs['GroupId']}")
            else:
                raise DemistoException(f"Failed to revoke security group ingress rule: {str(e)}")

    @staticmethod
    def authorize_security_group_ingress_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Adds an inbound rule to a security group.

        The command supports two modes:
        1. Simple mode: using protocol, port, and cidr arguments
        2. Full mode: using ip_permissions for complex configurations
        """

        def parse_port_range(port: str) -> tuple[Optional[int], Optional[int]]:
            """Parse port argument which can be a single port or range (min-max)."""
            if not port:
                return None, None

            if "-" in port:
                from_port, to_port = port.split("-", 1)
                return int(from_port.strip()), int(to_port.strip())
            else:
                _port: int = int(port.strip())
                return _port, _port

        kwargs = {"GroupId": args.get("group_id"), "IpProtocol": args.get("protocol"), "CidrIp": args.get("cidr")}
        kwargs["FromPort"], kwargs["ToPort"] = parse_port_range(args.get("port", ""))

        if ip_permissions := args.get("ip_permissions"):
            try:
                kwargs["IpPermissions"] = json.loads(ip_permissions)
            except json.JSONDecodeError as e:
                raise DemistoException(f"Received invalid `ip_permissions` JSON object: {e}")

        remove_nulls_from_dictionary(kwargs)
        try:
            response = client.authorize_security_group_ingress(**kwargs)

            if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK and response["Return"]:
                return CommandResults(readable_output="The Security Group ingress rule was authorized")
            else:
                raise DemistoException(f"Unexpected response from AWS - EC2:\n{response}")

        except Exception as e:
            if "InvalidGroup.NotFound" in str(e):
                raise DemistoException(f"Security group {kwargs['GroupId']} not found")
            elif "InvalidGroupId.NotFound" in str(e):
                raise DemistoException(f"Invalid security group ID: {kwargs['GroupId']}")
            elif "InvalidPermission.Duplicate" in str(e):
                raise DemistoException("The specified rule already exists in the security group")
            else:
                raise DemistoException(f"Failed to authorize security group ingress rule: {str(e)}")

    @staticmethod
    def revoke_security_group_egress_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Revokes an egress rule from a security group.

        The command supports two modes:
        1. Simple mode: using protocol, port, and cidr arguments
        2. Full mode: using ip_permissions for complex configurations
        """

        def parse_port_range(port: str) -> tuple[Optional[int], Optional[int]]:
            """Parse port argument which can be a single port or range (min-max)."""
            if not port:
                return None, None

            if "-" in port:
                from_port, to_port = port.split("-", 1)
                return int(from_port.strip()), int(to_port.strip())
            else:
                _port: int = int(port.strip())
                return _port, _port

        kwargs = {"GroupId": args.get("group_id"), "IpProtocol": args.get("protocol"), "CidrIp": args.get("cidr")}
        kwargs["FromPort"], kwargs["ToPort"] = parse_port_range(args.get("port", ""))

        if ip_permissions := args.get("ip_permissions"):
            try:
                kwargs["IpPermissions"] = json.loads(ip_permissions)
            except json.JSONDecodeError as e:
                raise DemistoException(f"Received invalid `ip_permissions` JSON object: {e}")

        remove_nulls_from_dictionary(kwargs)
        try:
            response = client.revoke_security_group_egress(**kwargs)

            if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK and response["Return"]:
                if "UnknownIpPermissions" in response:
                    raise DemistoException("Security Group egress rule not found.")
                return CommandResults(readable_output="The Security Group egress rule was revoked")
            else:
                raise DemistoException(f"Unexpected response from AWS - EC2:\n{response}")

        except Exception as e:
            if "InvalidGroup.NotFound" in str(e):
                raise DemistoException(f"Security group {kwargs['GroupId']} not found")
            elif "InvalidGroupId.NotFound" in str(e):
                raise DemistoException(f"Invalid security group ID: {kwargs['GroupId']}")
            else:
                raise DemistoException(f"Failed to revoke security group egress rule: {str(e)}")


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
            if resources_vpc_config := args.get("resources_vpc_config"):
                resources_vpc_config = (
                    json.loads(resources_vpc_config) if isinstance(resources_vpc_config, str) else resources_vpc_config
                )
                validated_args["resourcesVpcConfig"] = resources_vpc_config
                # Convert specific string boolean values to actual boolean values
                if isinstance(resources_vpc_config, dict):
                    if "endpointPublicAccess" in resources_vpc_config and isinstance(
                        resources_vpc_config["endpointPublicAccess"], str
                    ):
                        resources_vpc_config["endpointPublicAccess"] = (
                            resources_vpc_config["endpointPublicAccess"].lower() == "true"
                        )
                    if "endpointPrivateAccess" in resources_vpc_config and isinstance(
                        resources_vpc_config["endpointPrivateAccess"], str
                    ):
                        resources_vpc_config["endpointPrivateAccess"] = (
                            resources_vpc_config["endpointPrivateAccess"].lower() == "true"
                        )

            if logging_arg := args.get("logging"):
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
                    readable_output=f"Failed to modify DB cluster snapshot attribute. Status code: {response['ResponseMetadata']['HTTPStatusCode']}",
                )

        except Exception as e:
            return CommandResults(
                entry_type=EntryType.ERROR, readable_output=f"Error modifying DB cluster snapshot attribute: {str(e)}"
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
                "ApplyImmediately": arg_to_bool_or_none(args.get("apply_immediately")),
                "AutoMinorVersionUpgrade": arg_to_bool_or_none(args.get("auto_minor_version_upgrade")),
                "DeletionProtection": arg_to_bool_or_none(args.get("deletion_protection")),
                "EnableIAMDatabaseAuthentication": arg_to_bool_or_none(args.get("enable_iam_database_authentication")),
                "PubliclyAccessible": arg_to_bool_or_none(args.get("publicly_accessible")),
                "CopyTagsToSnapshot": arg_to_bool_or_none(args.get("copy_tags_to_snapshot")),
                "BackupRetentionPeriod": arg_to_bool_or_none(args.get("backup_retention_period")),
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
                    readable_output=f"Failed to modify DB instance. Status code: {response['ResponseMetadata']['HTTPStatusCode']}",
                )

        except Exception as e:
            return CommandResults(entry_type=EntryType.ERROR, readable_output=f"Error modifying DB instance: {str(e)}")

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
                readable_output=f"Couldn't modify DB snapshot attribute for {args.get('db_snapshot_identifier')}",
            )


# CONCURRENCY_LIMIT = 25           # Rate limit by AWS
# SEMAPHORE = asyncio.Semaphore(CONCURRENCY_LIMIT)

# async def fetch_permissions_for_account(account_id: str) -> set:
#     async with SEMAPHORE:
#         # TODO
#         await asyncio.sleep(0) # placeholder for the real awaitable

#     return set()

# async def check_permissions():
#     errors: list[CommandResults] = []

#     accounts: list[str] = get_accounts_by_connector_id(connector_id='1')
#     tasks = [asyncio.create_task(fetch_permissions_for_account(account)) for account in accounts]

#     for task in asyncio.as_completed(tasks):
#         try:
#             account_permissions = await task

#             for missing in REQUIRED_PERMISSIONS - account_permissions:
#                 errors.append(HealthCheckResult.error(
#                     account_id=account,
#                     connector_id=connector_id,
#                     message=f"Missing permission {missing}",
#                     error="ErrPermissionMissing", # TODO - enum it
#                     error_type=ErrorType.PERMISSION_ERROR,
#                 ))
#         except Exception as exc:
#             # Prefer logging to stdout/stderr or struct-logging here
#             print(f"[WARN] Account task failed: {exc!r}")
#     return []

# def health_check() -> list[CommandResults] | str:
#     """
#     """
#     errors: list[CommandResults] = asyncio.run(check_permissions())
#     return errors or HealthCheckResult.ok()

COMMANDS_MAPPING: dict[str, Callable[[BotoClient, Dict[str, Any]], CommandResults]] = {
    "aws-s3-public-access-block-put": S3.put_public_access_block_command,
    "aws-s3-bucket-versioning-put": S3.put_bucket_versioning_command,
    
    "aws-iam-account-password-policy-get": IAM.get_account_password_policy_command,
    "aws-iam-account-password-policy-update": IAM.update_account_password_policy_command,
    "aws-iam-role-policy-put": IAM.put_role_policy_command,
    
    "aws-ec2-instance-metadata-options-modify": EC2.modify_instance_metadata_options_command,
    "aws-ec2-instance-attribute-modify": EC2.modify_instance_attribute_command,
    # "aws-ec2-snapshot-attribute-modify": EC2.modify_snapshot_attribute_command,
    "aws-ec2-image-attribute-modify": EC2.modify_image_attribute_command,
    "aws-ec2-security-group-ingress-revoke": EC2.revoke_security_group_ingress_command,
    "aws-ec2-security-group-ingress-authorize": EC2.authorize_security_group_ingress_command,
    
    "aws-eks-cluster-config-update": EKS.update_cluster_config_command,
    
    "aws-rds-db-cluster-modify": RDS.modify_db_cluster_command,
    "aws-rds-db-cluster-snapshot-attribute-modify": RDS.modify_db_cluster_command,
    "aws-rds-db-instance-modify": RDS.modify_db_instance_command,
    "aws-rds-db-snapshot-attribute-modify": RDS.modify_db_snapshot_attribute_command,
}

REQUIRED_ACTIONS: set[str] = {
    "iam:PassRole",
    "kms:CreateGrant",
    "kms:Decrypt",
    "kms:DescribeKey",
    "kms:GenerateDataKey",
    "rds:AddTagsToResource",
    "rds:CreateTenantDatabase",
    "secretsmanager:CreateSecret",
    "secretsmanager:RotateSecret",
    "secretsmanager:TagResource",
    "rds:ModifyDBCluster",
    "rds:ModifyDBClusterSnapshotAttribute",
    "rds:ModifyDBInstance",
    "rds:ModifyDBSnapshotAttribute",
    "s3:PutBucketAcl",
    "s3:PutBucketLogging",
    "s3:PutBucketVersioning",
    "s3:PutBucketPolicy",
    "ec2:RevokeSecurityGroupEgress",
    "ec2:ModifyImageAttribute",
    "ec2:ModifyInstanceAttribute",
    "ec2:ModifySnapshotAttribute",
    "ec2:RevokeSecurityGroupIngress",
    "eks:UpdateClusterConfig",
    "iam:DeleteLoginProfile",
    "iam:PutUserPolicy",
    "iam:RemoveRoleFromInstanceProfile",
    "iam:UpdateAccessKey",
    "iam:GetAccountPasswordPolicy",
    "iam:UpdateAccountPasswordPolicy",
    "s3:PutBucketPublicAccessBlock",
    "ec2:ModifyInstanceMetadataOptions",
    "iam:GetAccountAuthorizationDetails",
}


def check_account_permissions(account_id: str) -> HealthCheckError | None:
    """_summary_"""
    pass

def health_check(connector_id: str):
    accounts: list[dict] = get_accounts_by_connector_id(connector_id)
    account_ids: list[str] = [str(account.get("account_id")) for account in accounts if "account_id" in account]

    health_check = HealthCheck(connector_id)

    for account_id in account_ids:
        check_account_permissions(account_id)
        # TODO - TEST ERROR - REPLACE
        health_check.error(
            HealthCheckError(
                account_id=account_id,
                connector_id=connector_id,
                message=f"[BYOSI] Missing 'S3:GetObject' permission for {account_id}",
                error_type=ErrorType.PERMISSION_ERROR,
            )
        )

    return health_check.summarize()


def register_proxydome_header(boto_client: BotoClient) -> None:
    """
    Register ProxyDome authentication header for all AWS API requests.

    This function adds the ProxyDome caller ID header to every boto3 request
    by registering an event handler that injects the header before sending requests.

    Args:
        boto_client (BotoClient): The boto3 client to configure with ProxyDome headers
    """
    event_system = boto_client.meta.events
    proxydome_token: str = get_proxydome_token()

    def _add_proxydome_header(request, **kwargs):
        request.headers["x-caller-id"] = proxydome_token

    # Register the header injection function to be called before each request
    event_system.register_last("before-send.*.*", _add_proxydome_header)


def get_service_client(params: dict, args: dict, command: str, credentials: dict) -> BotoClient:
    """
    Create and configure a boto3 client for the specified AWS service.

    Args:
        params (dict): Integration configuration parameters
        args (dict): Command arguments containing region information
        command (str): AWS command name used to determine the service type
        credentials (dict): AWS credentials (access key, secret key, session token)

    Returns:
        BotoClient: Configured boto3 client with ProxyDome headers and proxy settings
    """
    aws_session: Session = Session(
        aws_access_key_id=credentials.get("key") or params.get("access_key_id"),
        aws_secret_access_key=credentials.get("access_token") or params.get("secret_access_key", {}).get("password"),
        aws_session_token=credentials.get("session_token"),
        region_name=args.get("region") or params.get("region", ""),
    )

    service = AWSServices(command.split("-")[1])

    client_config = Config(
        proxies={"https": DEFAULT_PROXYDOME}, 
        proxies_config={"proxy_ca_bundle": DEFAULT_PROXYDOME_CERTFICATE_PATH})
    client = aws_session.client(service, verify=False, config=client_config)

    register_proxydome_header(client)

    return client


def execute_aws_command(command: str, args: dict, params: dict) -> CommandResults:
    """
    Execute an AWS command by retrieving credentials, creating a service client, 
    and routing to the appropriate service handler.

    Args:
        command (str): The AWS command to execute (e.g., "aws-s3-public-access-block-put")
        args (dict): Command arguments including account_id, region, and service-specific parameters
        params (dict): Integration configuration parameters

    Returns:
        CommandResults: Command execution results with outputs and status
    """
    account_id: str = args.get("account_id", "")

    credentials = get_cloud_credentials(CloudTypes.AWS.value, account_id) if True else {}
    demisto.debug(f"cloud_creds: {json.dumps(credentials, indent=4)}")  # TODO - Remove
    service_client: BotoClient = get_service_client(params, args, command, credentials)
    return COMMANDS_MAPPING[command](service_client, args)


def main():  # pragma: no cover
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f"Params: {params}")
    demisto.debug(f"Command: {command}")
    demisto.debug(f"Args: {args}")
    skip_proxy()

    try:
        if command == "test-module":
            context = demisto.callingContext.get("context", {})
            cloud_info = context.get("CloudIntegrationInfo", {})
            results = health_check(connector_id) if (connector_id := cloud_info.get("connectorID")) else None
            return_results(results)

        elif command in COMMANDS_MAPPING:
            return_results(execute_aws_command(command, args, params))

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
