import demistomock as demisto
from AWSApiModule import *  # noqa: E402
# TODO - Enable # from COOCApiModule import * # noqa: E402
from CommonServerPython import *
from http import HTTPStatus
from datetime import date
from collections.abc import Callable
from botocore.client import BaseClient as BotoBaseClient
from boto3 import Session

DEFAULT_MAX_RETRIES: int = 5
DEFAULT_SESSION_NAME = "cortex-session"
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


# TODO - Shall we put it in AWSApiModule? ***


def create_policy_kwargs_dict(args):
    policy_kwargs_keys = (("fromPort", "FromPort"), ("toPort", "ToPort"))
    policy_kwargs = {}
    for args_key, dict_key in policy_kwargs_keys:
        if key := args.get(args_key):
            policy_kwargs.update({dict_key: arg_to_number(key)})
    policy_kwargs_keys = (
        ("cidrIp", "CidrIp"),
        ("ipProtocol", "IpProtocol"),
        ("sourceSecurityGroupName", "SourceSecurityGroupName"),
        ("SourceSecurityGroupOwnerId", "SourceSecurityGroupOwnerId"),
        ("cidrIpv6", "CidrIpv6"),
    )
    for args_key, dict_key in policy_kwargs_keys:
        if args.get(args_key) is not None:
            policy_kwargs.update({dict_key: args.get(args_key)})
    return policy_kwargs


def parse_resource_ids(resource_id):
    id_list = resource_id.replace(" ", "")
    resourceIds = id_list.split(",")
    return resourceIds


def create_ip_permissions_dict(args):
    IpPermissions_dict: dict[str, Any] = {}
    UserIdGroupPairs_keys = (("IpPermissionsfromPort", "FromPort"), ("IpPermissionsToPort", "ToPort"))
    for args_key, dict_key in UserIdGroupPairs_keys:
        if args.get(args_key) is not None:
            IpPermissions_dict.update({dict_key: int(args.get(args_key))})

    if args.get("IpPermissionsIpProtocol") is not None:
        IpPermissions_dict.update({"IpProtocol": str(args.get("IpPermissionsIpProtocol"))})

    if args.get("IpRangesCidrIp") is not None:
        IpRanges_dict = {"CidrIp": args.get("IpRangesCidrIp")}
        desc = args.get("IpRangesDesc", "") or args.get("IpRangesDescription", "")
        if desc:
            IpRanges_dict["Description"] = desc
        IpPermissions_dict.update({"IpRanges": [IpRanges_dict]})  # type: ignore
    if args.get("Ipv6RangesCidrIp") is not None:
        Ipv6Ranges_dict = {"CidrIp": args.get("Ipv6RangesCidrIp")}
        desc = args.get("Ipv6RangesDesc", "") or args.get("Ipv6RangesDescription", "")
        if desc:
            Ipv6Ranges_dict["Description"] = desc
        IpPermissions_dict.update({"Ipv6Ranges": [Ipv6Ranges_dict]})  # type: ignore
    if args.get("PrefixListId") is not None:
        PrefixListIds_dict = {"PrefixListId": args.get("PrefixListId")}
        desc = args.get("PrefixListIdDesc", "") or args.get("PrefixListIdDescription", "")
        if desc:
            PrefixListIds_dict["Description"] = desc
        IpPermissions_dict.update({"PrefixListIds": [PrefixListIds_dict]})  # type: ignore
    return IpPermissions_dict


def create_user_id_group_pairs_dict(args):
    UserIdGroupPairs_dict = {}
    UserIdGroupPairs_keys = (
        ("UserIdGroupPairsDescription", "Description"),
        ("UserIdGroupPairsGroupId", "GroupId"),
        ("UserIdGroupPairsGroupName", "GroupName"),
        ("UserIdGroupPairsPeeringStatus", "PeeringStatus"),
        ("UserIdGroupPairsUserId", "UserId"),
        ("UserIdGroupPairsVpcId", "VpcId"),
        ("UserIdGroupPairsVpcPeeringConnectionId", "VpcPeeringConnectionId"),
    )
    for args_key, dict_key in UserIdGroupPairs_keys:
        if args.get(args_key) is not None:
            UserIdGroupPairs_dict.update({dict_key: args.get(args_key)})
    return UserIdGroupPairs_dict

def get_client(params, command_args):
    """
    Creates an AWS client with the provided authentication parameters.

    Args:
        params (dict): Integration parameters containing AWS credentials and configuration.
        command_args (dict): Command arguments which may include account_id for role assumption.

    Returns:
        AWSClient: Configured AWS client object.

    Raises:
        DemistoException: If required parameters for authentication are missing.
    """

    # Role assumption parameters

    # Credentials
    aws_access_key_id = params.get("access_key_id")
    aws_secret_access_key = params.get("secret_access_key")
    # Session configuration
    aws_role_session_name = params.get("role_session_name") or DEFAULT_SESSION_NAME
    aws_role_session_duration = params.get("session_duration")
    aws_role_policy = None
    aws_session_token = None

    # Handle role-based authentication if credentials not provided directly
    aws_role_arn = None
    if not (aws_access_key_id and aws_secret_access_key):
        if aws_role_name := params.get("role_name"):
            if account_id := command_args.get("account_id"):
                aws_role_arn = f"arn:aws:iam::{account_id}:role/{aws_role_name}"
                aws_role_session_name = params.get("role_session_name") or "cortex-session"
                aws_role_session_duration = params.get("session_duration")
                # Reset access keys when using role
                aws_access_key_id = aws_secret_access_key = None
            else:
                raise DemistoException("For role-based authentication, 'account_id' must be provided")
        else:
            raise DemistoException("Either direct credentials or role-based authentication must be configured")
        demisto.debug(f"Using role-based authentication with role ARN: {aws_role_arn}")
    else:
        demisto.debug("Using direct AWS credentials for authentication")

    aws_default_region = command_args.get("region") or params.get("region")

    # Connection parameters
    verify_certificate = not argToBoolean(params.get("insecure", "True"))
    timeout = params.get("timeout")
    retries = int(params.get("retries", DEFAULT_MAX_RETRIES))

    # Endpoint configuration
    sts_endpoint_url = params.get("sts_endpoint_url")
    endpoint_url = params.get("endpoint_url")

    demisto.debug(f"Creating AWS client with region: {aws_default_region}, endpoint: {endpoint_url}, retries: {retries}")

    client = AWSClient(
        aws_default_region,
        aws_role_arn,
        aws_role_session_name,
        aws_role_session_duration,
        aws_role_policy,
        aws_access_key_id,
        aws_secret_access_key,
        verify_certificate,
        timeout,
        retries,
        aws_session_token,
        sts_endpoint_url,
        endpoint_url,
    )
    return client


def get_client_session(aws_client: AWSClient, service: str, args: Dict[str, Any]) -> BotoBaseClient:
    session = aws_client.aws_session(service=service, region=args.get("region"))
    return session


class S3:
    """
    Simple Storage Service
    """

    def __init__(self, aws_client: AWSClient, args: Dict[str, Any]):
        self.client_session: BotoBaseClient = get_client_session(aws_client, "s3", args)

    def put_public_access_block_command(self, args: Dict[str, Any]) -> CommandResults:
        """_summary_

        Args:
            args (Dict[str, Any]): _description_

        Returns:
            CommandResults: _description_
        """
        try:
            response = self.client_session.get_public_access_block(Bucket=args.get("bucket"))
            public_access_block_configuration = response.get("PublicAccessBlockConfiguration")
            kwargs = {
                "BlockPublicAcls": public_access_block_configuration.get("BlockPublicAcls"),
                "IgnorePublicAcls": public_access_block_configuration.get("IgnorePublicAcls"),
                "BlockPublicPolicy": public_access_block_configuration.get("BlockPublicPolicy"),
                "RestrictPublicBuckets": public_access_block_configuration.get("RestrictPublicBuckets"),
            }
        except Exception:
            return CommandResults(
                readable_output=f"Couldn't check current public access block to the {args.get('bucket')} bucket"
            )

        command_args: dict[str, Union[bool, None]] = {
            "BlockPublicAcls": argToBoolean(args.get("block_public_acls")) if "block_public_acls" in args else None,
            "IgnorePublicAcls": argToBoolean(args.get("ignore_public_acls")) if "ignore_public_acls" in args else None,
            "BlockPublicPolicy": argToBoolean(args.get("block_public_policy")) if "block_public_policy" in args else None,
            "RestrictPublicBuckets": argToBoolean(args.get("restrict_public_buckets"))
            if "restrict_public_buckets" in args
            else None,
        }

        remove_nulls_from_dictionary(command_args)
        for arg_key, arg_value in command_args.items():
            kwargs[arg_key] = arg_value

        response = self.client_session.put_public_access_block(Bucket=args.get("bucket"), PublicAccessBlockConfiguration=kwargs)

        if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
            return CommandResults(readable_output=f"Successfully applied public access block to the {args.get('bucket')} bucket")
        return CommandResults(
            readable_output=f"Request completed but received unexpected status code: {response['ResponseMetadata']['HTTPStatusCode']}"
        )

    def put_bucket_acl_command(self, args: Dict[str, Any]) -> CommandResults:
        """_summary_

        Args:
            args (Dict[str, Any]): _description_

        Returns:
            CommandResults: _description_
        """
        acl, bucket = args.get("acl"), args.get("bucket")
        response = self.client_session.put_bucket_acl(Bucket=bucket, ACL=acl)
        if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
            return CommandResults(f"Successfully updated ACL for bucket {bucket} to '{acl}'")
        return CommandResults(
            f"Request completed but received unexpected status code: {response['ResponseMetadata']['HTTPStatusCode']}"
        )

    def put_bucket_logging_command(self, args: Dict[str, Any]) -> CommandResults:
        """
        Enables/configures logging for an S3 bucket.

        Args:
            args (Dict[str, Any]): Command arguments including:
                - bucket (str): The name of the bucket to configure logging for
                - bucket-logging-status (str, optional): JSON string containing logging configuration
                - target-bucket (str, optional): The target bucket where logs will be stored
                - target_prefix (str, optional): The prefix for log objects in the target bucket

        Returns:
            CommandResults: Results of the command execution
        """
        bucket = args.get("bucket")
        if not bucket:
            return CommandResults(readable_output="Error: 'bucket' parameter is required")

        try:
            # Handle both options: full JSON configuration or individual parameters
            if args.get("bucket-logging-status"):
                try:
                    bucket_logging_status = json.loads(args.get("bucket-logging-status"))
                except json.JSONDecodeError:
                    return CommandResults(readable_output="Error: 'bucket-logging-status' must be a valid JSON string")
            elif args.get("target-bucket"):
                # Build configuration from individual parameters
                bucket_logging_status = {
                    "LoggingEnabled": {"TargetBucket": args.get("target-bucket"), "TargetPrefix": args.get("target_prefix", "")}
                }
            else:
                # If neither full config nor target bucket provided, disable logging
                bucket_logging_status = {}

            response = self.client_session.put_bucket_logging(Bucket=bucket, BucketLoggingStatus=bucket_logging_status)

            if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
                if bucket_logging_status.get("LoggingEnabled"):
                    target_bucket = bucket_logging_status["LoggingEnabled"].get("TargetBucket", "")
                    target_prefix = bucket_logging_status["LoggingEnabled"].get("TargetPrefix", "")
                    return CommandResults(
                        readable_output=f"Successfully enabled logging for bucket '{bucket}'. Logs will be stored in '{target_bucket}/{target_prefix}'."
                    )
                else:
                    return CommandResults(readable_output=f"Successfully disabled logging for bucket '{bucket}'")

            return CommandResults(
                entry_type=EntryType.WARNING,
                readable_output=f"Request completed but received unexpected status code: {response['ResponseMetadata']['HTTPStatusCode']}",
            )

        except Exception as e:
            return CommandResults(
                entry_type=EntryType.ERROR, readable_output=f"Failed to configure logging for bucket '{bucket}'. Error: {str(e)}"
            )

    def put_bucket_versioning_command(self, args: Dict[str, Any]) -> CommandResults:
        """
        Set the versioning state of an Amazon S3 bucket.

        Args:
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
            response = self.client_session.put_bucket_versioning(Bucket=bucket, VersioningConfiguration=versioning_configuration)

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

    def put_bucket_policy_command(self, args: Dict[str, Any]) -> CommandResults:
        """_summary_

        Args:
            args (Dict[str, Any]): _description_

        Returns:
            CommandResults: _description_
        """
        kwargs = {"Bucket": args.get("bucket", "").lower(), "Policy": json.dumps(args.get("policy"))}
        if args.get("confirmRemoveSelfBucketAccess") is not None:
            kwargs.update({"ConfirmRemoveSelfBucketAccess": args.get("confirmRemoveSelfBucketAccess") == "True"})

        try:
            response = self.client_session.put_bucket_policy(**kwargs)
            if response["ResponseMetadata"]["HTTPStatusCode"] in [HTTPStatus.OK, HTTPStatus.NO_CONTENT]:
                return CommandResults(readable_output=f"Successfully applied bucket policy to {args.get('bucket')} bucket")
            return CommandResults(
                entry_type=EntryType.ERROR,
                readable_output=f"Couldn't apply bucket policy to {args.get('bucket')} bucket. Status code: {response['ResponseMetadata']['HTTPStatusCode']}, Response: {json.dumps(response)}",
            )
        except Exception as e:
            return CommandResults(
                entry_type=EntryType.ERROR,
                readable_output=f"Couldn't apply bucket policy to {args.get('bucket')} bucket. Error: {str(e)}",
            )


class IAM:
    """
    Identity & Access Management
    """

    def __init__(self, aws_client: AWSClient, args: Dict[str, Any]):
        self.client_session: BotoBaseClient = get_client_session(aws_client, "iam", args)

    def get_account_password_policy_command(self, args: Dict[str, Any]) -> CommandResults:
        """_summary_

        Args:
            args (Dict[str, Any]): _description_

        Returns:
            CommandResults: _description_
        """
        response = self.client_session.get_account_password_policy()
        data = json.loads(json.dumps(response["PasswordPolicy"], cls=DatetimeEncoder))

        human_readable = tableToMarkdown("AWS IAM Account Password Policy", data)

        return CommandResults(
            outputs=data, readable_output=human_readable, outputs_prefix="AWS.IAM.PasswordPolicy", outputs_key_field="AccountId"
        )

    def update_account_password_policy_command(self, args: Dict[str, Any]) -> CommandResults:
        """_summary_

        Args:
            args (Dict[str, Any]): _description_

        Returns:
            CommandResults: _description_
        """
        try:
            response = self.client_session.get_account_password_policy()
            kwargs = response["PasswordPolicy"]
        except Exception:
            return CommandResults(
                readable_output=f"Couldn't check current account password policy for account: {args.get('account_id')}"
            )

        # ExpirePasswords is part of the response but cannot be included in the request
        if "ExpirePasswords" in kwargs:
            kwargs.pop("ExpirePasswords")

        command_args: Dict[str, tuple[str, Callable[[Any], Any]]] = {
            "minimum_password_length": ("MinimumPasswordLength", arg_to_number),
            "require_symbols": ("RequireSymbols", argToBoolean),
            "require_numbers": ("RequireNumbers", argToBoolean),
            "require_uppercase_characters": ("RequireUppercaseCharacters", argToBoolean),
            "require_lowercase_characters": ("RequireLowercaseCharacters", argToBoolean),
            "allow_users_to_change_password": ("AllowUsersToChangePassword", argToBoolean),
            "max_password_age": ("MaxPasswordAge", arg_to_number),
            "password_reuse_prevention": ("PasswordReusePrevention", arg_to_number),
            "hard_expiry": ("HardExpiry", argToBoolean),
        }

        remove_nulls_from_dictionary(args)
        for arg_key, (kwarg_key, converter_func) in command_args.items():
            if arg_key in args:
                kwargs[kwarg_key] = converter_func(args[arg_key])

        response = self.client_session.update_account_password_policy(**kwargs)

        if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
            return CommandResults(
                readable_output=f"Successfully updated account password policy for account: {args.get('account_id')}"
            )
        else:
            return CommandResults(
                readable_output=f"Couldn't updated account password policy for account: {args.get('account_id')}"
            )


class EC2:
    """
    Elastic Compute Cloud
    """

    def __init__(self, aws_client: AWSClient, args: Dict[str, Any]):
        self.client_session: BotoBaseClient = get_client_session(aws_client, "ec2", args)

    def instance_metadata_options_modify_command(self, args: Dict[str, Any]) -> CommandResults:
        """_summary_

        Args:
            args (Dict[str, Any]): _description_

        Returns:
            CommandResults: _description_
        """
        kwargs = {
            "InstanceId": args.get("instance_id"),
            "HttpTokens": args.get("http_tokens"),
            "HttpEndpoint": args.get("http_endpoint"),
        }
        remove_nulls_from_dictionary(kwargs)

        response = self.client_session.modify_instance_metadata_options(**kwargs)

        if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
            return CommandResults(readable_output=f"Successfully updated EC2 instance metadata for {args.get('instance_id')}")
        else:
            return CommandResults(readable_output=f"Couldn't updated public EC2 instance metadata for {args.get('instance_id')}")

    def revoke_security_group_ingress_command(self, args: Dict[str, Any]) -> CommandResults:
        kwargs = {"GroupId": args.get("groupId")}
        if IpPermissionsFull := args.get("IpPermissionsFull", None):
            IpPermissions = json.loads(IpPermissionsFull)
            kwargs["IpPermissions"] = IpPermissions
        else:
            kwargs.update(create_policy_kwargs_dict(args))

        response = self.client_session.revoke_security_group_ingress(**kwargs)
        if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK and response["Return"]:
            if "UnknownIpPermissions" in response:
                raise DemistoException("Security Group ingress rule not found.")
            return CommandResults(readable_output="The Security Group ingress rule was revoked")
        else:
            raise DemistoException(f"Unexpected response from AWS - EC2:\n{response}")

    def modify_snapshot_permission_command(self, args: Dict[str, Any]) -> CommandResults:
        """
        Modifies permission for the specified snapshot

        Args:
            args: Command arguments from XSOAR

        Returns:
            CommandResults: results with output readable by War Room
        """
        group_names = argToList(args.get("groupNames"))
        user_ids = argToList(args.get("userIds"))
        if (group_names and user_ids) or not (group_names or user_ids):
            raise DemistoException('Please provide either "groupNames" or "userIds"')

        accounts = assign_params(GroupNames=group_names, UserIds=user_ids)

        operation_type = args.get("operationType")
        response = self.client_session.modify_snapshot_attribute(
            Attribute="createVolumePermission",
            SnapshotId=args.get("snapshotId"),
            OperationType=operation_type,
            DryRun=argToBoolean(args.get("dryRun", False)),
            **accounts,
        )
        if response["ResponseMetadata"]["HTTPStatusCode"] != HTTPStatus.OK:
            raise DemistoException(f"Unexpected response from AWS - EC2:\n{response}")
        return CommandResults(readable_output=f"Snapshot {args.get('snapshotId')} permissions was successfully updated.")

    def modify_instance_attribute_command(self, args: Dict[str, Any]) -> CommandResults:
        """
        Modifies an attribute of an instance.

        Args:
            args (dict): The command arguments containing the instance ID and attributes to modify

        Returns:
            CommandResults: A CommandResults object with the operation result
        """
        kwargs = {"InstanceId": args.get("instanceId")}
        if args.get("sourceDestCheck") is not None:
            kwargs.update({"SourceDestCheck": {"Value": argToBoolean(args.get("sourceDestCheck"))}})
        if args.get("disableApiTermination") is not None:
            kwargs.update({"DisableApiTermination": {"Value": argToBoolean(args.get("disableApiTermination"))}})
        if args.get("ebsOptimized") is not None:
            kwargs.update({"EbsOptimized": {"Value": argToBoolean(args.get("ebsOptimized"))}})
        if args.get("enaSupport") is not None:
            kwargs.update({"EnaSupport": {"Value": argToBoolean(args.get("enaSupport"))}})
        if args.get("instanceType") is not None:
            kwargs.update({"InstanceType": {"Value": args.get("instanceType")}})
        if args.get("instanceInitiatedShutdownBehavior") is not None:
            kwargs.update({"InstanceInitiatedShutdownBehavior": {"Value": args.get("instanceInitiatedShutdownBehavior")}})
        if args.get("groups") is not None:
            kwargs.update({"Groups": parse_resource_ids(args.get("groups"))})

        response = self.client_session.modify_instance_attribute(**kwargs)
        if response["ResponseMetadata"]["HTTPStatusCode"] != HTTPStatus.OK:
            raise DemistoException(f"Unexpected response from AWS - EC2:\n{response}")
        return CommandResults(readable_output="The Instance attribute was successfully modified")

    def modify_image_attribute_command(self, args: Dict[str, Any]) -> CommandResults:
        """_summary_

        Args:
            args (Dict[str, Any]): _description_

        Raises:
            DemistoException: _description_

        Returns:
            CommandResults: _description_
        """
        kwargs = {}

        if args.get("Attribute") is not None:
            kwargs.update({"Attribute": args.get("Attribute")})
        if args.get("Description") is not None:
            kwargs.update({"Description": {"Value": args.get("Description")}})
        if args.get("ImageId") is not None:
            kwargs.update({"ImageId": args.get("ImageId")})

        LaunchPermission = {"Add": [], "Remove": []}  # type: dict
        if args.get("LaunchPermission-Add-Group") is not None:
            LaunchPermission["Add"].append({"Group": args.get("LaunchPermission-Add-Group")})
        if args.get("LaunchPermission-Add-UserId") is not None:
            LaunchPermission["Add"].append({"UserId": args.get("LaunchPermission-Add-UserId")})

        if args.get("LaunchPermission-Remove-Group") is not None:
            LaunchPermission["Remove"].append({"Group": args.get("LaunchPermission-Remove-Group")})
        if args.get("LaunchPermission-Remove-UserId") is not None:
            LaunchPermission["Remove"].append({"UserId": args.get("LaunchPermission-Remove-UserId")})

        if LaunchPermission:
            kwargs.update({"LaunchPermission": LaunchPermission})

        if args.get("OperationType") is not None:
            kwargs.update({"OperationType": args.get("OperationType")})
        if args.get("ProductCodes") is not None:
            kwargs.update({"ProductCodes": parse_resource_ids(args.get("ProductCodes"))})
        if args.get("UserGroups") is not None:
            kwargs.update({"UserGroups": parse_resource_ids(args.get("UserGroups"))})
        if args.get("UserIds") is not None:
            kwargs.update({"UserIds": parse_resource_ids(args.get("UserIds"))})
        if args.get("Value") is not None:
            kwargs.update({"Value": args.get("Value")})

        response = self.client_session.modify_image_attribute(**kwargs)
        if response["ResponseMetadata"]["HTTPStatusCode"] != HTTPStatus.OK:
            raise DemistoException(f"Unexpected response from AWS - EC2:\n{response}")
        return CommandResults(readable_output="Image attribute successfully modified")

    def revoke_security_group_egress_command(self, args: Dict[str, Any]) -> CommandResults:
        """
        Revokes a security group egress rule.

        Args:
            args (dict): Command arguments from XSOAR.

        Returns:
            CommandResults: Output for XSOAR.
        """
        kwargs = {"GroupId": args.get("groupId")}

        if IpPermissionsFull := args.get("IpPermissionsFull"):
            IpPermissions = json.loads(IpPermissionsFull)
            kwargs["IpPermissions"] = IpPermissions
        else:
            IpPermissions_dict = create_ip_permissions_dict(args)
            UserIdGroupPairs_dict = create_user_id_group_pairs_dict(args)

            IpPermissions_dict["UserIdGroupPairs"] = [UserIdGroupPairs_dict]
            kwargs["IpPermissions"] = [IpPermissions_dict]

        response = self.client_session.revoke_security_group_egress(**kwargs)
        if not (response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK and response["Return"]):
            demisto.debug(response.message)
            raise DemistoException(f"An error has occurred: {response}")
        if "UnknownIpPermissions" in response:
            raise DemistoException("Security Group egress rule not found.")
        demisto.info(f"the response is: {response}")
        return CommandResults(readable_output="The Security Group egress rule was revoked")


class RDS:
    """
    Relational Database Services
    """

    def __init__(self, aws_client: AWSClient, args: Dict[str, Any]):
        self.client_session: BotoBaseClient = get_client_session(aws_client, "rds", args)

    def modify_db_cluster_command(self, args: Dict[str, Any]) -> CommandResults:
        """
        Modifies settings for an Amazon RDS DB cluster.

        Args:
            args (Dict[str, Any]): Command arguments including:
                - db-cluster-identifier (str): The identifier of the DB cluster to modify
                - deletion-protection (str, optional): Enable/disable deletion protection
                - enable-iam-database-authentication (str, optional): Enable/disable IAM database authentication

        Returns:
            CommandResults: Results of the command execution to be displayed in XSOAR
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

            response = self.client_session.modify_db_cluster(**kwargs)

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

    def modify_db_cluster_snapshot_attribute_command(self, args: Dict[str, Any]) -> CommandResults:
        """
        Modifies the attributes of a DB cluster snapshot.

        Args:
            args (Dict[str, Any]): Command arguments including:
                - account_id: AWS account ID
                - region: AWS region
                - db-cluster-snapshot-identifier: The identifier for the DB cluster snapshot
                - attribute-name: The name of the DB cluster snapshot attribute to modify
                - values-to-remove: List of DB cluster snapshot attributes to remove
                - values-to-add: List of DB cluster snapshot attributes to add

        Returns:
            CommandResults: The results of the command execution
        """
        try:
            kwargs = {
                "DBClusterSnapshotIdentifier": args.get("db-cluster-snapshot-identifier"),
                "AttributeName": args.get("attribute-name"),
            }

            # Optional parameters
            if "values-to-add" in args:
                kwargs["ValuesToAdd"] = argToList(args.get("values-to-add"))

            if "values-to-remove" in args:
                kwargs["ValuesToRemove"] = argToList(args.get("values-to-remove"))

            remove_nulls_from_dictionary(kwargs)

            response = self.client_session.modify_db_cluster_snapshot_attribute(**kwargs)

            if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
                attributes = response.get("DBClusterSnapshotAttributesResult", {})

                readable_output = (
                    f"Successfully modified DB cluster snapshot attribute for {args.get('db-cluster-snapshot-identifier')}"
                )

                if attributes:
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
                    readable_output=f"Failed to modify DB cluster snapshot attribute. Status code: {response['ResponseMetadata']['HTTPStatusCode']}"
                )

        except Exception as e:
            return CommandResults(readable_output=f"Error modifying DB cluster snapshot attribute: {str(e)}")

    def modify_db_instance_command(self, args: Dict[str, Any]) -> CommandResults:
        """_summary_

        Args:
            args (Dict[str, Any]): _description_

        Returns:
            CommandResults: _description_
        """
        try:
            kwargs = {
                "DBInstanceIdentifier": args.get("db-instance-identifier"),
            }

            # Optional parameters
            optional_params = {
                "PubliclyAccessible": "publicly-accessible",
                "CopyTagsToSnapshot": "copy-tags-to-snapshot",
                "BackupRetentionPeriod": "backup-retention-period",
                "EnableIAMDatabaseAuthentication": "enable-iam-database-authentication",
                "DeletionProtection": "deletion-protection",
                "AutoMinorVersionUpgrade": "auto-minor-version-upgrade",
                "MultiAZ": "multi-az",
                "ApplyImmediately": "apply-immediately",
            }

            for param, arg_name in optional_params.items():
                if arg_name in args:
                    kwargs[param] = argToBoolean(args[arg_name]) if param in optional_params else args[arg_name]

            response = self.client_session.modify_db_instance(**kwargs)

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
                    readable_output=f"Failed to modify DB instance. Status code: {response['ResponseMetadata']['HTTPStatusCode']}"
                )

        except Exception as e:
            return CommandResults(readable_output=f"Error modifying DB instance: {str(e)}")

    def modify_db_snapshot_attribute_command(self, args: Dict[str, Any]) -> CommandResults:
        """_summary_

        Args:
            args (Dict[str, Any]): _description_

        Returns:
            CommandResults: _description_
        """
        kwargs = {
            "DBSnapshotIdentifier": args.get("db_snapshot_identifier"),
            "AttributeName": args.get("attribute_name"),
            "ValuesToAdd": argToList(args.get("values_to_add")) if "values_to_add" in args else None,
            "ValuesToRemove": argToList(args.get("values_to_remove")) if "values_to_remove" in args else None,
        }
        remove_nulls_from_dictionary(kwargs)

        response = self.client_session.modify_db_snapshot_attribute(**kwargs)

        if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
            # Return the changed fields in the command results:
            return CommandResults(
                readable_output=f"Successfully modified DB snapshot attribute for {args.get('db_snapshot_identifier')}:\n{tableToMarkdown('Modified', kwargs)}"
            )

        else:
            return CommandResults(
                readable_output=f"Couldn't modify DB snapshot attribute for {args.get('db_snapshot_identifier')}"
            )


class EKS:
    """
    Elastic Kubernetes Service
    """

    def __init__(self, aws_client: AWSClient, args: Dict[str, Any]):
        self.client_session: BotoBaseClient = get_client_session(aws_client, "eks", args)

    def update_cluster_config_command(self, args: Dict[str, Any]) -> CommandResults:
        """
        Updates an Amazon EKS cluster configuration.
        Args:
            args: Command Arguments

        Returns:
            A Command Results object
        """
        
        def validate_args(args: Dict[str, Any]) -> dict:
            """
            Check that exactly one argument is passed, and if not raises a value error
            """
            validated_args = {"name": args.get("cluster_name")}
            
            if resources_vpc_config := args.get('resources_vpc_config'):
                resources_vpc_config = json.loads(resources_vpc_config) if isinstance(resources_vpc_config, str) else resources_vpc_config
                validated_args = {"resourcesVpcConfig": resources_vpc_config}
            if logging_arg := args.get('logging'):
                logging_arg = json.loads(logging_arg) if isinstance(logging_arg, str) else logging_arg
                validated_args = {"logging": logging_arg}
                
            if logging_arg and resources_vpc_config:
                raise ValueError
            
            result = remove_empty_elements(validated_args)
            if isinstance(result, dict):
                return result
            else:
                raise ValueError("No valid configuration argument provided")
                                  
        validated_args: dict = validate_args(args)
        try:
            response = self.client_session.update_cluster_config(**validated_args)

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


def test_module(params, command_args) -> str:
    return "ok"
    # if test_account_id := params.get("test_account_id"):
    #     command_args["account_id"] = test_account_id
    # else:
    #     return "Please provide Test AWS Account ID for the Integration instance to run test"

    # aws_client = get_client(params, command_args)
    # client_session = aws_client.aws_session(service="sts")
    # if client_session:
    #     return "ok"
    # else:
    # return "fail"


COMMANDS: dict[str, Callable] = {
    # S3
    "aws-s3-public-access-block-put": lambda aws_client, args: S3(aws_client, args).put_public_access_block_command(args),
    "aws-s3-bucket-acl-put": lambda aws_client, args: S3(aws_client, args).put_bucket_acl_command(args),
    "aws-s3-bucket-logging-put": lambda aws_client, args: S3(aws_client, args).put_bucket_logging_command(args),
    "aws-s3-bucket-versioning-put": lambda aws_client, args: S3(aws_client, args).put_bucket_versioning_command(args),
    "aws-s3-bucket-policy-put": lambda aws_client, args: S3(aws_client, args).put_bucket_policy_command(args),
    # IAM
    "aws-iam-account-password-policy-get": lambda aws_client, args: IAM(aws_client, args).get_account_password_policy_command(
        args
    ),
    "aws-iam-account-password-policy-update": lambda aws_client, args: IAM(
        aws_client, args
    ).update_account_password_policy_command(args),
    # EC2
    "aws-ec2-instance-metadata-options-modify": lambda aws_client, args: EC2(
        aws_client, args
    ).instance_metadata_options_modify_command(args),
    "aws-ec2-security-group-ingress-revoke": lambda aws_client, args: EC2(aws_client, args).revoke_security_group_ingress_command(
        args
    ),
    "aws-ec2-security-group-egress-revoke": lambda aws_client, args: EC2(aws_client, args).revoke_security_group_egress_command(
        args
    ),
    "aws-ec2-snapshot-permission-modify": lambda aws_client, args: EC2(aws_client, args).modify_snapshot_permission_command(args),
    "aws-ec2-instance-attribute-modify": lambda aws_client, args: EC2(aws_client, args).modify_instance_attribute_command(args),
    "aws-ec2-image-attribute-modify": lambda aws_client, args: EC2(aws_client, args).modify_image_attribute_command(args),
    # RDS
    "aws-rds-db-cluster-modify": lambda aws_client, args: RDS(aws_client, args).modify_db_cluster_command(args),
    "aws-rds-db-cluster-snapshot-attribute-modify": lambda aws_client, args: RDS(
        aws_client, args
    ).modify_db_cluster_snapshot_attribute_command(args),
    "aws-rds-db-instance-modify": lambda aws_client, args: RDS(aws_client, args).modify_db_instance_command(args),
    "aws-rds-db-snapshot-attribute-modify": lambda aws_client, args: RDS(aws_client, args).modify_db_snapshot_attribute_command(
        args
    ),
    # EKS
    "aws-eks-cluster-config-update": lambda aws_client, args: EKS(aws_client, args).update_cluster_config_command(args),
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
        # TODO - Enable >>
        # # Getting credentials from CTS (Cloud Token Service) endpoint.
        # credentials: dict = get_access_token(cloud_type=CloudTypes.AWS)
        # aws_session: Session = Session(
        #     aws_access_key_id=credentials["key"],
        #     aws_secret_access_key=credentials["access_token"],
        #     aws_session_token=credentials["session_token"],
        #     region_name=args.get('region') or param.get('region')
        # )
        # TODO - Enable <<
        if command == "test-module":
            return_results(test_module(params, command_args))
        elif command_function := COMMANDS.get(command):
            
            # TODO - Enable # return_results(command_function(aws_session, command_args))
            return_results(command_function(aws_client, command_args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builatins"):  # pragma: no cover
    main()
