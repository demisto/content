import demistomock as demisto  # noqa: F401
from COOCApiModule import *  # noqa: E402
from CommonServerPython import *  # noqa: F401
from http import HTTPStatus
from datetime import date
from collections.abc import Callable
from botocore.client import BaseClient as BotoClient
from botocore.config import Config
from botocore.exceptions import ClientError
from boto3 import Session

DEFAULT_MAX_RETRIES: int = 5
DEFAULT_SESSION_NAME = "cortex-session"
DEFAULT_PROXYDOME_CERTFICATE_PATH = os.getenv("EGRESSPROXY_CA_PATH") or "/etc/certs/egress.crt"
DEFAULT_PROXYDOME = os.getenv("CRTX_HTTP_PROXY") or "10.181.0.100:11117"
TIMEOUT_CONFIG = Config(connect_timeout=60, read_timeout=60)
DEFAULT_REGION = "us-east-1"


def parse_resource_ids(resource_id: str | None) -> list[str]:
    if resource_id is None:
        raise ValueError("Resource ID cannot be empty")
    id_list = resource_id.replace(" ", "")
    resource_ids = id_list.split(",")
    return resource_ids


def convert_datetimes_to_iso_safe(data):
    """
    Converts datetime objects in a data structure to ISO 8601 strings
    by serializing to and then deserializing from JSON using a custom encoder.
    """
    json_string = json.dumps(data, cls=ISOEncoder)
    return json.loads(json_string)


class AWSErrorHandler:
    """
    Centralized error handling for AWS boto3 client errors.
    Provides specialized handling for permission errors and general AWS API errors.
    """

    # Permission-related error codes that should be handled specially
    PERMISSION_ERROR_CODES = [
        "AccessDenied",
        "UnauthorizedOperation",
        "Forbidden",
        "AccessDeniedException",
        "UnauthorizedOperationException",
        "InsufficientPrivilegesException",
        "NotAuthorized",
    ]

    @classmethod
    def handle_response_error(cls, response: dict, account_id: str | None = None) -> None:
        """
        Handle boto3 response errors.
        For permission errors, returns a structured error entry using return_error.
        For other errors, raises DemistoException with informative error message.
        Args:
            err (ClientError): The boto3 ClientError exception
            account_id (str, optional): AWS account ID. If not provided, will try to get from demisto.args()
        """
        # Create informative error message
        detailed_error = (
            f"AWS API Error occurred while executing: {demisto.command()} with arguments: {demisto.args()}\n"
            f"Request Id: {response.get('ResponseMetadata',{}).get('RequestId', 'N/A')}\n"
            f"HTTP Status Code: {response.get('ResponseMetadata',{}).get('HTTPStatusCode', 'N/A')}"
        )

        return_error(detailed_error)

    @classmethod
    def handle_client_error(cls, err: ClientError, account_id: str | None = None) -> None:
        """
        Handle boto3 client errors with special handling for permission issues.
        For permission errors, returns a structured error entry using return_error.
        For other errors, raises DemistoException with informative error message.
        Args:
            err (ClientError): The boto3 ClientError exception
            account_id (str, optional): AWS account ID. If not provided, will try to get from demisto.args()
        """
        error_code = err.response.get("Error", {}).get("Code", "")
        error_message = err.response.get("Error", {}).get("Message", "")
        http_status_code = err.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        demisto.debug(f"[AWSErrorHandler] Got an client error: {error_message}")
        # Check if this is a permission-related error
        if (error_code in cls.PERMISSION_ERROR_CODES) or (http_status_code in [401, 403]):
            cls._handle_permission_error(err, error_code, error_message, account_id)
        else:
            cls._handle_general_error(err, error_code, error_message)

    @classmethod
    def _handle_permission_error(
        cls, err: ClientError, error_code: str, error_message: str, account_id: str | None = None
    ) -> None:
        """
        Handle permission-related errors by returning structured error entry.
        Args:
            err (ClientError): The boto3 ClientError exception
            error_code (str): The AWS error code
            error_message (str): The AWS error message
            account_id (str, optional): AWS account ID
        """
        # Get account_id from args if not provided
        if not account_id:
            account_id = demisto.args().get("account_id", "unknown")

        action = cls._extract_action_from_message(error_message)
        # When encountering an unauthorized error, an encoded authorization message may be returned with different
        # encoding each time. This will create different error entries for each unauthorized error and will confuse the user.
        # Therefore we will omit the actual encoded message.
        demisto.info(f"Original error message: {error_message}")
        error_entry = {
            "account_id": account_id,
            "message": cls.remove_encoded_authorization_message(error_message),
            "name": action,
        }
        demisto.debug(f"Permission error detected: {error_entry}")
        return_multiple_permissions_error([error_entry])

    @classmethod
    def remove_encoded_authorization_message(cls, message: str) -> str:
        """
        Remove encoded authorization messages from AWS error responses.
        Args:
            message (str): Original error message
        Returns:
            str: Cleaned error message without encoded authorization details
        """
        index = message.lower().find("encoded authorization failure message:")
        if index != -1:  # substring found
            return message[:index]
        else:
            return message

    @classmethod
    def _handle_general_error(cls, err: ClientError, error_code: str, error_message: str) -> None:
        """
        Handle general (non-permission) errors with informative error messages.
        Args:
            err (ClientError): The boto3 ClientError exception
            error_code (str): The AWS error code
            error_message (str): The AWS error message
        """
        # Get additional error details
        request_id = err.response.get("ResponseMetadata", {}).get("RequestId", "N/A")
        http_status = err.response.get("ResponseMetadata", {}).get("HTTPStatusCode", "N/A")

        # Create informative error message
        detailed_error = (
            f"AWS API Error occurred while executing: {demisto.command()} with arguments: {demisto.args()}\n"
            f"Error Code: {error_code}\n"
            f"Error Message: {error_message}\n"
            f"HTTP Status Code: {http_status}\n"
            f"Request ID: {request_id}"
        )

        demisto.error(f"AWS API Error: {detailed_error}")
        return_error(detailed_error)

    @classmethod
    def _extract_action_from_message(cls, error_message: str) -> str:
        """
        Extract AWS permission name from error message using regex patterns.
        Args:
            error_message (str): The AWS error message
        Returns:
            str: The extracted permission name or 'unknown' if not found
        """
        # Sanitize input to prevent regex injection
        if not error_message or not isinstance(error_message, str):
            return "unknown"

        for action in REQUIRED_ACTIONS:
            try:
                match = re.search(action, error_message, re.IGNORECASE)
                if match and match.group(0) == action:
                    return action
            except re.error:
                pass

        return "unknown"


class AWSServices(str, Enum):
    S3 = "s3"
    IAM = "iam"
    EC2 = "ec2"
    RDS = "rds"
    EKS = "eks"
    LAMBDA = "lambda"
    CloudTrail = "cloudtrail"


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
            "RestrictPublicBuckets": (
                argToBoolean(args.get("restrict_public_buckets")) if args.get("restrict_public_buckets") else None
            ),
        }

        remove_nulls_from_dictionary(kwargs)
        response = client.put_public_access_block(Bucket=args.get("bucket"), PublicAccessBlockConfiguration=kwargs)

        if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
            return CommandResults(readable_output=f"Successfully applied public access block to the {args.get('bucket')} bucket")

        raise DemistoException(f"Couldn't apply public access block to the {args.get('bucket')} bucket. {json.dumps(response)}")

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
            raise DemistoException(
                f"Request completed but received unexpected status code: "
                f"{response['ResponseMetadata']['HTTPStatusCode']}. "
                f"{json.dumps(response)}"
            )

        except Exception as e:
            raise DemistoException(f"Failed to update versioning configuration for bucket {bucket}. Error: {str(e)}")

    @staticmethod
    def put_bucket_logging_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
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
        bucket = args["bucket"]

        try:
            if target_bucket := args.get("target_bucket"):
                # Build logging configuration.
                bucket_logging_status = {
                    "LoggingEnabled": {"TargetBucket": target_bucket, "TargetPrefix": args.get("target_prefix", "")}
                }
            else:
                # If neither full config nor target bucket provided, disable logging
                bucket_logging_status = {}

            response = client.put_bucket_logging(Bucket=bucket, BucketLoggingStatus=bucket_logging_status)

            if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
                if bucket_logging_status.get("LoggingEnabled"):
                    target_bucket = bucket_logging_status["LoggingEnabled"].get("TargetBucket", "")
                    target_prefix = bucket_logging_status["LoggingEnabled"].get("TargetPrefix", "")
                    return CommandResults(
                        readable_output=(
                            f"Successfully enabled logging for bucket '{bucket}'. "
                            f"Logs will be stored in '{target_bucket}/{target_prefix}'."
                        )
                    )
                else:
                    return CommandResults(readable_output=f"Successfully disabled logging for bucket '{bucket}'")
            raise DemistoException(
                f"Couldn't apply bucket policy to {args.get('bucket')} bucket. "
                f"Status code: {response['ResponseMetadata']['HTTPStatusCode']}."
                f"{json.dumps(response)}"
            )

        except Exception as e:
            raise DemistoException(f"Failed to configure logging for bucket '{bucket}'. Error: {str(e)}")

    @staticmethod
    def put_bucket_acl_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Set the Access Control List (ACL) permissions for an Amazon S3 bucket.

        Args:
            client (BotoClient): The boto3 client for S3 service
            args (Dict[str, Any]): Command arguments including:
                - bucket (str): The name of the bucket
                - acl (str): The canned ACL to apply (e.g., 'private', 'public-read', 'public-read-write')

        Returns:
            CommandResults: Results of the operation with success/failure message
        """
        acl, bucket = args.get("acl"), args.get("bucket")
        response = client.put_bucket_acl(Bucket=bucket, ACL=acl)
        if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
            return CommandResults(readable_output=f"Successfully updated ACL for bucket {bucket} to '{acl}'")
        raise DemistoException(
            f"Request completed but received unexpected status code: "
            f"{response['ResponseMetadata']['HTTPStatusCode']}. {json.dumps(response)}"
        )

    @staticmethod
    def put_bucket_policy_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Adds or updates a bucket policy for an Amazon S3 bucket.

        Args:
            client (BotoClient): The boto3 client for S3 service
            args (Dict[str, Any]): Command arguments including:
                - bucket (str): The name of the S3 bucket to apply the policy to
                - policy (dict): The JSON policy document to be applied to the bucket
                - confirmRemoveSelfBucketAccess (str, optional): Confirms removal of self bucket access if set to "True"

        Returns:
            CommandResults:
                - On success: A result indicating the bucket policy was successfully applied
                - On failure: An error result with details about why the policy application failed

        Raises:
            Exception: If there's an error while applying the bucket policy
        """
        kwargs = {"Bucket": args.get("bucket", ""), "Policy": json.dumps(args.get("policy"))}
        try:
            response = client.put_bucket_policy(**kwargs)
            if response["ResponseMetadata"]["HTTPStatusCode"] in [HTTPStatus.OK, HTTPStatus.NO_CONTENT]:
                return CommandResults(readable_output=f"Successfully applied bucket policy to {args.get('bucket')} bucket")
            raise DemistoException(
                f"Couldn't apply bucket policy to {args.get('bucket')} bucket. "
                f"Status code: {response['ResponseMetadata']['HTTPStatusCode']}."
                f"{json.dumps(response)}"
            )
        except Exception as e:
            raise DemistoException(f"Couldn't apply bucket policy to {args.get('bucket')} bucket. Error: {str(e)}")


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
            raise DemistoException(f"Couldn't check current account password policy for account: {args.get('account_id')}")

        # ExpirePasswords is part of the response but cannot be included in the request
        if "ExpirePasswords" in kwargs:
            kwargs.pop("ExpirePasswords")

        command_args: dict[str, Union[int, bool, None]] = {
            "MinimumPasswordLength": arg_to_number(args.get("minimum_password_length")),
            "RequireSymbols": argToBoolean(args.get("require_symbols")) if args.get("require_symbols") else None,
            "RequireNumbers": argToBoolean(args.get("require_numbers")) if args.get("require_numbers") else None,
            "RequireUppercaseCharacters": (
                argToBoolean(args.get("require_uppercase_characters")) if args.get("require_uppercase_characters") else None
            ),
            "RequireLowercaseCharacters": (
                argToBoolean(args.get("require_lowercase_characters")) if args.get("require_lowercase_characters") else None
            ),
            "AllowUsersToChangePassword": (
                argToBoolean(args.get("allow_users_to_change_password")) if args.get("allow_users_to_change_password") else None
            ),
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
            raise DemistoException(
                f"Couldn't updated account password policy for account: {args.get('account_id')}. {json.dumps(response)}"
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
        policy_document: str = args.get("policy_document", "")
        policy_name: str = args.get("policy_name", "")
        role_name: str = args.get("role_name", "")
        kwargs = {"PolicyDocument": policy_document, "PolicyName": policy_name, "RoleName": role_name}

        try:
            client.put_role_policy(**kwargs)
            human_readable = f"Policy '{policy_name}' was successfully added to role '{role_name}'"
            return CommandResults(readable_output=human_readable)
        except Exception as e:
            raise DemistoException(f"Failed to add policy '{policy_name}' to role '{role_name}'. Error: {str(e)}")

    @staticmethod
    def delete_login_profile_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Deletes the password for the specified IAM user, which terminates the user's ability to access AWS services
        through the AWS Management Console.

        Args:
            client (BotoClient): The boto3 client for IAM service
            args (Dict[str, Any]): Command arguments including:
                - user_name (str): The name of the user whose password you want to delete

        Returns:
            CommandResults: Results of the operation with success/failure message
        """
        user_name = args.get("user_name", "")

        try:
            response = client.delete_login_profile(UserName=user_name)

            if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
                return CommandResults(readable_output=f"Successfully deleted login profile for user '{user_name}'")
            else:
                raise DemistoException(
                    f"Failed to delete login profile for user '{user_name}'. "
                    f"Status code: {response['ResponseMetadata']['HTTPStatusCode']}. "
                    f"{json.dumps(response)}"
                )
        except Exception as e:
            raise DemistoException(f"Error deleting login profile for user '{user_name}': {str(e)}")

    @staticmethod
    def put_user_policy_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Adds or updates an inline policy document that is embedded in the specified IAM user.

        Args:
            client (BotoClient): The boto3 client for IAM service
            args (Dict[str, Any]): Command arguments including:
                - user_name (str): The name of the user to associate the policy with
                - policy_name (str): The name of the policy document
                - policy_document (str): The policy document in JSON format

        Returns:
            CommandResults: Results of the operation with success/failure message
        """
        user_name = args.get("user_name", "")
        policy_name = args.get("policy_name", "")
        policy_document = args.get("policy_document", "")

        try:
            response = client.put_user_policy(
                UserName=user_name,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document) if isinstance(policy_document, dict) else policy_document,
            )

            if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
                return CommandResults(readable_output=f"Successfully added/updated policy '{policy_name}' for user '{user_name}'")
            else:
                raise DemistoException(
                    f"Failed to add/update policy '{policy_name}' for user '{user_name}'. "
                    f"Status code: {response['ResponseMetadata']['HTTPStatusCode']}. "
                    f"{json.dumps(response)}"
                )
        except Exception as e:
            raise DemistoException(f"Error adding/updating policy '{policy_name}' for user '{user_name}': {str(e)}")

    @staticmethod
    def remove_role_from_instance_profile_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Removes the specified IAM role from the specified EC2 instance profile.

        Args:
            client (BotoClient): The boto3 client for IAM service
            args (Dict[str, Any]): Command arguments including:
                - instance_profile_name (str): The name of the instance profile to update
                - role_name (str): The name of the role to remove

        Returns:
            CommandResults: Results of the operation with success/failure message
        """
        instance_profile_name = args.get("instance_profile_name", "")
        role_name = args.get("role_name", "")

        try:
            response = client.remove_role_from_instance_profile(InstanceProfileName=instance_profile_name, RoleName=role_name)

            if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
                return CommandResults(
                    readable_output=f"Successfully removed role '{role_name}' from instance profile '{instance_profile_name}'"
                )
            else:
                raise DemistoException(
                    f"Failed to remove role '{role_name}' from instance profile '{instance_profile_name}'. "
                    f"Status code: {response['ResponseMetadata']['HTTPStatusCode']}. "
                    f"{json.dumps(response)}"
                )

        except Exception as e:
            raise DemistoException(f"Error removing role '{role_name}' from instance profile '{instance_profile_name}': {str(e)}")

    @staticmethod
    def update_access_key_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Changes the status of the specified access key from Active to Inactive, or vice versa.
        This operation can be used to disable a user's access key as part of a key rotation workflow.
        Args:
            client (BotoClient): The boto3 client for IAM service
            args (Dict[str, Any]): Command arguments including:
                - access_key_id (str): The access key ID of the secret access key you want to update
                - status (str): The status you want to assign to the secret access key (Active/Inactive)
                - user_name (str, optional): The name of the user whose key you want to update

        Returns:
            CommandResults: Results of the operation with success/failure message
        """
        access_key_id = args.get("access_key_id", "")
        status = args.get("status", "")
        user_name = args.get("user_name")

        kwargs = {"AccessKeyId": access_key_id, "Status": status}

        if user_name:
            kwargs["UserName"] = user_name

        try:
            response = client.update_access_key(**kwargs)

            if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
                user_info = f" for user '{user_name}'" if user_name else ""
                return CommandResults(
                    readable_output=f"Successfully updated access key '{access_key_id}' status to '{status}'{user_info}"
                )
            else:
                raise DemistoException(
                    f"Failed to update access key '{access_key_id}' status. "
                    f"Status code: {response['ResponseMetadata']['HTTPStatusCode']}. "
                    f"{json.dumps(response)}"
                )
        except Exception as e:
            raise DemistoException(f"Error updating access key '{access_key_id}' status: {str(e)}")


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
            raise DemistoException(f"Couldn't updated public EC2 instance metadata for {args.get('instance_id')}")

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
    def modify_snapshot_attribute_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Adds or removes permission settings for the specified snapshot.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including:
                - snapshot_id (str): The ID of the snapshot
                - attribute (str): The snapshot attribute to modify
                - operation_type (str): The operation to perform (add or remove)
                - user_ids (str, optional): Comma-separated list of AWS account IDs
                - group (str, optional): The group to add/remove (e.g., 'all')

        Returns:
            CommandResults: Results of the operation with success message
        """
        # Parse user IDs from comma-separated string
        user_ids_list = None
        if user_ids := args.get("user_ids"):
            user_ids_list = argToList(user_ids)

        # Parse group parameter
        group_names_list = None
        if group := args.get("group"):
            group_names_list = [group.strip()]

        # Build accounts parameter using assign_params to handle None values
        accounts = assign_params(GroupNames=group_names_list, UserIds=user_ids_list)

        response = client.modify_snapshot_attribute(
            Attribute=args.get("attribute"),
            SnapshotId=args.get("snapshot_id"),
            OperationType=args.get("operation_type"),
            **accounts,
        )

        if response["ResponseMetadata"]["HTTPStatusCode"] != HTTPStatus.OK:
            raise DemistoException(f"Unexpected response from AWS - EC2:\n{response}")

        return CommandResults(readable_output=f"Snapshot {args.get('snapshot_id')} permissions was successfully updated.")

    @staticmethod
    def modify_image_attribute_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Modify the specified attribute of an Amazon Machine Image (AMI).
        """
        kwargs = {
            "Attribute": args.get("attribute"),
            "ImageId": args.get("image_id"),
            "OperationType": args.get("operation_type"),
        }

        if desc := args.get("description"):
            kwargs["Description"] = {"Value": desc}

        # Map snake_case arg names → CapitalCase boto3 params
        resource_mapping = {
            "user_ids": "UserIds",
            "user_groups": "UserGroups",
            "product_codes": "ProductCodes",
        }
        for snake, capital in resource_mapping.items():
            if ids := args.get(snake):
                kwargs[capital] = parse_resource_ids(ids)

        # Build LaunchPermission block from snake_case args
        launch_perm: dict[str, list[dict[str, str]]] = {"Add": [], "Remove": []}
        perm_config = [
            ("launch_permission_add_group", "Group", "Add"),
            ("launch_permission_add_user_id", "UserId", "Add"),
            ("launch_permission_remove_group", "Group", "Remove"),
            ("launch_permission_remove_user_id", "UserId", "Remove"),
        ]

        for arg_key, perm_key, action in perm_config:
            if val := args.get(arg_key):
                launch_perm[action].append({perm_key: val})

        if launch_perm["Add"] or launch_perm["Remove"]:
            kwargs["LaunchPermission"] = launch_perm

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

        Modes:
        1) Full mode: use `ip_permissions` JSON
        2) Simple mode: protocol, port, cidr → build IpPermissions
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

        group_id = args.get("group_id")
        ip_permissions_arg = args.get("ip_permissions")

        if ip_permissions_arg:
            # Full mode: user provided the entire IpPermissions JSON
            try:
                ip_perms = json.loads(ip_permissions_arg)
            except json.JSONDecodeError as e:
                raise DemistoException(f"Invalid `ip_permissions` JSON: {e}")
        else:
            # Simple mode: build a single rule descriptor
            proto = args.get("protocol")
            from_port, to_port = parse_port_range(args.get("port", ""))
            cidr = args.get("cidr")
            ip_perms = [{"IpProtocol": proto, "FromPort": from_port, "ToPort": to_port, "IpRanges": [{"CidrIp": cidr}]}]

        kwargs = {"GroupId": group_id, "IpPermissions": ip_perms}

        try:
            resp = client.revoke_security_group_egress(**kwargs)
            status = resp.get("Return")
            if resp.get("ResponseMetadata", {}).get("HTTPStatusCode") == 200 and status:
                return CommandResults(readable_output="Egress rule revoked successfully.")
            else:
                # If no exception but Return is False, AWS may report unknown perms
                unknown = resp.get("UnknownIpPermissions")
                if unknown:
                    raise DemistoException("Specified egress rule not found.")
                raise DemistoException(f"Unexpected response: {resp}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("InvalidGroup.NotFound", "InvalidGroupId.NotFound"):
                raise DemistoException(f"Security group {group_id} not found.")
            raise DemistoException(f"Failed to revoke egress rule: {e}")


class EKS:
    service = AWSServices.EKS

    @staticmethod
    def update_cluster_config_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Updates an Amazon EKS cluster configuration. Only a single type of update
        (logging / resources_vpc_config) is allowed per call.
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
                "DBClusterIdentifier": args.get("db_cluster_identifier"),
            }

            # Optional parameters
            optional_params = {
                "DeletionProtection": "deletion_protection",
                "EnableIAMDatabaseAuthentication": "enable_iam_database_authentication",
            }

            for param, arg_name in optional_params.items():
                if arg_name in args:
                    kwargs[param] = argToBoolean(args[arg_name])

            demisto.debug(f"executing modify_db_cluster with {kwargs}")
            response = client.modify_db_cluster(**kwargs)
            if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
                db_cluster = response.get("DBCluster", {})
                readable_output = f"Successfully modified DB cluster {args.get('db-cluster-identifier')}"
                if db_cluster:
                    db_cluster = convert_datetimes_to_iso_safe(db_cluster)
                    readable_output += "\n\nUpdated DB Cluster details:"
                    readable_output += tableToMarkdown("", db_cluster)

                return CommandResults(
                    readable_output=readable_output,
                    outputs_prefix="AWS.RDS.DBCluster",
                    outputs=db_cluster,
                    outputs_key_field="DBClusterIdentifier",
                )
            else:
                raise DemistoException(
                    f"Failed to modify DB cluster. "
                    f"Status code: {response['ResponseMetadata']['HTTPStatusCode']}. "
                    f"{json.dumps(response)}"
                )

        except Exception as e:
            raise DemistoException(f"Error modifying DB cluster: {str(e)}")

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
                raise DemistoException(
                    f"Failed to modify DB cluster snapshot attribute. "
                    f"Status code: {response['ResponseMetadata']['HTTPStatusCode']}. "
                    f"{json.dumps(response)}"
                )

        except Exception as e:
            raise DemistoException(f"Error modifying DB cluster snapshot attribute: {str(e)}")

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
            demisto.info(f"modify_db_instance {kwargs=}")
            response = client.modify_db_instance(**kwargs)

            if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
                db_instance = response.get("DBInstance", {})
                readable_output = (
                    f"Successfully modified DB instance {args.get('db_instance_identifier')}"
                    f"\n\nUpdated DB Instance details:\n\n"
                )
                if db_instance:
                    db_instance = convert_datetimes_to_iso_safe(db_instance)
                    readable_output += tableToMarkdown("", t=db_instance, removeNull=True)

                return CommandResults(
                    readable_output=readable_output,
                    outputs_prefix="AWS.RDS.DBInstance",
                    outputs=db_instance,
                    outputs_key_field="DBInstanceIdentifier",
                )
            else:
                raise DemistoException(
                    f"Failed to modify DB instance. "
                    f"Status code: {response['ResponseMetadata']['HTTPStatusCode']}. "
                    f"Error {response['Error']['Message']}",
                )

        except Exception as e:
            raise DemistoException(f"Error modifying DB instance: {str(e)}")

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
                readable_output=(
                    f"Successfully modified DB snapshot attribute for {args.get('db_snapshot_identifier')}:\n"
                    f"{tableToMarkdown('Modified', kwargs)}"
                )
            )

        else:
            raise DemistoException(f"Couldn't modify DB snapshot attribute for {args.get('db_snapshot_identifier')}")


class CloudTrail:
    service = AWSServices.CloudTrail

    @staticmethod
    def start_logging_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Starts the recording of AWS API calls and log file delivery for a trail.
        """
        name = args.get("name")

        try:
            response = client.start_logging(Name=name)

            return CommandResults(readable_output=f"Successfully started logging for CloudTrail: {name}", raw_response=response)
        except Exception as e:
            raise DemistoException(f"Error starting logging for CloudTrail {name}: {str(e)}")

    @staticmethod
    def update_trail_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Updates trail settings that control what events you are logging, and how to handle log files.
        Changes to a trail do not require stopping the CloudTrail service.

        Args:
            client (BotoClient): The boto3 client for CloudTrail service
            args (Dict[str, Any]): Command arguments including trail name and configuration options

        Returns:
            CommandResults: Results of the operation with update information
        """
        try:
            kwargs = {
                "Name": args.get("name"),
                "S3BucketName": args.get("s3_bucket_name"),
                "S3KeyPrefix": args.get("s3_key_prefix"),
                "SnsTopicName": args.get("sns_topic_name"),
                "IncludeGlobalServiceEvents": arg_to_bool_or_none(args.get("include_global_service_events")),
                "IsMultiRegionTrail": arg_to_bool_or_none(args.get("is_multi_region_trail")),
                "EnableLogFileValidation": arg_to_bool_or_none(args.get("enable_log_file_validation")),
                "CloudWatchLogsLogGroupArn": args.get("cloud_watch_logs_log_group_arn"),
                "CloudWatchLogsRoleArn": args.get("cloud_watch_logs_role_arn"),
                "KMSKeyId": args.get("kms_key_id"),
            }

            remove_nulls_from_dictionary(kwargs)

            response = client.update_trail(**kwargs)

            if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
                trail_data = response.get("Trail", {})
                readable_output = f"Successfully updated CloudTrail: {args.get('name')}"

                if trail_data:
                    readable_output += "\n\nUpdated Trail Details:"
                    readable_output += tableToMarkdown("", trail_data)

                return CommandResults(
                    readable_output=readable_output,
                    outputs_prefix="AWS.CloudTrail.Trail",
                    outputs=trail_data,
                    outputs_key_field="TrailARN",
                    raw_response=response,
                )
            else:
                raise DemistoException(
                    f"Failed to update CloudTrail. "
                    f"Status code: {response['ResponseMetadata']['HTTPStatusCode']}. "
                    f"{json.dumps(response)}"
                )

        except Exception as e:
            raise DemistoException(f"Error updating CloudTrail {args.get('name')}: {str(e)}")


COMMANDS_MAPPING: dict[str, Callable[[BotoClient, Dict[str, Any]], CommandResults]] = {
    "aws-s3-public-access-block-update": S3.put_public_access_block_command,
    "aws-s3-bucket-versioning-put": S3.put_bucket_versioning_command,
    "aws-s3-bucket-logging-put": S3.put_bucket_logging_command,
    "aws-s3-bucket-acl-put": S3.put_bucket_acl_command,
    "aws-s3-bucket-policy-put": S3.put_bucket_policy_command,
    "aws-iam-account-password-policy-get": IAM.get_account_password_policy_command,
    "aws-iam-account-password-policy-update": IAM.update_account_password_policy_command,
    "aws-iam-role-policy-put": IAM.put_role_policy_command,
    "aws-iam-login-profile-delete": IAM.delete_login_profile_command,
    "aws-iam-user-policy-put": IAM.put_user_policy_command,
    "aws-iam-role-from-instance-profile-remove": IAM.remove_role_from_instance_profile_command,
    "aws-iam-access-key-update": IAM.update_access_key_command,
    "aws-ec2-instance-metadata-options-modify": EC2.modify_instance_metadata_options_command,
    "aws-ec2-instance-attribute-modify": EC2.modify_instance_attribute_command,
    "aws-ec2-snapshot-attribute-modify": EC2.modify_snapshot_attribute_command,
    "aws-ec2-image-attribute-modify": EC2.modify_image_attribute_command,
    "aws-ec2-security-group-ingress-revoke": EC2.revoke_security_group_ingress_command,
    "aws-ec2-security-group-ingress-authorize": EC2.authorize_security_group_ingress_command,
    "aws-ec2-security-group-egress-revoke": EC2.revoke_security_group_egress_command,
    "aws-eks-cluster-config-update": EKS.update_cluster_config_command,
    "aws-rds-db-cluster-modify": RDS.modify_db_cluster_command,
    "aws-rds-db-cluster-snapshot-attribute-modify": RDS.modify_db_cluster_snapshot_attribute_command,
    "aws-rds-db-instance-modify": RDS.modify_db_instance_command,
    "aws-rds-db-snapshot-attribute-modify": RDS.modify_db_snapshot_attribute_command,
    "aws-cloudtrail-logging-start": CloudTrail.start_logging_command,
    "aws-cloudtrail-trail-update": CloudTrail.update_trail_command,
}

REQUIRED_ACTIONS: list[str] = [
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
]


def print_debug_logs(client: BotoClient, message: str):
    """
    Print debug logs with service prefix and command context.
    Args:
        client (BotoClient): The AWS client object
        message (str): The debug message to log
    """
    service_name = client.meta.service_model.service_name
    demisto.debug(f"[{service_name}] {demisto.command()}: {message}")


def test_module(params):
    if params.get("test_account_id"):
        iam_client, _ = get_service_client(
            params=params,
            service_name=AWSServices.IAM,
            config=Config(connect_timeout=5, read_timeout=5, retries={"max_attempts": 1}),
        )
        demisto.info("[AWS Automation Test Module] Initialized IAM client")
    else:
        raise DemistoException("Missing AWS credentials or account ID for health check")


def health_check(credentials: dict, account_id: str, connector_id: str) -> list[HealthCheckError] | HealthCheckError | None:
    """
    Perform AWS service connectivity check with detailed error handling.

    Args:
        credentials (dict): AWS credentials
        account_id (str): AWS account ID
        connector_id (str): Connector identifier

    Returns:
        Single HealthCheckError if connectivity issues are found, None otherwise
    """
    # List to collect all connectivity errors
    failed_services: list[str] = []

    try:
        # Connectivity check for services
        for service in AWSServices:
            try:
                session = None
                # Attempt to create a client for each service
                client, session = get_service_client(
                    session=session,
                    service_name=service,
                    config=Config(connect_timeout=3, read_timeout=3, retries={"max_attempts": 1}),
                )
                demisto.info(f"[AWS Automation Health Check] Successfully created client for {service.value}")

            except Exception as service_error:
                demisto.error(f"[AWS Automation Health Check] Failed to create client for {service.value}: {str(service_error)}")
                failed_services.append(service.value)

        # If any services failed, create a single aggregated error
        if failed_services:
            error_msg = f"Failed to connect to AWS services: {', '.join(failed_services)}"
            connectivity_error = HealthCheckError(
                account_id=account_id,
                connector_id=connector_id,
                message=error_msg,
                error_type=ErrorType.CONNECTIVITY_ERROR,
            )
            demisto.info(f"[AWS Automation Health Check] Connectivity error: {error_msg}")
            return connectivity_error

        demisto.info("[AWS Automation Health Check] All services connected successfully")
        return None

    except Exception as err:
        demisto.error(f"[AWS Automation Health Check] Unexpected error during health check: {err}")

        # Create a general internal error
        internal_error = HealthCheckError(
            account_id=account_id,
            connector_id=connector_id,
            message=f"Unexpected error during health check: {str(err)}",
            error_type=ErrorType.INTERNAL_ERROR,
        )

        return internal_error


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


def get_service_client(
    credentials: dict = {},
    params: dict = {},
    args: dict = {},
    command: str = "",
    session: Optional[Session] = None,
    service_name: str = "",
    config: Optional[Config] = None,
) -> tuple[BotoClient, Optional[Session]]:
    """
    Create and configure a boto3 client for the specified AWS service.

    Args:
        params (dict): Integration configuration parameters
        args (dict): Command arguments containing region information
        command (str): AWS command name used to determine the service type
        credentials (dict): AWS credentials (access key, secret key, session token)

    Returns:
        BotoClient: Configured boto3 client with ProxyDome headers and proxy settings
        Session: Boto3 session object
    """
    aws_session: Session = session or Session(
        aws_access_key_id=credentials.get("key") or params.get("access_key_id"),
        aws_secret_access_key=credentials.get("access_token") or params.get("secret_access_key", {}).get("password"),
        aws_session_token=credentials.get("session_token"),
        region_name=args.get("region") or params.get("region", "") or DEFAULT_REGION,
    )

    # Resolve service name
    service_name = service_name or command.split("-")[1]
    service = AWSServices(service_name)

    client_config = Config(
        proxies={"https": DEFAULT_PROXYDOME}, proxies_config={"proxy_ca_bundle": DEFAULT_PROXYDOME_CERTFICATE_PATH}
    )
    if config:
        client_config.merge(config)

    client = aws_session.client(service, verify=False, config=client_config)

    register_proxydome_header(client)

    return client, session


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
    credentials: dict = {}
    if get_connector_id():
        credentials = get_cloud_credentials(CloudTypes.AWS.value, account_id)

    service_client, _ = get_service_client(credentials, params, args, command)
    return COMMANDS_MAPPING[command](service_client, args)


def main():  # pragma: no cover
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f"Params: {params}")
    demisto.debug(f"Command: {command}")
    demisto.debug(f"Args: {args}")
    handle_proxy()

    try:
        if command == "test-module":
            results = (
                run_health_check_for_accounts(connector_id, CloudTypes.AWS.value, health_check)
                if (connector_id := get_connector_id())
                else test_module(params)
            )
            demisto.info(f"[AWS Automation] Health Check Results: {results}")
            return_results(results)

        elif command in COMMANDS_MAPPING:
            return_results(execute_aws_command(command, args, params))
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
