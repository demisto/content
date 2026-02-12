import demistomock as demisto  # noqa: F401
from COOCApiModule import *  # noqa: E402
from CommonServerPython import *  # noqa: F401
from http import HTTPStatus
from datetime import date, datetime, timedelta, UTC
from collections.abc import Callable
from botocore.client import BaseClient as BotoClient
from botocore.config import Config
from botocore.exceptions import ClientError, WaiterError
from boto3 import Session
from xml.sax.saxutils import escape
import re
import copy

DEFAULT_MAX_RETRIES: int = 5
DEFAULT_SESSION_NAME = "cortex-session"
DEFAULT_PROXYDOME_CERTFICATE_PATH = os.getenv("EGRESSPROXY_CA_PATH") or "/etc/certs/egress.crt"
DEFAULT_PROXYDOME = os.getenv("CRTX_HTTP_PROXY") or "10.181.0.100:11117"
TIMEOUT_CONFIG = Config(connect_timeout=60, read_timeout=60)
DEFAULT_REGION = "us-east-1"
MAX_FILTERS = 50
MAX_TAGS = 50
MAX_FILTER_VALUES = 200
MAX_CHAR_LENGTH_FOR_FILTER_VALUE = 255
MAX_LIMIT_VALUE = 1000
DEFAULT_LIMIT_VALUE = 50


def handle_port_range(args: dict) -> tuple:
    """
    Parse and extract port range information from command arguments.

    Handles port specification in multiple formats:
    - Individual from_port and to_port arguments
    - Single port argument that can be a port number or range (e.g., "80" or "80-443")

    Args:
        args (dict): Command arguments dictionary containing port specifications

    Returns:
        tuple: A tuple containing (from_port, to_port) as integers, or (None, None) if no ports specified
    """
    from_port = arg_to_number(args.get("from_port"))
    to_port = arg_to_number(args.get("to_port"))

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

    if args.get("port") and (not from_port and not to_port):
        from_port, to_port = parse_port_range(args.get("port", ""))
    return from_port, to_port


def serialize_response_with_datetime_encoding(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Serialize AWS API response with proper datetime encoding for JSON compatibility.

    Args:
        response (Dict[str, Any]): Raw AWS API response containing datetime objects

    Returns:
        Dict[str, Any]: Serialized response with datetime objects converted to strings

    Raises:
        DemistoException: If serialization fails
    """
    try:
        # Use DatetimeEncoder to handle datetime objects
        serialized_json = json.dumps(response, cls=DatetimeEncoder)
        return json.loads(serialized_json)
    except (ValueError, TypeError) as e:
        demisto.error(f"Failed to serialize response with datetime encoding: {str(e)}")
    except Exception as e:
        demisto.error(f"Unexpected error during response serialization: {str(e)}")
    return response


def process_instance_data(instance: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process and extract relevant data from a single EC2 instance.

    Args:
        instance (Dict[str, Any]): Raw instance data from AWS API

    Returns:
        Dict[str, Any]: Processed instance data
    """
    instance_data = {
        "InstanceId": instance.get("InstanceId"),
        "ImageId": instance.get("ImageId"),
        "State": instance.get("State", {}).get("Name"),
        "PublicIPAddress": instance.get("PublicIpAddress"),
        "PrivateIpAddress": instance.get("PrivateIpAddress"),
        "Type": instance.get("InstanceType"),
        "LaunchDate": instance.get("LaunchTime"),
        "PublicDNSName": instance.get("PublicDnsName"),
        "Monitoring": instance.get("Monitoring", {}).get("State"),
        "AvailabilityZone": instance.get("Placement", {}).get("AvailabilityZone"),
    }
    instance_data = remove_empty_elements(instance_data)
    return instance_data


def build_pagination_kwargs(
    args: Dict[str, Any],
    minimum_limit: int = 0,
    max_limit: int = MAX_LIMIT_VALUE,
    next_token_name: str = "NextToken",
    limit_name: str = "MaxResults",
) -> Dict[str, Any]:
    """
    Build pagination parameters for AWS API calls with proper validation and limits.

    Args:
        args (Dict[str, Any]): Command arguments containing pagination parameters
        minimum_limit (int): The minimum possible limit for the pagination command.
        max_limit (int): The maximum possible limit for the pagination command.
        next_token_name (str): The name of the next token argument in AWS.
        limit_name (str): The name of the limit argument in AWS.

    Returns:
        Dict[str, Any]: Validated pagination parameters for AWS API

    Raises:
        ValueError: If limit exceeds maximum allowed value or is invalid
    """
    kwargs: Dict[str, Any] = {}

    limit_arg = args.get("limit")

    # Parse and validate limit
    try:
        if limit_arg is not None:
            limit = arg_to_number(limit_arg)
        else:
            limit = DEFAULT_LIMIT_VALUE  # Default limit
    except (ValueError, TypeError) as e:
        raise ValueError(f"Invalid limit parameter: {limit_arg}. Must be a valid number.") from e

    # Validate limit lower constraints
    if limit is not None and limit <= minimum_limit:
        raise ValueError(f"Limit must be greater than {minimum_limit}")

    # AWS API upper constraints
    if limit is not None and limit > max_limit:
        demisto.debug(f"Requested limit {limit} exceeds maximum {max_limit}, using {max_limit}")
        limit = max_limit

    # Handle pagination with next_token (for continuing previous requests)
    if next_token := args.get("next_token"):
        if (not isinstance(next_token, str)) or (len(next_token.strip()) == 0):
            raise ValueError("next_token must be a non-empty string")
        kwargs[next_token_name] = next_token.strip()
    kwargs.update({limit_name: limit})
    return kwargs


def parse_resource_ids(resource_id: str | None) -> list[str]:
    if resource_id is None:
        raise ValueError("Resource ID cannot be empty")
    id_list = resource_id.replace(" ", "")
    resource_ids = id_list.split(",")
    return resource_ids


def parse_filter_field(filter_string: str | None):
    """
    Parses a list representation of name and values with the form of 'name=<name>,values=<values>.
    You can specify up to 50 filters and up to 200 values per filter in a single request.
    Filter strings can be up to 255 characters in length.
    Args:
        filter_string: The name and values list
    Returns:
        A list of dicts with the form {"Name": <key>, "Values": [<value>]}
    """
    filters = []
    list_filters = argToList(filter_string, separator=";")
    if len(list_filters) > MAX_FILTERS:
        list_filters = list_filters[0:50]
        demisto.debug("Number of filter is larger then 50, parsing only first 50 filters.")
    regex = re.compile(
        r"^name=([\w:.-]+),values=([ \w@,.*-\/:]+)",
        flags=re.I,
    )
    for filter in list_filters:
        match_filter = regex.match(filter)
        if match_filter is None:
            raise ValueError(
                f"Could not parse field: {filter}. Please make sure you provided "
                "like so: name=<name>,values=<values>;name=<name>,values=<value1>,<value2>..."
            )
        demisto.debug(
            f'Number of filter values for filter {match_filter.group(1)} is {len(match_filter.group(2).split(","))}'
            f' if larger than {MAX_FILTER_VALUES},'
            f' parsing only first {MAX_FILTER_VALUES} values.'
        )
        filters.append({"Name": match_filter.group(1), "Values": match_filter.group(2).split(",")[0:MAX_FILTER_VALUES]})

    return filters


def parse_tag_field(tags_string: str | None):
    """
    Parses a list representation of key and value with the form of 'key=<name>,value=<value>.
    You can specify up to 50 tags per resource.
    Args:
        tags_string: The name and value list
    Returns:
        A list of dicts with the form {"key": <key>, "value": <value>}
    """
    tags = []
    list_tags = argToList(tags_string, separator=";")
    if len(list_tags) > MAX_TAGS:
        list_tags = list_tags[0:50]
        demisto.debug("Number of tags is larger then 50, parsing only first 50 tags.")
    # According to the AWS Tag restrictions docs.
    regex = re.compile(r"^key=([a-zA-Z0-9\s+\-=._:/@]{1,128}),value=(.{0,256})$", flags=re.UNICODE)
    for tag in list_tags:
        match_tag = regex.match(tag)
        if match_tag is None:
            raise ValueError(
                f"Could not parse field: {tag}. Please make sure you provided like so: key=abc,value=123;key=fed,value=456"
            )
        tags.append({"Key": match_tag.group(1), "Value": match_tag.group(2)})

    return tags


def convert_datetimes_to_iso_safe(data):
    """
    Converts datetime objects in a data structure to ISO 8601 strings
    by serializing to and then deserializing from JSON using a custom encoder.
    """
    json_string = json.dumps(data, cls=ISOEncoder)
    return json.loads(json_string)


def read_zip_to_bytes(filename: str) -> bytes:
    """
    Reads the entire zip file into a bytes object in chunks.

    Args:
        filename: Path to the zip file.

    Returns:
        A bytes object containing the complete zip file content.

    Raises:
        DemistoException: If an error occurs while reading the file.
    """
    try:
        with open(filename, "rb") as zip_file:
            data = b""
            for chunk in iter(lambda: zip_file.read(1024), b""):
                data += chunk
        return data
    except Exception as e:
        demisto.error(f"Failed to read zip file '{filename}': {str(e)}")
        raise DemistoException(f"Failed to read zip file '{filename}': {str(e)}")


def prepare_create_function_kwargs(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prepare arguments to be sent to the Lambda CreateFunction API.

    Args:
        args: Command arguments dictionary

    Returns:
        Dictionary of kwargs ready for create_function API call
    """
    create_function_api_keys = ["FunctionName", "Runtime", "Role", "Handler", "Description", "PackageType"]

    if code_path := args.get("code"):
        file_path = demisto.getFilePath(code_path).get("path")
        method_code = read_zip_to_bytes(file_path)
        code = {"ZipFile": method_code}
    elif s3_bucket := args.get("s3_bucket"):
        code = {"S3Bucket": s3_bucket}
    else:
        raise DemistoException("code or s3_bucket must be provided.")

    # Parse environment variables using parse_tag_field and convert to dictionary
    env_vars = None
    if args.get("environment"):
        parsed_env = parse_tag_field(args.get("environment"))
        env_vars = {item["Key"]: item["Value"] for item in parsed_env}

    kwargs: Dict[str, Any] = {
        "Code": code,
        "TracingConfig": {"Mode": args.get("tracing_config") or "Active"},
        "MemorySize": arg_to_number(args.get("memory_size")) or 128,
        "Timeout": arg_to_number(args.get("function_timeout")) or 3,
        "Publish": arg_to_bool_or_none(args.get("publish")),
        "Environment": {"Variables": env_vars} if env_vars else None,
        "Tags": parse_tag_field(args.get("tags")) if args.get("tags") else None,
        "Layers": argToList(args.get("layers")),
        "VpcConfig": {
            "SubnetIds": argToList(args.get("subnet_ids")),
            "SecurityGroupIds": argToList(args.get("security_group_ids")),
            "Ipv6AllowedForDualStack": arg_to_bool_or_none(args.get("ipv6_allowed_for_dual_stack")),
        },
    }

    for key in create_function_api_keys:
        arg_name = camel_case_to_underscore(key)
        if arg_name in args:
            kwargs.update({key: args.get(arg_name)})

    return remove_empty_elements(kwargs)


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
        try:
            error_code = err.response.get("Error", {}).get("Code")
            error_message = err.response.get("Error", {}).get("Message")
            http_status_code = err.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            demisto.debug(f"[AWSErrorHandler] Got an client error: {error_message}")
            if not error_code or not error_message or not http_status_code:
                return_error(err)
            # Check if this is a permission-related error
            if (error_code in cls.PERMISSION_ERROR_CODES) or (http_status_code in [401, 403]):
                cls._handle_permission_error(err, error_code, error_message, account_id)
            else:
                cls._handle_general_error(err, error_code, error_message)
        except Exception as e:
            demisto.debug(f"[AWSErrorHandler] Unhandled error: {str(e)}")
            return_error(err)

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
    ECS = "ecs"
    ACM = "acm"
    KMS = "kms"
    ELB = "elb"
    CostExplorer = "ce"
    BUDGETS = "budgets"


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
    def delete_bucket_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Delete an Amazon S3 bucket.

        Args:
            client (BotoClient): The boto3 client for S3 service
            args (Dict[str, Any]): Command arguments including:
                - bucket (str): The name of the bucket

        Returns:
            CommandResults: Results of the command execution.
        """
        bucket = args.get("bucket")

        print_debug_logs(client, f"Deleting bucket: {bucket}")

        response = client.delete_bucket(Bucket=bucket)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") == HTTPStatus.NO_CONTENT:
            return CommandResults(readable_output=f"Successfully deleted bucket '{bucket}'")
        else:
            return AWSErrorHandler.handle_response_error(response)

    @staticmethod
    def list_bucket_objects_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        List objects in an Amazon S3 bucket (up to 1000 objects).

        Args:
            client (BotoClient): The boto3 client for S3 service
            args (Dict[str, Any]): Command arguments including:
                - bucket (str): The name of the bucket
                - prefix (str): Limits the response to keys that begin with the specified prefix
                - delimiter (str): A delimiter is a character you use to group keys
                - limit (str): Sets the maximum number of keys returned in the response (default is 1000).
                - next_token (str): The marker for the next set of results (used for pagination).

        Returns:
            CommandResults: Results of the command execution including the list of objects and their metadata
        """
        bucket = args.get("bucket")
        prefix = args.get("prefix")
        delimiter = args.get("delimiter")

        print_debug_logs(client, f"Listing objects from bucket: {bucket}")

        pagination_kwargs = build_pagination_kwargs(
            args, minimum_limit=1, max_limit=1000, next_token_name="Marker", limit_name="MaxKeys"
        )

        print_debug_logs(client, f"Created those pagination parameters {pagination_kwargs=}")

        kwargs = {
            "Bucket": bucket,
            "Prefix": prefix,
            "Delimiter": delimiter,
        }
        kwargs.update(pagination_kwargs)
        remove_nulls_from_dictionary(kwargs)

        try:
            response = client.list_objects(**kwargs)

            if response["ResponseMetadata"]["HTTPStatusCode"] != HTTPStatus.OK:
                return AWSErrorHandler.handle_response_error(response)

            serialized_response = serialize_response_with_datetime_encoding(response)
            contents = serialized_response.get("Contents", [])

            if not contents:
                return CommandResults(readable_output=f"No objects found in bucket {bucket}.")

            table_data = []
            for obj in contents:
                table_data.append(
                    {
                        "Key": obj.get("Key"),
                        "Size (Bytes)": obj.get("Size"),
                        "LastModified": obj.get("LastModified"),
                        "StorageClass": obj.get("StorageClass"),
                    }
                )

            human_readable = tableToMarkdown(
                f"AWS S3 Bucket Object for Bucket: {bucket}",
                table_data,
                headers=["Key", "Size (Bytes)", "LastModified", "StorageClass"],
                removeNull=True,
                headerTransform=pascalToSpace,
            )
            return CommandResults(
                outputs_prefix="AWS.S3.Buckets",
                outputs_key_field="BucketName",
                outputs={"BucketName": bucket, "ObjectsNextToken": serialized_response.get("NextMarker"), "Objects": contents},
                readable_output=human_readable,
            )

        except Exception as e:
            raise DemistoException(f"Failed to list objects for bucket {bucket}. Error: {str(e)}")

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

    @staticmethod
    def delete_bucket_policy_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Delete the bucket policy from an Amazon S3 bucket.

        Args:
            client (BotoClient): The boto3 client for S3 service
            args (Dict[str, Any]): Command arguments including:
                - bucket (str): The name of the S3 bucket

        Returns:
            CommandResults: Results of the delete operation with success/failure message
        """
        bucket = args.get("bucket")

        print_debug_logs(client, f"Deleting bucket policy for bucket: {bucket}")

        response = client.delete_bucket_policy(Bucket=bucket)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") == HTTPStatus.NO_CONTENT:
            return CommandResults(readable_output=f"Successfully deleted bucket policy from bucket '{bucket}'")
        else:
            return AWSErrorHandler.handle_response_error(response)

    @staticmethod
    def get_public_access_block_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Get the Public Access Block configuration for an Amazon S3 bucket.

        Args:
            client (BotoClient): The boto3 client for S3 service
            args (Dict[str, Any]): Command arguments including:
                - bucket (str): The name of the S3 bucket
                - expected_bucket_owner (Str): TThe account ID of the expected bucket owner.

        Returns:
            CommandResults: Results containing the Public Access Block configuration
        """
        bucket_name = args.get("bucket")
        kwargs = {"Bucket": bucket_name, "ExpectedBucketOwner": args.get("expected_bucket_owner")}
        remove_nulls_from_dictionary(kwargs)
        print_debug_logs(client, f"Gets public access block for bucket: {bucket_name}")

        response = client.get_public_access_block(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") == HTTPStatus.OK:
            return CommandResults(
                outputs_prefix="AWS.S3-Buckets",
                outputs_key_field="BucketName",
                outputs={"BucketName": bucket_name, "PublicAccessBlock": response.get("PublicAccessBlockConfiguration", {})},
                readable_output=tableToMarkdown(
                    "Public Access Block configuration",
                    t=response.get("PublicAccessBlockConfiguration", {}),
                    removeNull=True,
                    headerTransform=pascalToSpace,
                ),
            )
        else:
            return AWSErrorHandler.handle_response_error(response)

    @staticmethod
    def get_bucket_encryption_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Get the encryption configuration for an Amazon S3 bucket.

        Args:
            client (BotoClient): The boto3 client for S3 service
            args (Dict[str, Any]): Command arguments including:
                - bucket (str): The name of the S3 bucket
                - expected_bucket_owner (Str): TThe account ID of the expected bucket owner.

        Returns:
            CommandResults: Results containing the bucket encryption configuration
        """
        bucket_name = args.get("bucket")
        kwargs = {"Bucket": bucket_name, "ExpectedBucketOwner": args.get("expected_bucket_owner")}
        remove_nulls_from_dictionary(kwargs)
        print_debug_logs(client, f"Gets encryption configuration for an Amazon S3 bucket: {bucket_name}")

        response = client.get_bucket_encryption(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") == HTTPStatus.OK:
            server_side_encryption_rules = response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            outputs = {
                "BucketName": bucket_name,
                "ServerSideEncryptionConfiguration": response.get("ServerSideEncryptionConfiguration", {}),
            }
            return CommandResults(
                outputs_prefix="AWS.S3-Buckets",
                outputs_key_field="BucketName",
                outputs=outputs,
                readable_output=tableToMarkdown(
                    f"Server Side Encryption Configuration for Bucket '{bucket_name}'",
                    t=server_side_encryption_rules,
                    removeNull=True,
                    headerTransform=pascalToSpace,
                ),
            )
        else:
            return AWSErrorHandler.handle_response_error(response)

    @staticmethod
    def get_bucket_policy_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Get the policy configuration for an Amazon S3 bucket.

        Args:
            client (BotoClient): The boto3 client for S3 service
            args (Dict[str, Any]): Command arguments including:
                - bucket (str): The name of the S3 bucket
                - expected_bucket_owner (Str): TThe account ID of the expected bucket owner.

        Returns:
            CommandResults: Results containing the bucket policy configuration
        """
        bucket_name = args.get("bucket")
        kwargs = {"Bucket": bucket_name, "ExpectedBucketOwner": args.get("expected_bucket_owner")}
        remove_nulls_from_dictionary(kwargs)
        print_debug_logs(client, f"Gets bucket policy for an Amazon S3 bucket: {bucket_name}")

        response = client.get_bucket_policy(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") == HTTPStatus.OK:
            json_response = json.loads(response.get("Policy", "{}"))
            json_statement = json_response.get("Statement", [])
            return CommandResults(
                outputs_prefix="AWS.S3-Buckets",
                outputs_key_field="BucketName",
                outputs={
                    "BucketName": bucket_name,
                    "Policy": json_response,
                },
                readable_output=tableToMarkdown(
                    f"Bucket Policy ID: {json_response.get('Id','N/A')} Version: {json_response.get('Version','N/A')}",
                    t=json_statement,
                    removeNull=True,
                    headerTransform=pascalToSpace,
                ),
            )
        else:
            return AWSErrorHandler.handle_response_error(response)

    @staticmethod
    def delete_bucket_website_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Deletes the static website configuration from the specified S3 bucket.
        Executes the DeleteBucketWebsite API operation. If successful, the website configuration is removed,
        but the bucket itself remains intact.

        Args:
            client (BotoClient): The initialized Boto3 S3 client.
            args (Dict[str, Any]): Command arguments, typically containing:
                - 'bucket' (str): The name of the S3 bucket. (Required)

        Returns:
            CommandResults: A CommandResults object with a success message on status 200/204.
        """
        kwargs = {"Bucket": args.get("bucket")}
        remove_nulls_from_dictionary(kwargs)
        try:
            response = client.delete_bucket_website(**kwargs)
            if response["ResponseMetadata"]["HTTPStatusCode"] in [HTTPStatus.OK, HTTPStatus.NO_CONTENT]:
                return CommandResults(
                    readable_output=f"Successfully removed the static website configuration from {args.get('bucket')} bucket."
                )
            raise DemistoException(f"Failed to delete bucket website for {args.get('bucket')}.")
        except Exception as e:
            raise DemistoException(f"Error: {str(e)}")

    @staticmethod
    def put_bucket_ownership_controls_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Specifies the rule that determines ownership of newly uploaded objects and manages the use of
        Access Control Lists (ACLs).
        Requires a validated JSON structure for 'the ownership_controls' argument.
        the role of Access Control Lists (ACLs). This operation requires a specific, validated JSON structure for
        the 'ownership_controls' argument.

        Args:
            client (BotoClient): The initialized Boto3 S3 client.
            args (Dict[str, Any]): Command arguments, typically containing:
                - 'bucket' (str): The name of the S3 bucket. (Required)
                - 'ownership_controls_rule' (str): A predefined rule specifying the desired ownership behavior.
                 Must be one of the following: BucketOwnerPreferred, ObjectWriter, BucketOwnerEnforced

        Returns:
            CommandResults: A CommandResults object with a success message on status 200/204.
        """
        ownership_controls = {"Rules": [{"ObjectOwnership": args.get("ownership_controls_rule")}]}
        kwargs = {"Bucket": args.get("bucket"), "OwnershipControls": ownership_controls}

        remove_nulls_from_dictionary(kwargs)
        try:
            response = client.put_bucket_ownership_controls(**kwargs)
            if response["ResponseMetadata"]["HTTPStatusCode"] in [HTTPStatus.OK, HTTPStatus.NO_CONTENT]:
                return CommandResults(readable_output=f"Bucket Ownership Controls successfully updated for {args.get('bucket')}")
            raise DemistoException(f"Failed to set Bucket Ownership Controls for {args.get('bucket')}.")
        except Exception as e:
            raise DemistoException(f"Error: {str(e)}")

    @staticmethod
    def file_download_command(client: BotoClient, args: Dict[str, Any]):
        """
        Download a file from an S3 bucket.

        Args:
            client (BotoClient): The initialized Boto3 S3 client.
            args (Dict[str, Any]): Command arguments, typically containing:
                - 'bucket' (str): The name of the S3 bucket. (Required)
                - 'key' (str): The key of the file to download. (Required)

        Returns:
            fileResult: fileResult object
        """
        bucket = args.get("bucket")
        key = args.get("key", "")
        print_debug_logs(client, f"downloading bucket={bucket}, key={key}")
        try:
            resp = client.get_object(Bucket=bucket, Key=key)
            body = resp["Body"]
            try:
                data = body.read()
            finally:
                try:
                    body.close()
                except Exception:
                    pass
            filename = key.rsplit("/", 1)[-1]
            return fileResult(filename, data)
        except ClientError as err:
            AWSErrorHandler.handle_client_error(err)
        except Exception as e:
            raise DemistoException(f"Error: {str(e)}")

    @staticmethod
    def file_upload_command(client: BotoClient, args: Dict[str, Any]):
        """
        Upload a file to an S3 bucket.

        Args:
            client (BotoClient): The initialized Boto3 S3 client.
            args (Dict[str, Any]): Command arguments, typically containing:
                - 'bucket' (str): The name of the S3 bucket. (Required)
                - 'key' (str): The key of the file to upload. (Required)
                - 'entryID' (str): The ID of the file to upload. (Required)

        Returns:
            CommandResults: A CommandResults object with a success/fail message.
        """
        bucket = args.get("bucket")
        key = args.get("key")
        entry_id = args.get("entryID")
        path = get_file_path(entry_id)
        print_debug_logs(client, f"uploading entryID={entry_id} to bucket={bucket}, key={key}")
        try:
            with open(path["path"], "rb") as data:
                client.upload_fileobj(data, bucket, key)
                return CommandResults(readable_output=f"File {key} was uploaded successfully to {bucket}")
        except ClientError as err:
            AWSErrorHandler.handle_client_error(err)
        except Exception as e:
            raise DemistoException(f"Error: {str(e)}")
        return CommandResults(readable_output="Failed to upload file")

    @staticmethod
    def get_bucket_website_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Retrieves the website configuration for a specified Amazon S3 bucket.
        The function calls the AWS S3 'get_bucket_website' API to check if the bucket
        is configured for static website hosting and, if so, what its configuration is.

        Args:
            client (BotoClient): The initialized Boto3 S3 client.
            args: A dictionary containing arguments, expected to include 'bucket'
                  (the name of the S3 bucket).

        Returns:
            CommandResults: An object containing the raw website configuration as outputs,
                            and a md table summarizing the configuration details
                            (IndexDocument, ErrorDocument, RedirectAllRequestsTo, RoutingRules).
        """
        kwargs = {"Bucket": args.get("bucket")}

        response = client.get_bucket_website(**kwargs)
        if response["ResponseMetadata"]["HTTPStatusCode"] not in [HTTPStatus.OK, HTTPStatus.NO_CONTENT]:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        response["WebsiteConfiguration"] = {
            "ErrorDocument": response.get("ErrorDocument"),
            "IndexDocument": response.get("IndexDocument"),
            "RedirectAllRequestsTo": response.get("RedirectAllRequestsTo"),
            "RoutingRules": response.get("RoutingRules"),
        }

        readable_output = tableToMarkdown(
            name="Bucket Website Configuration",
            t=response.get("WebsiteConfiguration", {}),
            removeNull=True,
            headers=["ErrorDocument", "IndexDocument", "RedirectAllRequestsTo", "RoutingRules"],
            headerTransform=pascalToSpace,
        )
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix="AWS.S3-Buckets.BucketWebsite",
            outputs=response.get("WebsiteConfiguration", {}),
            raw_response=response.get("WebsiteConfiguration", {}),
        )

    @staticmethod
    def get_bucket_acl_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Retrieves the Access Control List (ACL) of a specified Amazon S3 bucket.

        The function calls the AWS S3 'get_bucket_acl' API to determine the permissions
        granted to specific users or groups on the bucket.

        Args:
            client (BotoClient): The initialized Boto3 S3 client.
            args: A dictionary containing arguments, expected to include 'bucket'
                  (the name of the S3 bucket).

        Returns:
            CommandResults: An object containing the raw Access Control Policy details as
                            outputs, and a md table summarizing the ACL configuration
                            (Grants and Owner).
        """
        kwargs = {"Bucket": args.get("bucket")}

        response = client.get_bucket_acl(**kwargs)
        if response["ResponseMetadata"]["HTTPStatusCode"] not in [HTTPStatus.OK, HTTPStatus.NO_CONTENT]:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        response["AccessControlPolicy"] = {
            "Grants": response.get("Grants"),
            "Owner": response.get("Owner"),
        }
        readable_output = tableToMarkdown(
            name="Bucket Acl",
            t=response.get("AccessControlPolicy", {}),
            removeNull=True,
            headers=["Grants", "Owner"],
            headerTransform=pascalToSpace,
        )
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix="AWS.S3-Buckets.BucketAcl",
            outputs=response.get("AccessControlPolicy", {}),
            raw_response=response.get("AccessControlPolicy", {}),
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

        kwargs = {"GroupId": args.get("group_id"), "IpProtocol": args.get("protocol"), "CidrIp": args.get("cidr")}
        kwargs["FromPort"], kwargs["ToPort"] = handle_port_range(args)

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

        kwargs = {"GroupId": args.get("group_id"), "IpProtocol": args.get("protocol"), "CidrIp": args.get("cidr")}
        kwargs["FromPort"], kwargs["ToPort"] = handle_port_range(args)

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
            from_port, to_port = handle_port_range(args)

            cidr = args.get("cidr")
            ip_perms = [
                {"IpProtocol": proto, "FromPort": from_port, "ToPort": to_port, "IpRanges": [{"CidrIp": cidr}] if cidr else None}
            ]
            ip_perms = [remove_empty_elements(ip_perms[0])]
        kwargs = {"GroupId": group_id, "IpPermissions": ip_perms}

        try:
            resp = client.revoke_security_group_egress(**kwargs)
            status = resp.get("Return")
            if resp.get("ResponseMetadata", {}).get("HTTPStatusCode") == 200 and status:
                readable_output = (
                    "Egress rule revoked successfully."
                    if resp.get("RevokedSecurityGroupRules")
                    else "No egress rules were revoked."
                )
                return CommandResults(readable_output=readable_output, raw_response=resp)
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

    @staticmethod
    def create_snapshot_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Creates a snapshot of an Amazon EBS volume.
        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including:
                - volume_id (str): The ID of the volume to snapshot
                - description (str, optional): Description for the snapshot
                - tag_specifications (str, optional): Tag specifications for the snapshot
        Returns:
            CommandResults: Results of the snapshot creation operation
        """

        kwargs = {"VolumeId": args.get("volume_id")}

        if args.get("description") is not None:
            kwargs.update({"Description": args.get("description")})
        if args.get("tags") is not None:
            kwargs.update({"TagSpecifications": [{"ResourceType": "snapshot", "Tags": parse_tag_field(args.get("tags", ""))}]})

        response = client.create_snapshot(**kwargs)

        try:
            start_time = datetime.strftime(response["StartTime"], "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as e:
            raise DemistoException(f"Date could not be parsed. Please check the date again.\n{e}")

        data = {
            "Description": response["Description"],
            "Encrypted": response["Encrypted"],
            "Progress": response["Progress"],
            "SnapshotId": response["SnapshotId"],
            "State": response["State"],
            "VolumeId": response["VolumeId"],
            "VolumeSize": response["VolumeSize"],
            "StartTime": start_time,
            "Region": args.get("region"),
        }

        if "Tags" in response:
            for tag in response["Tags"]:
                data.update({tag["Key"]: tag["Value"]})

        try:
            output = json.dumps(response, cls=DatetimeEncoder)
            raw = json.loads(output)
            raw.update({"Region": args.get("region")})
        except ValueError as err_msg:
            raise DemistoException(f"Could not decode/encode the raw response - {err_msg}")
        return CommandResults(
            outputs=raw,
            outputs_prefix="AWS.EC2.Snapshot",
            readable_output=tableToMarkdown("AWS EC2 Snapshot", data),
            raw_response=raw,
        )

    @staticmethod
    def modify_snapshot_permission_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """Modifies the permissions of a snapshot.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including:
                - snapshot_id (str): The ID of the snapshot to modify
                - group_names (str, optional): The names of the security groups to add or remove permissions for
                - user_ids (str, optional): The IDs of the AWS accounts to add or remove permissions for
                - operation_type (str): The type of operation to perform (add | remove)

        Raises:
            DemistoException: If both group_names and user_ids are provided or if neither is provided

        Returns:
            CommandResults: _description_
        """
        group_names = argToList(args.get("group_names"))
        user_ids = argToList(args.get("user_ids"))
        if (group_names and user_ids) or not (group_names or user_ids):
            raise DemistoException('Please provide either "group_names" or "user_ids"')

        accounts = assign_params(GroupNames=group_names, UserIds=user_ids)
        operation_type = args.get("operation_type")
        client.modify_snapshot_attribute(
            Attribute="createVolumePermission",
            SnapshotId=args.get("snapshot_id"),
            OperationType=operation_type,
            DryRun=argToBoolean(args.get("dry_run", False)),
            **accounts,
        )
        return CommandResults(readable_output=f"Snapshot {args.get('snapshot_id')} permissions were successfully updated.")

    @staticmethod
    def describe_instances_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Retrieves detailed information about EC2 instances including status, configuration, and metadata.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments containing account_id, region, instance_ids, filters, etc.

        Returns:
            CommandResults: Formatted results with instance information
        """

        # Build API parameters
        kwargs = {}
        # Add instance IDs if provided
        if instance_ids := args.get("instance_ids"):
            kwargs["InstanceIds"] = argToList(instance_ids)

        # Add filters if provided
        if filters_arg := args.get("filters"):
            kwargs["Filters"] = parse_filter_field(filters_arg)

        if not instance_ids:
            pagination_kwargs = build_pagination_kwargs(args)
            kwargs.update(pagination_kwargs)

        print_debug_logs(client, f"Describing instances with parameters: {kwargs}")
        remove_nulls_from_dictionary(kwargs)
        response = client.describe_instances(**kwargs)
        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))
        response = serialize_response_with_datetime_encoding(response)
        # Extract instances from reservations
        reservations = response.get("Reservations", [])
        if not reservations:
            return CommandResults(
                readable_output="No instances found matching the specified criteria.",
            )
        readable_outputs = []
        instances_list = []
        for reservation in reservations:
            instances_list.extend(reservation.get("Instances", []))
            for instance in reservation.get("Instances", []):
                readable_outputs.append(process_instance_data(instance))
        outputs = {
            "AWS.EC2.Instances(val.InstanceId && val.InstanceId == obj.InstanceId)": instances_list,
            "AWS.EC2(true)": {"InstancesNextToken": response.get("NextToken")},
        }

        return CommandResults(
            outputs=outputs,
            readable_output=tableToMarkdown("AWS EC2 Instances", readable_outputs, removeNull=True),
            raw_response=response,
        )

    @staticmethod
    def run_instances_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Runs one or more Amazon EC2 instances.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments containing instance configuration parameters

        Returns:
            CommandResults: Results of the operation with instance launch information

        Raises:
            DemistoException: If required parameters are missing or API call fails
        """

        # Validate required parameters
        count = arg_to_number(args.get("count", 1))
        if not count or count <= 0:
            raise DemistoException("count parameter must be a positive integer")

        # Build base parameters
        kwargs: Dict[str, Any] = {"MinCount": count, "MaxCount": count}
        # Handle image specification - either direct AMI ID or launch template
        image_id = args.get("image_id")
        launch_template_id = args.get("launch_template_id")
        launch_template_name = args.get("launch_template_name")

        if launch_template_id or launch_template_name:
            # Using launch template
            launch_template = {}
            if launch_template_id:
                launch_template["LaunchTemplateId"] = launch_template_id
            elif launch_template_name:
                launch_template["LaunchTemplateName"] = launch_template_name

            if launch_template_version := args.get("launch_template_version"):
                launch_template["Version"] = launch_template_version

            kwargs["LaunchTemplate"] = launch_template

            # Image ID is optional when using launch template
            if image_id:
                kwargs["ImageId"] = image_id
        else:
            # Direct AMI specification
            kwargs["ImageId"] = image_id

        # Add optional basic parameters
        if instance_type := args.get("instance_type"):
            kwargs["InstanceType"] = instance_type

        if key_name := args.get("key_name"):
            kwargs["KeyName"] = key_name

        if subnet_id := args.get("subnet_id"):
            kwargs["SubnetId"] = subnet_id

        # Handle security groups
        if security_group_ids := args.get("security_group_ids"):
            kwargs["SecurityGroupIds"] = argToList(security_group_ids)

        if security_groups_names := args.get("security_groups_names"):
            kwargs["SecurityGroups"] = argToList(security_groups_names)

        # Handle user data with base64 encoding
        if user_data := args.get("user_data"):
            kwargs["UserData"] = user_data

        # Handle boolean parameters
        kwargs["DisableApiTermination"] = arg_to_bool_or_none(args.get("disable_api_termination"))
        kwargs["EbsOptimized"] = arg_to_bool_or_none(args.get("ebs_optimized"))

        # Handle IAM instance profile
        kwargs["IamInstanceProfile"] = {
            "Arn": args.get("iam_instance_profile_arn"),
            "Name": args.get("iam_instance_profile_name"),
        }

        ebs_config = remove_empty_elements(
            {
                "VolumeSize": arg_to_number(args.get("ebs_volume_size")),
                "SnapshotId": args.get("ebs_snapshot_id"),
                "VolumeType": args.get("ebs_volume_type"),
                "Iops": arg_to_number(args.get("ebs_iops")),
                "DeleteOnTermination": arg_to_bool_or_none(args.get("ebs_delete_on_termination")),
                "KmsKeyId": args.get("ebs_kms_key_id"),
                "Encrypted": arg_to_bool_or_none(args.get("ebs_encrypted")),
            }
        )

        kwargs["BlockDeviceMappings"] = [{"DeviceName": args.get("device_name"), "Ebs": ebs_config}]
        kwargs["Monitoring"] = {"Enabled": arg_to_bool_or_none(args.get("enabled_monitoring"))}
        kwargs["Placement"] = {"HostId": args.get("host_id")}

        tags = args.get("tags")
        if tags:
            kwargs["TagSpecifications"] = [{"ResourceType": "instance", "Tags": parse_tag_field(tags)}]

        # Remove null values to clean up API call
        kwargs = remove_empty_elements(kwargs)

        response = client.run_instances(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))
        response = serialize_response_with_datetime_encoding(response)
        instances = response.get("Instances", [])
        if not instances:
            return CommandResults(readable_output="No instances were launched.")

        # Format output data
        instances_data = []
        for instance in instances:
            instances_data.append(process_instance_data(instance))
        readable_output = tableToMarkdown(
            f"Launched {len(instances)} EC2 Instance(s)",
            instances_data,
            headers=[
                "InstanceId",
                "ImageId",
                "State",
                "Type",
                "PublicIPAddress",
                "PrivateIpAddress",
                "LaunchDate",
                "AvailabilityZone",
                "PublicDNSName",
                "Monitoring",
            ],
            headerTransform=string_to_table_header,
            removeNull=True,
        )
        return CommandResults(
            outputs_prefix="AWS.EC2.Instances", outputs=instances, readable_output=readable_output, raw_response=response
        )

    @staticmethod
    def _manage_instances_command(
        client: BotoClient, args: Dict[str, Any], action: str, additional_params: Optional[Dict[str, str]] = None
    ) -> CommandResults | None:
        """
        General function to manage EC2 instances (start, stop, terminate).

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments containing instance_ids and other parameters
            action (str): The action to perform ('start', 'stop', 'terminate')
            additional_params (Optional[Dict[str, str]]): Additional parameter names to extract from args

        Returns:
            CommandResults: Results of the operation with instance management information

        Raises:
            DemistoException: If instance_ids parameter is missing or invalid action provided
        """
        # Validate action
        valid_actions = {"start", "stop", "terminate"}
        if action not in valid_actions:
            raise DemistoException(f"Invalid action '{action}'. Must be one of: {valid_actions}")

        # Validate and extract instance IDs
        instance_ids = argToList(args.get("instance_ids", []))
        if not instance_ids:
            raise DemistoException("instance_ids parameter is required")

        # Build base parameters
        base_params = {"InstanceIds": instance_ids}

        # Add action-specific parameters
        if additional_params:
            for param_name, arg_key in additional_params.items():
                if arg_key in args:
                    base_params[param_name] = argToBoolean(args.get(arg_key, False))

        base_params = remove_empty_elements(base_params)

        # Define action configuration
        action_config = {
            "start": {
                "method_name": "start_instances",
                "response_key": "StartingInstances",
                "success_message": "started",
                "failure_message": "Failed to start instances",
            },
            "stop": {
                "method_name": "stop_instances",
                "response_key": "StoppingInstances",
                "success_message": "stopped",
                "failure_message": "Failed to stop instances",
            },
            "terminate": {
                "method_name": "terminate_instances",
                "response_key": "TerminatingInstances",
                "success_message": "terminated",
                "failure_message": "Failed to terminate instances",
            },
        }

        config = action_config[action]

        print_debug_logs(client, f"{action.title()}ing instances: {instance_ids}")

        # Get the appropriate client method dynamically
        client_method = getattr(client, config["method_name"])
        response = client_method(**base_params)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") == HTTPStatus.OK:
            readable_output = (
                f"The instances have been {config['success_message']} successfully."
                if response.get(config["response_key"])
                else f"No instances were {config['success_message']}."
            )
            return CommandResults(readable_output=readable_output, raw_response=response)
        else:
            return AWSErrorHandler.handle_response_error(response)

    @staticmethod
    def stop_instances_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Stops one or more Amazon EC2 instances.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments containing instance_ids and other parameters

        Returns:
            CommandResults: Results of the operation with instance stop information
        """
        additional_params = {"Force": "force", "Hibernate": "hibernate"}
        return EC2._manage_instances_command(client, args, "stop", additional_params)

    @staticmethod
    def terminate_instances_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Terminates one or more Amazon EC2 instances.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments containing instance_ids and other parameters

        Returns:
            CommandResults: Results of the operation with instance termination information
        """
        return EC2._manage_instances_command(client, args, "terminate")

    @staticmethod
    def start_instances_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Starts one or more stopped Amazon EC2 instances.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments containing instance_ids and other parameters

        Returns:
            CommandResults: Results of the operation with instance start information
        """
        return EC2._manage_instances_command(client, args, "start")

    @staticmethod
    def modify_subnet_attribute_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Modifies a single attribute on a specified Amazon EC2 subnet.
        This command performs the 'ModifySubnetAttribute' API operation.

        Args:
            client (BotoClient): The initialized Boto3 EC2 client.
            args (Dict[str, Any]): Command arguments, typically containing:
                - 'subnet_id' (str): The ID of the subnet to modify. (Required)
                - 'map_public_ip_on_launch' (str): Boolean value to control auto-assign public IPv4.
                - 'assign_ipv6_address_on_creation' (str): Boolean value to control auto-assign IPv6 address.
                - 'enable_dns64' (str): Boolean value to enable DNS64 resolution.
                - 'enable_resource_name_dns_a_record_on_launch' (str): Boolean value to enable DNS A records based
                 on instance resource name.
                - 'enable_resource_name_dns_aaaa_record_on_launch' (str): Boolean value to enable DNS AAAA records based on
                 instance resource name.
                - 'private_dns_hostname_type_on_launch' (str): String value for private DNS hostname generation.
                - 'customer_owned_ipv4_pool' (str): The ID of the Customer Owned IPv4 Pool (CoIP) to associate with the subnet.
                - 'map_customer_owned_ip_on_launch' (str): Boolean value to auto-assign CoIPs to instances.
                - 'enable_lni_at_device_index' (str): Integer (1-15) to set the device index for LNI assignment.
                - 'disable_lni_at_device_index' (str): Boolean value to disable LNI assignment at a device index.


        Returns:
            CommandResults: A CommandResults object with a success message.
        """
        kwargs = {
            "SubnetId": args.get("subnet_id"),
            "AssignIpv6AddressOnCreation": arg_to_bool_or_none(args.get("assign_ipv6_address_on_creation")),
            "CustomerOwnedIpv4Pool": args.get("customer_owned_ipv4_pool"),
            "DisableLniAtDeviceIndex": arg_to_bool_or_none(args.get("disable_lni_at_device_index")),
            "EnableDns64": arg_to_bool_or_none(args.get("enable_dns64")),
            "EnableLniAtDeviceIndex": arg_to_number(args.get("enable_lni_at_device_index")),
            "EnableResourceNameDnsAAAARecordOnLaunch": arg_to_bool_or_none(
                args.get("enable_resource_name_dns_aaaa_record_on_launch")
            ),
            "EnableResourceNameDnsARecordOnLaunch": arg_to_bool_or_none(args.get("enable_resource_name_dns_a_record_on_launch")),
            "MapCustomerOwnedIpOnLaunch": arg_to_bool_or_none(args.get("map_customer_owned_ip_on_launch")),
            "MapPublicIpOnLaunch": arg_to_bool_or_none(args.get("map_public_ip_on_launch")),
            "PrivateDnsHostnameTypeOnLaunch": args.get("private_dns_hostname_type_on_launch"),
        }

        remove_nulls_from_dictionary(kwargs)
        try:
            response = client.modify_subnet_attribute(**kwargs)
            if response["ResponseMetadata"]["HTTPStatusCode"] in [HTTPStatus.OK, HTTPStatus.NO_CONTENT]:
                demisto.debug(f"RequestId={response.get('ResponseMetadata').get('RequestId')}")
                return CommandResults(readable_output="Subnet configuration successfully updated.")
            raise DemistoException("Modification could not be performed.")
        except Exception as e:
            raise DemistoException(f"Error: {str(e)}")

    @staticmethod
    def describe_vpcs_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Describes one or more of your VPCs.
        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including VPC IDs

        Returns:
            CommandResults: Results of the operation with VPC information
        """
        kwargs = {}
        data = []
        if args.get("filters"):
            kwargs.update({"Filters": parse_filter_field(args.get("filters"))})
        if args.get("vpc_ids"):
            kwargs.update({"VpcIds": parse_resource_ids(args.get("vpc_ids"))})

        response = client.describe_vpcs(**kwargs)

        if len(response["Vpcs"]) == 0:
            return CommandResults(readable_output="No VPCs were found.")
        for i, vpc in enumerate(response["Vpcs"]):
            data.append(
                {
                    "CidrBlock": vpc["CidrBlock"],
                    "DhcpOptionsId": vpc["DhcpOptionsId"],
                    "State": vpc["State"],
                    "VpcId": vpc["VpcId"],
                    "InstanceTenancy": vpc["InstanceTenancy"],
                    "IsDefault": vpc["IsDefault"],
                    "Region": args["region"],
                }
            )

            if "Tags" in vpc:
                for tag in vpc["Tags"]:
                    data[i].update({tag["Key"]: tag["Value"]})

        try:
            output = json.dumps(response["Vpcs"], cls=DatetimeEncoder)
            raw = json.loads(output)
            raw[0].update({"Region": args["region"]})
        except ValueError as e:
            raise DemistoException(f"Could not decode/encode the raw response - {e}")
        return CommandResults(
            outputs=raw,
            outputs_prefix="AWS.EC2.Vpcs",
            outputs_key_field="VpcId",
            readable_output=tableToMarkdown(
                "AWS EC2 Vpcs",
                data,
                headers=["VpcId", "IsDefault", "CidrBlock", "DhcpOptionsId", "State", "InstanceTenancy", "Region"],
                removeNull=True,
            ),
            raw_response=response,
        )

    @staticmethod
    def describe_subnets_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Describes one or more of your subnets.
        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including subnet IDs

        Returns:
            CommandResults: Results of the operation with subnet information
        """
        kwargs = {}
        data = []
        if args.get("filters"):
            kwargs.update({"Filters": parse_filter_field(args.get("filters"))})
        if args.get("subnet_ids"):
            kwargs.update({"SubnetIds": parse_resource_ids(args.get("subnet_ids"))})

        response = client.describe_subnets(**kwargs)

        if len(response["Subnets"]) == 0:
            return CommandResults(readable_output="No subnets were found.")
        for i, subnet in enumerate(response["Subnets"]):
            data.append(
                {
                    "AvailabilityZone": subnet["AvailabilityZone"],
                    "AvailableIpAddressCount": subnet["AvailableIpAddressCount"],
                    "CidrBlock": subnet.get("CidrBlock", ""),
                    "DefaultForAz": subnet["DefaultForAz"],
                    "State": subnet["State"],
                    "SubnetId": subnet["SubnetId"],
                    "VpcId": subnet["VpcId"],
                    "Region": args["region"],
                }
            )

            if "Tags" in subnet:
                for tag in subnet["Tags"]:
                    data[i].update({tag["Key"]: tag["Value"]})

        try:
            output = json.dumps(response["Subnets"], cls=DatetimeEncoder)
            raw = json.loads(output)
            raw[0].update({"Region": args["region"]})
        except ValueError as e:
            raise DemistoException(f"Could not decode/encode the raw response - {e}")
        return CommandResults(
            outputs=raw,
            outputs_prefix="AWS.EC2.Subnets",
            outputs_key_field="SubnetId",
            readable_output=tableToMarkdown(
                "AWS EC2 Subnets",
                data,
                headers=[
                    "SubnetId",
                    "AvailabilityZone",
                    "AvailableIpAddressCount",  # noqa: E501
                    "CidrBlock",
                    "DefaultForAz",
                    "State",
                    "VpcId",
                    "Region",
                ],
                removeNull=True,
            ),
            raw_response=response,
        )

    @staticmethod
    def describe_ipam_resource_discoveries_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """Describes one or more IPAM resource discoveries.
        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including filters, max results, next token, and IPAM resource discovery IDs

        Returns:
            CommandResults: Results of the operation with IPAM resource discovery information
        """
        kwargs = {
            "Filters": parse_filter_field(args.get("filters")),
            "IpamResourceDiscoveryIds": argToList(args.get("ipam_resource_discovery_ids")),
        }
        if not args.get("ipam_resource_discovery_ids"):
            pagination_kwargs = build_pagination_kwargs(args, minimum_limit=5)
            kwargs.update(pagination_kwargs)

        remove_nulls_from_dictionary(kwargs)

        response = client.describe_ipam_resource_discoveries(**kwargs)

        if len(response["IpamResourceDiscoveries"]) == 0:
            return CommandResults(readable_output="No Ipam Resource Discoveries were found.")

        human_readable = tableToMarkdown("Ipam Resource Discoveries", response["IpamResourceDiscoveries"], removeNull=True)
        command_results = CommandResults(
            outputs_prefix="AWS.EC2.IpamResourceDiscoveries",
            outputs_key_field="IpamResourceDiscoveryId",
            outputs=response["IpamResourceDiscoveries"],
            raw_response=response,
            readable_output=human_readable,
        )
        return command_results

    @staticmethod
    def describe_ipam_resource_discovery_associations_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """Describes one or more IPAM resource discovery associations.
        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including filters, max results, next token, and IPAM resource discovery IDs

        Returns:
            CommandResults: Results of the operation with IPAM resource discovery association information
        """
        kwargs = {
            "Filters": parse_filter_field(args.get("filters")),
            "IpamResourceDiscoveryAssociationIds": argToList(args.get("ipam_resource_discovery_association_ids")),
        }
        if not args.get("ipam_resource_discovery_association_ids"):
            pagination_kwargs = build_pagination_kwargs(args, minimum_limit=5)
            kwargs.update(pagination_kwargs)

        remove_nulls_from_dictionary(kwargs)

        response = client.describe_ipam_resource_discovery_associations(**kwargs)

        if len(response["IpamResourceDiscoveryAssociations"]) == 0:
            return CommandResults(readable_output="No Ipam Resource Discovery Associations were found.")

        human_readable = tableToMarkdown(
            "Ipam Resource Discovery Associations", response["IpamResourceDiscoveryAssociations"], removeNull=True
        )  # noqa: E501
        command_results = CommandResults(
            outputs_prefix="AWS.EC2.IpamResourceDiscoveryAssociations",
            outputs_key_field="IpamResourceDiscoveryId",
            outputs=response["IpamResourceDiscoveryAssociations"],
            raw_response=response,
            readable_output=human_readable,
        )
        return command_results

    @staticmethod
    def get_latest_ami_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Retrieves information about the latest Amazon Machine Image (AMI) based on provided filters.
        The function calls the AWS EC2 'describe_images' API, sorts the results by
        'CreationDate' in descending order, and returns the first image in the list.
        Args:
            client (BotoClient): The initialized Boto3 EC2 client.
            args (Dict[str, Any]): Command arguments, typically containing:
                  Expected keys include 'executable_by', 'filters', 'owners', 'image_id',
                  'include_deprecated', and 'include_disabled'.

        Returns:
            CommandResults: An object containing the raw image details as outputs,
                            and a md table with a concise summary of the latest AMI.
        """
        kwargs = {
            "ExecutableUsers": parse_resource_ids(args.get("executable_users")) if args.get("executable_users") else None,
            "Filters": parse_filter_field(args.get("filters")),
            "Owners": parse_resource_ids(args.get("owners")) if args.get("owners") else None,
            "ImageIds": parse_resource_ids(args.get("image_ids")) if args.get("image_ids") else None,
            "IncludeDeprecated": arg_to_bool_or_none(args.get("include_deprecated")),
            "IncludeDisabled": arg_to_bool_or_none(args.get("include_disabled")),
        }

        remove_nulls_from_dictionary(kwargs)
        response = client.describe_images(**kwargs)
        if response["ResponseMetadata"]["HTTPStatusCode"] not in [HTTPStatus.OK, HTTPStatus.NO_CONTENT]:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))
        amis = response.get("Images", [])
        iterates = 1

        while response.get("nextToken"):
            demisto.info(f"iterate #{iterates}")
            kwargs["NextToken"] = response.get("nextToken")
            response = client.describe_images(**kwargs)
            if response["ResponseMetadata"]["HTTPStatusCode"] not in [HTTPStatus.OK, HTTPStatus.NO_CONTENT]:
                AWSErrorHandler.handle_response_error(response, args.get("account_id"))
            amis.extend(response.get("Images", []))
            iterates += 1

        # return CommandResults(readable_output=f"Fetched {len(amis)} AMIs")
        demisto.info(f"Fetched {len(amis)} AMIs")
        if not amis:
            return CommandResults(readable_output="No AMIs found.")

        sorted_amis = sorted(amis, key=lambda x: x["CreationDate"], reverse=True)
        image = sorted_amis[0]
        data = {
            "CreationDate": image.get("CreationDate"),
            "ImageId": image.get("ImageId"),
            "Public": image.get("Public"),
            "Name": image.get("Name"),
            "State": image.get("State"),
            "Region": args.get("region"),
            "Description": image.get("Description"),
        }
        data.update({tag["Key"]: tag["Value"] for tag in image["Tags"]}) if "Tags" in image else None
        remove_nulls_from_dictionary(data)

        return CommandResults(
            outputs=image,
            outputs_prefix="AWS.EC2.Images",
            readable_output=tableToMarkdown("AWS EC2 latest Image", data, headerTransform=pascalToSpace, removeNull=True),
            outputs_key_field="ImageId",
        )

    @staticmethod
    def create_network_acl_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Creates a Network Access Control List (Network ACL) for the specified VPC.
        The function calls the AWS EC2 'create_network_acl' API. It requires the ID
        of the VPC where the Network ACL will be created.

        Args:
           client (BotoClient): The initialized Boto3 EC2 client.
            args: A dictionary containing arguments for creating the Network ACL.
                  Expected keys include 'vpc_id' (required), 'client_token', and
                  'tag_specification'.

        Returns:
            CommandResults: An object containing the raw Network ACL details as outputs,
                            and a md table with a summary of the created Network ACL
                            and its default entries.
        """
        kwargs = {
            "VpcId": args.get("vpc_id"),
            "ClientToken": args.get("client_token"),
            "TagSpecifications": parse_tag_field(args.get("tag_specifications")),
        }

        remove_nulls_from_dictionary(kwargs)
        if tag_specifications := kwargs.get("TagSpecifications"):
            kwargs["TagSpecifications"] = [{"ResourceType": "network-acl", "Tags": tag_specifications}]

        response = client.create_network_acl(**kwargs)
        if response["ResponseMetadata"]["HTTPStatusCode"] not in [HTTPStatus.OK, HTTPStatus.NO_CONTENT]:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        network_acl = response.get("NetworkAcl")
        readable_data = {
            "Associations": network_acl.get("Associations"),
            "IsDefault": network_acl.get("IsDefault"),
            "NetworkAclId": network_acl.get("NetworkAclId"),
            "Tags": network_acl.get("Tags"),
            "VpcId": network_acl.get("VpcId"),
        }
        return CommandResults(
            outputs=network_acl,
            outputs_prefix="AWS.EC2.VpcId.NetworkAcl",
            outputs_key_field="VpcId",
            readable_output=(
                tableToMarkdown(
                    "The AWS EC2 Instance ACL",
                    readable_data,
                    removeNull=True,
                    headerTransform=pascalToSpace,
                )
                + tableToMarkdown(
                    f"The Entries of AWS EC2 ACL {network_acl.get('NetworkAclId')}",
                    [entry for entry in network_acl.get("Entries")],  # noqa: C416
                    removeNull=True,
                    headerTransform=pascalToSpace,
                )
            ),
        )

    @staticmethod
    def get_ipam_discovered_public_addresses_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        aws-ec2-get-ipam-discovered-public-addresses: Gets the public IP addresses that have been discovered by IPAM.

        Args:
            client (BotoClient): The initialized Boto3 EC2 client.
            args (dict): all command arguments, usually passed from ``demisto.args()``.

        Returns:
            CommandResults: A ``CommandResults`` object that is then passed to ``return_results``,
             that contains public IP addresses that have been discovered by IPAM.
        """
        kwargs = {
            "IpamResourceDiscoveryId": args.get("ipam_resource_discovery_id"),
            "AddressRegion": args.get("address_region"),
            "Filters": parse_filter_field(args.get("filters")),
            "MaxResults": arg_to_number(args.get("limit", 1000)),
            "NextToken": args.get("next_token"),
        }

        remove_nulls_from_dictionary(kwargs)
        response = client.get_ipam_discovered_public_addresses(**kwargs)
        if response["ResponseMetadata"]["HTTPStatusCode"] not in [HTTPStatus.OK, HTTPStatus.NO_CONTENT]:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))
        if not response.get("IpamDiscoveredPublicAddresses"):
            return CommandResults(readable_output="No Ipam Discovered Public Addresses were found.")

        output = json.loads(json.dumps(response, cls=DatetimeEncoder))
        human_readable = tableToMarkdown(
            "Ipam Discovered Public Addresses",
            output.get("IpamDiscoveredPublicAddresses"),
            headerTransform=pascalToSpace,
            removeNull=True,
        )
        return CommandResults(
            outputs_prefix="AWS.EC2.IpamDiscoveredPublicAddresses",
            outputs_key_field="Address",
            outputs=output.get("IpamDiscoveredPublicAddresses"),
            raw_response=output,
            readable_output=human_readable,
        )

    @staticmethod
    def create_tags_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Adds or overwrites one or more tags for the specified AWS resources.

        The function calls the AWS EC2 'create_tags' API. It requires a list of resource IDs
        to tag and a list of key-value pairs representing the tags to apply.

        Args:
            client (BotoClient): The initialized Boto3 EC2 client.
            args: A dictionary containing arguments for creating the tags.
                  Expected keys are 'resources' (list of resource IDs) and 'tags'
                  (list of key-value tag dictionaries).

        Returns:
            CommandResults: An object confirming the successful tagging operation via a
                            readable output message. The command has no explicit outputs.
        """
        kwargs = {
            "Resources": parse_resource_ids(args.get("resources")),
            "Tags": parse_tag_field(args.get("tags")),
        }

        response = client.create_tags(**kwargs)
        if response["ResponseMetadata"]["HTTPStatusCode"] not in [HTTPStatus.OK, HTTPStatus.NO_CONTENT]:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        return CommandResults(readable_output="The resources where tagged successfully")

    @staticmethod
    def create_security_group_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Creates a new security group in the specified VPC or EC2-Classic.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including:
                - group_name (str): Name of the security group.
                - description (str): Description of the security group.
                - vpc_id (str, optional): VPC ID where security group will be created.

        Returns:
            CommandResults: Results of the operation with security group creation details
        """
        group_name = args.get("group_name")
        description = args.get("description")
        vpc_id = args.get("vpc_id")
        kwargs = {"Description": description, "GroupName": group_name, "VpcId": vpc_id}
        remove_nulls_from_dictionary(kwargs)
        response = client.create_security_group(**kwargs)
        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") == HTTPStatus.OK and (group_id := response.get("GroupId")):
            return CommandResults(
                readable_output=f'The security group "{group_id}" was created successfully.',
                raw_response=response,
            )
        else:
            return AWSErrorHandler.handle_response_error(response)

    @staticmethod
    def delete_security_group_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Deletes a security group.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including:
                - group_id (str, optional): ID of the security group to delete.
                - group_name (str, optional): Name of the security group to delete.

        Returns:
            CommandResults: Results of the operation with deletion confirmation
        """
        group_id = args.get("group_id")
        group_name = args.get("group_name")

        if not group_id and not group_name:
            raise DemistoException("Either group_id or group_name must be provided")

        if group_id and group_name:
            raise DemistoException("Cannot specify both group_id and group_name. Please provide only one.")

        kwargs = {}

        if group_id:
            kwargs["GroupId"] = group_id
        else:
            kwargs["GroupName"] = group_name

        remove_nulls_from_dictionary(kwargs)
        response = client.delete_security_group(**kwargs)
        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") == HTTPStatus.OK and response.get("GroupId"):
            return CommandResults(
                readable_output=f"Successfully deleted security group: {response.get('GroupId')}",
                raw_response=response,
            )
        else:
            # If group_id was not found or no GroupId in response, raise an exception
            return AWSErrorHandler.handle_response_error(response)

    @staticmethod
    def describe_security_groups_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Describes one or more security groups in your account.
        Returns detailed information about security groups including their rules, tags, and associated VPC information.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including:
                - group_ids (str, optional): Comma-separated list of security group IDs
                - group_names (str, optional): Comma-separated list of security group names
                - filters (str, optional): Custom filters to apply


        Returns:
            CommandResults: Results containing security group details
        """
        kwargs = {}
        data = []
        if args.get("filters") is not None:
            kwargs.update({"Filters": parse_filter_field(args.get("filters"))})
        if args.get("group_ids") is not None:
            kwargs.update({"GroupIds": argToList(args.get("group_ids", []))})
        if args.get("group_names") is not None:
            kwargs.update({"GroupNames": argToList(args.get("group_names", []))})
        # Can't add limit when specify GroupIds or GroupNames
        if not args.get("group_ids") and not args.get("group_names"):
            kwargs.update(build_pagination_kwargs(args))

        remove_nulls_from_dictionary(kwargs)
        response = client.describe_security_groups(**kwargs)
        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") == HTTPStatus.OK:
            if len(response["SecurityGroups"]) == 0:
                return CommandResults(readable_output="No security groups were found.")
            for _, sg in enumerate(response["SecurityGroups"]):
                data.append(
                    {
                        "Description": sg["Description"],
                        "GroupName": sg["GroupName"],
                        "OwnerId": sg["OwnerId"],
                        "GroupId": sg["GroupId"],
                        "VpcId": sg["VpcId"],
                        "tags": sg.get("Tags"),
                    }
                )
            output = json.dumps(response["SecurityGroups"], cls=DatetimeEncoder)

            outputs = {
                "AWS.EC2.SecurityGroups(val.GroupId && val.GroupId == obj.GroupId)": json.loads(output),
                "AWS.EC2(true)": {"SecurityGroupsNextToken": response.get("NextToken")},
            }
            return CommandResults(
                outputs=outputs,
                readable_output=tableToMarkdown("AWS EC2 SecurityGroups", data, removeNull=True),
                raw_response=response,
            )
        else:
            return AWSErrorHandler.handle_response_error(response)

    @staticmethod
    def describe_addresses_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Describes one or more Elastic IP addresses.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including:
                - filters (str, optional): One or more filters separated by ';'
                - public_ips (str, optional): Comma-separated list of public IP addresses
                - allocation_ids (str, optional): Comma-separated list of allocation IDs

        Returns:
            CommandResults: Results containing Elastic IP address information
        """
        kwargs = {}

        # Add filters if provided
        if filters_arg := args.get("filters"):
            kwargs["Filters"] = parse_filter_field(filters_arg)

        # Add public IPs if provided
        if public_ips := args.get("public_ips"):
            kwargs["PublicIps"] = parse_resource_ids(public_ips)

        # Add allocation IDs if provided
        if allocation_ids := args.get("allocation_ids"):
            kwargs["AllocationIds"] = parse_resource_ids(allocation_ids)

        print_debug_logs(client, f"Describing addresses with parameters: {kwargs}")
        remove_nulls_from_dictionary(kwargs)

        response = client.describe_addresses(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        addresses = response.get("Addresses", [])
        if not addresses:
            return CommandResults(readable_output="No Elastic IP addresses were found.")

        # Serialize response to handle datetime objects
        response = serialize_response_with_datetime_encoding(response)
        addresses = response.get("Addresses", [])

        return CommandResults(
            outputs_prefix="AWS.EC2.ElasticIPs",
            outputs_key_field="AllocationId",
            outputs=addresses,
            readable_output=tableToMarkdown(
                "AWS EC2 Elastic IP Addresses",
                addresses,
                headers=[
                    "PublicIp",
                    "AllocationId",
                    "Domain",
                    "InstanceId",
                    "AssociationId",
                    "NetworkInterfaceId",
                    "PrivateIpAddress",
                ],
                removeNull=True,
                headerTransform=pascalToSpace,
            ),
            raw_response=response,
        )

    @staticmethod
    def allocate_address_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Allocates an Elastic IP address to your AWS account.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including:
                - address (str, optional): The Elastic IP address to recover
                - public_ipv4_pool (str, optional): The ID of an address pool
                - network_border_group (str, optional): A unique set of Availability Zones, Local Zones, or Wavelength Zones
                - customer_owned_ipv4_pool (str, optional): The ID of a customer-owned address pool
                - tag_specifications (str, optional): Tags to assign to the Elastic IP address

        Returns:
            CommandResults: Results containing the allocated Elastic IP information
        """
        kwargs = {
            "Address": args.get("address"),
            "PublicIpv4Pool": args.get("public_ipv4_pool"),
            "NetworkBorderGroup": args.get("network_border_group"),
            "CustomerOwnedIpv4Pool": args.get("customer_owned_ipv4_pool"),
        }

        if tag_specifications := args.get("tag_specifications"):
            kwargs["TagSpecifications"] = [{"ResourceType": "elastic-ip", "Tags": parse_tag_field(tag_specifications)}]

        remove_nulls_from_dictionary(kwargs)
        print_debug_logs(client, f"Allocating address with parameters: {kwargs}")
        response = client.allocate_address(**kwargs)
        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        # Serialize response to handle datetime objects
        response = serialize_response_with_datetime_encoding(response)
        outputs = {k: v for k, v in response.items() if k != "ResponseMetadata"}

        return CommandResults(
            outputs_prefix="AWS.EC2.ElasticIPs",
            outputs_key_field="AllocationId",
            outputs=outputs,
            readable_output=tableToMarkdown(
                "AWS EC2 Allocated Elastic IP",
                outputs,
                headers=["PublicIp", "AllocationId", "Domain", "PublicIpv4Pool", "NetworkBorderGroup"],
                removeNull=True,
                headerTransform=pascalToSpace,
            ),
            raw_response=response,
        )

    @staticmethod
    def associate_address_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Associates an Elastic IP address with an instance or a network interface.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including:
                - allocation_id (str): The allocation ID (required for VPC)
                - instance_id (str, optional): The ID of the instance
                - network_interface_id (str, optional): The ID of the network interface
                - private_ip_address (str, optional): The primary or secondary private IP address
                - allow_reassociation (str, optional): Whether to allow reassociation
        Returns:
            CommandResults: Results containing the association information
        """
        kwargs = {
            "AllocationId": args.get("allocation_id"),
            "InstanceId": args.get("instance_id"),
            "NetworkInterfaceId": args.get("network_interface_id"),
            "PrivateIpAddress": args.get("private_ip_address"),
            "AllowReassociation": arg_to_bool_or_none(args.get("allow_reassociation")),
        }

        remove_nulls_from_dictionary(kwargs)
        print_debug_logs(client, f"Associating address with parameters: {kwargs}")

        response = client.associate_address(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        # Build output data
        output_data = {
            "AllocationId": args.get("allocation_id"),
            "AssociationId": response.get("AssociationId"),
        }
        output_data = remove_empty_elements(output_data)
        return CommandResults(
            outputs_prefix="AWS.EC2.ElasticIPs",
            outputs_key_field="AllocationId",
            outputs=output_data,
            readable_output=tableToMarkdown(
                "AWS EC2 Elastic IP Association",
                output_data,
                headers=["AllocationId", "AssociationId"],
                removeNull=True,
                headerTransform=pascalToSpace,
            ),
            raw_response=response,
        )

    @staticmethod
    def disassociate_address_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Disassociates an Elastic IP address from the instance or network interface it's associated with.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including:
                - association_id (str): The association ID (required for VPC)
        Returns:
            CommandResults: Results of the disassociation operation
        """
        kwargs = {"AssociationId": args.get("association_id")}

        print_debug_logs(client, f"Disassociating address with parameters: {kwargs}")

        response = client.disassociate_address(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        return CommandResults(
            readable_output=f"Successfully disassociated Elastic IP address (Association ID: {args.get('association_id')})",
            raw_response=response,
        )

    @staticmethod
    def release_address_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Releases the specified Elastic IP address.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including:
                - allocation_id (str): The allocation ID (required for VPC)
                - network_border_group (str, optional): The set of Availability Zones, Local Zones, or Wavelength Zones

        Returns:
            CommandResults: Results of the release operation
        """
        kwargs = {
            "AllocationId": args.get("allocation_id"),
            "NetworkBorderGroup": args.get("network_border_group"),
        }

        remove_nulls_from_dictionary(kwargs)
        print_debug_logs(client, f"Releasing address with parameters: {kwargs}")

        response = client.release_address(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        return CommandResults(
            readable_output=f"Successfully released Elastic IP address (Allocation ID: {args.get('allocation_id')})",
            raw_response=response,
        )

    @staticmethod
    def authorize_security_group_egress_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Adds the specified outbound (egress) rules to a security group.

        The command supports two modes:
        1. Simple mode: using protocol, port, and cidr arguments
        2. Full mode: using ip_permissions for complex configurations
        """

        kwargs: Dict[str, Any] = {"GroupId": args.get("group_id")}
        from_port = arg_to_number(args.get("from_port"))
        to_port = arg_to_number(args.get("to_port"))

        if ip_permissions := args.get("ip_permissions"):
            try:
                kwargs["IpPermissions"] = json.loads(ip_permissions)
            except json.JSONDecodeError as e:
                raise DemistoException(f"Received invalid `ip_permissions` JSON object: {e}")
        else:
            kwargs["IpPermissions"] = [
                {
                    "IpProtocol": args.get("protocol"),
                    "FromPort": from_port,
                    "ToPort": to_port,
                    "IpRanges": [{"CidrIp": args.get("cidr")}] if args.get("cidr") else None,
                }
            ]

        remove_nulls_from_dictionary(kwargs["IpPermissions"][0])
        response = client.authorize_security_group_egress(**kwargs)

        if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK and response["Return"]:
            readable_output = (
                "The Security Group egress rule was authorized"
                if response.get("SecurityGroupRules")
                else "No Security Group egress rule was authorized"
            )
            return CommandResults(readable_output=readable_output, raw_response=response)
        else:
            return AWSErrorHandler.handle_response_error(response)

    @staticmethod
    def describe_images_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Describes one or more Amazon Machine Images (AMIs) available to you.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including:
                - filters (str, optional): One or more filters separated by ';'
                - image_ids (str, optional): Comma-separated list of image IDs
                - owners (str, optional): Comma-separated list of image owners
                - executable_users (str, optional): Comma-separated list of users with explicit launch permissions
                - include_deprecated (str, optional): Whether to include deprecated AMIs
                - include_disabled (str, optional): Whether to include disabled AMIs
                - limit (int, optional): Maximum number of AMIs to return
                - next_token (str, optional): The token for the next set of AMIs to return.

        Returns:
            CommandResults: Results containing AMI information
        """

        kwargs = {}

        # Add filters if provided
        if filters_arg := args.get("filters"):
            kwargs["Filters"] = parse_filter_field(filters_arg)

        # Add image IDs if provided
        if image_ids := args.get("image_ids"):
            kwargs["ImageIds"] = parse_resource_ids(image_ids)

        # Add owners if provided
        if owners := args.get("owners"):
            kwargs["Owners"] = parse_resource_ids(owners)

        # Add executable users if provided
        if executable_users := args.get("executable_users"):
            kwargs["ExecutableUsers"] = parse_resource_ids(executable_users)

        # Add include_deprecated if provided
        if include_deprecated := args.get("include_deprecated"):
            kwargs["IncludeDeprecated"] = argToBoolean(include_deprecated)

        # Add include_disabled if provided
        if include_disabled := args.get("include_disabled"):
            kwargs["IncludeDisabled"] = argToBoolean(include_disabled)

        pagination_kwargs = build_pagination_kwargs(args, minimum_limit=5)
        kwargs.update(pagination_kwargs)

        remove_nulls_from_dictionary(kwargs)
        print_debug_logs(client, f"Describing images with parameters: {kwargs}")

        response = client.describe_images(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        images = response.get("Images", [])
        if not images:
            return CommandResults(readable_output="No images were found.")

        # Serialize response to handle datetime objects
        response = serialize_response_with_datetime_encoding(response)
        images = response.get("Images", [])

        outputs = {
            "AWS.EC2.Images(val.ImageId && val.ImageId == obj.ImageId)": images,
            "AWS.EC2(true)": {
                "ImagesNextPageToken": response.get("NextToken"),
            },
        }

        next_token = response.get("NextToken")
        next_token_text = f"ImagesNextPageToken: {escape(next_token)}" if next_token else ""

        return CommandResults(
            outputs=outputs,
            readable_output=tableToMarkdown(
                "AWS EC2 Images",
                images,
                headers=["ImageId", "Name", "CreationDate", "State", "Public", "Description"],
                removeNull=True,
                headerTransform=pascalToSpace,
                metadata=next_token_text,
            ),
            raw_response=response,
        )

    @staticmethod
    def create_image_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Creates an Amazon EBS-backed AMI from an Amazon EBS-backed instance.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including:
                - name (str): A name for the new image (required)
                - instance_id (str): The ID of the instance (required)
                - description (str, optional): A description for the new image
                - no_reboot (boolean, optional): By default, Amazon EC2 attempts to shut down and reboot the instance
                  before creating the image. If set to true, Amazon EC2 won't shut down the instance
                - block_device_mappings (str, optional): JSON string of block device mappings
                - tag_specifications (str, optional): Tags to apply to the AMI and snapshots

        Returns:
            CommandResults: Results containing the created AMI information
        """
        kwargs = {
            "Name": args.get("name"),
            "InstanceId": args.get("instance_id"),
            "Description": args.get("description"),
            "NoReboot": arg_to_bool_or_none(args.get("no_reboot")),
        }

        # Handle block device mappings if provided
        if block_device_mappings := args.get("block_device_mappings"):
            try:
                kwargs["BlockDeviceMappings"] = (
                    json.loads(block_device_mappings) if isinstance(block_device_mappings, str) else block_device_mappings
                )
            except json.JSONDecodeError as e:
                raise DemistoException(f"Invalid block_device_mappings JSON: {e}")

        # Handle tag specifications if provided
        if tag_specifications := args.get("tag_specifications"):
            kwargs["TagSpecifications"] = [{"ResourceType": "image", "Tags": parse_tag_field(tag_specifications)}]

        remove_nulls_from_dictionary(kwargs)
        print_debug_logs(client, f"Creating image with parameters: {kwargs}")

        response = client.create_image(**kwargs)
        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        # Serialize response to handle datetime objects
        response = serialize_response_with_datetime_encoding(response)
        # Build output data
        output_data = {
            "ImageId": response.get("ImageId"),
            "Name": args.get("name"),
            "InstanceId": args.get("instance_id"),
            "Region": args.get("region"),
        }
        output_data = remove_empty_elements(output_data)

        return CommandResults(
            outputs_prefix="AWS.EC2.Images",
            outputs_key_field="ImageId",
            outputs=output_data,
            readable_output=tableToMarkdown(
                "AWS EC2 Image Created",
                output_data,
                headers=["ImageId", "Name", "InstanceId", "Region"],
                removeNull=True,
                headerTransform=pascalToSpace,
            ),
            raw_response=response,
        )

    @staticmethod
    def deregister_image_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Deregisters the specified Amazon Machine Image (AMI).

        After you deregister an AMI, it can't be used to launch new instances. However, it doesn't affect
        any instances that you've already launched from the AMI.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including:
                - image_id (str): The ID of the AMI to deregister (required)

        Returns:
            CommandResults: Results of the deregistration operation
        """
        image_id = args.get("image_id")
        print_debug_logs(client, f"Deregistering image: {image_id}")
        response = client.deregister_image(ImageId=image_id)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        return CommandResults(
            readable_output=f"Successfully deregistered AMI: {image_id}",
            raw_response=response,
        )

    @staticmethod
    def copy_image_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Copy an Amazon Machine Image (AMI) from a source region to the current region.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including:
                - name (str): Name for the new AMI in the destination region (required)
                - source_image_id (str): ID of the AMI to copy (required)
                - source_region (str): Region that contains the AMI to copy (required)
                - description (str, optional): Description for the new AMI
                - encrypted (boolean, optional): Whether destination snapshots should be encrypted
                - kms_key_id (str, optional): KMS key ID for encryption
                - client_token (str, optional): Idempotency token

        Returns:
            CommandResults: Results containing the new ImageId and Region
        """
        # Validate required parameters
        name = args.get("name", "")
        source_image_id = args.get("source_image_id", "")
        source_region = args.get("source_region", "")

        print_debug_logs(client, f"Copying image {source_image_id} from region {source_region}")

        # Build API parameters
        kwargs: Dict[str, Any] = {
            "Name": name,
            "SourceImageId": source_image_id,
            "SourceRegion": source_region,
            "Description": args.get("description"),
            "Encrypted": arg_to_bool_or_none(args.get("encrypted")),
            "KmsKeyId": args.get("kms_key_id"),
            "ClientToken": args.get("client_token"),
        }

        # Remove None values
        remove_nulls_from_dictionary(kwargs)
        print_debug_logs(client, f"Copying image with parameters: {kwargs}")
        response = client.copy_image(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        region = args.get("region", "")

        # Prepare outputs
        outputs = {
            "ImageId": response["ImageId"],
            "Name": name,
            "SourceImageId": source_image_id,
            "SourceRegion": source_region,
            "Region": region,
        }

        # Prepare human-readable output
        readable_output = tableToMarkdown(
            "AWS EC2 Image Copy",
            outputs,
            headers=["ImageId", "Name", "SourceImageId", "SourceRegion", "Region"],
            headerTransform=pascalToSpace,
            removeNull=True,
        )

        return CommandResults(
            outputs_prefix="AWS.EC2.Images",
            outputs_key_field="ImageId",
            outputs=outputs,
            readable_output=readable_output,
            raw_response=response,
        )

    @staticmethod
    def image_available_waiter_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Waits until an Amazon Machine Image (AMI) becomes available.

        This command uses AWS EC2's built-in waiter functionality to poll the image state
        until it reaches the 'available' state. The waiter will check the image status at
        regular intervals (configurable via waiter_delay) up to a maximum number of attempts
        (configurable via waiter_max_attempts).

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including:
                - filters (str, optional): One or more filters separated by ';'
                - image_ids (str, optional): Comma-separated list of image IDs to wait for
                - owners (str, optional): Comma-separated list of image owners
                - executable_users (str, optional): Comma-separated list of users with explicit launch permissions
                - waiter_delay (str, optional): Time in seconds to wait between polling attempts (default: 15)
                - waiter_max_attempts (str, optional): Maximum number of polling attempts (default: 40)

        Returns:
            CommandResults: Results with success message when image becomes available

        Raises:
            WaiterError: If the waiter times out or encounters an error
        """
        kwargs: Dict[str, Any] = {}

        # Add optional filters
        if filters := args.get("filters"):
            kwargs["Filters"] = parse_filter_field(filters)

        # Add optional image IDs
        if image_ids := args.get("image_ids"):
            kwargs["ImageIds"] = parse_resource_ids(image_ids)

        # Add optional executable users
        if executable_users := args.get("executable_users"):
            kwargs["ExecutableUsers"] = parse_resource_ids(executable_users)

        # Add optional owners
        if owners := args.get("owners"):
            kwargs["Owners"] = parse_resource_ids(owners)

        # Configure waiter settings
        waiter_config: Dict[str, int] = {}
        if waiter_delay := arg_to_number(args.get("waiter_delay")):
            waiter_config["Delay"] = waiter_delay
        if waiter_max_attempts := arg_to_number(args.get("waiter_max_attempts")):
            waiter_config["MaxAttempts"] = waiter_max_attempts

        if waiter_config:
            kwargs["WaiterConfig"] = waiter_config

        print_debug_logs(client, f"Waiting for image to become available with parameters: {kwargs}")
        remove_nulls_from_dictionary(kwargs)

        try:
            waiter = client.get_waiter("image_available")
            waiter.wait(**kwargs)

            return CommandResults(readable_output="Image is now available.")
        except Exception as e:
            raise DemistoException(f"Waiter error: {str(e)}")

    @staticmethod
    def monitor_instances_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Enables detailed monitoring for one or more Amazon EC2 instances.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments containing:
                - instance_ids (str): Comma-separated list of instance IDs to monitor

        Returns:
            CommandResults: Results of the operation with monitoring status information
        """
        instance_ids = parse_resource_ids(args.get("instance_ids"))
        print_debug_logs(client, f"Monitoring instance(s): {instance_ids}")
        response = client.monitor_instances(InstanceIds=instance_ids)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        instance_monitorings = response.get("InstanceMonitorings", [])

        if not instance_monitorings:
            return CommandResults(readable_output="No instances were monitored.")

        # Format output data
        readable_data = []
        for monitoring in instance_monitorings:
            readable_data.append(
                {"InstanceId": monitoring.get("InstanceId"), "MonitoringState": monitoring.get("Monitoring", {}).get("State")}
            )

        readable_output = tableToMarkdown(
            "Successfully enabled monitoring for instances",
            readable_data,
            headers=["InstanceId", "MonitoringState"],
            headerTransform=pascalToSpace,
            removeNull=True,
        )

        return CommandResults(
            outputs_prefix="AWS.EC2.Instances",
            outputs_key_field="InstanceId",
            outputs=instance_monitorings,
            readable_output=readable_output,
            raw_response=response,
        )

    @staticmethod
    def unmonitor_instances_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Disables detailed monitoring for one or more Amazon EC2 instances.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments containing:
                - instance_ids (str): Comma-separated list of instance IDs to unmonitor

        Returns:
            CommandResults: Results of the operation with monitoring status information
        """
        instance_ids = parse_resource_ids(args.get("instance_ids"))
        print_debug_logs(client, f"Unmonitoring instance(s): {instance_ids}")
        response = client.unmonitor_instances(InstanceIds=instance_ids)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        instance_monitorings = response.get("InstanceMonitorings", [])

        if not instance_monitorings:
            return CommandResults(readable_output="No instances were unmonitored.")

        # Format output data
        readable_data = []
        for monitoring in instance_monitorings:
            readable_data.append(
                {"InstanceId": monitoring.get("InstanceId"), "MonitoringState": monitoring.get("Monitoring", {}).get("State")}
            )

        readable_output = tableToMarkdown(
            "Successfully disabled monitoring for instances",
            readable_data,
            headers=["InstanceId", "MonitoringState"],
            headerTransform=pascalToSpace,
            removeNull=True,
        )

        return CommandResults(
            outputs_prefix="AWS.EC2.Instances",
            outputs_key_field="InstanceId",
            outputs=instance_monitorings,
            readable_output=readable_output,
            raw_response=response,
        )

    @staticmethod
    def reboot_instances_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Requests a reboot of one or more Amazon EC2 instances.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments containing:
                - instance_ids (str): Comma-separated list of instance IDs to reboot

        Returns:
            CommandResults: Results of the operation with reboot confirmation
        """
        instance_ids = parse_resource_ids(args.get("instance_ids"))
        print_debug_logs(client, f"Rebooting instance(s): {instance_ids}")
        response = client.reboot_instances(InstanceIds=instance_ids)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        return CommandResults(
            readable_output=f"Successfully initiated reboot for instances: {', '.join(instance_ids)}", raw_response=response
        )

    @staticmethod
    def instance_running_waiter_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Waits until EC2 instances are in the 'running' state.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments containing:
                - instance_ids (str, optional): Comma-separated list of instance IDs
                - filters (str, optional): Filters for instances
                - waiter_delay (int, optional): Delay between attempts in seconds (default: 15)
                - waiter_max_attempts (int, optional): Maximum number of attempts (default: 40)

        Returns:
            CommandResults: Results indicating instances are running
        """
        kwargs = {}

        if filters := args.get("filters"):
            kwargs["Filters"] = parse_filter_field(filters)

        if instance_ids := args.get("instance_ids"):
            kwargs["InstanceIds"] = parse_resource_ids(instance_ids)

        waiter_config = {
            "Delay": arg_to_number(args.get("waiter_delay", "15")),
            "MaxAttempts": arg_to_number(args.get("waiter_max_attempts", "40")),
        }
        kwargs["WaiterConfig"] = waiter_config

        try:
            waiter = client.get_waiter("instance_running")
            waiter.wait(**kwargs)
            return CommandResults(readable_output="Instance(s) are now running.")
        except Exception as e:
            raise DemistoException(f"Waiter error: {str(e)}")

    @staticmethod
    def instance_status_ok_waiter_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Waits until EC2 instance status checks pass.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments containing:
                - instance_ids (str, optional): Comma-separated list of instance IDs
                - filters (str, optional): Filters for instances
                - include_all_instances (bool, optional): Specifies whether to include the health status for all
                 instances or only for those currently running.
                - waiter_delay (int, optional): Delay between attempts in seconds (default: 15)
                - waiter_max_attempts (int, optional): Maximum number of attempts (default: 40)

        Returns:
            CommandResults: Results indicating instance status is OK
        """
        kwargs = {"IncludeAllInstances": arg_to_bool_or_none(args.get("include_all_instances"))}
        # IncludeAllInstances
        if filters := args.get("filters"):
            kwargs["Filters"] = parse_filter_field(filters)

        if instance_ids := args.get("instance_ids"):
            kwargs["InstanceIds"] = parse_resource_ids(instance_ids)

        waiter_config = {
            "Delay": arg_to_number(args.get("waiter_delay", "15")),
            "MaxAttempts": arg_to_number(args.get("waiter_max_attempts", "40")),
        }
        kwargs["WaiterConfig"] = waiter_config
        remove_nulls_from_dictionary(kwargs)

        try:
            waiter = client.get_waiter("instance_status_ok")
            waiter.wait(**kwargs)
            return CommandResults(readable_output="Instance status is now OK.")
        except Exception as e:
            raise DemistoException(f"Waiter error: {str(e)}")

    @staticmethod
    def instance_stopped_waiter_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Waits until EC2 instances are in the 'stopped' state.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments containing:
                - instance_ids (str, optional): Comma-separated list of instance IDs
                - filters (str, optional): Filters for instances
                - waiter_delay (int, optional): Delay between attempts in seconds (default: 15)
                - waiter_max_attempts (int, optional): Maximum number of attempts (default: 40)

        Returns:
            CommandResults: Results indicating instances are stopped
        """
        kwargs = {}

        if filters := args.get("filters"):
            kwargs["Filters"] = parse_filter_field(filters)

        if instance_ids := args.get("instance_ids"):
            kwargs["InstanceIds"] = parse_resource_ids(instance_ids)

        waiter_config = {
            "Delay": arg_to_number(args.get("waiter_delay", "15")),
            "MaxAttempts": arg_to_number(args.get("waiter_max_attempts", "40")),
        }
        kwargs["WaiterConfig"] = waiter_config

        try:
            waiter = client.get_waiter("instance_stopped")
            waiter.wait(**kwargs)
            return CommandResults(readable_output="Instance(s) are now stopped.")
        except Exception as e:
            raise DemistoException(f"Waiter error: {str(e)}")

    @staticmethod
    def instance_terminated_waiter_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Waits until EC2 instances are in the 'terminated' state.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments containing:
                - instance_ids (str, optional): Comma-separated list of instance IDs
                - filters (str, optional): Filters for instances
                - waiter_delay (int, optional): Delay between attempts in seconds (default: 15)
                - waiter_max_attempts (int, optional): Maximum number of attempts (default: 40)

        Returns:
            CommandResults: Results indicating instances are terminated
        """
        kwargs = {}

        if filters := args.get("filters"):
            kwargs["Filters"] = parse_filter_field(filters)

        if instance_ids := args.get("instance_ids"):
            kwargs["InstanceIds"] = parse_resource_ids(instance_ids)

        waiter_config = {
            "Delay": arg_to_number(args.get("waiter_delay", "15")),
            "MaxAttempts": arg_to_number(args.get("waiter_max_attempts", "40")),
        }
        kwargs["WaiterConfig"] = waiter_config

        try:
            waiter = client.get_waiter("instance_terminated")
            waiter.wait(**kwargs)
            return CommandResults(readable_output="Instance(s) are now terminated.")
        except Exception as e:
            raise DemistoException(f"Waiter error: {str(e)}")

    @staticmethod
    def describe_iam_instance_profile_associations_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Describes IAM instance profile associations.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments containing:
                - association_ids (str, optional): Comma-separated list of association IDs
                - filters (str, optional): Filters for associations
                - limit (int, optional): Maximum number of results
                - next_token (str, optional): Token for pagination

        Returns:
            CommandResults: Results containing IAM instance profile association information
        """
        kwargs = {}

        if filters := args.get("filters"):
            kwargs["Filters"] = parse_filter_field(filters)

        if association_ids := args.get("association_ids"):
            kwargs["AssociationIds"] = parse_resource_ids(association_ids)

        pagination_kwargs = build_pagination_kwargs(args)
        kwargs.update(pagination_kwargs)

        print_debug_logs(client, f"Describe IAM instance profile associations parameters: {kwargs}")
        response = client.describe_iam_instance_profile_associations(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        associations = response.get("IamInstanceProfileAssociations", [])

        if not associations:
            return CommandResults(readable_output="No IAM instance profile associations were found.")

        outputs = {
            "AWS.EC2.IamInstanceProfileAssociations(val.AssociationId && val.AssociationId == obj.AssociationId)": associations,
            "AWS.EC2(true)": {"IamInstanceProfileAssociationsNextToken": response.get("NextToken")},
        }

        return CommandResults(
            outputs=outputs,
            readable_output=tableToMarkdown(
                "AWS IAM Instance Profile Associations",
                associations,
                headers=["AssociationId", "InstanceId", "State", "IamInstanceProfile"],
                headerTransform=pascalToSpace,
                removeNull=True,
            ),
            raw_response=response,
        )

    @staticmethod
    def get_password_data_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Retrieves the encrypted administrator password for a running Windows instance.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments containing:
                - instance_id (str): The ID of the Windows instance

        Returns:
            CommandResults: Results containing the password data
        """
        instance_id = args.get("instance_id")
        print_debug_logs(client, f"Get password data for instance {instance_id}")
        response = client.get_password_data(InstanceId=instance_id)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        # Serialize datetime
        response = serialize_response_with_datetime_encoding(response)

        password_data = {
            "InstanceId": response.get("InstanceId"),
            "PasswordData": response.get("PasswordData"),
            "Timestamp": response.get("Timestamp"),
        }

        readable_output = tableToMarkdown(
            "AWS EC2 Instance Password Data",
            password_data,
            headers=["InstanceId", "PasswordData", "Timestamp"],
            headerTransform=pascalToSpace,
            removeNull=True,
        )

        outputs = {"PasswordData": password_data, "InstanceId": password_data.get("InstanceId")}

        return CommandResults(
            outputs_prefix="AWS.EC2.Instances",
            outputs_key_field="InstanceId",
            outputs=outputs,
            readable_output=readable_output,
            raw_response=response,
        )

    @staticmethod
    def describe_reserved_instances_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Describes one or more Reserved Instances.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments containing:
                - reserved_instances_ids (str, optional): Comma-separated list of Reserved Instance IDs
                - filters (str, optional): Filters for Reserved Instances
                - offering_class (str, optional): The offering class (standard or convertible)
                - offering_type (str, optional): The offering type (Heavy Utilization |
                 Medium Utilization | Light Utilization | No Upfront | Partial Upfront | All Upfront)

        Returns:
            CommandResults: Results containing Reserved Instance information
        """
        kwargs = {"OfferingClass": args.get("offering_class"), "OfferingType": args.get("offering_type")}

        if filters := args.get("filters"):
            kwargs["Filters"] = parse_filter_field(filters)

        if reserved_instances_ids := args.get("reserved_instances_ids"):
            kwargs["ReservedInstancesIds"] = parse_resource_ids(reserved_instances_ids)

        remove_nulls_from_dictionary(kwargs)

        print_debug_logs(client, f"Describing reserved instances with parameters: {kwargs}")
        response = client.describe_reserved_instances(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        # Serialize datetime objects
        serialized_response = serialize_response_with_datetime_encoding(response)
        reserved_instances = serialized_response.get("ReservedInstances", [])
        print_debug_logs(client, f"Reserved Instances: {reserved_instances}")

        if not reserved_instances:
            return CommandResults(readable_output="No Reserved Instances were found.")

        readable_output = tableToMarkdown(
            "AWS EC2 Reserved Instances",
            reserved_instances,
            headers=[
                "ReservedInstancesId",
                "InstanceType",
                "InstanceCount",
                "State",
                "Start",
                "End",
                "Duration",
                "OfferingClass",
                "Scope",
            ],
            headerTransform=pascalToSpace,
            removeNull=True,
        )

        return CommandResults(
            outputs_prefix="AWS.EC2.ReservedInstances",
            outputs_key_field="ReservedInstancesId",
            outputs=reserved_instances,
            readable_output=readable_output,
            raw_response=response,
        )

    @staticmethod
    def describe_volumes_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Describes the specified EBS volumes or all of your EBS volumes.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including filters and volume IDs

        Returns:
            CommandResults: Results containing volume information
        """
        kwargs = {}

        # Add filters if provided
        if filters_arg := args.get("filters"):
            kwargs["Filters"] = parse_filter_field(filters_arg)

        # Add volume IDs if provided
        if volume_ids := args.get("volume_ids"):
            kwargs["VolumeIds"] = argToList(volume_ids)

        if not volume_ids:
            pagination_kwargs = build_pagination_kwargs(args, minimum_limit=5)
            kwargs.update(pagination_kwargs)

        remove_nulls_from_dictionary(kwargs)
        print_debug_logs(client, f"Describing volumes with parameters: {kwargs}")
        response = client.describe_volumes(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        response = serialize_response_with_datetime_encoding(response)
        volumes = response.get("Volumes", [])

        if not volumes:
            return CommandResults(readable_output="No EC2 volumes were found.")

        readable_output = tableToMarkdown(
            "AWS EC2 Volumes",
            volumes,
            headers=["VolumeId", "VolumeType", "AvailabilityZone", "Encrypted", "State", "CreateTime"],
            removeNull=True,
        )

        outputs = {
            "AWS.EC2.Volumes(val.VolumeId && val.VolumeId == obj.VolumeId)": volumes,
            "AWS.EC2(true)": {"VolumesNextToken": response.get("NextToken")},
        }

        return CommandResults(
            outputs=outputs,
            readable_output=readable_output,
            raw_response=response,
        )

    @staticmethod
    def modify_volume_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Modifies several parameters of an existing EBS volume, including volume size, volume type, and IOPS capacity.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including volume ID and modification parameters

        Returns:
            CommandResults: Results containing volume modification information
        """
        kwargs = {
            "VolumeId": args.get("volume_id"),
            "VolumeType": args.get("volume_type"),
            "MultiAttachEnabled": arg_to_bool_or_none(args.get("multi_attach_enabled")),
            "Iops": arg_to_number(args.get("iops")),
            "Size": arg_to_number(args.get("size")),
            "Throughput": arg_to_number(args.get("throughput")),
        }

        remove_nulls_from_dictionary(kwargs)
        print_debug_logs(client, f"Modifying volume with parameters: {kwargs}")
        response = client.modify_volume(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        response = serialize_response_with_datetime_encoding(response)
        volume_modification = response.get("VolumeModification", {})
        outputs = {
            "VolumeId": volume_modification.pop("VolumeId", None),
            "Size": volume_modification.pop("TargetSize", None),
            "Iops": volume_modification.pop("TargetIops", None),
            "VolumeType": volume_modification.pop("TargetVolumeType", None),
            "Throughput": volume_modification.pop("TargetThroughput", None),
            "MultiAttachEnabled": volume_modification.pop("TargetMultiAttachEnabled", None),
            "Modification": volume_modification,
        }
        remove_nulls_from_dictionary(outputs)

        readable_output = tableToMarkdown(
            "AWS EC2 Volume Modification",
            outputs,
            headers=[
                "VolumeId",
                "Size",
                "Iops",
                "VolumeType",
                "Throughput",
                "MultiAttachEnabled",
            ],
            removeNull=True,
        )

        return CommandResults(
            outputs_prefix="AWS.EC2.Volumes",
            outputs_key_field="VolumeId",
            outputs=outputs,
            readable_output=readable_output,
            raw_response=response,
        )

    @staticmethod
    def create_volume_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Creates an EBS volume that can be attached to an instance in the same Availability Zone.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including availability zone and volume parameters

        Returns:
            CommandResults: Results containing created volume information
        """
        kwargs = {
            "AvailabilityZone": args.get("availability_zone"),
            "Encrypted": arg_to_bool_or_none(args.get("encrypted")),
            "KmsKeyId": args.get("kms_key_id"),
            "OutpostArn": args.get("outpost_arn"),
            "SnapshotId": args.get("snapshot_id"),
            "VolumeType": args.get("volume_type"),
            "MultiAttachEnabled": arg_to_bool_or_none(args.get("multi_attach_enabled")),
            "ClientToken": args.get("client_token"),
            "Iops": arg_to_number(args.get("iops")),
            "Size": arg_to_number(args.get("size")),
            "Throughput": arg_to_number(args.get("throughput")),
        }

        if tags := args.get("tags"):
            kwargs["TagSpecifications"] = [{"ResourceType": "volume", "Tags": parse_tag_field(tags)}]

        remove_nulls_from_dictionary(kwargs)
        print_debug_logs(client, f"Creating volume with parameters: {kwargs}")
        response = client.create_volume(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        response = serialize_response_with_datetime_encoding(response)

        outputs = {k: v for k, v in response.items() if k != "ResponseMetadata"}
        readable_output = tableToMarkdown(
            "AWS EC2 Volumes",
            outputs,
            headers=["VolumeId", "VolumeType", "AvailabilityZone", "CreateTime", "Encrypted", "Size", "State", "Iops"],
            removeNull=True,
        )

        return CommandResults(
            outputs_prefix="AWS.EC2.Volumes",
            outputs_key_field="VolumeId",
            outputs=outputs,
            readable_output=readable_output,
            raw_response=response,
        )

    @staticmethod
    def attach_volume_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Attaches an EBS volume to a running or stopped instance and exposes it to the instance with the specified device name.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including device, instance ID, and volume ID

        Returns:
            CommandResults: Results containing volume attachment information
        """
        kwargs = {
            "Device": args.get("device"),
            "InstanceId": args.get("instance_id"),
            "VolumeId": args.get("volume_id"),
        }

        print_debug_logs(client, f"Attaching volume with parameters: {kwargs}")
        response = client.attach_volume(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        response = serialize_response_with_datetime_encoding(response)
        outputs = {k: v for k, v in response.items() if k != "ResponseMetadata"}

        readable_output = tableToMarkdown(
            "AWS EC2 Volume Attachments",
            outputs,
            headers=["VolumeId", "InstanceId", "AttachTime", "Device", "State", "DeleteOnTermination"],
            removeNull=True,
        )

        return CommandResults(
            outputs_prefix="AWS.EC2.Volumes",
            outputs_key_field="VolumeId",
            outputs={"Attachments": outputs, "VolumeId": response.get("VolumeId")},
            readable_output=readable_output,
            raw_response=response,
        )

    @staticmethod
    def detach_volume_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Detaches an EBS volume from an instance.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including volume ID and optional parameters

        Returns:
            CommandResults: Results containing volume detachment information
        """
        kwargs = {
            "VolumeId": args.get("volume_id"),
            "Force": arg_to_bool_or_none(args.get("force")),
            "Device": args.get("device"),
            "InstanceId": args.get("instance_id"),
        }

        remove_nulls_from_dictionary(kwargs)
        print_debug_logs(client, f"Detaching volume with parameters: {kwargs}")
        response = client.detach_volume(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        response = serialize_response_with_datetime_encoding(response)

        outputs = {k: v for k, v in response.items() if k != "ResponseMetadata"}

        readable_output = tableToMarkdown(
            "AWS EC2 Volume Attachments",
            outputs,
            headers=["VolumeId", "InstanceId", "AttachTime", "Device", "State", "DeleteOnTermination"],
            removeNull=True,
        )

        return CommandResults(
            outputs_prefix="AWS.EC2.Volumes",
            outputs_key_field="VolumeId",
            outputs={"Attachments": outputs, "VolumeId": response.get("VolumeId")},
            readable_output=readable_output,
            raw_response=response,
        )

    @staticmethod
    def delete_volume_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Deletes the specified EBS volume. The volume must be in the available state (not attached to an instance).

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including volume ID

        Returns:
            CommandResults: Results with success message
        """
        volume_id = args.get("volume_id")
        print_debug_logs(client, f"Deleting volume: {volume_id}")
        response = client.delete_volume(VolumeId=volume_id)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        return CommandResults(readable_output=f"Successfully deleted volume {volume_id}")

    @staticmethod
    def describe_snapshots_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Describes one or more Amazon EBS snapshots available to you.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including:
                - filters (str, optional): One or more filters separated by ';'
                - owner_ids (str, optional): Comma-separated list of snapshot owner IDs
                - snapshot_ids (str, optional): Comma-separated list of snapshot IDs
                - restorable_by_user_ids (str, optional): Comma-separated list of user IDs that can create
                 volumes from the snapshot
                - limit (int, optional): Maximum number of snapshots to return
                - next_token (str, optional): Token for pagination

        Returns:
            CommandResults: Results containing snapshot information including description, encryption status, owner, progress,
             state, and volume details
        """
        kwargs = {}
        if filters := args.get("filters"):
            kwargs["Filters"] = parse_filter_field(filters)
        if owner_ids := args.get("owner_ids"):
            kwargs["OwnerIds"] = parse_resource_ids(owner_ids)
        if snapshot_ids := args.get("snapshot_ids"):
            kwargs["SnapshotIds"] = parse_resource_ids(snapshot_ids)
        if restorable_by_user_ids := args.get("restorable_by_user_ids"):
            kwargs["RestorableByUserIds"] = parse_resource_ids(restorable_by_user_ids)

        if not snapshot_ids:
            pagination_kwargs = build_pagination_kwargs(args)
            kwargs.update(pagination_kwargs)

        remove_nulls_from_dictionary(kwargs)
        print_debug_logs(client, f"Describing snapshots with parameters: {kwargs}")

        response = client.describe_snapshots(**kwargs)
        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        response = serialize_response_with_datetime_encoding(response)
        snapshots = response.get("Snapshots", [])

        if not snapshots:
            return CommandResults(readable_output="No snapshots were found.")

        readable_output = tableToMarkdown(
            "AWS EC2 Snapshots",
            snapshots,
            headers=[
                "SnapshotId",
                "Description",
                "VolumeId",
                "VolumeSize",
                "Encrypted",
                "OwnerId",
                "Progress",
                "StartTime",
                "State",
            ],
            removeNull=True,
            headerTransform=pascalToSpace,
        )

        outputs = {
            "AWS.EC2.Snapshots(val.SnapshotId && val.SnapshotId == obj.SnapshotId)": snapshots,
            "AWS.EC2(true)": {"SnapshotsNextPageToken": response.get("NextToken")},
        }

        return CommandResults(
            outputs=outputs,
            readable_output=readable_output,
            raw_response=response,
        )

    @staticmethod
    def delete_snapshot_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Deletes the specified Amazon EBS snapshot.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including:
                - snapshot_id (str): The ID of the snapshot to delete (required)

        Returns:
            CommandResults: Results of the deletion operation with success message
        """
        snapshot_id = args.get("snapshot_id")
        print_debug_logs(client, f"Deleting snapshot: {snapshot_id}")
        response = client.delete_snapshot(SnapshotId=snapshot_id)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        return CommandResults(readable_output=f"Successfully deleted snapshot {snapshot_id}", raw_response=response)

    @staticmethod
    def copy_snapshot_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Copies a point-in-time snapshot of an Amazon EBS volume and stores it in Amazon S3.

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including:
                - source_snapshot_id (str): The ID of the snapshot to copy (required)
                - source_region (str): The region containing the source snapshot (required)
                - description (str, optional): Description for the new snapshot
                - destination_outpost_arn (str, optional): The ARN of the Outpost to which to copy the snapshot
                - encrypted (boolean, optional): Whether the destination snapshot should be encrypted
                - kms_key_id (str, optional): KMS key ID for encryption
                - presigned_url (str, optional): Pre-signed URL for the copy operation
                - tag_specifications (str, optional): Tags to apply to the new snapshot

        Returns:
            CommandResults: Results containing the new snapshot ID and region information
        """
        kwargs = {
            "SourceSnapshotId": args.get("source_snapshot_id"),
            "SourceRegion": args.get("source_region"),
            "Description": args.get("description"),
            "DestinationOutpostArn": args.get("destination_outpost_arn"),
            "Encrypted": arg_to_bool_or_none(args.get("encrypted")),
            "KmsKeyId": args.get("kms_key_id"),
            "PresignedUrl": args.get("presigned_url"),
        }

        if tag_specifications := args.get("tag_specifications"):
            kwargs["TagSpecifications"] = [{"ResourceType": "snapshot", "Tags": parse_tag_field(tag_specifications)}]

        remove_nulls_from_dictionary(kwargs)
        print_debug_logs(client, f"Copying snapshot with parameters: {kwargs}")

        response = client.copy_snapshot(**kwargs)
        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        outputs = {k: v for k, v in response.items() if k != "ResponseMetadata"}
        readable_output = tableToMarkdown(
            "Copy AWS EC2 Snapshots", outputs, headers=["SnapshotId"], removeNull=True, headerTransform=pascalToSpace
        )

        return CommandResults(
            outputs_prefix="AWS.EC2.Snapshots",
            outputs_key_field="SnapshotId",
            outputs=outputs,
            readable_output=readable_output,
            raw_response=response,
        )

    @staticmethod
    def snapshot_completed_waiter_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Waits until an Amazon EBS snapshot reaches the completed state.

        This command uses AWS EC2's built-in waiter functionality to poll the snapshot state
        until it reaches the 'completed' state. The waiter will check the snapshot status at
        regular intervals (configurable via waiter_delay) up to a maximum number of attempts
        (configurable via waiter_max_attempts).

        Args:
            client (BotoClient): The boto3 client for EC2 service
            args (Dict[str, Any]): Command arguments including:
                - filters (str, optional): One or more filters separated by ';'
                - owner_ids (str, optional): Comma-separated list of snapshot owner IDs
                - snapshot_ids (str, optional): Comma-separated list of snapshot IDs to wait for
                - restorable_by_user_ids (str, optional): Comma-separated list of user IDs that can create volumes
                from the snapshot
                - waiter_delay (str, optional): Time in seconds to wait between polling attempts (default: 15)
                - waiter_max_attempts (str, optional): Maximum number of polling attempts (default: 40)

        Returns:
            CommandResults: Results with success message when snapshot is completed

        Raises:
            WaiterError: If the waiter times out or encounters an error
        """
        kwargs = {}
        if filters := args.get("filters"):
            kwargs["Filters"] = parse_filter_field(filters)
        if owner_ids := args.get("owner_ids"):
            kwargs["OwnerIds"] = parse_resource_ids(owner_ids)
        if snapshot_ids := args.get("snapshot_ids"):
            kwargs["SnapshotIds"] = parse_resource_ids(snapshot_ids)
        if restorable_by_user_ids := args.get("restorable_by_user_ids"):
            kwargs["RestorableByUserIds"] = parse_resource_ids(restorable_by_user_ids)

        # Configure waiter settings
        kwargs["WaiterConfig"] = {
            "Delay": arg_to_number(args.get("waiter_delay")),
            "MaxAttempts": arg_to_number(args.get("waiter_max_attempts")),
        }

        remove_nulls_from_dictionary(kwargs)
        print_debug_logs(client, f"Waiting for snapshot completion with parameters: {kwargs}")

        try:
            waiter = client.get_waiter("snapshot_completed")
            waiter.wait(**kwargs)
            return CommandResults(readable_output="Snapshot is now completed.")
        except WaiterError as e:
            raise DemistoException(f"Waiter error: {str(e)}")


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

    @staticmethod
    def describe_cluster_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Describes an Amazon EKS cluster.
        Args:
            client(boto3 client): The configured AWS session.
            args: command arguments

        Returns:
            A Command Results object
        """
        cluster_name = args.get("cluster_name")

        print_debug_logs(client, f"Describing clusters with parameters: {cluster_name}")
        response = client.describe_cluster(name=cluster_name)
        response_data = response.get("cluster", {})
        response_data["createdAt"] = datetime_to_string(response_data.get("createdAt"))
        activation_expiry = response_data.get("connectorConfig", {}).get("activationExpiry")
        if activation_expiry:
            response_data.get("connectorConfig", {})["activationExpiry"] = datetime_to_string(activation_expiry)

        headers = ["name", "id", "status", "arn", "createdAt", "version"]
        readable_output = tableToMarkdown(
            name="Describe Cluster Information",
            t=response_data,
            removeNull=True,
            headers=headers,
            headerTransform=pascalToSpace,
        )
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix="AWS.EKS.Cluster",
            outputs=response_data,
            raw_response=response_data,
            outputs_key_field="name",
        )

    @staticmethod
    def associate_access_policy_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Associates an access policy and its scope to an access entry.
        Args:
            client(boto3 client): The configured AWS session.
            args: command arguments

        Returns:
            A Command Results object
        """
        cluster_name = args.get("cluster_name")
        principal_arn = args.get("principal_arn")
        policy_arn = args.get("policy_arn")
        type_arg = args.get("type")
        namespaces = argToList(args.get("namespaces"))
        if type_arg and type_arg == "namespace" and not namespaces:
            raise Exception(f"When the {type_arg=}, you must enter a namespace.")

        access_scope = {"type": type_arg, "namespaces": namespaces}

        print_debug_logs(
            client,
            f"Associating access policy with parameters: {cluster_name=}, {principal_arn=}, {policy_arn=}, {access_scope=}",
        )
        response = client.associate_access_policy(
            clusterName=cluster_name, principalArn=principal_arn, policyArn=policy_arn, accessScope=access_scope
        )
        response_data = response.get("associatedAccessPolicy", {})
        response_data["clusterName"] = response.get("clusterName")
        response_data["principalArn"] = response.get("principalArn")

        response_data["associatedAt"] = datetime_to_string(response_data.get("associatedAt"))
        response_data["modifiedAt"] = datetime_to_string(response_data.get("modifiedAt"))

        headers = ["clusterName", "principalArn", "policyArn", "associatedAt"]
        readable_output = tableToMarkdown(
            name="The access policy was associated to the access entry successfully.",
            t=response_data,
            removeNull=True,
            headers=headers,
            headerTransform=pascalToSpace,
        )

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix="AWS.EKS.AssociatedAccessPolicy",
            outputs=response_data,
            raw_response=response_data,
            outputs_key_field="clusterName",
        )


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
                "BackupRetentionPeriod": int(args.get("backup_retention_period", ""))
                if args.get("backup_retention_period")
                else None,
                "VpcSecurityGroupIds": argToList(args.get("vpc_security_group_ids")),
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

    @staticmethod
    def modify_event_subscription_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Modifies the configuration of an existing Amazon RDS event notification subscription.
        This command performs the 'ModifyEventSubscription' API operation, allowing updates to the target SNS topic,
        the list of event categories, the source type, and the enabled state of the subscription.

        Args:
            client (BotoClient): The initialized Boto3 client.
            args (Dict[str, Any]): Command arguments, typically containing:
                - 'subscription_name' (str): The unique name of the subscription to modify. (Required)
                - 'enabled' (str): Boolean string ('true' or 'false') to activate/deactivate the subscription. (Optional)
                - 'event_categories' (str | List[str]): A list of event categories to subscribe to. (Optional)
                - 'sns_topic_arn' (str): The ARN of the new SNS topic to publish events to. (Optional)
                - 'source_type' (str): The type of resource generating events. (Optional)

        Returns:
            CommandResults: A CommandResults object containing the modified EventSubscription details.
        """
        kwargs = {
            "SubscriptionName": args.get("subscription_name"),
            "Enabled": arg_to_bool_or_none(args.get("enabled")),
            "EventCategories": argToList(args.get("event_categories", [])),
            "SnsTopicArn": args.get("sns_topic_arn"),
            "SourceType": args.get("source_type"),
        }
        remove_nulls_from_dictionary(kwargs)

        try:
            response = client.modify_event_subscription(**kwargs)

            if response["ResponseMetadata"]["HTTPStatusCode"] in [HTTPStatus.OK, HTTPStatus.NO_CONTENT]:
                headers = [
                    "CustomerAwsId",
                    "CustSubscriptionId",
                    "SnsTopicArn",
                    "Status",
                    "SubscriptionCreationTime",
                    "SourceType",
                    "EventCategoriesList",
                    "Enabled",
                    "EventSubscriptionArn",
                    "SourceIdsList",
                ]

                return CommandResults(
                    readable_output=tableToMarkdown(
                        name=f"Event subscription {args.get('subscription_name')} successfully modified.",
                        headers=headers,
                        t=response.get("EventSubscription"),
                        removeNull=True,
                    ),
                    outputs_prefix="AWS.RDS.EventSubscription",
                    outputs=response.get("EventSubscription"),
                    outputs_key_field="CustSubscriptionId",
                )
            raise DemistoException(f"Failed to modify event subscription {args.get('subscription_name')}.")
        except Exception as e:
            raise DemistoException(f"Error: {str(e)}")


class CostExplorer:
    service = AWSServices.CostExplorer

    @staticmethod
    def billing_cost_usage_list_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Retrieves cost and usage data from AWS Cost Explorer API.

        This command provides detailed cost and usage information for AWS services over a specified time period.
        It supports multiple metrics including costs (blended, unblended, amortized) and usage quantities.
        Results can be filtered by AWS services and support pagination for large datasets.

        Args:
            client (BotoClient): AWS Cost Explorer boto3 client
            args (Dict[str, Any]): Command arguments containing:
                - metrics: List of metrics to retrieve (UsageQuantity, BlendedCost, etc.)
                - start_date: Start date for the report (YYYY-MM-DD format)
                - end_date: End date for the report (YYYY-MM-DD format)
                - granularity: Time granularity (Daily, Monthly, Hourly)
                - aws_services: Optional filter for specific AWS services
                - next_page_token: Token for pagination

        Returns:
            CommandResults: Contains usage data grouped by time periods and metrics,
                          with separate tables for each metric type in readable output

        Raises:
            DemistoException: If AWS API call fails or invalid parameters provided
        """
        today_utc = datetime.now(UTC)
        metrics = argToList(args.get("metrics", "UsageQuantity"))
        allowed_metrics = {
            "AmortizedCost",
            "BlendedCost",
            "NetAmortizedCost",
            "NetUnblendedCost",
            "NormalizedUsageAmount",
            "UnblendedCost",
            "UsageQuantity",
        }
        invalid_metrics = [m for m in metrics if m not in allowed_metrics]
        if invalid_metrics:
            raise DemistoException(
                f"Invalid metrics: {', '.join(invalid_metrics)}. Allowed metrics: {', '.join(sorted(allowed_metrics))}"
            )
        start_date = arg_to_datetime(args.get("start_date")) or (today_utc - timedelta(days=7))
        end_date = arg_to_datetime(args.get("end_date")) or today_utc
        granularity = args.get("granularity", "Daily").upper()
        aws_services = argToList(args.get("aws_services"))
        token = args.get("next_page_token")

        request = {
            "TimePeriod": {
                "Start": start_date.date().isoformat(),
                "End": end_date.date().isoformat(),
            },
            "Granularity": granularity,
            "Metrics": metrics,
        }
        if aws_services:
            request["Filter"] = {
                "Dimensions": {
                    "Key": "SERVICE",
                    "MatchOptions": ["EQUALS"],
                    "Values": aws_services,
                }
            }
        if token:
            request["NextPageToken"] = token
        demisto.debug(f"AWS get_cost_and_usage request: {request}")

        response = client.get_cost_and_usage(**request)

        results = response.get("ResultsByTime", [])
        next_token = response.get("NextPageToken", "")
        demisto.debug(f"AWS get_cost_and_usage response - ResultsByTime count: {len(results)},\n NextToken: {next_token}")

        results_by_metric: dict[str, list] = {metric: [] for metric in metrics}
        for result in results:
            total = result.get("Total")
            service = total.get("Keys", [None])[0] if total.get("Keys") else None
            for metric in metrics:
                results_by_metric[metric].append(
                    {
                        "Service": service,
                        "StartDate": result.get("TimePeriod", {}).get("Start"),
                        "EndDate": result.get("TimePeriod", {}).get("End"),
                        "Amount": total.get(metric, {}).get("Amount", ""),
                        "Unit": total.get(metric, {}).get("Unit", ""),
                    }
                )
        outputs = {"AWS.Billing.Usage": results, "AWS.Billing(true)": {"UsageNextToken": next_token}}
        readable_tables = []
        for metric in metrics:
            metric_results = results_by_metric[metric]
            if metric_results:
                table = tableToMarkdown(
                    f"AWS Billing Usage - {metric}",
                    metric_results,
                    headers=["Service", "StartDate", "EndDate", "Amount", "Unit"],
                    removeNull=True,
                    headerTransform=pascalToSpace,
                )
                readable_tables.append(table)
        readable = "\n".join(readable_tables) if readable_tables else "No billing usage data found."
        if next_token:
            readable = f"Next Page Token: {next_token}\n\n" + readable
        return CommandResults(
            readable_output=readable,
            outputs=outputs,
            raw_response=response,
        )

    @staticmethod
    def billing_forecast_list_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Retrieves cost forecast data from AWS Cost Explorer API.

        This command provides forecasted cost information for AWS services over a future time period.
        It uses historical data to predict future spending patterns and supports multiple cost metrics.
        Results can be filtered by AWS services and include prediction intervals for accuracy assessment.

        Args:
            client (BotoClient): AWS Cost Explorer boto3 client
            args (Dict[str, Any]): Command arguments containing:
                - metric: Single forecast metric (AMORTIZED_COST, BLENDED_COST, etc.)
                - start_date: Start date for the forecast (YYYY-MM-DD format, defaults to today)
                - end_date: End date for the forecast (YYYY-MM-DD format, defaults to +7 days)
                - granularity: Time granularity (Daily, Monthly, Hourly)
                - aws_services: Optional filter for specific AWS services
                - next_page_token: Token for pagination

        Returns:
            CommandResults: Contains forecast data with mean values and prediction intervals,
                          organized by time periods for the specified metric

        Raises:
            DemistoException: If AWS API call fails or invalid parameters provided
        """
        today_utc = datetime.now(UTC)
        metric = args.get("metric", "AMORTIZED_COST")
        start_date = arg_to_datetime(args.get("start_date")) or today_utc
        end_date = arg_to_datetime(args.get("end_date")) or (today_utc + timedelta(days=7))
        granularity = args.get("granularity", "Daily").upper()
        aws_services = argToList(args.get("aws_services"))
        token = args.get("next_page_token")

        request = {
            "TimePeriod": {
                "Start": start_date.date().isoformat(),
                "End": end_date.date().isoformat(),
            },
            "Granularity": granularity,
            "Metric": metric,
        }
        if aws_services:
            request["Filter"] = {
                "Dimensions": {
                    "Key": "SERVICE",
                    "MatchOptions": ["EQUALS"],
                    "Values": aws_services,
                }
            }
        if token:
            request["NextPageToken"] = token
        demisto.debug(f"AWS Cost Forecast request: {request}")

        response = client.get_cost_forecast(**request)

        results = response.get("ForecastResultsByTime", [])
        next_token = response.get("NextPageToken", "")
        demisto.debug(f"AWS Cost Forecast response - ForecastResultsByTime count: {len(results)},\nNextToken: {next_token}")

        metric_results = []
        for result in results:
            metric_results.append(
                {
                    "StartDate": result.get("TimePeriod", {}).get("Start"),
                    "EndDate": result.get("TimePeriod", {}).get("End"),
                    "TotalAmount": f"{float(result.get('MeanValue', 0)):.2f}",
                    "TotalUnit": response.get("Unit"),
                }
            )

        outputs = {
            "AWS.Billing.Forecast": results,
            "AWS.Billing(true)": {"ForecastNextToken": next_token},
        }

        readable = tableToMarkdown(
            f"AWS Billing Forecast - {metric}",
            metric_results,
            headers=["StartDate", "EndDate", "TotalAmount", "TotalUnit"],
            removeNull=True,
            headerTransform=pascalToSpace,
        )
        if next_token:
            readable = f"Next Page Token: {next_token}\n\n" + readable

        return CommandResults(
            readable_output=readable,
            outputs=outputs,
            raw_response=response,
        )


class Budgets:
    service = AWSServices.BUDGETS

    @staticmethod
    def billing_budgets_list_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Retrieves budget information from AWS Budgets API.

        This command lists all configured budgets for a specified AWS account, providing detailed
        information about budget limits, actual spending, forecasted spending, and time periods.
        Supports various budget types including cost, usage, and savings plans budgets.

        Args:
            client (BotoClient): AWS Budgets boto3 client
            args (Dict[str, Any]): Command arguments containing:
                - account_id: AWS account ID to retrieve budgets for (required)
                - max_result: Maximum number of results to return (default: 50, max: 1000)
                - show_filter_expression: Whether to include filter expressions in output
                - next_page_token: Token for pagination

        Returns:
            CommandResults: Contains budget data including names, types, limits, actual spend,
                          forecasted spend, and time periods with pagination support

        Raises:
            DemistoException: If AWS API call fails, account_id is invalid, or other errors occur
        """
        max_results = int(args.get("max_result", 50))
        token = args.get("next_page_token")
        account_id = args.get("account_id")
        show_filter_expression = argToBoolean(args.get("show_filter_expression"))
        request = {"AccountId": account_id, "MaxResults": max_results}
        if token:
            request["NextToken"] = token
        if show_filter_expression:
            request["ShowFilterExpression"] = show_filter_expression
        demisto.debug(f"AWS Budgets request: {request}")

        response = client.describe_budgets(**request)

        budgets = response.get("Budgets", [])
        next_token = response.get("NextToken")
        demisto.debug(f"AWS Budgets response - Budgets count: {len(budgets)},\n NextToken: {next_token}")
        results = []
        for b in budgets:
            budget_limit = b.get("BudgetLimit", {})
            actual_spend = b.get("CalculatedSpend", {}).get("ActualSpend", {})
            start = b.get("TimePeriod", {}).get("Start").strftime("%Y-%m-%d")
            end = b.get("TimePeriod", {}).get("End").strftime("%Y-%m-%d")
            results.append(
                {
                    "BudgetName": b.get("BudgetName"),
                    "BudgetType": b.get("BudgetType"),
                    "BudgetLimitAmount": budget_limit.get("Amount"),
                    "BudgetLimitUnit": budget_limit.get("Unit"),
                    "ActualSpendAmount": actual_spend.get("Amount"),
                    "ActualSpendUnit": actual_spend.get("Unit"),
                    "TimePeriod": f"{start} - {end}",
                    "FilterExpression": b.get("FilterExpression") if show_filter_expression else None,
                }
            )
        outputs = {
            "AWS.Billing.Budget(val.BudgetName && val.BudgetName == obj.BudgetName)": results,
            "AWS.Billing(true)": {"BudgetNextToken": next_token},
        }
        readable = tableToMarkdown(
            "AWS Budgets",
            results,
            headers=[
                "BudgetName",
                "TimePeriod",
                "BudgetType",
                "BudgetLimitAmount",
                "BudgetLimitUnit",
                "FilterExpression",
                "ActualSpendAmount",
                "ActualSpendUnit",
            ],
            removeNull=True,
            headerTransform=pascalToSpace,
        )
        if next_token:
            readable = f"Next Page Token: {next_token}\n\n" + readable
        return CommandResults(
            readable_output=readable,
            outputs=outputs,
            raw_response=json.loads(json.dumps(response, cls=DatetimeEncoder)),
        )

    @staticmethod
    def billing_budget_notification_list_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Retrieves notification configurations for a specific budget from AWS Budgets API.

        This command lists all notification settings associated with a particular budget,
        including notification types (actual vs forecasted), thresholds, comparison operators,
        and subscriber information (email addresses or SNS topics).

        Args:
            client (BotoClient): AWS Budgets boto3 client
            args (Dict[str, Any]): Command arguments containing:
                - account_id: AWS account ID that owns the budget (required)
                - budget_name: Name of the budget to retrieve notifications for (required)
                - max_result: Maximum number of results to return (default: 50, max: 100)
                - next_page_token: Token for pagination

        Returns:
            CommandResults: Contains notification configurations including notification types,
                          thresholds, comparison operators, and subscriber details

        Raises:
            DemistoException: If AWS API call fails, budget doesn't exist, or invalid parameters provided
        """
        budget_name = args.get("budget_name")
        max_results = int(args.get("max_result", 50))
        token = args.get("next_page_token")
        request = {"AccountId": args["account_id"], "BudgetName": budget_name, "MaxResults": max_results}
        if token:
            request["NextToken"] = token
        demisto.debug(f"AWS Budget Notifications request: {request}")

        response = client.describe_notifications_for_budget(**request)

        notifications = response.get("Notifications", [])
        next_token = response.get("NextToken", "")
        demisto.debug(f"AWS Budget Notifications response - Notifications count: {len(notifications)},\n NextToken: {next_token}")
        outputs = {
            "AWS.Billing.Notification": notifications,
            "AWS.Billing(true)": {"NotificationNextToken": next_token},
        }
        readable = tableToMarkdown(f"Notifications for Budget: {budget_name}", notifications)
        if next_token:
            readable = f"Next Page Token: {next_token}\n\n" + readable
        return CommandResults(
            readable_output=readable,
            outputs=outputs,
            raw_response=response,
        )


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

    @staticmethod
    def describe_trails_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Retrieves descriptions of the specified trail or all trails in the account.

        Args:
            client (BotoClient): The boto3 client for CloudTrail service
            args (Dict[str, Any]): Command arguments including trail names (optional)

        Returns:
            CommandResults: Detailed information about CloudTrail trails
        """
        trail_names = argToList(args.get("trail_names", []))
        include_shadow_trails = arg_to_bool_or_none(args.get("include_shadow_trails", True))
        kwargs = {"trailNameList": trail_names, "includeShadowTrails": include_shadow_trails}
        remove_nulls_from_dictionary(kwargs)
        response = client.describe_trails(**kwargs)
        trail_data = response.get("trailList", [])
        headers = [
            "Name",
            "S3BucketName",
            "IncludeGlobalServiceEvents",
            "IsMultiRegionTrail",
            "TrailARN",
            "LogFileValidationEnabled",
            "HomeRegion",
        ]
        readable_output = tableToMarkdown(
            name="Trail List",
            t=trail_data,
            removeNull=True,
            headers=headers,
            headerTransform=pascalToSpace,
        )
        return CommandResults(
            outputs_prefix="AWS.CloudTrail.Trails",
            outputs_key_field="TrailARN",
            raw_response=response,
            outputs=trail_data,
            readable_output=readable_output,
        )


class ECS:
    service = AWSServices.ECS

    @staticmethod
    def update_cluster_settings_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Updates the containerInsights setting of an ECS cluster.

        Args:
            client (BotoClient): The boto3 client for ECS service
            args (Dict[str, Any]): Command arguments including cluster name and setting value

        Returns:
            CommandResults: Results of the operation with updated cluster settings
        """
        setting_value = args.get("value")
        print_debug_logs(client, f"Updating ECS cluster settings with parameters: {setting_value=}")  # noqa: E501
        response = client.update_cluster_settings(
            cluster=args.get("cluster_name"),
            settings=[
                {"name": "containerInsights", "value": setting_value},
            ],
        )

        if response["ResponseMetadata"]["HTTPStatusCode"] == HTTPStatus.OK:
            cluster_data = response.get("cluster", {})
            readable_output = f"Successfully updated ECS cluster: {args.get('cluster_name')}"

            if cluster_data:
                readable_output += "\n\nUpdated Cluster Details:ֿֿֿֿֿ\n"
                readable_output += tableToMarkdown("", cluster_data)

            return CommandResults(
                readable_output=readable_output,
                outputs_prefix="AWS.ECS.Cluster",
                outputs=cluster_data,
                outputs_key_field="clusterArn",
                raw_response=response,
            )
        else:
            raise DemistoException(
                f"Failed to update ECS cluster. "
                f"Status code: {response['ResponseMetadata']['HTTPStatusCode']}. "
                f"{json.dumps(response)}"
            )


class KMS:
    service = AWSServices.KMS

    @staticmethod
    def enable_key_rotation_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Enables automatic rotation for a symmetric customer-managed KMS key.
        Uses a custom rotation period (days) from args; valid range is 90–2560.
        Args:
            client (BotoClient): The boto3 client for KMS service.
            args (Dict[str, Any]): Command arguments including key id and rotation period in days.

        Returns:
            CommandResults: Results of the operation with updated key rotation settings.
        """
        key_id = args.get("key_id", "")
        rot_period = arg_to_number(args.get("rotation_period_in_days"))
        kwargs = {"KeyId": key_id, "RotationPeriodInDays": rot_period}
        remove_nulls_from_dictionary(kwargs)
        print_debug_logs(client, f"EnableKeyRotation params: {kwargs}")

        try:
            resp = client.enable_key_rotation(**kwargs)
            status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if status in (HTTPStatus.OK, HTTPStatus.NO_CONTENT):
                hr = f"Enabled automatic rotation for KMS key '{key_id}' (rotation period: {rot_period} days)."
                return CommandResults(readable_output=hr, raw_response=resp)
            return AWSErrorHandler.handle_response_error(resp)

        except ClientError as e:
            return AWSErrorHandler.handle_client_error(e)

        except Exception as e:
            raise DemistoException(f"Error enabling key rotation for '{key_id}': {str(e)}")


class ELB:
    service = AWSServices.ELB

    @staticmethod
    def modify_load_balancer_attributes_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Modifies Classic ELB attributes:
        Cross-Zone Load Balancing, Access Logs, Connection Draining, Connection Settings, AdditionalAttributes.
        Sends only sub-blocks provided by the user.
        Args:
            client (BotoClient): The boto3 client for ELB service.
            args (Dict[str, Any]): Command arguments including load balancer name and setting values:
                - cross-zone load balancing (enabled).
                - access logs (enabled, s3 bucket name, s3 bucket prefix, emit interval).
                - connection draining (enabled, timeout).
                - connection settings (idle timeout).
                - desync mitigation mode (monitor, defensive, strictest).

        Returns:
            CommandResults: Results of the operation with updated load balancer attributes.
        """
        lb_name = args.get("load_balancer_name", "")
        attrs: Dict[str, Any] = {}
        # Cross-zone
        ELB.add_block_if_any(
            block_name="CrossZoneLoadBalancing",
            block={"Enabled": arg_to_bool_or_none(args.get("cross_zone_load_balancing_enabled"))},
            target=attrs,
        )
        # Access logs
        ELB.add_block_if_any(
            block_name="AccessLog",
            block={
                "Enabled": arg_to_bool_or_none(args.get("access_log_enabled")),
                "S3BucketName": args.get("access_log_s3_bucket_name"),
                "S3BucketPrefix": args.get("access_log_s3_bucket_prefix"),
                "EmitInterval": arg_to_number(args.get("access_log_interval")),
            },
            target=attrs,
        )
        # Connection draining
        ELB.add_block_if_any(
            block_name="ConnectionDraining",
            block={
                "Enabled": arg_to_bool_or_none(args.get("connection_draining_enabled")),
                "Timeout": arg_to_number(args.get("connection_draining_timeout")),
            },
            target=attrs,
        )
        # Connection settings (idle timeout)
        ELB.add_block_if_any(
            block_name="ConnectionSettings",
            block={"IdleTimeout": arg_to_number(args.get("connection_settings_idle_timeout"))},
            target=attrs,
        )
        # Additional attributes (JSON list of {Key,Value})
        # Only one additional attribute is supported on classic ELB, Therefore we directly set the key and value
        if desync_mitigation_mode := args.get("desync_mitigation_mode"):
            attrs["AdditionalAttributes"] = [{"Key": "elb.http.desyncmitigationmode", "Value": desync_mitigation_mode}]

        kwargs = {"LoadBalancerName": lb_name, "LoadBalancerAttributes": attrs}
        remove_nulls_from_dictionary(kwargs)
        print_debug_logs(client, f"ModifyLoadBalancerAttributes params: {kwargs}")

        try:
            resp = client.modify_load_balancer_attributes(**kwargs)
            status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if status == HTTPStatus.OK:
                lb_attrs = resp.get("LoadBalancerAttributes", {})
                out = {"LoadBalancerName": lb_name, "LoadBalancerAttributes": lb_attrs}
                hr = ELB.format_elb_modify_attributes_hr(lb_name, resp)
                return CommandResults(
                    readable_output=hr,
                    outputs_prefix="AWS.ELB.LoadBalancer",
                    outputs_key_field="LoadBalancerName",
                    outputs=out,
                    raw_response=resp,
                )

            return AWSErrorHandler.handle_response_error(resp)

        except ClientError as e:
            return AWSErrorHandler.handle_client_error(e)

        except Exception as e:
            raise DemistoException(f"Error modifying load balancer '{lb_name}': {str(e)}")

    @staticmethod
    def add_block_if_any(block_name: str, block: dict, target: dict) -> None:
        """
        Adds a block to the target dictionary if the value is not empty.
        Args:
            block_name (str): The name of the block to add.
            block (dict): The block to add.
            target (dict): The target dictionary to add the block to.
        Returns:
            None
        """
        remove_nulls_from_dictionary(block)
        if block:
            target[block_name] = block

    @staticmethod
    def format_elb_modify_attributes_hr(lb_name: str, resp: dict) -> str:
        """
        Minimal formatter:
        - prints "Updated attributes for <lb>"
        - then one table per attribute block under LoadBalancerAttributes
        Args:
            lb_name (str): The name of the Classic ELB.
            resp (dict): The response from the modify_load_balancer_attributes API call.
        Returns:
            str: The formatted output.
        """
        lb_attrs = resp.get("LoadBalancerAttributes", {})
        sections: list[str] = [f"### Updated attributes for Classic ELB {lb_name}"]

        for attr_name, attr_values in lb_attrs.items():
            title = attr_name
            if isinstance(attr_values, dict):
                sections.append(tableToMarkdown(title, [attr_values], removeNull=True))
            elif attr_values and isinstance(attr_values, list):
                for attr_value in attr_values:
                    sections.append(tableToMarkdown(title, attr_value, removeNull=True))
            else:
                sections.append(tableToMarkdown(title, [{"Value": attr_values}], removeNull=True))
        return "\n\n".join(sections)


class Lambda:
    service = AWSServices.LAMBDA

    @staticmethod
    def get_function_configuration_command(client: BotoClient, args: Dict[str, Any]):
        """
        Retrieves the configuration information for a Lambda function.

        Args:
            client (BotoClient): The boto3 client for Lambda service
            args (Dict[str, Any]): Command arguments including function name and optional qualifier

        Returns:
            CommandResults: Results of the operation with function configuration details
        """
        # Prepare parameters
        function_name = args.get("function_name")
        params = {"FunctionName": function_name}
        if qualifier := args.get("qualifier"):
            params["Qualifier"] = qualifier

        # Get function configuration
        response = client.get_function_configuration(**params)

        # Remove ResponseMetadata for cleaner output
        if "ResponseMetadata" in response:
            del response["ResponseMetadata"]

        # Create human readable output
        human_readable = tableToMarkdown(
            f"Lambda Function Configuration: {function_name}",
            response,
            headers=[
                "FunctionName",
                "FunctionArn",
                "Runtime",
                "CodeSha256",
                "State",
                "Description",
                "RevisionId",
                "LastModified",
            ],
            headerTransform=pascalToSpace,
            removeNull=True,
        )

        return CommandResults(
            outputs_prefix="AWS.Lambda.FunctionConfig",
            outputs_key_field="FunctionArn",
            outputs=response,
            readable_output=human_readable,
            raw_response=response,
        )

    @staticmethod
    def get_function_url_configuration_command(client: BotoClient, args: Dict[str, Any]):
        """
        Retrieves the configuration for a Lambda function URL.

        Args:
            client (BotoClient): The AWS Lambda client used to retrieve the function URL configuration.
            args (Dict[str, Any]): A dictionary containing the function URL configuration parameters including
                                   function_name and optional qualifier.

        Returns:
            CommandResults: An object containing the function URL configuration details including FunctionUrl,
                           FunctionArn, AuthType, CreationTime, LastModifiedTime, and InvokeMode.
        """
        function_name = args.get("function_name")
        qualifier = args.get("qualifier")

        # Prepare parameters
        params = {"FunctionName": function_name}
        if qualifier:
            params["Qualifier"] = qualifier

        # Get function URL configuration
        response = client.get_function_url_config(**params)

        # Remove ResponseMetadata for cleaner output
        if "ResponseMetadata" in response:
            del response["ResponseMetadata"]

        # Create human readable output
        human_readable = tableToMarkdown(
            f"Lambda Function URL Configuration: {function_name}",
            response,
            headers=["FunctionUrl", "FunctionArn", "AuthType", "CreationTime", "LastModifiedTime", "InvokeMode"],
            headerTransform=pascalToSpace,
        )

        return CommandResults(
            outputs_prefix="AWS.Lambda.FunctionURLConfig",
            outputs_key_field="FunctionArn",
            outputs=response,
            readable_output=human_readable,
            raw_response=response,
        )

    @staticmethod
    def update_function_url_configuration_command(client: BotoClient, args: Dict[str, Any]):
        """
        Updates the configuration for a Lambda function URL.

        Args:
            client (BotoClient): The AWS Lambda client used to update the function URL configuration.
            args (Dict[str, Any]): A dictionary containing the function URL configuration parameters including
                                   function_name, qualifier, auth_type, CORS settings (allow_credentials,
                                   allow_headers, allow_methods, allow_origins, expose_headers, max_age),
                                   and invoke_mode.

        Returns:
            CommandResults: An object containing a success message and raw response for updating the function URL configuration.
        """
        params = {
            "FunctionName": args.get("function_name"),
            "Qualifier": args.get("qualifier"),
            "AuthType": args.get("auth_type"),
            "InvokeMode": args.get("invoke_mode"),
        }
        cors = {
            "AllowCredentials": arg_to_bool_or_none(args.get("cors_allow_credentials")),
            "AllowHeaders": argToList(args.get("cors_allow_headers", [])),
            "AllowMethods": argToList(args.get("cors_allow_methods", [])),
            "AllowOrigins": argToList(args.get("cors_allow_origins", [])),
            "ExposeHeaders": argToList(args.get("cors_expose_headers", [])),
            "MaxAge": arg_to_number(args.get("cors_max_age")),
        }
        fixed_cors = remove_empty_elements(cors)
        if any(fixed_cors.values()):
            params.update({"Cors": fixed_cors})
        fixed_params = remove_empty_elements(params)
        response = client.update_function_url_config(**fixed_params)
        # Create human readable output
        human_readable = tableToMarkdown(
            f"The Updated Lambda Function URL Configuration: {response.get('FunctionArn',args.get('function_name'))}",
            response,
            headers=["FunctionUrl", "FunctionArn", "AuthType", "CreationTime", "LastModifiedTime", "InvokeMode"],
            headerTransform=pascalToSpace,
        )

        return CommandResults(
            outputs_prefix="AWS.Lambda.FunctionURLConfig",
            outputs_key_field="FunctionArn",
            outputs=response,
            readable_output=human_readable,
            raw_response=response,
        )

    @staticmethod
    def _parse_policy_response(data: dict[str, Any]) -> tuple[dict, list | None]:
        """
        Parses the response data representing a policy into a structured format.

        Args:
            data (dict): The response data containing the policy information.

        Returns:
            tuple[dict[str, Any], list[dict[str, str | None]]]: A tuple containing the parsed policy information.
                The first element of the tuple is a dictionary representing the policy metadata with the following keys:
                    - "Id" (str): The ID of the policy.
                    - "Version" (str): The version of the policy.
                    - "RevisionId" (str): The revision ID of the policy.
                The second element of the tuple is a list of dictionaries representing the policy statements.
                Each dictionary in the list represents a statement with the following keys:
                    - "Sid" (str): The ID of the statement.
                    - "Effect" (str): The effect of the statement (e.g., "Allow" or "Deny").
                    - "Action" (str): The action associated with the statement.
                    - "Resource" (str): The resource associated with the statement.
                    - "Principal" (str | None): The principal associated with the statement, if applicable.
        """
        policy: dict[str, Any] = data.get("Policy", {})
        statements: list[dict[str, str | None]] = policy.get("Statement", [])

        if len(statements) == 1:
            return {
                "Sid": statements[0].get("Sid"),
                "Effect": statements[0].get("Effect"),
                "Action": statements[0].get("Action"),
                "Resource": statements[0].get("Resource"),
                "Principal": statements[0].get("Principal"),
            }, None

        else:
            policy_table = {
                "Id": policy.get("Id"),
                "Version": policy.get("Version"),
                "RevisionId": data.get("RevisionId"),
            }
            statements_table = [
                {
                    "Sid": statement.get("Sid"),
                    "Effect": statement.get("Effect"),
                    "Action": statement.get("Action"),
                    "Resource": statement.get("Resource"),
                    "Principal": statement.get("Principal"),
                }
                for statement in statements
            ]
            return policy_table, statements_table

    @staticmethod
    def get_policy_command(client: BotoClient, args: Dict[str, Any]):
        """
        Retrieves the policy for a Lambda function from AWS and parses it into a dictionary.

        Args:
            args (dict): A dictionary containing the function name and optional qualifier.
            aws_client: The AWS client(boto3 client) used to retrieve the policy.

        Returns:
            CommandResults: An object containing the parsed policy as outputs, a readable output in Markdown format,
                            and relevant metadata.
        """
        kwargs = {"FunctionName": args["function_name"]}
        if qualifier := args.get("qualifier"):
            kwargs["Qualifier"] = qualifier

        response = client.get_policy(**kwargs)
        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        fixed_response = {}
        fixed_response["AccountId"] = args.get("account_id", "")
        fixed_response["FunctionName"] = args["function_name"]
        fixed_response["Region"] = args["region"]
        response["Policy"] = json.loads(response["Policy"])
        fixed_response.update(response["Policy"])
        fixed_response.update({"RevisionId": response.get("RevisionId")})

        parsed_policy, parsed_statement = Lambda._parse_policy_response(response)

        policy_table = tableToMarkdown(name="Policy Statements", t=parsed_policy)

        if parsed_statement:  # if policy contains a multiple statements, then print the statements in another table
            statements_table = tableToMarkdown("Statements", t=parsed_statement)
            policy_table = policy_table + statements_table

        return CommandResults(
            outputs=fixed_response,
            readable_output=policy_table,
            outputs_prefix="AWS.Lambda.Policy",
            outputs_key_field=["Region", "FunctionName", "AccountId"],
            raw_response=response,
        )

    @staticmethod
    def invoke_command(client: BotoClient, args: Dict[str, Any]):
        """
        Invokes a Lambda function with the specified parameters and returns the response.

        Args:
            client (BotoClient): The AWS Lambda client used to invoke the function.
            args (Dict[str, Any]): A dictionary containing the function invocation parameters including
                                   functionName, invocationType, logType, clientContext, payload, and qualifier.

        Returns:
            CommandResults: An object containing the invocation response data including function name,
                            region, request payload, log results, response payload, executed version,
                            and any function errors, formatted as readable output.
        """
        payload = args.get("payload")
        kwargs: dict[str, Any] = {
            "FunctionName": args.get("function_name"),
            "InvocationType": args.get("invocation_type"),
            "LogType": args.get("log_type"),
            "ClientContext": args.get("client_context"),
            "Payload": json.dumps(payload)
            if (not isinstance(payload, str)) or (not payload.startswith("{") and not payload.startswith("["))
            else payload,
            "Qualifier": args.get("qualifier"),
        }
        fixed_kwargs = remove_empty_elements(kwargs)
        response = client.invoke(**fixed_kwargs)
        data = {
            "FunctionName": args.get("function_name"),
            "Region": args.get("region"),
            "RequestPayload": args.get("payload"),
        }
        remove_nulls_from_dictionary(data)
        if "LogResult" in response:
            data.update({"LogResult": base64.b64decode(response["LogResult"]).decode("utf-8")})  # type:ignore
        if "Payload" in response:
            data.update({"Payload": response["Payload"].read().decode("utf-8")})  # type:ignore
            response["Payload"] = data["Payload"]
        if "ExecutedVersion" in response:
            data.update({"ExecutedVersion": response["ExecutedVersion"]})  # type:ignore
        if "FunctionError" in response:
            data.update({"FunctionError": response["FunctionError"]})

        human_readable = tableToMarkdown("AWS Lambda Invoked Functions", data)
        return CommandResults(
            outputs=data,
            readable_output=human_readable,
            outputs_prefix="AWS.Lambda.InvokedFunction",
            outputs_key_field=["FunctionName", "Region"],
            raw_response=response,
        )

    @staticmethod
    def get_function_command(client: BotoClient, args: Dict[str, Any]):
        """
        Retrieves information about a Lambda function including configuration, code location, and metadata.

        Args:
            client (BotoClient): The boto3 client for Lambda service
            args (Dict[str, Any]): Command arguments including:
                - function_name (str): The name of the Lambda function
                - qualifier (str, optional): Version or alias to retrieve
                - region (str): AWS region
                - account_id (str): AWS account ID

        Returns:
            CommandResults: Results containing function configuration, code location, tags, and concurrency settings
        """
        # Build API parameters
        kwargs = {"FunctionName": args.get("function_name")}
        if qualifier := args.get("qualifier"):
            kwargs["Qualifier"] = qualifier

        print_debug_logs(client, f"Getting Lambda function with parameters: {kwargs}")

        response = client.get_function(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        # Serialize response with datetime encoding
        response = serialize_response_with_datetime_encoding(response)

        # Add region to response
        response["Region"] = args.get("region")

        # Extract configuration for readable output
        func_config = response.get("Configuration", {})
        func_config["Location"] = response.get("Code").get("Location")  # type: ignore
        func_config["Region"] = args.get("region")
        response["FunctionArn"] = func_config["FunctionArn"]
        outputs = copy.deepcopy(response)
        outputs.pop("ResponseMetadata", None)

        human_readable = tableToMarkdown(
            "AWS Lambda Function",
            func_config,
            headerTransform=pascalToSpace,
            removeNull=True,
            headers=["FunctionName", "FunctionArn", "Runtime", "Region", "Location"],
        )
        return CommandResults(
            outputs_prefix="AWS.Lambda.Functions",
            outputs_key_field="FunctionArn",
            outputs=outputs,
            readable_output=human_readable,
            raw_response=response,
        )

    @staticmethod
    def list_functions_command(client: BotoClient, args: Dict[str, Any]):
        """
        Lists Lambda functions in the specified region.

        Args:
            client (BotoClient): The boto3 client for Lambda service
            args (Dict[str, Any]): Command arguments including:
                - region (str): AWS region
                - account_id (str): AWS account ID
                - limit (int, optional): Maximum number of functions to return
                - next_token (str, optional): Token for pagination

        Returns:
            CommandResults: Results containing list of Lambda functions with their configurations
        """

        # Build pagination parameters using build_pagination_kwargs
        pagination_kwargs = build_pagination_kwargs(
            args, minimum_limit=1, max_limit=50, next_token_name="Marker", limit_name="MaxItems"
        )

        print_debug_logs(client, f"Listing Lambda functions with pagination parameters: {pagination_kwargs}")

        response = client.list_functions(**pagination_kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        # Serialize response with datetime encoding
        serialized_response = serialize_response_with_datetime_encoding(response)
        functions_list = serialized_response.get("Functions", [])
        next_marker = serialized_response.get("NextMarker")

        if not functions_list:
            return CommandResults(readable_output="No Lambda functions found.")

        # Add region to each function
        for func in functions_list:
            func["Region"] = args.get("region")

        human_readable = tableToMarkdown(
            "AWS Lambda Functions",
            functions_list,
            headerTransform=pascalToSpace,
            removeNull=True,
            headers=["FunctionName", "FunctionArn", "Runtime", "LastModified", "Region"],
        )

        # Prepare outputs with pagination support
        outputs = {
            "AWS.Lambda.Functions(val.FunctionArn && val.FunctionArn == obj.FunctionArn)": functions_list,
            "AWS.Lambda(true)": {"FunctionsNextToken": next_marker},
        }

        return CommandResults(
            outputs=outputs,
            readable_output=human_readable,
            raw_response=serialized_response,
        )

    @staticmethod
    def list_aliases_command(client: BotoClient, args: Dict[str, Any]):
        """
        Lists aliases for a Lambda function.

        Args:
            client (BotoClient): The boto3 client for Lambda service
            args (Dict[str, Any]): Command arguments including:
                - function_name (str): The name of the Lambda function
                - function_version (str, optional): Function version to filter aliases
                - limit (int, optional): Maximum number of aliases to return
                - next_token (str, optional): Token for pagination
                - region (str): AWS region
                - account_id (str): AWS account ID

        Returns:
            CommandResults: Results containing list of aliases for the function
        """
        kwargs = {"FunctionName": args.get("function_name")}
        if function_version := args.get("function_version"):
            kwargs["FunctionVersion"] = function_version

        # Build pagination parameters using build_pagination_kwargs
        pagination_kwargs = build_pagination_kwargs(
            args, minimum_limit=1, max_limit=10000, next_token_name="Marker", limit_name="MaxItems"
        )
        kwargs.update(pagination_kwargs)

        print_debug_logs(client, f"Listing Lambda aliases with parameters: {kwargs}")

        response = client.list_aliases(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        # Serialize response with datetime encoding
        serialized_response = serialize_response_with_datetime_encoding(response)
        aliases_list = serialized_response.get("Aliases", [])
        next_marker = serialized_response.get("NextMarker")

        if not aliases_list:
            return CommandResults(readable_output=f"No aliases found for function {args.get('function_name')}.")

        # Prepare readable output
        human_readable = tableToMarkdown(
            "AWS Lambda Aliases",
            aliases_list,
            headerTransform=pascalToSpace,
            removeNull=True,
            headers=["AliasArn", "Name", "FunctionVersion"],
        )

        # Prepare outputs with pagination support
        outputs = {
            "AWS.Lambda.Aliases(val.AliasArn && val.AliasArn == obj.AliasArn)": aliases_list,
            "AWS.Lambda(true)": {"AliasesNextToken": next_marker},
        }

        return CommandResults(
            outputs=outputs,
            readable_output=human_readable,
            raw_response=serialized_response,
        )

    @staticmethod
    def get_account_settings_command(client: BotoClient, args: Dict[str, Any]):
        """
        Retrieves account settings for AWS Lambda.

        Args:
            client (BotoClient): The boto3 client for Lambda service
            args (Dict[str, Any]): Command arguments including:
                - region (str): AWS region
                - account_id (str): AWS account ID

        Returns:
            CommandResults: Results containing account limits and usage
        """
        print_debug_logs(client, "Getting Lambda account settings")

        response = client.get_account_settings()

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        # Serialize response with datetime encoding
        serialized_response = serialize_response_with_datetime_encoding(response)

        account_limit = serialized_response.get("AccountLimit", {})
        account_usage = serialized_response.get("AccountUsage", {})

        # Prepare readable output
        readable_data = {
            "AccountLimit": {
                "TotalCodeSize": str(account_limit.get("TotalCodeSize")),
                "CodeSizeUnzipped": str(account_limit.get("CodeSizeUnzipped")),
                "CodeSizeZipped": str(account_limit.get("CodeSizeZipped")),
                "ConcurrentExecutions": str(account_limit.get("ConcurrentExecutions")),
                "UnreservedConcurrentExecutions": str(account_limit.get("UnreservedConcurrentExecutions")),
            },
            "AccountUsage": {
                "TotalCodeSize": str(account_usage.get("TotalCodeSize")),
                "FunctionCount": str(account_usage.get("FunctionCount")),
            },
        }

        human_readable = tableToMarkdown(
            "AWS Lambda Account Settings",
            readable_data,
            headerTransform=pascalToSpace,
            removeNull=True,
        )

        # Add region and account_id to the root of the output for context
        output = {
            "Region": args.get("region"),
            "AccountId": args.get("account_id"),
            "AccountLimit": account_limit,
            "AccountUsage": account_usage,
        }

        return CommandResults(
            outputs_prefix="AWS.Lambda.AccountSettings",
            outputs_key_field="AccountId",
            outputs=output,
            readable_output=human_readable,
            raw_response=serialized_response,
        )

    @staticmethod
    def list_versions_by_function_command(client: BotoClient, args: Dict[str, Any]):
        """
        Lists the versions of a Lambda function and returns the results.

        Args:
            client (BotoClient): The boto3 client for Lambda service
            args (Dict[str, Any]): Command arguments including:
                - function_name (str): The name of the Lambda function
                - next_token (str, optional): The token for pagination
                - limit (int, optional): The maximum number of items to return
                - region (str): AWS region
                - account_id (str): AWS account ID

        Returns:
            CommandResults: Results containing list of function versions with their configurations
        """
        kwargs = {"FunctionName": args.get("function_name")}

        # Build pagination parameters using build_pagination_kwargs
        pagination_kwargs = build_pagination_kwargs(
            args, minimum_limit=1, max_limit=50, next_token_name="Marker", limit_name="MaxItems"
        )
        kwargs.update(pagination_kwargs)

        print_debug_logs(client, f"Listing Lambda function versions with parameters: {kwargs}")

        response = client.list_versions_by_function(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        # Serialize response with datetime encoding
        serialized_response = serialize_response_with_datetime_encoding(response)

        versions = serialized_response.get("Versions", [])
        next_marker = serialized_response.get("NextMarker")

        if not versions:
            return CommandResults(readable_output=f"No versions found for function {args.get('function_name')}.")

        headers = ["FunctionName", "Role", "Runtime", "LastModified", "State", "Description"]
        human_readable = tableToMarkdown(
            "AWS Lambda Function Versions",
            versions,
            headers=headers,
            headerTransform=pascalToSpace,
            removeNull=True,
        )

        # Prepare output with region context
        output = {
            "FunctionVersions": versions,
            "FunctionArn": versions[0].get("FunctionArn"),
        }

        outputs = {
            "AWS.Lambda.Functions(val.FunctionArn && val.FunctionArn == obj.FunctionArn)": output,
            "AWS.Lambda.Functions(true)": {"FunctionVersionsNextToken": next_marker},
        }

        return CommandResults(
            outputs=outputs,
            readable_output=human_readable,
            raw_response=serialized_response,
        )

    @staticmethod
    def delete_function_url_config_command(client: BotoClient, args: Dict[str, Any]):
        """
        Deletes the URL configuration for a Lambda function in AWS.

        Args:
            client (BotoClient): The boto3 client for Lambda service
            args (Dict[str, Any]): Command arguments including:
                - function_name (str): The name of the Lambda function
                - qualifier (str, optional): The qualifier of the function
                - region (str): AWS region
                - account_id (str): AWS account ID

        Returns:
            CommandResults: Results of the deletion operation with success message
        """
        kwargs = {"FunctionName": args.get("function_name")}
        if qualifier := args.get("qualifier"):
            kwargs["Qualifier"] = qualifier

        print_debug_logs(client, f"Deleting Lambda function URL config with parameters: {kwargs}")

        response = client.delete_function_url_config(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") in [HTTPStatus.OK, HTTPStatus.NO_CONTENT]:
            return CommandResults(
                readable_output=f"Successfully deleted function URL configuration for {args.get('function_name')}"
            )
        return None

    @staticmethod
    def create_function_command(client: BotoClient, args: Dict[str, Any]):
        """
        Creates a Lambda function from AWS.

        Args:
            client (BotoClient): The boto3 client for Lambda service
            args (Dict[str, Any]): Command arguments including function configuration
                - function_name (str): The name of the function
                - runtime (str): The runtime environment
                - role (str): The ARN of the function's execution role
                - handler (str): The function entry point
                - code (str, optional): Entry ID of uploaded ZIP file
                - s3_bucket (str, optional): S3 bucket containing the code
                - description (str, optional): Function description
                - memory_size (int, optional): Memory size in MB (default: 128)
                - function_timeout (int, optional): Timeout in seconds (default: 3)
                - publish (bool, optional): Whether to publish the first version
                - environment (str/dict, optional): Environment variables
                - tags (str/dict, optional): Tags for the function
                - layers (list, optional): List of layer ARNs
                - vpc_config (str/dict, optional): VPC configuration
                - tracing_config (str, optional): Tracing mode (default: Active)
                - package_type (str, optional): Deployment package type
                - region (str): AWS region
                - account_id (str): AWS account ID

        Returns:
            CommandResults: Results containing the created function details
        """
        kwargs = prepare_create_function_kwargs(args)

        print_debug_logs(client, f"Creating Lambda function: {args.get('function_name')} using {kwargs=}")

        response = client.create_function(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.CREATED:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        # Serialize response with datetime encoding
        response = serialize_response_with_datetime_encoding(response)
        outputs = copy.deepcopy(response)
        outputs.pop("ResponseMetadata", None)
        # Prepare readable output
        output_headers = [
            "FunctionName",
            "FunctionArn",
            "Description",
            "Version",
        ]

        readable_output = tableToMarkdown(
            name=f"Created Lambda Function: {args.get('function_name')}",
            t=outputs,
            headerTransform=pascalToSpace,
            removeNull=True,
            headers=output_headers,
        )
        return CommandResults(
            outputs=outputs,
            raw_response=response,
            outputs_prefix="AWS.Lambda.Functions",
            outputs_key_field="FunctionArn",
            readable_output=readable_output,
        )

    @staticmethod
    def list_layer_versions_command(client: BotoClient, args: Dict[str, Any]):
        """
        Lists the versions of an Lambda layer.

        Args:
            client (BotoClient): The boto3 client for Lambda service
            args (Dict[str, Any]): Command arguments including:
                - layer_name (str): The name or ARN of the layer
                - compatible_runtime (str, optional): A runtime identifier
                - next_token (str, optional): Pagination token
                - limit (int, optional): Maximum number of versions to return
                - compatible_architecture (str, optional): Compatible architecture
                - region (str): AWS region
                - account_id (str): AWS account ID

        Returns:
            CommandResults: Results containing list of layer versions
        """
        kwargs = {
            "LayerName": args.get("layer_name"),
            "CompatibleRuntime": args.get("compatible_runtime"),
            "CompatibleArchitecture": args.get("compatible_architecture"),
        }

        # Build pagination parameters using build_pagination_kwargs
        pagination_kwargs = build_pagination_kwargs(
            args, minimum_limit=1, max_limit=50, next_token_name="Marker", limit_name="MaxItems"
        )
        kwargs.update(pagination_kwargs)

        remove_nulls_from_dictionary(kwargs)

        print_debug_logs(client, f"Listing Lambda layer versions with parameters: {kwargs}")

        response = client.list_layer_versions(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        # Serialize response with datetime encoding
        serialized_response = serialize_response_with_datetime_encoding(response)

        layer_versions = serialized_response.get("LayerVersions", [])
        next_marker = serialized_response.get("NextMarker")

        if not layer_versions:
            return CommandResults(readable_output=f"No layer versions found for {args.get('layer_name')}.")

        # Prepare outputs
        outputs = {
            "AWS.Lambda.Layers(val.LayerVersionArn && val.LayerVersionArn == obj.LayerVersionArn)": layer_versions,
            "AWS.Lambda.Layers(true)": {"LayerVersionsNextToken": next_marker},
        }

        headers = ["LayerVersionArn", "Description", "CreatedDate", "Version"]

        readable_output = tableToMarkdown(
            name="Layer Version List", t=layer_versions, headers=headers, headerTransform=pascalToSpace, removeNull=True
        )

        return CommandResults(
            outputs=remove_empty_elements(outputs),
            outputs_prefix="AWS.Lambda.Layers",
            raw_response=serialized_response,
            readable_output=readable_output,
        )

    @staticmethod
    def delete_function_command(client: BotoClient, args: Dict[str, Any]):
        """
        Deletes a Lambda function from AWS.

        Args:
            client (BotoClient): The boto3 client for Lambda service
            args (Dict[str, Any]): Command arguments including:
                - function_name (str): The name of the Lambda function
                - qualifier (str, optional): The qualifier of the function
                - region (str): AWS region
                - account_id (str): AWS account ID

        Returns:
            CommandResults: Results of the deletion operation with success message
        """
        kwargs = {"FunctionName": args.get("function_name")}
        if qualifier := args.get("qualifier"):
            kwargs["Qualifier"] = qualifier

        print_debug_logs(client, f"Deleting Lambda function with parameters: {kwargs}")

        response = client.delete_function(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") in [HTTPStatus.OK, HTTPStatus.NO_CONTENT]:
            return CommandResults(readable_output=f"Successfully deleted Lambda function: {args.get('function_name')}")
        return None

    @staticmethod
    def delete_layer_version_command(client: BotoClient, args: Dict[str, Any]):
        """
        Deletes a version of a Lambda layer.

        Args:
            client (BotoClient): The boto3 client for Lambda service
            args (Dict[str, Any]): Command arguments including:
                - layer_name (str): The name or ARN of the layer
                - version_number (int): The version number to delete
                - region (str): AWS region
                - account_id (str): AWS account ID

        Returns:
            CommandResults: Results of the deletion operation with success message
        """
        kwargs = {"LayerName": args.get("layer_name"), "VersionNumber": arg_to_number(args.get("version_number"))}

        print_debug_logs(client, f"Deleting Lambda layer version with parameters: {kwargs}")

        response = client.delete_layer_version(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") in [HTTPStatus.OK, HTTPStatus.NO_CONTENT]:
            msg = f"Successfully deleted version {kwargs.get('VersionNumber')} of layer {kwargs.get('LayerName')}"
            return CommandResults(readable_output=msg)
        return None

    @staticmethod
    def publish_layer_version_command(client: BotoClient, args: Dict[str, Any]):
        """
        Creates a Lambda layer from a ZIP archive.

        Args:
            client (BotoClient): The boto3 client for Lambda service
            args (Dict[str, Any]): Command arguments including:
                - layer_name (str): The name of the layer
                - description (str, optional): Description of the layer version
                - zip_file (str, optional): Entry ID of uploaded ZIP file
                - s3_bucket (str, optional): S3 bucket containing the layer code
                - s3_key (str, optional): S3 key of the layer code
                - s3_object_version (str, optional): S3 object version
                - compatible_runtimes (list, optional): Compatible runtimes
                - compatible_architectures (list, optional): Compatible architectures
                - region (str): AWS region
                - account_id (str): AWS account ID

        Returns:
            CommandResults: Results containing the published layer version details
        """

        # Prepare content configuration
        content = {}
        s3_bucket = args.get("s3_bucket")
        s3_key = args.get("s3_key")
        s3_object_version = args.get("s3_object_version")

        if zip_file := args.get("zip_file"):
            file_path = demisto.getFilePath(zip_file).get("path")
            content["ZipFile"] = read_zip_to_bytes(file_path)
        elif s3_bucket and s3_key and s3_object_version:
            content["S3Bucket"] = s3_bucket
            content["S3Key"] = s3_key
            content["S3ObjectVersion"] = s3_object_version
        else:
            raise DemistoException(
                "Either zip_file or a combination of s3_bucket, s3_key and s3_object_version must be provided."
            )

        kwargs = {
            "LayerName": args.get("layer_name"),
            "Description": args.get("description", ""),
            "Content": content,
            "CompatibleRuntimes": argToList(args.get("compatible_runtimes")),
            "CompatibleArchitectures": argToList(args.get("compatible_architectures")),
        }

        remove_nulls_from_dictionary(kwargs)

        print_debug_logs(client, f"Publishing Lambda layer version: {kwargs=}")

        response = client.publish_layer_version(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") not in [HTTPStatus.OK, HTTPStatus.CREATED]:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        # Serialize response with datetime encoding
        outputs = serialize_response_with_datetime_encoding(response)
        outputs.pop("ResponseMetadata", None)

        # Extract outputs based on headers
        outputs["Region"] = args.get("region")
        output_headers = [
            "LayerVersionArn",
            "LayerArn",
            "Description",
            "CreatedDate",
            "Version",
        ]
        readable_output = tableToMarkdown(
            name=f"Published Layer Version: {response.get('LayerArn')}",
            t=outputs,
            headers=output_headers,
            headerTransform=pascalToSpace,
            removeNull=True,
        )

        return CommandResults(
            outputs=remove_empty_elements(outputs),
            raw_response=serialize_response_with_datetime_encoding(response),
            outputs_prefix="AWS.Lambda.LayerVersions",
            outputs_key_field="LayerVersionArn",
            readable_output=readable_output,
        )


class ACM:
    service = AWSServices.ACM

    @staticmethod
    def update_certificate_options_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Updates Certificate Transparency (CT) logging preference for an ACM certificate.
        Args:
            client: The AWS ACM boto3 client used to perform the update request.
            args (dict): A dictionary containing the certificate ARN and the desired
                transparency logging preference ("ENABLED" or "DISABLED").

        Returns:
            CommandResults: An object containing a human-readable summary of the change,
                the raw AWS API response, and related metadata.
        """
        arn = args.get("certificate_arn")
        pref = args.get("transparency_logging_preference")
        kwargs = {"CertificateArn": arn, "Options": {"CertificateTransparencyLoggingPreference": pref}}
        remove_nulls_from_dictionary(kwargs)
        print_debug_logs(client, f"UpdateCertificateOptions params: {kwargs}")

        try:
            resp = client.update_certificate_options(**kwargs)
            status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if status in (HTTPStatus.OK, HTTPStatus.NO_CONTENT):
                hr = f"Updated Certificate Transparency (CT) logging to '{pref}' for certificate '{arn}'."
                return CommandResults(readable_output=hr, raw_response=resp)
            return AWSErrorHandler.handle_response_error(resp)

        except ClientError as e:
            return AWSErrorHandler.handle_client_error(e)

        except Exception as e:
            raise DemistoException(f"Error updating certificate options for '{arn}': {str(e)}")


def get_file_path(file_id):
    filepath_result = demisto.getFilePath(file_id)
    return filepath_result


COMMANDS_MAPPING: dict[str, Callable[[BotoClient, Dict[str, Any]], CommandResults | None]] = {
    "aws-billing-cost-usage-list": CostExplorer.billing_cost_usage_list_command,
    "aws-billing-forecast-list": CostExplorer.billing_forecast_list_command,
    "aws-billing-budgets-list": Budgets.billing_budgets_list_command,
    "aws-billing-budget-notification-list": Budgets.billing_budget_notification_list_command,
    "aws-s3-public-access-block-update": S3.put_public_access_block_command,
    "aws-s3-public-access-block-quick-action": S3.put_public_access_block_command,
    "aws-s3-bucket-delete": S3.delete_bucket_command,
    "aws-s3-bucket-objects-list": S3.list_bucket_objects_command,
    "aws-s3-bucket-versioning-put": S3.put_bucket_versioning_command,
    "aws-s3-bucket-versioning-enable-quick-action": S3.put_bucket_versioning_command,
    "aws-s3-bucket-logging-put": S3.put_bucket_logging_command,
    "aws-s3-bucket-enable-bucket-access-logging-quick-action": S3.put_bucket_logging_command,
    "aws-s3-bucket-acl-put": S3.put_bucket_acl_command,
    "aws-s3-bucket-acl-set-to-private-quick-action": S3.put_bucket_acl_command,
    "aws-s3-bucket-policy-put": S3.put_bucket_policy_command,
    "aws-s3-bucket-website-delete": S3.delete_bucket_website_command,
    "aws-s3-bucket-website-disable-hosting-quick-action": S3.delete_bucket_website_command,
    "aws-s3-bucket-ownership-controls-put": S3.put_bucket_ownership_controls_command,
    "aws-s3-file-upload": S3.file_upload_command,
    "aws-s3-file-download": S3.file_download_command,
    "aws-s3-bucket-website-get": S3.get_bucket_website_command,
    "aws-s3-bucket-acl-get": S3.get_bucket_acl_command,
    "aws-iam-account-password-policy-get": IAM.get_account_password_policy_command,
    "aws-iam-account-password-policy-update": IAM.update_account_password_policy_command,
    "aws-iam-role-policy-put": IAM.put_role_policy_command,
    "aws-iam-login-profile-delete": IAM.delete_login_profile_command,
    "aws-iam-user-policy-put": IAM.put_user_policy_command,
    "aws-iam-role-from-instance-profile-remove": IAM.remove_role_from_instance_profile_command,
    "aws-iam-access-key-update": IAM.update_access_key_command,
    "aws-ec2-instance-metadata-options-modify": EC2.modify_instance_metadata_options_command,
    "aws-ec2-enable-imdsv2-quick-action": EC2.modify_instance_metadata_options_command,
    "aws-ec2-instance-attribute-modify": EC2.modify_instance_attribute_command,
    "aws-ec2-instance-attribute-modify-quick-action": EC2.modify_instance_attribute_command,
    "aws-ec2-snapshot-attribute-modify": EC2.modify_snapshot_attribute_command,
    "aws-ec2-image-attribute-modify": EC2.modify_image_attribute_command,
    "aws-ec2-image-attribute-set-ami-to-private-quick-action": EC2.modify_image_attribute_command,
    "aws-ec2-security-group-ingress-revoke": EC2.revoke_security_group_ingress_command,
    "aws-ec2-security-group-ingress-authorize": EC2.authorize_security_group_ingress_command,
    "aws-ec2-security-group-egress-revoke": EC2.revoke_security_group_egress_command,
    "aws-ec2-snapshot-create": EC2.create_snapshot_command,
    "aws-ec2-snapshot-permission-modify": EC2.modify_snapshot_permission_command,
    "aws-ec2-subnet-attribute-modify": EC2.modify_subnet_attribute_command,
    "aws-ec2-vpcs-describe": EC2.describe_vpcs_command,
    "aws-ec2-subnets-describe": EC2.describe_subnets_command,
    "aws-ec2-ipam-resource-discoveries-describe": EC2.describe_ipam_resource_discoveries_command,
    "aws-ec2-ipam-resource-discovery-associations-describe": EC2.describe_ipam_resource_discovery_associations_command,
    "aws-ec2-set-snapshot-to-private-quick-action": EC2.modify_snapshot_permission_command,
    "aws-ec2-latest-ami-get": EC2.get_latest_ami_command,
    "aws-ec2-network-acl-create": EC2.create_network_acl_command,
    "aws-ec2-ipam-discovered-public-addresses-get": EC2.get_ipam_discovered_public_addresses_command,
    "aws-ec2-security-group-create": EC2.create_security_group_command,
    "aws-ec2-security-group-delete": EC2.delete_security_group_command,
    "aws-ec2-security-groups-describe": EC2.describe_security_groups_command,
    "aws-ec2-security-group-egress-authorize": EC2.authorize_security_group_egress_command,
    "aws-ec2-images-describe": EC2.describe_images_command,
    "aws-ec2-image-create": EC2.create_image_command,
    "aws-ec2-image-deregister": EC2.deregister_image_command,
    "aws-ec2-image-copy": EC2.copy_image_command,
    "aws-ec2-image-available-waiter": EC2.image_available_waiter_command,
    "aws-ec2-instances-monitor": EC2.monitor_instances_command,
    "aws-ec2-instances-unmonitor": EC2.unmonitor_instances_command,
    "aws-ec2-instances-reboot": EC2.reboot_instances_command,
    "aws-ec2-instance-running-waiter": EC2.instance_running_waiter_command,
    "aws-ec2-instance-status-ok-waiter": EC2.instance_status_ok_waiter_command,
    "aws-ec2-instance-stopped-waiter": EC2.instance_stopped_waiter_command,
    "aws-ec2-instance-terminated-waiter": EC2.instance_terminated_waiter_command,
    "aws-ec2-iam-instance-profile-associations-describe": EC2.describe_iam_instance_profile_associations_command,
    "aws-ec2-password-data-get": EC2.get_password_data_command,
    "aws-ec2-reserved-instances-describe": EC2.describe_reserved_instances_command,
    "aws-ec2-snapshots-describe": EC2.describe_snapshots_command,
    "aws-ec2-snapshot-delete": EC2.delete_snapshot_command,
    "aws-ec2-snapshot-copy": EC2.copy_snapshot_command,
    "aws-ec2-snapshot-completed-waiter": EC2.snapshot_completed_waiter_command,
    "aws-eks-cluster-config-update": EKS.update_cluster_config_command,
    "aws-eks-enable-control-plane-logging-quick-action": EKS.update_cluster_config_command,
    "aws-eks-disable-public-access-quick-action": EKS.update_cluster_config_command,
    "aws-eks-cluster-describe": EKS.describe_cluster_command,
    "aws-eks-access-policy-associate": EKS.associate_access_policy_command,
    "aws-rds-db-cluster-modify": RDS.modify_db_cluster_command,
    "aws-rds-db-cluster-enable-iam-auth-quick-action": RDS.modify_db_cluster_command,
    "aws-rds-db-cluster-enable-deletion-protection-quick-action": RDS.modify_db_cluster_command,
    "aws-rds-db-cluster-snapshot-attribute-modify": RDS.modify_db_cluster_snapshot_attribute_command,
    "aws-rds-db-cluster-snapshot-set-to-private-quick-action": RDS.modify_db_cluster_snapshot_attribute_command,
    "aws-rds-db-instance-modify": RDS.modify_db_instance_command,
    "aws-rds-db-instance-modify-publicly-accessible-quick-action": RDS.modify_db_instance_command,
    "aws-rds-db-instance-modify-copy-tags-on-rds-snapshot-quick-action": RDS.modify_db_instance_command,
    "aws-rds-db-instance-modify-enable-automatic-backup-quick-action": RDS.modify_db_instance_command,
    "aws-rds-db-instance-enable-iam-auth-quick-action": RDS.modify_db_instance_command,
    "aws-rds-db-instance-enable-deletion-protection-quick-action": RDS.modify_db_instance_command,
    "aws-rds-db-instance-enable-auto-upgrade-quick-action": RDS.modify_db_instance_command,
    "aws-rds-db-instance-enable-multi-az-quick-action": RDS.modify_db_instance_command,
    "aws-rds-db-snapshot-attribute-modify": RDS.modify_db_snapshot_attribute_command,
    "aws-rds-event-subscription-modify": RDS.modify_event_subscription_command,
    "aws-rds-db-snapshot-attribute-set-snapshot-to-private-quick-action": RDS.modify_db_snapshot_attribute_command,
    "aws-cloudtrail-logging-start": CloudTrail.start_logging_command,
    "aws-cloudtrail-logging-start-enable-logging-quick-action": CloudTrail.start_logging_command,
    "aws-cloudtrail-trail-update": CloudTrail.update_trail_command,
    "aws-cloudtrail-trail-enable-log-validation-quick-action": CloudTrail.update_trail_command,
    "aws-ec2-instances-describe": EC2.describe_instances_command,
    "aws-ec2-instances-start": EC2.start_instances_command,
    "aws-ec2-instances-stop": EC2.stop_instances_command,
    "aws-ec2-instances-terminate": EC2.terminate_instances_command,
    "aws-ec2-instances-run": EC2.run_instances_command,
    "aws-ec2-tags-create": EC2.create_tags_command,
    "aws-s3-bucket-policy-delete": S3.delete_bucket_policy_command,
    "aws-s3-public-access-block-get": S3.get_public_access_block_command,
    "aws-s3-bucket-encryption-get": S3.get_bucket_encryption_command,
    "aws-s3-bucket-policy-get": S3.get_bucket_policy_command,
    "aws-cloudtrail-trails-describe": CloudTrail.describe_trails_command,
    "aws-acm-certificate-options-update": ACM.update_certificate_options_command,
    "aws-ecs-cluster-settings-update": ECS.update_cluster_settings_command,
    "aws-lambda-function-configuration-get": Lambda.get_function_configuration_command,
    "aws-lambda-function-url-config-get": Lambda.get_function_url_configuration_command,
    "aws-lambda-policy-get": Lambda.get_policy_command,
    "aws-lambda-invoke": Lambda.invoke_command,
    "aws-lambda-function-url-config-update": Lambda.update_function_url_configuration_command,
    "aws-lambda-function-get": Lambda.get_function_command,
    "aws-lambda-functions-list": Lambda.list_functions_command,
    "aws-lambda-aliases-list": Lambda.list_aliases_command,
    "aws-lambda-account-settings-get": Lambda.get_account_settings_command,
    "aws-lambda-function-versions-list": Lambda.list_versions_by_function_command,
    "aws-lambda-function-url-config-delete": Lambda.delete_function_url_config_command,
    "aws-lambda-function-create": Lambda.create_function_command,
    "aws-lambda-layer-version-list": Lambda.list_layer_versions_command,
    "aws-lambda-function-delete": Lambda.delete_function_command,
    "aws-lambda-layer-version-delete": Lambda.delete_layer_version_command,
    "aws-lambda-layer-version-publish": Lambda.publish_layer_version_command,
    "aws-kms-key-rotation-enable": KMS.enable_key_rotation_command,
    "aws-elb-load-balancer-attributes-modify": ELB.modify_load_balancer_attributes_command,
    "aws-ec2-addresses-describe": EC2.describe_addresses_command,
    "aws-ec2-address-allocate": EC2.allocate_address_command,
    "aws-ec2-address-associate": EC2.associate_address_command,
    "aws-ec2-address-disassociate": EC2.disassociate_address_command,
    "aws-ec2-address-release": EC2.release_address_command,
    "aws-ec2-volumes-describe": EC2.describe_volumes_command,
    "aws-ec2-volume-modify": EC2.modify_volume_command,
    "aws-ec2-volume-create": EC2.create_volume_command,
    "aws-ec2-volume-attach": EC2.attach_volume_command,
    "aws-ec2-volume-detach": EC2.detach_volume_command,
    "aws-ec2-volume-delete": EC2.delete_volume_command,
}

REQUIRED_ACTIONS: list[str] = [
    "kms:CreateGrant",
    "kms:Decrypt",
    "kms:DescribeKey",
    "kms:GenerateDataKey",
    "kms:EnableKeyRotation",
    "secretsmanager:CreateSecret",
    "secretsmanager:RotateSecret",
    "secretsmanager:TagResource",
    "rds:AddTagsToResource",
    "rds:CreateTenantDatabase",
    "rds:ModifyDBCluster",
    "rds:ModifyDBClusterSnapshotAttribute",
    "rds:ModifyDBInstance",
    "rds:ModifyDBSnapshotAttribute",
    "s3:PutBucketAcl",
    "s3:PutBucketLogging",
    "s3:PutBucketVersioning",
    "s3:PutBucketPolicy",
    "s3:PutBucketPublicAccessBlock",
    "s3:PutObject",
    "s3:GetObject",
    "ec2:RevokeSecurityGroupEgress",
    "ec2:ModifyImageAttribute",
    "ec2:ModifyInstanceAttribute",
    "ec2:ModifySnapshotAttribute",
    "ec2:RevokeSecurityGroupIngress",
    "ec2:CreateSnapshot",
    "ec2:DescribeVpcs",
    "ec2:DescribeSubnets",
    "ec2:DescribeIpamResourceDiscoveries",
    "ec2:DescribeIpamResourceDiscoveryAssociations",
    "ec2:DescribeImages",
    "ec2:CreateImage",
    "ec2:DeregisterImage",
    "ec2:CopyImage",
    "ec2:DescribeSnapshots",
    "ec2:DeleteSnapshot",
    "ec2:CopySnapshot",
    "ec2:DescribeRegions",
    "eks:DescribeCluster",
    "eks:AssociateAccessPolicy",
    "ec2:CreateSecurityGroup",
    "ec2:CreateNetworkAcl",
    "ec2:GetIpamDiscoveredPublicAddresses",
    "ec2:CreateTags",
    "ec2:DeleteSecurityGroup",
    "ec2:DescribeAddresses",
    "ec2:AllocateAddress",
    "ec2:AssociateAddress",
    "ec2:DisassociateAddress",
    "ec2:ReleaseAddress",
    "ec2:DescribeInstances",
    "ec2:DescribeInstanceStatus",
    "ec2:DescribeSecurityGroups",
    "ec2:AuthorizeSecurityGroupEgress",
    "ec2:AuthorizeSecurityGroupIngress",
    "ec2:ModifyInstanceMetadataOptions",
    "ec2:MonitorInstances",
    "ec2:UnmonitorInstances",
    "ec2:RebootInstances",
    "ec2:DescribeIamInstanceProfileAssociations",
    "ec2:GetPasswordData",
    "ec2:DescribeReservedInstances",
    "ec2:DescribeInstances",
    "ec2:StartInstances",
    "ec2:StopInstances",
    "ec2:TerminateInstances",
    "ec2:RunInstances",
    "eks:UpdateClusterConfig",
    "iam:PassRole",
    "iam:DeleteLoginProfile",
    "iam:PutUserPolicy",
    "iam:RemoveRoleFromInstanceProfile",
    "iam:UpdateAccessKey",
    "iam:GetAccountPasswordPolicy",
    "iam:UpdateAccountPasswordPolicy",
    "iam:GetAccountAuthorizationDetails",
    "ecs:UpdateClusterSettings",
    "s3:GetBucketPolicy",
    "s3:GetBucketWebsite",
    "s3:GetBucketAcl",
    "s3:GetBucketPublicAccessBlock",
    "s3:GetEncryptionConfiguration",
    "s3:DeleteBucketPolicy",
    "s3:ListBuckets",
    "s3:DeleteBucket",
    "acm:UpdateCertificateOptions",
    "cloudtrail:DescribeTrails",
    "lambda:GetFunctionConfiguration",
    "lambda:GetFunctionUrlConfig",
    "lambda:GetPolicy",
    "lambda:InvokeFunction",
    "lambda:UpdateFunctionUrlConfig",
    "lambda:GetFunction",
    "lambda:ListFunctions",
    "lambda:ListAliases",
    "lambda:GetAccountSettings",
    "lambda:ListVersionsByFunction",
    "lambda:DeleteFunctionUrlConfig",
    "lambda:CreateFunction",
    "lambda:ListLayerVersions",
    "lambda:DeleteFunction",
    "lambda:DeleteLayerVersion",
    "lambda:PublishLayerVersion",
    "elasticloadbalancing:ModifyLoadBalancerAttributes",
    "ce:GetCostAndUsage",
    "ce:GetCostForecast",
    "budgets:DescribeBudgets",
    "budgets:DescribeNotificationsForBudget",
    "ec2:DescribeVolumes",
    "ec2:ModifyVolume",
    "ec2:CreateVolume",
    "ec2:AttachVolume",
    "ec2:DetachVolume",
    "ec2:DeleteVolume",
]

COMMAND_SERVICE_MAP = {
    "aws-billing-cost-usage-list": "ce",
    "aws-billing-forecast-list": "ce",
    "aws-billing-budgets-list": "budgets",
    "aws-billing-budget-notification-list": "budgets",
}


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
    session: Session | None = None,
    service_name: str = "",
    config: Config | None = None,
) -> tuple[BotoClient, Session | None]:
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
    if command in COMMAND_SERVICE_MAP:
        service_name = COMMAND_SERVICE_MAP[command]
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


def execute_aws_command(command: str, args: dict, params: dict) -> CommandResults | None:
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

    except ClientError as client_err:
        account_id = args.get("account_id", "")
        AWSErrorHandler.handle_client_error(client_err, account_id)

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
