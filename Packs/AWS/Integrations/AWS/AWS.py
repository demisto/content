import demistomock as demisto  # noqa: F401
from COOCApiModule import *  # noqa: E402
from CommonServerPython import *  # noqa: F401
from http import HTTPStatus
from datetime import date, datetime, timedelta, UTC
from collections.abc import Callable
from botocore.client import BaseClient as BotoClient
from botocore.config import Config
from botocore.exceptions import ClientError
from boto3 import Session
import re

DEFAULT_MAX_RETRIES: int = 5
DEFAULT_SESSION_NAME = "cortex-session"
DEFAULT_PROXYDOME_CERTFICATE_PATH = os.getenv("EGRESSPROXY_CA_PATH") or "/etc/certs/egress.crt"
DEFAULT_PROXYDOME = os.getenv("CRTX_HTTP_PROXY") or "10.181.0.100:11117"
TIMEOUT_CONFIG = Config(connect_timeout=60, read_timeout=60)
DEFAULT_REGION = "us-east-1"
MAX_FILTERS = 50
MAX_TAGS = 50
MAX_FILTER_VALUES = 200
MAX_TARGET_VALUES = 50
MAX_CHAR_LENGTH_FOR_FILTER_VALUE = 255
MAX_LIMIT_VALUE = 1000
DEFAULT_LIMIT_VALUE = 50
MAXIMUM_COMMAND_TIMEOUT = 2592000  # Maximum timeout for running commands in ssm (30 days).
MINIMUM_COMMAND_TIMEOUT = 30  # Minimum timeout for running commands in ssm.
DEFAULT_INTERVAL_IN_SECONDS = 30  # Interval for polling commands.
DEFAULT_TIMEOUT = 600  # Default timeout for polling commands.
TERMINAL_COMMAND_STATUSES = {  # the status for run command command
    "Success": "The command completed successfully.",
    "Failed": "The command wasn't successfully on the managed node.",
    "Delivery Timed Out": "The command wasn't delivered to the managed node before the total timeout expired.",
    "Incomplete": "The command was attempted on all managed nodes and one or more of the invocations "
    "doesn't have a value of Success. However, not enough invocations failed for the status to be Failed.",
    "Cancelled": "The command was canceled before it was completed.",
    "Canceled": "The command was canceled before it was completed.",  # AWS typo, British English (canceled)
    "Rate Exceeded": "The number of managed nodes targeted by the command exceeded the account quota for pending invocations. "
    "The system has canceled the command before executing it on any node.",
    "Access Denied": "The user or role initiating the command doesn't have access to the targeted resource group. AccessDenied "
    "doesn't count against the parent command's max-errors limit, "
    "but does contribute to whether the parent command status is Success or Failed.",
    "No Instances In Tag": "The tag key-pair value or resource group targeted by the command doesn't match any managed nodes. ",
}


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
        next_token_name (str): The name of the next token argument in AWS
        limit_name (str): The name of the limit argument in AWS

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


def parse_target_field(target_string: str | None):
    """
    Parses a list representation of key and values with the form of 'key=<key>,values=<values>.
    the maximum number of values for a key might be lower than the global maximum of 50.
    Key minimum length of 1, maximum length of 163.

    Args:
        target_string (str): The key and values list
    Returns:
        A list of dicts with the form {"Key": <key>, "Values": [<value>]}
    """
    targets = []
    list_targets = argToList(target_string, separator=";")
    regex = re.compile(
        r"^key=(^[\p{L}\p{Z}\p{N}_.:/=\-@]*$|resource-groups:ResourceTypeFilters|resource-groups:Name),values=([ \w@,.*-\/:]+)",
        flags=re.I,
    )
    for target in list_targets:
        match_target = regex.match(target)
        if match_target is None:
            raise ValueError(
                f"Could not parse target: {target}. Please make sure you provided "
                "like so: key=<key>,values=<values>;name=<name>,values=<value1>,<value2>..."
            )
        demisto.debug(
            f'Number of target values for {match_target.group(1)} is {len(match_target.group(2).split(","))}'
            f' if larger than {MAX_TARGET_VALUES},'
            f' parsing only first {MAX_TARGET_VALUES} values.'
        )
        targets.append({"Key": match_target.group(1), "Values": match_target.group(2).split(",")[0:MAX_TARGET_VALUES]})

    return targets


def parse_parameters_arg(parameters_str: str) -> dict:
    """
    Parses a list representation of key and values 'key=<key1>,values=<value>,<value>;key=<key2>,values=<value>,<value>.

    Args:
        parameters_str (str): The key and values list
    Returns:
        A dictionary containing the parameters
        {"key1" : [ "string", "string"], "key2" : [ "string", "string"]}
    """
    parameters = {}
    list_parameters = argToList(parameters_str, separator=";")
    for param in list_parameters:
        first_split = param.split(",values=")
        key = first_split[0][4:]  # remove 'key='
        values = first_split[1].split(',')
        parameters[key] = values
    return parameters


def parse_triple_filter(filter_string: str | None):
    """
    Parses a list representation of name and values and type with the form of 'name=<name>,values=<values>,type=<type>'.
    You can specify up to 50 filters, up to 200 values, and 1 type per filter in a single request.
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
        r"^name=([\w:.-]+),values=([ \w@,.*-\/:]+),type=([\w:.-]+)",
        flags=re.I,
    )
    for f in list_filters:
        match_filter = regex.match(f)
        if match_filter is None:
            raise ValueError(
                f"Could not parse field: {f}. Please make sure you provided "
                "like so: name=<name>,values=<values>,type=<type>;name=<name>,values=<value1>,<value2>,type=<type>..."
            )
        demisto.debug(
            f'Number of filter values for filter {match_filter.group(1)} is {len(match_filter.group(2).split(","))}'
            f' if larger than {MAX_FILTER_VALUES},'
            f' parsing only first {MAX_FILTER_VALUES} values.'
        )
        filters.append(
            {
                "Name": match_filter.group(1),
                "Values": match_filter.group(2).split(",")[0:MAX_FILTER_VALUES],
                "Type": match_filter.group(3),
            }
        )

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


def build_kwargs_network_interface_attribute(args: dict, network_interface_id: str) -> dict:
    """
    Build the kwargs for network_interface_attribute_modify_command.
    Args:
        args (dict): The command arguments.
        network_interface_id (str): the network interface id.
    Returns:
        A dictionary with the relevant values.
    """
    kwargs = {
        "EnaSrdSpecification": arg_to_bool_or_none(args.get("ena_srd_enabled")),
        "EnablePrimaryIpv6": arg_to_bool_or_none(args.get("enable_primary_ipv6")),
        "AssociatePublicIpAddress": arg_to_bool_or_none(args.get("associate_public_ip_address")),
        "AssociatedSubnetIds": argToList(args.get("associated_subnet_ids")),
        "NetworkInterfaceId": network_interface_id,
        "Groups": argToList(args.get("groups")),
    }
    if ena_srd_udp_enabled := arg_to_bool_or_none(args.get("ena_srd_udp_enabled")):
        kwargs["EnaSrdUdpSpecification"] = {"EnaSrdUdpEnabled": ena_srd_udp_enabled}
    if tcp_established_timeout := arg_to_number(args.get("tcp_established_timeout")):
        kwargs["ConnectionTrackingSpecification"]["TcpEstablishedTimeout"] = tcp_established_timeout
    if udp_stream_timeout := arg_to_number(args.get("udp_stream_timeout")):
        kwargs["ConnectionTrackingSpecification"]["UdpStreamTimeout"] = udp_stream_timeout
    if udp_timeout := arg_to_number(args.get("udp_timeout")):
        kwargs["ConnectionTrackingSpecification"]["UdpTimeout"] = udp_timeout
    if description := args.get("description"):
        kwargs["Description"] = {"Value": description}
    if source_dest_check := arg_to_bool_or_none(args.get("source_dest_check")):
        kwargs["SourceDestCheck"] = {"Value": source_dest_check}
    if default_ena_queue_count := arg_to_bool_or_none(args.get("default_ena_queue_count")):
        kwargs["Attachment"]["DefaultEnaQueueCount"] = default_ena_queue_count
    if ena_queue_count := arg_to_number(args.get("ena_queue_count")):
        kwargs["Attachment"]["EnaQueueCount"] = ena_queue_count
    if attachment_id := args.get("attachment_id"):
        kwargs["Attachment"]["AttachmentId"] = attachment_id
    if delete_on_termination := arg_to_bool_or_none(args.get("delete_on_termination")):
        kwargs["Attachment"]["DeleteOnTermination"] = delete_on_termination

    if (attachment_id and not delete_on_termination) or (not attachment_id and delete_on_termination):
        raise DemistoException(
            "If one of the arguments 'attachment_id' or 'delete_on_termination' is given, the other one must be given as well.")
    return kwargs


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
    SSM = "ssm"


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

    @staticmethod
    def bucket_create_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Creates a new S3 bucket.

        Args:
            client (BotoClient): The initialized Boto3 S3 client.
            args (dict): A dictionary containing the arguments entered to the command.

        Returns:
            CommandResults: A success message and information on the newly created bucket.
        """
        bucket_name = args.get("bucket_name")
        location = args.get("location_constraint") or args.get('region', "")
        kwargs = {
            "Bucket": bucket_name,
            "GrantFullControl": args.get("grant_full_control"),
            "GrantRead": args.get("grant_read"),
            "GrantReadACP": args.get("grant_read_acp"),
            "GrantWrite": args.get("grant_write"),
            "GrantWriteACP": args.get("grant_write_acp"),
        }
        # The "us-east-1" is the default value for LocationConstraint, when added to the request the S3 API views that
        # specific string as an invalid/unsupported value for the constraint.
        if location != "us-east-1":
            kwargs["CreateBucketConfiguration"] = {"LocationConstraint": location}
        remove_nulls_from_dictionary(kwargs)
        demisto.debug(f"{kwargs=}")

        response = client.create_bucket(**kwargs)
        demisto.debug(f"{response=}")

        if response["ResponseMetadata"]["HTTPStatusCode"] not in [HTTPStatus.OK, HTTPStatus.NO_CONTENT]:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        return CommandResults(readable_output=f"The bucket {bucket_name}, was created successfully")

    @staticmethod
    def buckets_list_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Returns a list of all buckets owned by the authenticated sender of the request.

        Args:
            client (BotoClient): The initialized Boto3 S3 client.
            args (dict): A dictionary containing the following arguments: account_id, region, limit, next_page_token, prefix.

        Returns:
            CommandResults: Containing the list of buckets.
        """
        account_id = args.get("account_id")
        region = args.get("region")
        filter_by_region = args.get("filter_by_region")
        prefix = args.get("prefix")
        kwargs = {
            "Prefix": prefix,
            "BucketRegion": filter_by_region
        }
        kwargs.update(build_pagination_kwargs(args, 1, 10000, "ContinuationToken", "MaxBuckets"))
        remove_nulls_from_dictionary(kwargs)
        demisto.debug(f"{kwargs=}")
        response = client.list_buckets(**kwargs)

        if response["ResponseMetadata"]["HTTPStatusCode"] not in [HTTPStatus.OK, HTTPStatus.NO_CONTENT]:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        next_token = response.get("ContinuationToken")
        metadata = (
            "Run the following command to retrieve the next batch of buckets:\n"
            f"!aws-s3-buckets-list {account_id=} {region=} page_token={next_token}"
            if next_token
            else None
        )
        if limit := kwargs.get("MaxBuckets") != 50:
            metadata = f"{metadata} {limit=}"
        if prefix:
            metadata = f"{metadata} {prefix=}"
        if filter_by_region:
            metadata = f"{metadata} {filter_by_region=}"

        buckets = response.get("Buckets")
        for bucket in buckets:
            bucket["CreationDate"] = datetime.strftime(bucket["CreationDate"], "%Y-%m-%dT%H:%M:%S")
        readable_output = tableToMarkdown(
            "The list of buckets", buckets, removeNull=True, headerTransform=pascalToSpace, metadata=metadata
        )
        outputs = {
            "AWS.S3.Buckets(val.BucketArn && val.BucketArn == obj.BucketArn)": buckets,
            "AWS.S3(true)": {
                "BucketsOwner": response.get("Owner"),
                "BucketsNextPageToken": response.get("ContinuationToken"),
                "BucketsPrefix": response.get("Prefix"),
            },
        }

        return CommandResults(readable_output=readable_output, outputs=outputs, raw_response=response)


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
    def network_interface_attribute_modify_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Modifies the specified network interface attribute.
        Args:
            client (BotoClient): The initialized Boto3 EC2 client.
            args (dict): A dictionary of the command arguments.

        Returns:
            CommandResults: A success message in case the modification was successful.
        """
        network_interface_id = args.get("network_interface_id")
        kwargs = build_kwargs_network_interface_attribute(args, network_interface_id)
        remove_nulls_from_dictionary(kwargs)
        demisto.debug(f"{kwargs=}")
        response = client.modify_network_interface_attribute(**kwargs)

        if response["ResponseMetadata"]["HTTPStatusCode"] not in [HTTPStatus.OK, HTTPStatus.NO_CONTENT]:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        return CommandResults(readable_output=f"The Network Interface attribute {network_interface_id} was modified successfully.")

    @staticmethod
    def regions_describe_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
        """
        Describes the Regions that are enabled for your account, or all Regions.

        Args:
            client (BotoClient): The initialized Boto3 EC2 client.
            args (dict): A dictionary containing arguments for creating the tags.
                  account_id (str): The account id
                  region_names (str): The names of the regions to retrieve
                  all_regions (bool): Indicates whether to display all Regions.
                  filters (str): A filter name and value pair that is used to return a more specific list of results.
                    name=<name>,values=<values>;name=<name>,values=<values>

        Returns:
            CommandResults: A list of Regions.
        """
        region_names = argToList(args.get("region_names", ""))
        all_regions = arg_to_bool_or_none(args.get("all_regions"))
        kwargs = {"RegionNames": region_names, "AllRegions": all_regions, "Filters": parse_filter_field(args.get("filters"))}
        if (region_names and all_regions is not None) or (not region_names and all_regions is None):
            raise DemistoException("Exactly one of the arguments 'region_name' and 'all_regions' should be provided.")

        remove_nulls_from_dictionary(kwargs)
        demisto.debug(f"{kwargs=}")
        response = client.describe_regions(**kwargs)
        if response["ResponseMetadata"]["HTTPStatusCode"] not in [HTTPStatus.OK, HTTPStatus.NO_CONTENT]:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        regions = response.get("Regions")
        readable_output = tableToMarkdown(
            f"The regions {region_names} information:",
            regions,
            removeNull=True,
            headerTransform=pascalToSpace,
        )

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix="AWS.EC2.Regions",
            outputs=regions,
            raw_response=response,
            outputs_key_field="RegionName",
        )
    
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


class SSM:
    service = AWSServices.SSM

    @staticmethod
    def inventory_entries_list(client: BotoClient, args: Dict[str, Any]) -> CommandResults | None:
        """
        Returns an inventory item, and it's list of entries.
        Args:
            client: The AWS ACM boto3 client used to perform the update request.
            args (dict): A dictionary containing the command arguments.

        Returns:
            CommandResults: An object containing an inventory item, and it's list of entries.
        """
        instance_id = args.get("instance_id")
        kwargs = {
            "InstanceId": instance_id,
            "TypeName": args.get("type_name"),
            "Filters": parse_triple_filter(args.get("filters")),
        }
        kwargs.update(build_pagination_kwargs(args, 1, 50))
        remove_nulls_from_dictionary(kwargs)
        demisto.debug(f"{kwargs=}")
        response = client.list_inventory_entries(**kwargs)

        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))

        if response.get('Entries'):
            data = {
                "TypeName": response.get("TypeName"),
                "InstanceId": response.get("InstanceId"),
                "Entries": response.get("Entries"),
            }
            headers = ["InstanceId", "TypeName", "Entries"]
            readable_output = tableToMarkdown(
                f"The inventory item {instance_id} and it's entries", data, headers, headerTransform=pascalToSpace, removeNull=True
            )
            if response.get("NextToken"):
                response["EntriesNextPageToken"] = response.pop("NextToken")
            return CommandResults(
                outputs_prefix="AWS.SSM.Inventory",
                outputs_key_field="InstanceId",
                outputs=response,
                readable_output=readable_output,
                raw_response=response,
            )
        else:
            return CommandResults(readable_output=f"No entries found for the item {instance_id}.")

    @polling_function(
        name="aws-ssm-command-run",
        interval=arg_to_number(
            demisto.args().get("interval_in_seconds", DEFAULT_INTERVAL_IN_SECONDS),
        ),
        timeout=arg_to_number(demisto.args().get("polling_timeout", DEFAULT_TIMEOUT)),
        requires_polling_arg=False,  # means it will always be default to poll, poll=true,
    )
    def command_run_command(client: BotoClient, args: Dict[str, Any]) -> PollResult | None:
        """
        Runs commands on one or more managed nodes.
        Args:
            client: The AWS ACM boto3 client used to perform the update request.
            args (dict): A dictionary containing the command arguments.

        Returns:
            CommandResults: An object containing an inventory item, and it's list of entries.
        """
        if command_id := args.get("command_id"):
            response_command_list = client.list_commands(CommandId=command_id)
            status = response_command_list.get("Commands", {}.get("Status"))
            if status in TERMINAL_COMMAND_STATUSES:
                return PollResult(
                    response=CommandResults(
                        readable_output=f"The command status is {status}, {TERMINAL_COMMAND_STATUSES[status]}",
                    ),
                    continue_to_poll=False,
                )
            #  if command not in TERMINAL_COMMAND_STATUSES, continue polling
            return PollResult(
                continue_to_poll=True,
                args_for_next_run=args,
                response=None,
            )
        kwargs = {
            "InstanceIds": argToList(args.get("instance_ids")),
            "DocumentName": args.get("document_name"),
            "DocumentVersion": args.get("document_version"),
            "DocumentHash": args.get("document_hash"),
            "Comment": args.get("comment"),
            "OutputS3BucketName": args.get("output_s3_bucket_name"),
            "OutputS3KeyPrefix": args.get("output_s3_key_prefix"),
            "MaxConcurrency": args.get("max_concurrency"),
            "MaxErrors": args.get("max_errors"),
        }
        if targets := args.get("Targets"):
            kwargs["Targets"] = parse_target_field(targets)
        if args.get("document_hash"):
            kwargs["DocumentHashType"] = "Sha256"
        if parameters := args.get("parameters"):
            kwargs["Parameters"] = parse_parameters_arg(parameters)
        if command_timeout := arg_to_number(args.get("command_timeout")):
            if MAXIMUM_COMMAND_TIMEOUT < command_timeout < MINIMUM_COMMAND_TIMEOUT:
                raise DemistoException(
                    f"Command timeout must be between {MINIMUM_COMMAND_TIMEOUT} and {MAXIMUM_COMMAND_TIMEOUT} seconds."
                )
            kwargs["TimeoutSeconds"] = command_timeout
        remove_nulls_from_dictionary(kwargs)
        response_command_run = client.send_command(**kwargs)
        command_id = response_command_run.get('Command', {}).get('CommandId', '')
        args["command_id"] = command_id
        command_response = serialize_response_with_datetime_encoding(response_command_run.get('Command', {}))
        return PollResult(
            response=None,
            continue_to_poll=True,
            args_for_next_run=args,
            partial_result=CommandResults(
                readable_output=f"Command {command_id} was sent successfully.",
                outputs=command_response,
                outputs_prefix="AWS.SSM.Command",
                outputs_key_field="CommandId",
            ),
        )

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
    "aws-s3-bucket-create": S3.bucket_create_command,
    "aws-s3-buckets-list": S3.buckets_list_command,
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
    "aws-ec2-regions-describe": EC2.regions_describe_command,
    "aws-ec2-network-interface-attribute-modify": EC2.network_interface_attribute_modify_command,
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
    "aws-kms-key-rotation-enable": KMS.enable_key_rotation_command,
    "aws-elb-load-balancer-attributes-modify": ELB.modify_load_balancer_attributes_command,
    "aws-ssm-inventory-entries-list": SSM.inventory_entries_list,
    "aws-ssm-command-run": SSM.command_run_command
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
    "s3:CreateBucket",
    "s3:ListAllMyBuckets",
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
    "ec2:DescribeRegions",
    "eks:DescribeCluster",
    "eks:AssociateAccessPolicy",
    "ec2:CreateSecurityGroup",
    "ec2:CreateNetworkAcl",
    "ec2:GetIpamDiscoveredPublicAddresses",
    "ec2:CreateTags",
    "ec2:DeleteSecurityGroup",
    "ec2:DescribeInstances",
    "ec2:DescribeSecurityGroups",
    "ec2:AuthorizeSecurityGroupEgress",
    "ec2:AuthorizeSecurityGroupIngress",
    "ec2:ModifyInstanceMetadataOptions",
    "ec2:DescribeInstances",
    "ec2:StartInstances",
    "ec2:StopInstances",
    "ec2:TerminateInstances",
    "ec2:RunInstances",
    "ec2:ModifyNetworkInterfaceAttribute",
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
    "acm:UpdateCertificateOptions",
    "cloudtrail:DescribeTrails",
    "lambda:GetFunctionConfiguration",
    "lambda:GetFunctionUrlConfig",
    "lambda:GetPolicy",
    "lambda:InvokeFunction",
    "lambda:UpdateFunctionUrlConfig",
    "elasticloadbalancing:ModifyLoadBalancerAttributes",
    "ce:GetCostAndUsage",
    "ce:GetCostForecast",
    "budgets:DescribeBudgets",
    "budgets:DescribeNotificationsForBudget",
    "ssm:SendCommand",
    "ssm:ListCommands",
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
            result = execute_aws_command(command, args, params)
            demisto.debug("before return_results")
            return_results(result)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except ClientError as client_err:
        account_id = args.get("account_id", "")
        AWSErrorHandler.handle_client_error(client_err, account_id)

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
