import demistomock as demisto  # noqa: F401
import urllib3.util
from CommonServerPython import *  # noqa: F401
from AWSApiModule import *  # noqa: E402
from botocore.client import BaseClient as BotoClient

# Disable insecure warnings
urllib3.disable_warnings()

DEFAULT_RETRIES = 5


def validate_aws_params(
    aws_region: str | None,
    aws_role_arn: str | None,
    aws_role_session_name: str | None,
    aws_access_key_id: str | None,
    aws_secret_access_key: str | None,
) -> None:
    """Validate that the provided parameters are compatible with the chosen authentication method.

    Args:
        aws_region (str | None): The AWS region to operate in.
        aws_role_arn (str | None): The ARN of the IAM role to assume.
        aws_role_session_name (str | None): The session name used when assuming the role.
        aws_access_key_id (str | None): The AWS access key id (when using credentials auth).
        aws_secret_access_key (str | None): The AWS secret access key (when using credentials auth).

    Raises:
        DemistoException: If the region is missing or the credentials/role parameters are inconsistent.
    """
    if not aws_region:
        raise DemistoException("You must specify the AWS region.")

    if bool(aws_access_key_id) != bool(aws_secret_access_key):
        raise DemistoException("You must provide both Access Key id and Secret Key to configure the instance with credentials.")

    if bool(aws_role_arn) != bool(aws_role_session_name):
        raise DemistoException("Role session name is required when using a role ARN.")


def parse_tag_field(tags_str: str) -> list:
    """Parse a string of key/value pairs into a list of tag dictionaries.

    The expected format is ``key=<key>,value=<value>`` with multiple pairs separated by ``;``.

    Args:
        tags_str (str): The keys and values string.

    Returns:
        list: A list of dicts with the form ``{"Key": <key>, "Value": <value>}``.
    """
    tags = []
    regex = re.compile(r"key=([\w\d_:.-]+),value=([ /\w\d@_,.*-]+)", flags=re.I)
    regex_parse_result = regex.findall(tags_str)
    for key, value in regex_parse_result:
        tags.append({"Key": key, "Value": value})
    return tags


def build_client(params: dict) -> BotoClient:
    """Build and return a boto3 Security Hub client based on the integration parameters.

    The client is created through the shared ``AWSClient`` (AWSApiModule), which centrally
    handles STS role assumption, credentials, certificate (SSL) verification, request
    timeouts, retries and proxy resolution. Proxy support is wired automatically: the
    ``AWSClient`` constructor calls ``handle_proxy(proxy_param_name="proxy", ...)``
    internally, so the integration's ``proxy`` parameter is honored without any extra
    handling here.

    Args:
        params (dict): The integration parameters (``demisto.params()``).

    Returns:
        BotoClient: An initialized boto3 ``securityhub`` client.
    """
    aws_region = params.get("region")
    aws_role_arn = params.get("role_arn")
    aws_role_session_name = params.get("role_session_name")
    aws_role_session_duration = params.get("session_duration")
    aws_role_policy = None
    aws_access_key_id = params.get("credentials", {}).get("identifier")
    aws_secret_access_key = params.get("credentials", {}).get("password")
    # SSL verification is enabled by default; disabled only when the user checks
    # the "Trust any certificate (not secure)" box.
    verify_certificate = not argToBoolean(params.get("insecure", False))
    timeout = params.get("timeout")
    retries = arg_to_number(params.get("retries")) or DEFAULT_RETRIES
    sts_endpoint_url = params.get("sts_endpoint_url") or None
    endpoint_url = params.get("endpoint_url") or None

    validate_aws_params(aws_region, aws_role_arn, aws_role_session_name, aws_access_key_id, aws_secret_access_key)

    aws_client = AWSClient(
        aws_region,
        aws_role_arn,
        aws_role_session_name,
        aws_role_session_duration,
        aws_role_policy,
        aws_access_key_id,
        aws_secret_access_key,
        verify_certificate,
        timeout,
        retries,
        sts_endpoint_url=sts_endpoint_url,
        endpoint_url=endpoint_url,
    )

    return aws_client.aws_session(
        service="securityhub",
        region=aws_region,
        role_arn=aws_role_arn,
        role_session_name=aws_role_session_name,
        role_session_duration=aws_role_session_duration,
    )


def test_module(client: BotoClient) -> str:
    """Test connectivity and authentication against the AWS Security Hub V2 API.
    Args:
        client (BotoClient): An initialized boto3 ``securityhub`` client.
    Returns:
        str: ``"ok"`` if the call succeeds.
    Raises:
        DemistoException: With a user-friendly message when Security Hub V2 is not enabled
            or the credentials/role do not have sufficient permissions.
    """
    demisto.debug("[AWS_Security_Hub_V2] Test Connectivity and Authentication")
    try:
        client.describe_security_hub_v2()
    except client.exceptions.ResourceNotFoundException:
        raise DemistoException(
            "Security Hub V2 is not enabled in the configured account/region. "
            "Enable Security Hub V2 or verify the configured region."
        )
    except client.exceptions.AccessDeniedException:
        raise DemistoException(
            "Access denied. Verify the configured role/credentials have the "
            "'securityhub:DescribeSecurityHubV2' permission."
        )
    return "ok"


def enable_security_hub_command(client: BotoClient, args: dict) -> CommandResults:
    """Enable AWS Security Hub V2 for the configured account and region.

    Args:
        client (BotoClient): The boto3 ``securityhub`` client.
        args (dict): Command arguments. Optional ``tags`` - a string of key/value pairs in the
            format ``key=key1,value=value1;key=key2,value=value2`` to assign to the resource.

    Returns:
        CommandResults: The ARN of the enabled Security Hub V2 resource.
    """
    # Security Hub V2 expects Tags as a flat {key: value} mapping, unlike V1's list of {Key, Value}.
    parsed_tags = parse_tag_field(args.get("tags", ""))
    tags = {tag["Key"]: tag["Value"] for tag in parsed_tags}
    kwargs = remove_empty_elements({"Tags": tags})

    demisto.debug(f"[AWS_Security_Hub_V2] Enabling Security Hub V2 with tag keys: {list(tags.keys())}")
    response = client.enable_security_hub_v2(**kwargs)

    security_hub_arn = response.get("SecurityHubV2Arn")
    outputs = {"SecurityHubV2Arn": security_hub_arn}
    return CommandResults(
        outputs_prefix="AWS.SecurityHub.Hub",
        outputs_key_field="SecurityHubV2Arn",
        outputs=outputs,
        readable_output=tableToMarkdown("AWS Security Hub V2 Enabled", outputs, removeNull=True),
        raw_response=response,
    )


def disable_security_hub_command(client: BotoClient, args: dict) -> CommandResults:
    """Disable AWS Security Hub V2 for the configured account and region.

    Args:
        client (BotoClient): The boto3 ``securityhub`` client.
        args (dict): Command arguments. No arguments are required.

    Returns:
        CommandResults: A confirmation message that Security Hub V2 was disabled.
    """
    demisto.debug("[AWS_Security_Hub_V2] Disabling Security Hub V2")
    response = client.disable_security_hub_v2()

    return CommandResults(
        readable_output="AWS Security Hub V2 was successfully disabled.",
        raw_response=response,
    )


def main():  # pragma: no cover
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f"Command being called is {command}")

    try:
        client = build_client(params)

        if command == "test-module":
            return_results(test_module(client))
        elif command == "aws-securityhub-security-hub-enable":
            return_results(enable_security_hub_command(client, args))
        elif command == "aws-securityhub-security-hub-disable":
            return_results(disable_security_hub_command(client, args))

        # elif command == "aws-securityhub-get-findings":
        #     return_results(get_findings_command(client, args))
        # elif command == "aws-securityhub-get-finding-statistics":
        #     return_results(get_finding_statistics_command(client, args))
        # elif command == "fetch-incidents":
        #     fetch_incidents(client, params)
        #     return
        # elif command == "get-remote-data":
        #     return_results(get_remote_data_command(client, args))
        #     return
        # elif command == "update-remote-system":
        #     return_results(update_remote_system_command(client, args))
        #     return
        # elif command == "get-mapping-fields":
        #     return_results(get_mapping_fields_command())
        #     return
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as e:
        return_error(f"Error has occurred in the AWS Security Hub V2 Integration: {type(e)} {e}", error=e)


if __name__ in ["__builtin__", "builtins", "__main__"]:  # pragma: no cover
    main()
