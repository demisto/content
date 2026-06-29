import demistomock as demisto  # noqa: F401
import urllib3.util
from CommonServerPython import *  # noqa: F401
from AWSApiModule import *  # noqa: E402
from botocore.client import BaseClient as BotoClient

# Disable insecure warnings
urllib3.disable_warnings()

DEFAULT_RETRIES = 5


def parse_tags(tags_str: str) -> dict:
    """Parse a string of key/value pairs into the flat tag mapping the Security Hub V2 API expects.

    The expected input format is ``key=<key>,value=<value>`` with multiple pairs separated by ``;``.

    Args:
        tags_str (str): The keys and values string.

    Returns:
        dict: A flat mapping of ``{<key>: <value>}`` suitable for the ``Tags`` API parameter.
    """
    regex = re.compile(r"key=([\w\d_:.-]+),value=([ /\w\d@_,.*-]+)", flags=re.I)
    return {key: value for key, value in regex.findall(tags_str)}


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
    verify_certificate = not argToBoolean(params.get("insecure", False))
    timeout = params.get("timeout")
    retries = arg_to_number(params.get("retries")) or DEFAULT_RETRIES
    sts_endpoint_url = params.get("sts_endpoint_url") or None
    endpoint_url = params.get("endpoint_url") or None

    validate_params(aws_region, aws_role_arn, aws_role_session_name, aws_access_key_id, aws_secret_access_key)

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
    tags = parse_tags(args.get("tags", ""))
    kwargs = remove_empty_elements({"Tags": tags})

    demisto.debug(f"[AWS_Security_Hub_V2] Enabling Security Hub V2 with tag keys: {list(tags.keys())}")
    response = client.enable_security_hub_v2(**kwargs)

    hub_arn = response.get("HubV2Arn")
    outputs = {"HubV2Arn": hub_arn}
    return CommandResults(
        outputs_prefix="AWS.SecurityHub.Hub",
        outputs_key_field="HubV2Arn",
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


def parse_filter_entries(filters_str: str) -> list[dict]:
    """Parse a filter argument into a list of key/value entry dictionaries.

    Each entry is a comma-separated list of ``key=value`` pairs, and entries are separated by ``;``.
    For example ``fieldname=severity,value=High,comparison=EQUALS;fieldname=status,value=New``
    yields two entries, each a dict of its key/value pairs.

    Args:
        filters_str (str): The raw filter argument string.

    Returns:
        list[dict]: A list of dictionaries, one per entry.
    """
    entries = []
    for raw_entry in filters_str.split(";"):
        raw_entry = raw_entry.strip()
        if not raw_entry:
            continue
        entry = {}
        for pair in raw_entry.split(","):
            if "=" not in pair:
                continue
            key, _, value = pair.partition("=")
            entry[key.strip().lower()] = value.strip()
        if entry:
            entries.append(entry)
    return entries


def parse_string_filters(filters_str: str) -> list[dict]:
    """Parse ``string_filters`` arg entries (``fieldname``, ``value``, ``comparison``)."""
    return [
        {"FieldName": e["fieldname"], "Filter": {"Value": e["value"], "Comparison": e.get("comparison", "EQUALS")}}
        for e in parse_filter_entries(filters_str)
        if e.get("fieldname") and e.get("value")
    ]


def parse_date_filters(filters_str: str) -> list[dict]:
    """Parse ``date_filters`` arg entries (``fieldname``, ``start``, ``end``).

    Empty ``Start``/``End`` values are not stripped here; ``remove_empty_elements`` is applied
    once at the top level in the command and recursively cleans these nested values.
    """
    return [
        {"FieldName": e["fieldname"], "Filter": {"Start": e.get("start"), "End": e.get("end")}}
        for e in parse_filter_entries(filters_str)
        if e.get("fieldname") and (e.get("start") or e.get("end"))
    ]


def parse_boolean_filters(filters_str: str) -> list[dict]:
    """Parse ``boolean_filters`` arg entries (``fieldname``, ``value``)."""
    return [
        {"FieldName": e["fieldname"], "Filter": {"Value": argToBoolean(e["value"])}}
        for e in parse_filter_entries(filters_str)
        if e.get("fieldname") and e.get("value")
    ]


def parse_number_filters(filters_str: str) -> list[dict]:
    """Parse ``number_filters`` arg entries (``fieldname``, ``operator`` of eq/gt/gte/lt/lte, ``value``)."""
    operator_map = {"eq": "Eq", "gt": "Gt", "gte": "Gte", "lt": "Lt", "lte": "Lte"}
    filters = []
    for e in parse_filter_entries(filters_str):
        operator = operator_map.get(e.get("operator", "eq").lower())
        if not (e.get("fieldname") and e.get("value") and operator):
            continue
        filters.append({"FieldName": e["fieldname"], "Filter": {operator: arg_to_number(e["value"])}})
    return filters


def parse_map_filters(filters_str: str) -> list[dict]:
    """Parse ``map_filters`` arg entries (``fieldname``, ``key``, ``value``, ``comparison``)."""
    return [
        {
            "FieldName": e["fieldname"],
            "Filter": {"Key": e["key"], "Value": e["value"], "Comparison": e.get("comparison", "EQUALS")},
        }
        for e in parse_filter_entries(filters_str)
        if e.get("fieldname") and e.get("key") and e.get("value")
    ]


def parse_ip_filters(filters_str: str) -> list[dict]:
    """Parse ``ip_filters`` arg entries (``fieldname``, ``cidr``)."""
    return [
        {"FieldName": e["fieldname"], "Filter": {"Cidr": e["cidr"]}}
        for e in parse_filter_entries(filters_str)
        if e.get("fieldname") and e.get("cidr")
    ]


def generate_filters_for_get_findings(args: dict) -> dict | None:
    """Build the Security Hub V2 composite ``Filters`` object from the per-category filter arguments.

    Each filter category (string, date, boolean, number, map, ip) is parsed from its dedicated
    command argument and placed in a single composite filter, combined using ``composite_operator``.

    Args:
        args (dict): Demisto command arguments.

    Returns:
        dict | None: The composite ``Filters`` structure, or ``None`` when no filters were supplied.
    """
    composite_filter: dict = {
        "StringFilters": parse_string_filters(args.get("string_filters", "")),
        "DateFilters": parse_date_filters(args.get("date_filters", "")),
        "BooleanFilters": parse_boolean_filters(args.get("boolean_filters", "")),
        "NumberFilters": parse_number_filters(args.get("number_filters", "")),
        "MapFilters": parse_map_filters(args.get("map_filters", "")),
        "IpFilters": parse_ip_filters(args.get("ip_filters", "")),
    }
    # Drop empty filter categories; if no actual conditions remain, there is no filter to apply.
    composite_filter = {key: value for key, value in composite_filter.items() if value}
    if not composite_filter:
        return None

    composite_filter["Operator"] = args.get("filter_operator", "AND")
    return {"CompositeFilters": [composite_filter], "CompositeOperator": args.get("composite_operator", "AND")}


def findings_get_command(client: BotoClient, args: dict) -> CommandResults:
    """Retrieve a list of OCSF-formatted findings from AWS Security Hub V2.

    Args:
        client (BotoClient): The boto3 ``securityhub`` client.
        args (dict): Command arguments. Optional per-category filter arguments (``string_filters``,
            ``date_filters``, ``boolean_filters``, ``number_filters``, ``map_filters``, ``ip_filters``,
            ``filter_operator``, ``composite_operator``), plus ``sort_field``, ``sort_order``
            (``asc``/``desc``), ``limit`` (default 50) and ``next_token``.

    Returns:
        CommandResults: The retrieved findings and the pagination token, if any.
    """
    sort_field = args.get("sort_field")
    sort_criteria = [{"Field": sort_field, "SortOrder": args.get("sort_order")}] if sort_field else None

    kwargs = remove_empty_elements(
        {
            "Filters": generate_filters_for_get_findings(args),
            "SortCriteria": sort_criteria,
            "MaxResults": arg_to_number(args.get("limit")) or 50,
            "NextToken": args.get("next_token"),
        }
    )

    demisto.debug("[AWS_Security_Hub_V2] Getting findings")
    response = client.get_findings_v2(**kwargs)

    findings = response.get("Findings", [])
    if not findings:
        return CommandResults(readable_output="No findings found.")

    next_token = response.get("NextToken")
    outputs = {
        "AWS.SecurityHub.Findings(val.metadata.uid && val.metadata.uid == obj.metadata.uid)": findings,
        "AWS.SecurityHub(true)": {"FindingsNextToken": next_token},
    }
    return CommandResults(
        outputs=remove_empty_elements(outputs),
        readable_output=tableToMarkdown(
            "AWS Security Hub V2 Findings",
            findings,
            headers=["finding_info", "severity", "status", "class_name", "compliance", "cloud", "resources"],
            removeNull=True,
        ),
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
        elif command == "aws-securityhub-findings-get":
            return_results(findings_get_command(client, args))

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
