import demistomock as demisto  # noqa: F401
import urllib3.util
from datetime import UTC
from CommonServerPython import *  # noqa: F401
from AWSApiModule import *  # noqa: E402
from botocore.client import BaseClient as BotoClient

# Disable insecure warnings
urllib3.disable_warnings()

DEFAULT_RETRIES = 5
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
DEFAULT_FIRST_FETCH = "3 days"
DEFAULT_MAX_FETCH = 50
MAX_FETCH_LIMIT = 200

# OCSF severity_id (https://schema.ocsf.io) -> XSOAR incident severity.
# OCSF: 0=Unknown, 1=Informational, 2=Low, 3=Medium, 4=High, 5=Critical, 6=Fatal.
# XSOAR: 0=Unknown, 0.5=Informational, 1=Low, 2=Medium, 3=High, 4=Critical.
# XSOAR has no severity above Critical, so OCSF "Fatal" (6) collapses to XSOAR Critical.
OCSF_SEVERITY_ID_TO_XSOAR = {
    1: IncidentSeverity.INFO,
    2: IncidentSeverity.LOW,
    3: IncidentSeverity.MEDIUM,
    4: IncidentSeverity.HIGH,
    5: IncidentSeverity.CRITICAL,
    6: IncidentSeverity.CRITICAL,  # Fatal -> Critical (XSOAR has no higher severity)
}
# Minimum severity label -> OCSF severity_id, used to build the fetch severity filter.
SEVERITY_LABEL_TO_OCSF_ID = {
    "Informational": 1,
    "Low": 2,
    "Medium": 3,
    "High": 4,
    "Critical": 5,
    "Fatal": 6,
}
MIRROR_DIRECTION_MAPPING = {
    "None": None,
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}


# Configuration driving the generic ``parse_filters`` helper. For each filter category, ``fields``
# maps a user-facing entry key to a (API ``Filter`` key, value-coercion callable) tuple, ``required``
# lists the entry keys that must be present for an entry to be valid, and ``defaults`` provides
# fallback values applied when the user omits an optional key.
#   * string  -> Filter {Value, Comparison}
#   * number  -> Filter {Eq|Gt|Gte|Lt|Lte} (the operator is the entry key, value is numeric)
#   * boolean -> Filter {Value}
#   * map     -> Filter {Key, Value, Comparison}
#   * ip      -> Filter {Cidr}
FILTER_CONFIGS: dict[str, dict] = {
    "string": {
        "fields": {"value": ("Value", str), "comparison": ("Comparison", str)},
        "required": ["value"],
        "defaults": {"comparison": "EQUALS"},
    },
    "number": {
        "fields": {
            "eq": ("Eq", arg_to_number),
            "gt": ("Gt", arg_to_number),
            "gte": ("Gte", arg_to_number),
            "lt": ("Lt", arg_to_number),
            "lte": ("Lte", arg_to_number),
        },
        "required": [],
        "defaults": {},
        "require_any": ["eq", "gt", "gte", "lt", "lte"],
    },
    "boolean": {
        "fields": {"value": ("Value", argToBoolean)},
        "required": ["value"],
        "defaults": {},
    },
    "map": {
        "fields": {"key": ("Key", str), "value": ("Value", str), "comparison": ("Comparison", str)},
        "required": ["key", "value"],
        "defaults": {"comparison": "EQUALS"},
    },
    "ip": {
        "fields": {"cidr": ("Cidr", str)},
        "required": ["cidr"],
        "defaults": {},
    },
}


""" HELPER FUNCTIONS """


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


def parse_filters(filters_str: str, category: str) -> list[dict]:
    """Generically parse a filter argument into the API ``{FieldName, Filter}`` structure.

    The per-category mapping in ``FILTER_CONFIGS`` controls which user-facing entry keys are
    accepted, how they map to the API ``Filter`` keys, and how each value is coerced (str/number/
    bool). This single helper backs the ``string``, ``number``, ``boolean``, ``map`` and ``ip``
    filter categories (``date`` is handled separately by ``parse_date_filters`` due to its
    ``oneOf`` structure).

    Each entry requires ``fieldname`` plus the category-specific required keys. Entries missing
    ``fieldname`` or any required key are skipped.

    Args:
        filters_str (str): The raw filter argument string.
        category (str): The filter category key into ``FILTER_CONFIGS``.

    Returns:
        list[dict]: A list of ``{FieldName, Filter}`` dictionaries.
    """
    config = FILTER_CONFIGS[category]
    fields, required = config["fields"], config["required"]
    require_any = config.get("require_any")
    filters = []

    for entry in parse_filter_entries(filters_str):
        field_name = entry.get("fieldname")
        if not field_name:
            continue
        if any(not entry.get(key) for key in required):
            continue
        if require_any and not any(entry.get(key) for key in require_any):
            continue

        merged = {**config["defaults"], **{key: value for key, value in entry.items() if key in fields}}
        api_filter = {fields[key][0]: fields[key][1](value) for key, value in merged.items()}
        filters.append({"FieldName": field_name, "Filter": api_filter})

    return filters


def parse_date_filters(filters_str: str) -> list[dict]:
    """Parse ``date_filters`` arg entries into the API ``DateFilters`` structure.

    The API's date ``Filter`` is a ``oneOf`` of two mutually exclusive forms:
        * Absolute range: ``Start`` and ``End`` (both required together).
        * Relative ``DateRange``: ``{Value, Unit, Comparison}`` describing a window relative to now.

    Each entry supports the following keys:
        * ``fieldname`` (required).
        * Absolute form: ``start`` + ``end`` (both required together).
        * Relative form: ``value`` (required) with optional ``unit`` (default ``DAYS``) and
          optional ``comparison``. ``days`` is accepted as a convenience alias for
          ``value`` with ``unit=DAYS``.

    Args:
        filters_str (str): The raw date filters argument string.

    Returns:
        list[dict]: A list of ``{FieldName, Filter}`` dictionaries.

    Raises:
        DemistoException: If an entry mixes the absolute and relative forms, provides only one of
            ``start``/``end``, or provides neither form.
    """
    filters = []
    for e in parse_filter_entries(filters_str):
        field_name = e.get("fieldname")
        if not field_name:
            continue
        start, end = e.get("start"), e.get("end")
        # "days" is a convenience alias for the DateRange "value" with Unit=DAYS.
        value = e.get("value") or e.get("days")
        has_range = bool(value)
        has_absolute = bool(start or end)

        if has_range and has_absolute:
            raise DemistoException(
                f"Date filter for '{field_name}': use either the absolute form ('start'+'end') "
                f"or the relative 'DateRange' form ('value'/'days'), not both."
            )
        if has_range:
            date_range = {
                "Value": arg_to_number(value),
                "Unit": e.get("unit", "DAYS"),
                "Comparison": e.get("comparison"),
            }
            date_filter = {"DateRange": remove_empty_elements(date_range)}
        elif start and end:
            date_filter = {"Start": start, "End": end}
        else:
            raise DemistoException(
                f"Date filter for '{field_name}' requires either the relative 'DateRange' form "
                f"('value' with optional 'unit'/'comparison', or 'days'), or both 'start' and 'end'."
            )
        filters.append({"FieldName": field_name, "Filter": date_filter})
    return filters


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
        "StringFilters": parse_filters(args.get("string_filters", ""), "string"),
        "DateFilters": parse_date_filters(args.get("date_filters", "")),
        "BooleanFilters": parse_filters(args.get("boolean_filters", ""), "boolean"),
        "NumberFilters": parse_filters(args.get("number_filters", ""), "number"),
        "MapFilters": parse_filters(args.get("map_filters", ""), "map"),
        "IpFilters": parse_filters(args.get("ip_filters", ""), "ip"),
    }
    # Drop empty filter categories; if no actual conditions remain, there is no filter to apply.
    composite_filter = {key: value for key, value in composite_filter.items() if value}
    if not composite_filter:
        return None

    composite_filter["Operator"] = args.get("filter_operator", "AND")
    return {"CompositeFilters": [composite_filter], "CompositeOperator": args.get("composite_operator", "AND")}


def parse_finding_identifiers(identifiers_str: str) -> list[dict]:
    """Parse the ``finding_identifiers`` argument into the API ``FindingIdentifiers`` structure.

    Each entry is a comma-separated list of ``key=value`` pairs, and entries are separated by ``;``.
    Required keys per entry: ``cloud_account_uid``, ``finding_info_uid``, ``metadata_product_uid``.

    Args:
        identifiers_str (str): The raw finding identifiers argument string.

    Returns:
        list[dict]: A list of ``{CloudAccountUid, FindingInfoUid, MetadataProductUid}`` dictionaries.
    """
    return [
        {
            "CloudAccountUid": e["cloud_account_uid"],
            "FindingInfoUid": e["finding_info_uid"],
            "MetadataProductUid": e["metadata_product_uid"],
        }
        for e in parse_filter_entries(identifiers_str)
        if e.get("cloud_account_uid") and e.get("finding_info_uid") and e.get("metadata_product_uid")
    ]


def build_fetch_filters(start_time: str, end_time: str, min_severity: str | None, additional_filters: str | None) -> dict:
    """Build the Security Hub V2 composite ``Filters`` object used by the fetch loop.

    The fetch always filters on the OCSF ``finding_info.created_time_dt`` field within the
    ``[start_time, end_time)`` window. Optionally, a minimum severity (mapped to an OCSF
    ``severity_id >=`` number filter) and any extra string filters are combined with ``AND``.

    Args:
        start_time (str): ISO8601 start of the fetch window (exclusive lower bound is handled by the caller).
        end_time (str): ISO8601 end of the fetch window.
        min_severity (str | None): Minimum severity label (e.g. ``High``) to include.
        additional_filters (str | None): Extra ``string_filters``-formatted entries to AND into the query.

    Returns:
        dict: The composite ``Filters`` structure for ``get_findings_v2``.
    """
    composite_filter: dict = {
        "DateFilters": [
            {
                "FieldName": "finding_info.created_time_dt",
                "Filter": {"Start": start_time, "End": end_time},
            }
        ],
    }

    if min_severity and (severity_id := SEVERITY_LABEL_TO_OCSF_ID.get(min_severity)):
        composite_filter["NumberFilters"] = [{"FieldName": "severity_id", "Filter": {"Gte": severity_id}}]

    if additional_filters and (string_filters := parse_filters(additional_filters, "string")):
        composite_filter["StringFilters"] = string_filters

    composite_filter["Operator"] = "AND"
    return {"CompositeFilters": [composite_filter], "CompositeOperator": "AND"}


def parse_tags(tags_str: str) -> dict:
    """Parse a string of key/value pairs into the flat tag mapping the Security Hub V2 API expects.

    The expected input format is ``key=<key>,value=<value>`` with multiple pairs separated by ``;``.

    Args:
        tags_str (str): The keys and values string.

    Returns:
        dict: A flat mapping of ``{<key>: <value>}`` suitable for the ``Tags`` API parameter.
    """
    regex = re.compile(r"key=([\w\d_:.-]+),value=([ /\w\d@_,.*-]+)", flags=re.I)
    return dict(regex.findall(tags_str))


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


""" COMMAND FUNCTIONS """


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


def findings_batch_update_command(client: BotoClient, args: dict) -> CommandResults:
    """Update one or more AWS Security Hub V2 findings in a single batch request.

    Findings can be targeted either by ``metadata_uids`` (a comma-separated list of OCSF metadata
    UIDs) or by ``finding_identifiers`` (composite identifier triples). At least one targeting
    argument is required.

    Args:
        client (BotoClient): The boto3 ``securityhub`` client.
        args (dict): Command arguments. Targeting: ``metadata_uids`` and/or ``finding_identifiers``.
            Updates: ``comment``, ``severity_id`` (OCSF severity ID), ``status_id`` (OCSF status ID).

    Returns:
        CommandResults: The processed and unprocessed findings returned by the API.

    Raises:
        DemistoException: If neither ``metadata_uids`` nor ``finding_identifiers`` is provided.
    """
    metadata_uids = argToList(args.get("metadata_uids"))
    finding_identifiers = parse_finding_identifiers(args.get("finding_identifiers", ""))

    if not metadata_uids and not finding_identifiers:
        raise DemistoException("You must provide either 'metadata_uids' or 'finding_identifiers' to target findings.")

    kwargs = remove_empty_elements(
        {
            "MetadataUids": metadata_uids or None,
            "FindingIdentifiers": finding_identifiers or None,
            "Comment": args.get("comment"),
            "SeverityId": arg_to_number(args.get("severity_id")),
            "StatusId": arg_to_number(args.get("status_id")),
        }
    )

    demisto.debug("[AWS_Security_Hub_V2] Batch updating findings")
    response = client.batch_update_findings_v2(**kwargs)

    processed = response.get("ProcessedFindings", [])
    unprocessed = response.get("UnprocessedFindings", [])
    outputs = {
        "ProcessedFindings": processed,
        "UnprocessedFindings": unprocessed,
    }
    readable_output = tableToMarkdown(
        "AWS Security Hub V2 Batch Update Findings",
        {"Processed": len(processed), "Unprocessed": len(unprocessed)},
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix="AWS.SecurityHub.BatchUpdateFindings",
        outputs=remove_empty_elements(outputs),
        readable_output=readable_output,
        raw_response=response,
    )


def fetch_incidents(client: BotoClient, params: dict) -> None:
    """Fetch AWS Security Hub V2 findings as XSOAR incidents.

    Findings are queried via ``get_findings_v2`` filtered on ``finding_info.created_time_dt`` within
    a moving time window, optionally narrowed by a minimum severity and additional string filters.
    The last fetched creation time (advanced by 1ms to avoid duplicates) and any pagination token are
    persisted via ``demisto.setLastRun``; the ``next_token`` is consumed first on the following run so
    large backlogs drain over multiple cycles.

    Args:
        client (BotoClient): The boto3 ``securityhub`` client.
        params (dict): Integration parameters (``first_fetch``, ``max_fetch``, ``min_severity``,
            ``fetch_filters``, ``mirror_direction``).
    """
    last_run = demisto.getLastRun()
    start_time = last_run.get("last_fetch")
    next_token = last_run.get("next_token")

    if not start_time:
        first_fetch = (params.get("first_fetch") or DEFAULT_FIRST_FETCH).strip()
        start_time = arg_to_datetime(first_fetch, required=True).strftime(DATE_FORMAT)  # type: ignore[union-attr]

    end_time = datetime.now(UTC).strftime(DATE_FORMAT)
    max_fetch = min(arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH, MAX_FETCH_LIMIT)
    mirror_direction = MIRROR_DIRECTION_MAPPING.get(params.get("mirror_direction", "None"))

    filters = build_fetch_filters(
        start_time=start_time,
        end_time=end_time,
        min_severity=params.get("min_severity"),
        additional_filters=params.get("fetch_filters"),
    )

    # A NextToken from a previous run continues that exact query; the API rejects combining it with
    # Filters, so it is sent on its own. Otherwise start a fresh window-bounded query.
    if next_token:
        demisto.debug("[AWS_Security_Hub_V2] Fetch: continuing previous page using next_token.")
        kwargs: dict = {"NextToken": next_token, "MaxResults": max_fetch}
    else:
        demisto.debug(f"[AWS_Security_Hub_V2] Fetch: querying findings created in [{start_time}, {end_time}).")
        kwargs = {"Filters": filters, "MaxResults": max_fetch}

    response = client.get_findings_v2(**kwargs)
    findings = response.get("Findings", [])
    new_next_token = response.get("NextToken")
    demisto.debug(f"[AWS_Security_Hub_V2] Fetch: received {len(findings)} findings.")

    incidents = []
    latest_created = start_time
    for finding in findings:
        finding["mirror_direction"] = mirror_direction
        finding["mirror_instance"] = demisto.integrationInstance()

        finding_info = finding.get("finding_info") or {}
        created_time = finding_info.get("created_time_dt")
        incidents.append(
            {
                "name": finding_info.get("title") or finding.get("metadata", {}).get("uid"),
                "occurred": created_time,
                "severity": OCSF_SEVERITY_ID_TO_XSOAR.get(finding.get("severity_id"), IncidentSeverity.UNKNOWN),
                "rawJSON": json.dumps(finding),
            }
        )
        if created_time and created_time > latest_created:
            latest_created = created_time

    # Advance the window only when this was a fresh (non-token) page; a token page keeps the same
    # window so its findings are not dropped from the next fresh query.
    if not next_token and findings:
        latest_dt = arg_to_datetime(latest_created, required=True) + timedelta(milliseconds=1)  # type: ignore[operator]
        new_last_fetch = latest_dt.strftime(DATE_FORMAT)
    else:
        new_last_fetch = start_time

    demisto.setLastRun({"last_fetch": new_last_fetch, "next_token": new_next_token})
    demisto.incidents(incidents)


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
            "Access denied. Verify the configured role/credentials have the " "'securityhub:DescribeSecurityHubV2' permission."
        )
    return "ok"


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
        elif command == "aws-securityhub-findings-batch-update":
            return_results(findings_batch_update_command(client, args))
        elif command == "fetch-incidents":
            fetch_incidents(client, params)
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as e:
        return_error(f"Error has occurred in the AWS Security Hub V2 Integration: {type(e)} {e}", error=e)


if __name__ in ["__builtin__", "builtins", "__main__"]:  # pragma: no cover
    main()
