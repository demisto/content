import demistomock as demisto  # noqa: F401
from datetime import UTC
from CommonServerPython import *  # noqa: F401
from AWSApiModule import *  # noqa: E402
from botocore.client import BaseClient as BotoClient
from dateparser import parse


DEFAULT_RETRIES = 5
DEFAULT_FIRST_FETCH = "3 days"
DEFAULT_MAX_FETCH = 50
MAX_FETCH_LIMIT = 100  # AWS Security Hub V2 caps get_findings_v2 MaxResults at 100.
FETCH_SORT_CRITERIA = [{"Field": "finding_info.created_time_dt", "SortOrder": "asc"}]

# Maps the integration mirror-direction param to the value XSOAR stores on incidents.
MIRROR_DIRECTION_MAPPING = {
    "None": None,
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}
# OCSF status_id values (https://schema.ocsf.io).
OCSF_STATUS_ID_NEW = 1
OCSF_STATUS_ID_IN_PROGRESS = 2
OCSF_STATUS_ID_SUPPRESSED = 3
OCSF_STATUS_ID_RESOLVED = 4
# OCSF statuses that close the mirrored-in XSOAR incident, mapped to the XSOAR close reason.
OCSF_STATUS_ID_TO_CLOSE_REASON = {
    OCSF_STATUS_ID_RESOLVED: "Resolved",
    OCSF_STATUS_ID_SUPPRESSED: "Other",
}
# OCSF statuses that reopen the mirrored-in XSOAR incident.
OCSF_OPEN_STATUS_IDS = {OCSF_STATUS_ID_NEW, OCSF_STATUS_ID_IN_PROGRESS}
# Outgoing delta keys written verbatim to the batch_update_findings_v2 kwarg.
OUTGOING_DELTA_TO_KWARG = {
    "severityid": "SeverityId",
    "statusid": "StatusId",
    "comment": "Comment",
}
# Outgoing mapping schema surfaced by get-mapping-fields. Includes the built-in "severity" field,
# which is translated (not written verbatim) to OCSF SeverityId in update_remote_system_command.
OUTGOING_FIELD_DESCRIPTIONS = {
    "severityid": "The OCSF severity_id to set on the finding (1=Informational .. 6=Fatal).",
    "statusid": "The OCSF status_id to set on the finding (1=New, 2=In Progress, 3=Suppressed, 4=Resolved).",
    "comment": "A comment describing the reason for the update.",
    "severity": "The built-in incident severity; mirrored to the finding's OCSF severity in AWS.",
}

# OCSF severity_id -> XSOAR incident severity. Fatal (6) collapses to Critical (XSOAR has no higher).
OCSF_SEVERITY_ID_TO_XSOAR = {
    1: IncidentSeverity.INFO,
    2: IncidentSeverity.LOW,
    3: IncidentSeverity.MEDIUM,
    4: IncidentSeverity.HIGH,
    5: IncidentSeverity.CRITICAL,
    6: IncidentSeverity.CRITICAL,
}
# XSOAR incident severity -> OCSF severity_id. XSOAR Unknown (0) has no OCSF equivalent (skipped by caller).
XSOAR_SEVERITY_TO_OCSF_ID = {
    IncidentSeverity.INFO: 1,
    IncidentSeverity.LOW: 2,
    IncidentSeverity.MEDIUM: 3,
    IncidentSeverity.HIGH: 4,
    IncidentSeverity.CRITICAL: 5,
}


def effective_severity_id(finding: dict) -> int:
    """Return the finding's current severity_id (top-level), falling back to vendor_attributes, else 0.

    Args:
        finding (dict): The OCSF finding.

    Returns:
        int: The OCSF severity_id, or 0 (Unknown) when absent.
    """
    vendor_attributes = finding.get("vendor_attributes") or {}
    return finding.get("severity_id") or vendor_attributes.get("severity_id") or 0


# Minimum severity label -> OCSF severity_id, used to build the fetch severity filter.
SEVERITY_LABEL_TO_OCSF_ID = {
    "Informational": 1,
    "Low": 2,
    "Medium": 3,
    "High": 4,
    "Critical": 5,
    "Fatal": 6,
}


# Drives the generic parse_filters helper. Per category: "fields" maps an entry key to
# (API Filter key, coercion callable); "required" lists mandatory entry keys; "defaults" supplies
# fallbacks; "require_any" (optional) requires at least one of the listed keys.
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
    """Parse a filter argument (";"-separated entries of ","-separated key=value pairs) into dicts.

    Args:
        filters_str (str): The raw filter argument string.

    Returns:
        list[dict]: One key/value dict per entry.
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
    """Parse a filter argument into the API ``{FieldName, Filter}`` structure using FILTER_CONFIGS.

    Backs the string/number/boolean/map/ip categories (date is handled by parse_date_filters).
    Entries missing ``field_name`` or a category-required key are skipped.

    Args:
        filters_str (str): The raw filter argument string.
        category (str): The FILTER_CONFIGS category key.

    Returns:
        list[dict]: A list of ``{FieldName, Filter}`` dictionaries.
    """
    config = FILTER_CONFIGS[category]
    fields, required = config["fields"], config["required"]
    require_any = config.get("require_any")
    filters = []

    for entry in parse_filter_entries(filters_str):
        field_name = entry.get("field_name")
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
    """Parse ``date_filters`` entries into the API ``DateFilters`` structure.

    Each entry uses exactly one form: absolute (``start`` + ``end``) or relative DateRange
    (``value`` with optional ``unit``/``comparison``; ``days`` is an alias for ``value`` + ``unit=DAYS``).

    Args:
        filters_str (str): The raw date filters argument string.

    Returns:
        list[dict]: A list of ``{FieldName, Filter}`` dictionaries.

    Raises:
        DemistoException: If an entry mixes both forms, provides only one of ``start``/``end``, or neither.
    """
    filters = []
    for e in parse_filter_entries(filters_str):
        field_name = e.get("field_name")
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
    """Build the composite ``Filters`` object for get-findings from the per-category filter arguments.

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
    """Parse ``finding_identifiers`` into the API ``FindingIdentifiers`` structure.

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
    """Build the composite ``Filters`` object for the fetch loop.

    Filters on ``finding_info.created_time_dt`` within ``[start_time, end_time]``, AND-ed with an
    optional minimum-severity number filter and optional extra string filters.

    Args:
        start_time (str): ISO8601 inclusive lower bound of the fetch window.
        end_time (str): ISO8601 upper bound of the fetch window.
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
    """Parse ``key=<key>,value=<value>`` pairs (``;``-separated) into a flat ``{key: value}`` tag mapping.

    Args:
        tags_str (str): The keys and values string.

    Returns:
        dict: A flat mapping suitable for the ``Tags`` API parameter.
    """
    regex = re.compile(r"key=([\w\d_:.-]+),value=([ /\w\d@_,.*-]+)", flags=re.I)
    return dict(regex.findall(tags_str))


def build_client(params: dict) -> BotoClient:
    """Build a boto3 ``securityhub`` client via the shared ``AWSClient`` (AWSApiModule).

    ``AWSClient`` handles role assumption, credentials, SSL verification, timeouts, retries and proxy.

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
        outputs_prefix="AWS.SecurityHubV2.Hub",
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
        args (dict): Command arguments (per-category filters, sort_field/sort_order, limit, next_token).

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
        "AWS.SecurityHubV2.Findings(val.metadata.uid && val.metadata.uid == obj.metadata.uid)": findings,
        "AWS.SecurityHubV2(true)": {"FindingsNextToken": next_token},
    }
    findings_table = [
        {
            "uid": finding.get("metadata", {}).get("uid"),
            "severity": finding.get("severity"),
            "status": finding.get("status"),
            "class_name": finding.get("class_name"),
            "resource_uid": ", ".join(
                resource.get("uid") for resource in (finding.get("resources") or []) if resource.get("uid")
            ),
        }
        for finding in findings
    ]
    return CommandResults(
        outputs=remove_empty_elements(outputs),
        readable_output=tableToMarkdown(
            "AWS Security Hub V2 Findings",
            findings_table,
            headers=["uid", "severity", "status", "class_name", "resource_uid"],
            removeNull=True,
        ),
        raw_response=response,
    )


def findings_batch_update_command(client: BotoClient, args: dict) -> CommandResults:
    """Update one or more findings in a single batch request.

    Args:
        client (BotoClient): The boto3 ``securityhub`` client.
        args (dict): Targeting (``metadata_uids`` and/or ``finding_identifiers``) and updates
            (``comment``, ``severity_id``, ``status_id``).

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
        {
            "Processed": [finding.get("MetadataUid") for finding in processed],
            "Unprocessed": [finding.get("MetadataUid") for finding in unprocessed],
        },
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix="AWS.SecurityHubV2.BatchUpdateFindings",
        outputs=remove_empty_elements(outputs),
        readable_output=readable_output,
        raw_response=response,
    )


def dedup_findings(findings: list, last_fetch: str, fetched_ids: list, mirror_direction: str | None = None) -> tuple[list, list]:
    """Drop already-seen findings and build XSOAR incidents from the new ones.

    Against the previous fetch boundary (inclusive ``Start``), a finding is dropped if it was created
    before ``last_fetch`` (stale) or exactly at ``last_fetch`` with its uid in ``fetched_ids`` (already
    ingested). Surviving findings are tagged with mirroring metadata when ``mirror_direction`` is set.

    Args:
        findings (list): Raw OCSF findings returned by ``get_findings_v2``.
        last_fetch (str): ISO8601 boundary timestamp from the previous run.
        fetched_ids (list): Uids already ingested at the ``last_fetch`` boundary.
        mirror_direction (str | None): XSOAR mirror direction to stamp on incidents, or ``None`` to disable.

    Returns:
        tuple[list, list]: ``(new_findings, incidents)``.
    """
    incidents: list = []
    new_findings: list = []
    for finding in findings:
        finding_info = finding.get("finding_info") or {}
        created_time = finding_info.get("created_time_dt")
        uid = finding.get("metadata", {}).get("uid")

        if created_time and last_fetch and created_time < last_fetch:
            demisto.debug(
                f"[AWS_Security_Hub_V2] Dedup: skipping STALE finding uid={uid} (created={created_time} < Start={last_fetch})."
            )
            continue
        if created_time and last_fetch and created_time == last_fetch and uid in fetched_ids:
            demisto.debug(
                f"[AWS_Security_Hub_V2] Dedup: skipping ALREADY-SEEN boundary finding uid={uid} (created={created_time})."
            )
            continue

        if mirror_direction:
            finding["mirror_direction"] = mirror_direction
            finding["mirror_instance"] = demisto.integrationInstance()
            demisto.debug(
                f"[AWS_Security_Hub_V2] Dedup: tagged uid={uid} for mirroring "
                f"(mirror_direction={mirror_direction}, mirror_instance={finding['mirror_instance']})."
            )

        severity_id = effective_severity_id(finding)
        xsoar_severity = OCSF_SEVERITY_ID_TO_XSOAR.get(severity_id, IncidentSeverity.UNKNOWN)
        incidents.append(
            {
                "name": finding_info.get("title") or uid,
                "occurred": created_time,
                "severity": xsoar_severity,
                "rawJSON": json.dumps(finding),
            }
        )
        demisto.debug(
            f"[AWS_Security_Hub_V2] Dedup: created incident uid={uid}, created={created_time}, "
            f"effective severity_id={severity_id} (top-level={finding.get('severity_id')}, "
            f"vendor_attributes={(finding.get('vendor_attributes') or {}).get('severity_id')}) "
            f"-> xsoar_severity={xsoar_severity}."
        )

        new_findings.append(finding)

    return new_findings, incidents


def fetch_incidents(client: BotoClient, params: dict) -> None:
    """Fetch AWS Security Hub V2 findings as XSOAR incidents."""
    demisto.debug("[AWS_Security_Hub_V2] Fetch: ===== fetch-incidents START =====")
    max_fetch = min(arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH, MAX_FETCH_LIMIT)
    last_run = demisto.getLastRun()
    demisto.debug(
        f"[AWS_Security_Hub_V2] Fetch: raw lastRun from server: {last_run}, min_severity={params.get('min_severity')},"
        f" fetch_filters={params.get('fetch_filters')}, {max_fetch=}"
    )
    first_fetch = (params.get("first_fetch") or DEFAULT_FIRST_FETCH).strip()
    format_first_fetch = parse(f"{first_fetch} UTC")
    if not format_first_fetch:
        raise DemistoException(f"Invalid 'First fetch time' value: {first_fetch!r}.")
    last_fetch = last_run.get("last_fetch") or format_first_fetch.isoformat()
    demisto.debug(f"[AWS_Security_Hub_V2] Fetch: {last_fetch=}")

    next_token = last_run.get("next_token")
    fetched_ids: list = list(last_run.get("fetched_ids") or [])

    raw_filters = last_run.get("filters") or {}
    filters = json.loads(raw_filters) if isinstance(raw_filters, str) else raw_filters

    if next_token:
        demisto.debug("[AWS_Security_Hub_V2] Fetch: continuing previous page using next_token.")
        try:
            response = client.get_findings_v2(
                NextToken=next_token, MaxResults=max_fetch, Filters=filters, SortCriteria=FETCH_SORT_CRITERIA
            )
            demisto.debug("[AWS_Security_Hub_V2] Fetch: token query succeeded.")
        except client.exceptions.ClientError as e:
            error = e.response.get("Error", {})
            error_code = error.get("Code", "")
            error_message = error.get("Message", "")
            demisto.debug(
                f"[AWS_Security_Hub_V2] Fetch: token query raised {type(e).__name__} "
                f"(Code={error_code}, Message={error_message})."
            )
            raise DemistoException(e.response.get("Error", {}).get("Message", ""))
    else:
        demisto.debug("[AWS_Security_Hub_V2] Fetch: fresh window query for findings.")
        try:
            filters = build_fetch_filters(
                start_time=last_fetch,
                end_time=datetime.now(UTC).isoformat(),
                min_severity=params.get("min_severity"),
                additional_filters=params.get("fetch_filters"),
            )
            demisto.debug(f"[AWS_Security_Hub_V2] Fetch: built Filters object: {json.dumps(filters)}")

            response = client.get_findings_v2(MaxResults=max_fetch, Filters=filters, SortCriteria=FETCH_SORT_CRITERIA)
            demisto.debug("[AWS_Security_Hub_V2] Fetch: fresh window query succeeded.")
        except client.exceptions.ClientError as e:
            raise DemistoException(e.response.get("Error", {}).get("Message", ""))

    findings = response.get("Findings", [])
    new_next_token = response.get("NextToken")
    demisto.debug(f"[AWS_Security_Hub_V2] Fetch: API returned {len(findings)} findings. {new_next_token=}")

    mirror_direction = MIRROR_DIRECTION_MAPPING.get(params.get("mirror_direction", "None"))
    demisto.debug(
        f"[AWS_Security_Hub_V2] Fetch: mirror_direction param={params.get('mirror_direction', 'None')} "
        f"-> resolved dbot direction={mirror_direction} "
        f"({'incidents will be enrolled in mirroring' if mirror_direction else 'mirroring disabled'})."
    )
    new_findings, incidents = dedup_findings(findings, last_fetch, fetched_ids, mirror_direction)

    sorted_findings = sorted(new_findings, key=lambda x: (x.get("finding_info") or {}).get("created_time_dt") or "", reverse=True)
    matching_uids = fetched_ids
    if sorted_findings:
        first_finding_info = sorted_findings[0].get("finding_info") or {}
        first_created_time = first_finding_info.get("created_time_dt")
        matching_uids = [
            finding.get("metadata", {}).get("uid")
            for finding in sorted_findings
            if (finding.get("finding_info") or {}).get("created_time_dt") == first_created_time
        ]

        last_fetch = first_created_time

    new_last_run = {
        "last_fetch": last_fetch,
        "next_token": new_next_token,
        "fetched_ids": matching_uids,
        "filters": json.dumps(filters) if new_next_token else {},
    }

    demisto.info(f"[AWS_Security_Hub_V2] Fetch: summary -> created {len(incidents)} incidents; new lastRun -> {new_last_run=}")
    demisto.setLastRun(new_last_run)
    demisto.incidents(incidents)
    demisto.debug("[AWS_Security_Hub_V2] Fetch: ===== fetch-incidents END =====")


def build_close_reopen_entries(finding: dict) -> list:
    """Build the incoming-mirror entries that close or reopen the XSOAR incident based on AWS status.

    Full lifecycle sync: an OCSF ``status_id`` of Resolved (4) or Suppressed (3) closes the XSOAR
    incident (``dbotIncidentClose``); an open status (New/In Progress) reopens it
    (``dbotIncidentReopen``). Any other/unknown status yields no entry so the incident is left as-is.

    Args:
        finding (dict): The OCSF finding returned by AWS Security Hub V2.

    Returns:
        list: A single-element entry list instructing the server to close/reopen, or an empty list.
    """
    status_id = finding.get("status_id")
    if status_id is None:
        return []
    close_reason = OCSF_STATUS_ID_TO_CLOSE_REASON.get(status_id)
    if close_reason:
        finding_status = finding.get("status") or close_reason
        return [
            {
                "Type": EntryType.NOTE,
                "Contents": {
                    "dbotIncidentClose": True,
                    "closeReason": close_reason,
                    "closeNotes": f"Closed by mirroring: AWS Security Hub finding status is '{finding_status}'.",
                },
                "ContentsFormat": EntryFormat.JSON,
            }
        ]
    if status_id in OCSF_OPEN_STATUS_IDS:
        return [
            {
                "Type": EntryType.NOTE,
                "Contents": {"dbotIncidentReopen": True},
                "ContentsFormat": EntryFormat.JSON,
            }
        ]
    return []


def get_remote_data_command(client: BotoClient, args: dict) -> GetRemoteDataResponse:
    """Re-fetch a single mirrored finding by its uid and return its current state for incoming mirroring.

    ``get-modified-remote-data`` is intentionally not implemented: Security Hub V2 does not advance
    ``modified_time_dt`` on manual edits, so the server instead calls this per mirror-enrolled incident
    each cycle and diffs the returned finding against the incident (catching untimestamped console edits).

    Args:
        client (BotoClient): The boto3 ``securityhub`` client.
        args (dict): Command arguments. ``id`` - the finding ``metadata.uid`` to retrieve.

    Returns:
        GetRemoteDataResponse: The updated finding object and any close/reopen entries.
    """
    demisto.debug("[AWS_Security_Hub_V2] Mirror-in: ===== get-remote-data START =====")
    demisto.debug(f"[AWS_Security_Hub_V2] Mirror-in: raw args from server: {json.dumps(args, default=str)}")
    remote_args = GetRemoteDataArgs(args)
    finding_uid = remote_args.remote_incident_id
    demisto.debug(
        f"[AWS_Security_Hub_V2] Mirror-in: fetching current state of finding uid={finding_uid} "
        f"(server-provided lastUpdate={remote_args.last_update})"
    )

    filters = {
        "CompositeFilters": [
            {
                "StringFilters": [{"FieldName": "metadata.uid", "Filter": {"Value": finding_uid, "Comparison": "EQUALS"}}],
                "Operator": "AND",
            }
        ],
        "CompositeOperator": "AND",
    }
    demisto.debug(f"[AWS_Security_Hub_V2] Mirror-in: get-remote-data Filters object: {json.dumps(filters)}")

    try:
        response = client.get_findings_v2(Filters=filters, MaxResults=1)
        demisto.debug("[AWS_Security_Hub_V2] Mirror-in: get_findings_v2 query succeeded.")
    except client.exceptions.ClientError as e:
        error = e.response.get("Error", {})
        error_code = error.get("Code", "")
        error_message = error.get("Message", "")
        demisto.debug(
            f"[AWS_Security_Hub_V2] Mirror-in: get-remote-data query raised {type(e).__name__} "
            f"(Code={error_code}, Message={error_message})."
        )
        raise DemistoException(error_message)

    findings = response.get("Findings", [])
    if not findings:
        demisto.debug(
            f"[AWS_Security_Hub_V2] Mirror-in: no finding found for uid={finding_uid}; nothing to mirror. "
            "===== get-remote-data END ====="
        )
        return GetRemoteDataResponse(mirrored_object={}, entries=[])

    finding = findings[0]
    # Attach the XSOAR severity so the incoming mapper can map it 1:1 (no transformer).
    severity_id = effective_severity_id(finding)
    finding["xsoar_severity"] = OCSF_SEVERITY_ID_TO_XSOAR.get(severity_id, IncidentSeverity.UNKNOWN)

    # Lifecycle sync: close/reopen the XSOAR incident to match the AWS finding status.
    entries = build_close_reopen_entries(finding)

    demisto.debug(
        f"[AWS_Security_Hub_V2] Mirror-in: returning current finding uid={finding_uid} "
        f"(severity_id={severity_id} -> xsoar_severity={finding['xsoar_severity']}, "
        f"status_id={finding.get('status_id')}, close/reopen entries={len(entries)}). "
        "===== get-remote-data END ====="
    )
    return GetRemoteDataResponse(mirrored_object=finding, entries=entries)


def get_mapping_fields_command() -> GetMappingFieldsResponse:
    """Return the schema of fields available for outgoing mirroring (from OUTGOING_FIELD_DESCRIPTIONS).

    Returns:
        GetMappingFieldsResponse: The outgoing mapping schema for the Security Hub finding incident type.
    """
    demisto.debug("[AWS_Security_Hub_V2] Mirror-out: get-mapping-fields")
    finding_scheme = SchemeTypeMapping(type_name="AWS Security Hub Finding")
    for name, description in OUTGOING_FIELD_DESCRIPTIONS.items():
        finding_scheme.add_field(name=name, description=description)

    mapping_response = GetMappingFieldsResponse()
    mapping_response.add_scheme_type(finding_scheme)
    return mapping_response


def update_remote_system_command(client: BotoClient, args: dict, resolve_finding: bool) -> str:
    """Push local (XSOAR) incident changes to the corresponding finding via batch_update_findings_v2.

    Mirrors out only delta fields whitelisted in ``OUTGOING_DELTA_TO_KWARG`` (plus the built-in severity).
    When ``resolve_finding`` is enabled and the incident is closed, the finding is set to Resolved.

    Args:
        client (BotoClient): The boto3 ``securityhub`` client.
        args (dict): The ``update-remote-system`` arguments (delta, incident status, remote id, etc.).
        resolve_finding (bool): Whether closing the incident in XSOAR should resolve the finding in AWS.

    Returns:
        str: The remote finding uid that was updated.
    """
    demisto.debug("[AWS_Security_Hub_V2] Mirror-out: ===== update-remote-system START =====")
    parsed_args = UpdateRemoteSystemArgs(args)
    remote_finding_uid = parsed_args.remote_incident_id
    delta = parsed_args.delta or {}
    demisto.debug(
        f"[AWS_Security_Hub_V2] Mirror-out: uid={remote_finding_uid}, incident_changed={parsed_args.incident_changed}, "
        f"inc_status={parsed_args.inc_status}, delta_keys={list(delta.keys())}, resolve_finding={resolve_finding}"
    )

    kwargs: dict = {}
    if parsed_args.incident_changed and delta:
        for delta_key, api_key in OUTGOING_DELTA_TO_KWARG.items():
            if delta_key in delta and delta[delta_key] not in (None, ""):
                value = delta[delta_key]
                # severity_id and status_id are numeric in the API.
                kwargs[api_key] = arg_to_number(value) if api_key in ("SeverityId", "StatusId") else value

        # Changing the built-in XSOAR "severity" field surfaces a "severity" delta key (an XSOAR
        # severity number). Translate it to the OCSF SeverityId so editing the incident severity
        # mirrors out. An explicit "severityid" delta (handled above) takes precedence if both exist.
        if "SeverityId" not in kwargs and delta.get("severity") not in (None, ""):
            xsoar_severity = arg_to_number(delta["severity"])
            ocsf_severity_id = XSOAR_SEVERITY_TO_OCSF_ID.get(float(xsoar_severity)) if xsoar_severity is not None else None
            if ocsf_severity_id:
                kwargs["SeverityId"] = ocsf_severity_id
            else:
                demisto.debug(
                    f"[AWS_Security_Hub_V2] Mirror-out: XSOAR severity={delta['severity']} has no OCSF "
                    "equivalent (e.g. Unknown); not mirroring severity."
                )

    # If configured, closing the incident in XSOAR resolves the finding in AWS (overrides any delta status).
    if resolve_finding and parsed_args.inc_status == IncidentStatus.DONE:
        kwargs["StatusId"] = OCSF_STATUS_ID_RESOLVED
        demisto.debug(
            f"[AWS_Security_Hub_V2] Mirror-out: incident closed and resolve_finding enabled; "
            f"forcing StatusId={OCSF_STATUS_ID_RESOLVED} (Resolved)."
        )

    if not kwargs:
        demisto.debug(
            f"[AWS_Security_Hub_V2] Mirror-out: no mirrorable changes for uid={remote_finding_uid}; skipping. "
            "===== update-remote-system END ====="
        )
        return remote_finding_uid

    kwargs["MetadataUids"] = [remote_finding_uid]
    demisto.debug(f"[AWS_Security_Hub_V2] Mirror-out: calling batch_update_findings_v2 with kwargs={kwargs}")
    try:
        response = client.batch_update_findings_v2(**kwargs)
        demisto.debug("[AWS_Security_Hub_V2] Mirror-out: batch_update_findings_v2 succeeded.")
    except client.exceptions.ClientError as e:
        error = e.response.get("Error", {})
        error_code = error.get("Code", "")
        error_message = error.get("Message", "")
        demisto.debug(
            f"[AWS_Security_Hub_V2] Mirror-out: batch_update_findings_v2 raised {type(e).__name__} "
            f"(Code={error_code}, Message={error_message})."
        )
        raise DemistoException(error_message)

    unprocessed = response.get("UnprocessedFindings", [])
    if unprocessed:
        demisto.error(f"[AWS_Security_Hub_V2] Mirror-out: {len(unprocessed)} finding(s) were not updated: {unprocessed}")
    demisto.debug(f"[AWS_Security_Hub_V2] Mirror-out: updated uid={remote_finding_uid}. ===== update-remote-system END =====")
    return remote_finding_uid


def test_module(client: BotoClient) -> str:
    """Test connectivity and authentication against the AWS Security Hub V2 API.

    Args:
        client (BotoClient): An initialized boto3 ``securityhub`` client.

    Returns:
        str: ``"ok"`` if the call succeeds.

    Raises:
        DemistoException: When Security Hub V2 is not enabled or permissions are insufficient.
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
        elif command == "aws-securityhub-v2-security-hub-enable":
            return_results(enable_security_hub_command(client, args))
        elif command == "aws-securityhub-v2-security-hub-disable":
            return_results(disable_security_hub_command(client, args))
        elif command == "aws-securityhub-v2-findings-get":
            return_results(findings_get_command(client, args))
        elif command == "aws-securityhub-v2-findings-batch-update":
            return_results(findings_batch_update_command(client, args))
        elif command == "fetch-incidents":
            fetch_incidents(client, params)
        elif command == "get-remote-data":
            return_results(get_remote_data_command(client, args))
        elif command == "get-mapping-fields":
            return_results(get_mapping_fields_command())
        elif command == "update-remote-system":
            resolve_finding = argToBoolean(params.get("resolve_finding", False))
            return_results(update_remote_system_command(client, args, resolve_finding))
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Error has occurred in the AWS Security Hub V2 Integration: {type(e)} {e}", error=e)


if __name__ in ["__builtin__", "builtins", "__main__"]:  # pragma: no cover
    main()
