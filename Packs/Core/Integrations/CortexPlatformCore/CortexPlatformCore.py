import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CoreIRApiModule import *
import dateparser

# Disable insecure warnings
urllib3.disable_warnings()

TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
INTEGRATION_CONTEXT_BRAND = "Core"
INTEGRATION_NAME = "Cortex Platform Core"
MAX_GET_INCIDENTS_LIMIT = 100
SEARCH_ASSETS_DEFAULT_LIMIT = 100

ASSET_FIELDS = {
    "asset_names": "xdm.asset.name",
    "asset_types": "xdm.asset.type.name",
    "asset_tags": "xdm.asset.tags",
    "asset_ids": "xdm.asset.id",
    "asset_providers": "xdm.asset.provider",
    "asset_realms": "xdm.asset.realm",
    "asset_group_ids": "xdm.asset.group_ids",
}

SEVERITY_MAPPING = {
    "info": "SEV_030_INFO",
    "low": "SEV_040_LOW",
    "medium": "SEV_050_MEDIUM",
    "high": "SEV_060_HIGH",
    "critical": "SEV_070_CRITICAL",
}

ASSET_GROUP_FIELDS = {
    "asset_group_name": "XDM__ASSET_GROUP__NAME",
    "asset_group_type": "XDM__ASSET_GROUP__TYPE",
    "asset_group_description": "XDM__ASSET_GROUP__DESCRIPTION",
    "asset_group_id": "XDM__ASSET_GROUP__ID",
}

WEBAPP_COMMANDS = ["core-get-vulnerabilities", "core-search-asset-groups"]
DATA_PLATFORM_COMMANDS = ["core-get-asset-details"]


class FilterField:
    def __init__(self, field_name: str, operator: str, values: Any):
        self.field_name = field_name
        self.operator = operator
        self.values = values


def build_webapp_request_data(
    table_name: str,
    filter_fields: list[FilterField],
    limit: int,
    sort_field: str,
    on_demand_fields: list | None = None,
    sort_order: str = "DESC",
) -> dict:
    """
    Builds the request data for the generic /api/webapp/get_data endpoint.
    """
    dynamic_filter = create_filter_from_fields(filter_fields)

    filter_data = {
        "sort": [{"FIELD": sort_field, "ORDER": sort_order}],
        "paging": {"from": 0, "to": limit},
        "filter": dynamic_filter,
    }
    demisto.debug(f"{filter_data=}")

    if on_demand_fields is None:
        on_demand_fields = []

    return {
        "type": "grid",
        "table_name": table_name,
        "filter_data": filter_data,
        "jsons": [],
        "onDemandFields": on_demand_fields,
    }


def replace_substring(data: dict | str, original: str, new: str) -> str | dict:
    """
    Replace all occurrences of a substring in the keys of a dictionary with a new substring or in a string.

    Args:
        data (dict | str): The dictionary to replace keys in.
        original (str): The substring to be replaced.
        new (str): The substring to replace with.

    Returns:
        dict: The dictionary with all occurrences of `original` replaced by `new` in its keys.
    """

    if isinstance(data, str):
        return data.replace(original, new)
    if isinstance(data, dict):
        for key in list(data.keys()):
            if isinstance(key, str) and original in key:
                new_key = key.replace(original, new)
                data[new_key] = data.pop(key)
    return data


def issue_to_alert(args: dict | str) -> dict | str:
    return replace_substring(args, "issue", "alert")


def alert_to_issue(output: dict | str) -> dict | str:
    return replace_substring(output, "alert", "issue")


def incident_to_case(output: dict | str) -> dict | str:
    return replace_substring(output, "incident", "case")


def case_to_incident(args: dict | str) -> dict | str:
    return replace_substring(args, "case", "incident")


def preprocess_get_cases_args(args: dict):
    demisto.debug(f"original args: {args}")
    args["limit"] = min(int(args.get("limit", MAX_GET_INCIDENTS_LIMIT)), MAX_GET_INCIDENTS_LIMIT)
    args = issue_to_alert(case_to_incident(args))
    demisto.debug(f"after preprocess_get_cases_args args: {args}")
    return args


def preprocess_get_cases_outputs(outputs: list | dict):
    def process(output: dict | str):
        return alert_to_issue(incident_to_case(output))

    if isinstance(outputs, list):
        return [process(o) for o in outputs]
    return process(outputs)


def preprocess_get_case_extra_data_outputs(outputs: list | dict):
    def process(output: dict | str):
        if isinstance(output, dict):
            if "incident" in output:
                output["incident"] = alert_to_issue(incident_to_case(output.get("incident", {})))
            alerts_data = output.get("alerts", {}).get("data", {})
            modified_alerts_data = [alert_to_issue(incident_to_case(alert)) for alert in alerts_data]
            if "alerts" in output and isinstance(output["alerts"], dict):
                output["alerts"]["data"] = modified_alerts_data
        return alert_to_issue(incident_to_case(output))

    if isinstance(outputs, list):
        return [process(o) for o in outputs]
    return process(outputs)


def filter_context_fields(output_keys: list, context: list):
    """
    Filters only specific keys from the context dictionary based on provided output_keys.
    """
    filtered_context = []
    for alert in context:
        filtered_context.append({key: alert.get(key) for key in output_keys})

    return filtered_context


class Client(CoreClient):
    def test_module(self):
        """
        Performs basic get request to get item samples
        """
        try:
            self.get_endpoints(limit=1)
        except Exception as err:
            if "API request Unauthorized" in str(err):
                # this error is received from the Core server when the client clock is not in sync to the server
                raise DemistoException(f"{err!s} please validate that your both XSOAR and Core server clocks are in sync")
            else:
                raise

    def get_asset_details(self, asset_id):
        reply = self._http_request(
            method="POST",
            json_data={"asset_id": asset_id},
            headers=self._headers,
            url_suffix="/unified-asset-inventory/get_asset/",
        )

        return reply

    def search_assets(self, filter, page_number, page_size, on_demand_fields):
        reply = self._http_request(
            method="POST",
            headers=self._headers,
            json_data={
                "request_data": {
                    "filters": filter,
                    "search_from": page_number * page_size,
                    "search_to": (page_number + 1) * page_size,
                    "on_demand_fields": on_demand_fields,
                },
            },
            url_suffix="/assets",
        )

        return reply

    def search_asset_groups(self, filter):
        reply = self._http_request(
            method="POST",
            headers=self._headers,
            json_data={"request_data": {"filters": filter}},
            url_suffix="/asset-groups",
        )

        return reply
    
    def update_issue(self, filter_data):
        reply = demisto._apiCall(
            method="POST", data=json.dumps(filter_data), headers=self._headers, path="/api/webapp/alerts/update_alerts"
        )

        return reply
    
    def get_webapp_data(self, request_data: dict) -> dict:
        reply = self._http_request(
            method="POST",
            url_suffix="/get_data",
            json_data=request_data,
        )
        
        return reply


def search_asset_groups_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves asset groups from the Cortex platform based on provided filters.

    Args:
        client (Client): The client instance used to send the request.
        args (dict): Dictionary containing the arguments for the command.
                     Expected to include:
                         - name (str, optional): Filter by asset group names
                         - type (str, optional): Filter by asset group type
                         - description (str, optional): Filter by description
                         - id (str, optional): Filter by asset group ids
                         - limit (str, optional): Maximum number of results to return

    Returns:
        CommandResults: Object containing the formatted asset groups,
                        raw response, and outputs for integration context.
    """
    limit = arg_to_number(args.get("limit")) or 50
    filter_fields = [
        FilterField(ASSET_GROUP_FIELDS["asset_group_name"], "CONTAINS", argToList(args.get("name", ""))),
        FilterField(ASSET_GROUP_FIELDS["asset_group_type"], "EQ", argToList(args.get("type", ""))),
        FilterField(ASSET_GROUP_FIELDS["asset_group_id"], "EQ", argToList(args.get("id", ""))),
        FilterField(ASSET_GROUP_FIELDS["asset_group_description"], "CONTAINS", argToList(args.get("description", ""))),
    ]

    request_data = build_webapp_request_data(
        table_name="UNIFIED_ASSET_MANAGEMENT_ASSET_GROUPS",
        filter_fields=filter_fields,
        limit=limit,
        sort_field="XDM__ASSET_GROUP__LAST_UPDATE_TIME",
    )

    response = client.get_webapp_data(request_data).get("reply", {}).get("DATA", [])

    response = [
        {(k.replace("XDM__ASSET_GROUP__", "") if k.startswith("XDM__ASSET_GROUP__") else k).lower(): v for k, v in item.items()} for item in response
    ]
    return CommandResults(
        readable_output=tableToMarkdown("AssetGroups", response, headerTransform=string_to_table_header),
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.AssetGroups",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )


def create_filter_from_fields(fields_to_filter: list[FilterField]):
    """
    Creates a filter from a list of FilterField objects.
    The filter will require each field to be one of the values provided.
    Args:
        fields_to_filter (list[FilterField]): List of FilterField objects to create a filter from.
    Returns:
        dict[str, list]: Filter object.
    """
    filter_structure: dict[str, list] = {"AND": []}

    for field in fields_to_filter:
        if not isinstance(field.values, list):
            field.values = [field.values]

        search_values = []
        for value in field.values:
            if value is None:
                continue

            search_values.append(
                {
                    "SEARCH_FIELD": field.field_name,
                    "SEARCH_TYPE": field.operator,
                    "SEARCH_VALUE": value,
                }
            )

        if search_values:
            search_obj = {"OR": search_values} if len(search_values) > 1 else search_values[0]
            filter_structure["AND"].append(search_obj)

    if not filter_structure["AND"]:
        filter_structure = {}

    return filter_structure


def prepare_start_end_time(args: dict) -> tuple[int | None, int | None]:
    """Prepare start and end time from args, parsing relative time strings."""
    start_time_str = args.get("start_time")
    end_time_str = args.get("end_time")

    if end_time_str and not start_time_str:
        raise DemistoException("When 'end_time' is provided, 'start_time' must be provided as well.")

    start_time, end_time = None, None

    if start_time_str:
        if start_dt := dateparser.parse(str(start_time_str)):
            start_time = int(start_dt.timestamp() * 1000)
        else:
            raise ValueError(f"Could not parse start_time: {start_time_str}")

    if end_time_str:
        if end_dt := dateparser.parse(str(end_time_str)):
            end_time = int(end_dt.timestamp() * 1000)
        else:
            raise ValueError(f"Could not parse end_time: {end_time_str}")

    if start_time and not end_time:
        # Set end_time to the current time if only start_time is provided
        end_time = int(datetime.now().timestamp() * 1000)

    return start_time, end_time


def get_vulnerabilities_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves vulnerabilities using the generic /api/webapp/get_data endpoint.
    """
    limit = arg_to_number(args.get("limit")) or 50
    sort_field = args.get("sort_field", "LAST_OBSERVED")
    sort_order = args.get("sort_order", "DESC")

    start_time, end_time = prepare_start_end_time(args)

    severities = argToList(args.get("severity"))
    api_severities = [SEVERITY_MAPPING[sev] for sev in severities if sev in SEVERITY_MAPPING]

    filter_fields = [
        FilterField("CVE_ID", "CONTAINS", argToList(args.get("cve_id"))),
        FilterField("CVSS_SCORE", "GTE", arg_to_number(args.get("cvss_score_gte"))),
        FilterField("EPSS_SCORE", "GTE", arg_to_number(args.get("epss_score_gte"))),
        FilterField("INTERNET_EXPOSED", "EQ", arg_to_bool_or_none(args.get("internet_exposed"))),
        FilterField("EXPLOITABLE", "EQ", arg_to_bool_or_none(args.get("exploitable"))),
        FilterField("HAS_KEV", "EQ", arg_to_bool_or_none(args.get("has_kev"))),
        FilterField("AFFECTED_SOFTWARE", "CONTAINS", argToList(args.get("affected_software"))),
        FilterField("PLATFORM_SEVERITY", "EQ", api_severities),
    ]

    if start_time and end_time:
        filter_fields.append(FilterField("LAST_OBSERVED", "RANGE", {"from": start_time, "to": end_time}))

    not_assigned = arg_to_bool_or_none(args.get("not_assigned"))
    if not_assigned is not None:
        not_assigned_operator = "IS_EMPTY" if not_assigned else "NIS_EMPTY"
        filter_fields.append(FilterField("ASSIGNED_TO", not_assigned_operator, ""))

    request_data = build_webapp_request_data(
        table_name="VULNERABLE_ISSUES_TABLE",
        filter_fields=filter_fields,
        limit=limit,
        sort_field=sort_field,
        sort_order=sort_order,
        on_demand_fields=argToList(args.get("on_demand_fields")),
    )
    response = client.get_webapp_data(request_data)
    reply = response.get("reply", {})
    data = reply.get("DATA", [])

    headers = [
        "ISSUE_ID",
        "ISSUE_NAME",
        "CVE_ID",
        "PLATFORM_SEVERITY",
        "CVSS_SEVERITY",
        "EPSS_SCORE",
        "CVSS_SCORE",
        "FIX_AVAILABLE",
        "ASSET_ID",
        "ASSIGNED_TO_PRETTY",
        "ASSIGNED_TO",
        "CVE_DESCRIPTION",
    ]
    return CommandResults(
        readable_output=tableToMarkdown("Vulnerabilities", data, headerTransform=string_to_table_header, headers=headers),
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.Vulnerability",
        outputs_key_field="ISSUE_ID",
        outputs=data,
        raw_response=response,
    )


def get_asset_details_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves details of a specific asset by its ID and formats the response.

    Args:
        client (Client): The client instance used to send the request.
        args (dict): Dictionary containing the arguments for the command.
                     Expected to include:
                         - asset_id (str): The ID of the asset to retrieve.

    Returns:
        CommandResults: Object containing the formatted asset details,
                        raw response, and outputs for integration context.
    """
    asset_id = args.get("asset_id")
    response = client.get_asset_details(asset_id)
    if not response:
        raise DemistoException(f"Failed to fetch asset details for {asset_id}. Ensure the asset ID is valid.")

    reply = response.get("reply")
    return CommandResults(
        readable_output=tableToMarkdown("Asset Details", reply, headerTransform=string_to_table_header),
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.CoreAsset",
        outputs=reply,
        raw_response=reply,
    )


def get_cases_command(client, args):
    """
    Retrieve a list of Cases from XDR, filtered by some filters.
    """
    args = preprocess_get_cases_args(args)
    _, _, raw_incidents = get_incidents_command(client, args)
    mapped_raw_cases = preprocess_get_cases_outputs(raw_incidents)
    return CommandResults(
        readable_output=tableToMarkdown("Cases", mapped_raw_cases, headerTransform=string_to_table_header),
        outputs_prefix="Core.Case",
        outputs_key_field="case_id",
        outputs=mapped_raw_cases,
        raw_response=mapped_raw_cases,
    )


def get_issue_id(args) -> str:
    """Retrieve the issue ID from either provided arguments or calling context.

    Args:
        args (dict): Arguments passed in the command, containing optional issue_id

    Returns:
        str: The extracted issue ID
    """
    issue_id = args.get("issue_id", "")
    if not issue_id:
        issue = demisto.callingContext.get("context", {}).get("Incidents")[0]
        issue_id = issue["id"]

    return issue_id


def create_filter_data(issue_id: str, update_args: dict) -> dict:
    """Creates filter data for updating an issue with specified parameters.

    Args:
        issue_id (bool): Issue ID from args or context
        update_args (dict): Dictionary of fields to update

    Returns:
        dict: Object representing updated issue details
    """
    filter_data = {
        "filter_data": {"filter": {"OR": [{"SEARCH_FIELD": "internal_id", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": issue_id}]}},
        "filter_type": "static",
    }
    update_data = {}
    for key, value in update_args.items():
        update_data[key] = value

    filter_data["update_data"] = update_data
    return filter_data


def update_issue_command(client: Client, args: dict):
    """Updates an issue with specified parameters.

    Args:
        client (Client): Client instance to execute the request
        args (dict): Command arguments for updating an issue
    """
    issue_id = get_issue_id(args)
    if not issue_id:
        return_error("Issue ID is required for updating an issue.")

    severity_map = {1: "SEV_020_LOW", 2: "SEV_030_MEDIUM", 3: "SEV_040_HIGH", 4: "SEV_050_CRITICAL"}
    severity_value = arg_to_number(args.get("severity"))
    update_args = {
        "assigned_user": args.get("assigned_user_mail"),
        "severity": severity_map.get(severity_value) if severity_value is not None else None,
        "name": args.get("name"),
        "occurred": args.get("occurred"),
        "phase": args.get("phase"),
    }

    # Remove None values before sending to API
    filtered_update_args = {k: v for k, v in update_args.items() if v is not None}

    # Send update to API
    filter_data = create_filter_data(issue_id, filtered_update_args)
    demisto.debug(filter_data)
    client.update_issue(filter_data)


def get_extra_data_for_case_id_command(client, args):
    """
    Retrieves extra data for a specific case ID.

    Args:
        client (Client): The client instance used to send the request.
        args (dict): Dictionary containing the arguments for the command.
                     Expected to include:
                         - case_id (str): The ID of the case to retrieve extra data for.
                         - issues_limit (int): The maximum number of issues to return per case. Default is 1000.

    Returns:
        CommandResults: Object containing the formatted extra data,
                        raw response, and outputs for integration context.
    """
    case_id = args.get("case_id")
    issues_limit = min(int(args.get("issues_limit", 1000)), 1000)
    response = client.get_incident_data(case_id, issues_limit)
    mapped_response = preprocess_get_case_extra_data_outputs(response)
    return CommandResults(
        readable_output=tableToMarkdown("Case", mapped_response, headerTransform=string_to_table_header),
        outputs_prefix="Core.CaseExtraData",
        outputs=mapped_response,
        raw_response=mapped_response,
    )


def search_assets_command(client: Client, args):
    """
    Search for assets in XDR based on some filters.
    """
    asset_group_ids = get_asset_group_ids_from_names(client, argToList(args.get("asset_groups", "")))
    fields_to_filter = [
        FilterField(ASSET_FIELDS["asset_names"], "CONTAINS", argToList(args.get("asset_names", ""))),
        FilterField(ASSET_FIELDS["asset_types"], "EQ", argToList(args.get("asset_types", ""))),
        FilterField(ASSET_FIELDS["asset_tags"], "JSON_WILDCARD", safe_load_json(args.get("asset_tags", []))),
        FilterField(ASSET_FIELDS["asset_ids"], "EQ", argToList(args.get("asset_ids", ""))),
        FilterField(ASSET_FIELDS["asset_providers"], "EQ", argToList(args.get("asset_providers", ""))),
        FilterField(ASSET_FIELDS["asset_realms"], "EQ", argToList(args.get("asset_realms", ""))),
        FilterField(ASSET_FIELDS["asset_group_ids"], "ARRAY_CONTAINS", asset_group_ids),
    ]

    filter = create_filter_from_fields(fields_to_filter)
    demisto.debug(f"Search Assets Filter: {filter}")
    page_size = arg_to_number(args.get("page_size", SEARCH_ASSETS_DEFAULT_LIMIT))
    page_number = arg_to_number(args.get("page_number", 0))
    on_demand_fields = ["xdm.asset.tags"]
    response = client.search_assets(filter, page_number, page_size, on_demand_fields).get("reply", {}).get("data", [])
    # Remove "xdm.asset." suffix from all keys in the response
    response = [
        {k.replace("xdm.asset.", "") if k.startswith("xdm.asset.") else k: v for k, v in item.items()} for item in response
    ]
    return CommandResults(
        readable_output=tableToMarkdown("Assets", response, headerTransform=string_to_table_header),
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.Asset",
        outputs=response,
        raw_response=response,
    )


def get_asset_group_ids_from_names(client: Client, group_names: list[str]) -> list[str]:
    """
    Retrieves the IDs of asset groups based on their names.

    Args:
        client (Client): The client instance used to send the request.
        group_names (list[str]): List of asset group names to retrieve IDs for.

    Returns:
        list[str]: List of asset group IDs.
    """
    if not group_names:
        return []

    filter = create_filter_from_fields([FilterField("XDM.ASSET_GROUP.NAME", "EQ", group_names)])

    groups = client.search_asset_groups(filter).get("reply", {}).get("data", [])

    group_ids = [group.get("XDM.ASSET_GROUP.ID") for group in groups if group.get("XDM.ASSET_GROUP.ID")]

    if len(group_ids) != len(group_names):
        found_groups = [group.get("XDM.ASSET_GROUP.NAME") for group in groups if group.get("XDM.ASSET_GROUP.ID")]
        missing_groups = [name for name in group_names if name not in found_groups]
        raise DemistoException(f"Failed to fetch asset group IDs for {missing_groups}. Ensure the asset group names are valid.")

    return group_ids


def main():  # pragma: no cover
    """
    Executes an integration command
    """
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    args = demisto.args()
    args["integration_context_brand"] = INTEGRATION_CONTEXT_BRAND
    args["integration_name"] = INTEGRATION_NAME
    headers: dict = {}

    public_api_url = "/api/webapp/public_api/v1"
    webapp_api_url = "/api/webapp"
    data_platform_api_url = f"{webapp_api_url}/data-platform"

    proxy = demisto.params().get("proxy", False)
    verify_cert = not demisto.params().get("insecure", False)

    try:
        timeout = int(demisto.params().get("timeout", 120))
    except ValueError as e:
        demisto.debug(f"Failed casting timeout parameter to int, falling back to 120 - {e}")
        timeout = 120

    client_url = public_api_url
    if command in WEBAPP_COMMANDS:
        client_url = webapp_api_url
    elif command in DATA_PLATFORM_COMMANDS:
        client_url = data_platform_api_url

    client = Client(
        base_url=client_url,
        proxy=proxy,
        verify=verify_cert,
        headers=headers,
        timeout=timeout,
    )

    try:
        if command == "test-module":
            client.test_module()
            demisto.results("ok")

        elif command == "core-get-asset-details":
            return_results(get_asset_details_command(client, args))

        elif command == "core-search-asset-groups":
            return_results(search_asset_groups_command(client, args))

        elif command == "core-get-issues":
            # replace all dict keys that contain issue with alert
            args = issue_to_alert(args)
            # Extract output_keys before calling get_alerts_by_filter_command
            output_keys = argToList(args.pop("output_keys", []))
            issues_command_results: CommandResults = get_alerts_by_filter_command(client, args)
            # Convert alert keys to issue keys
            if issues_command_results.outputs:
                issues_command_results.outputs = [alert_to_issue(output) for output in issues_command_results.outputs]  # type: ignore[attr-defined,arg-type]

            # Apply output_keys filtering if specified
            if output_keys and issues_command_results.outputs:
                issues_command_results.outputs = filter_context_fields(output_keys, issues_command_results.outputs)  # type: ignore[attr-defined,arg-type]

            return_results(issues_command_results)

        elif command == "core-get-cases":
            return_results(get_cases_command(client, args))

        elif command == "core-get-case-extra-data":
            return_results(get_extra_data_for_case_id_command(client, args))
        elif command == "core-search-assets":
            return_results(search_assets_command(client, args))

        elif command == "core-update-issue":
            return_results(update_issue_command(client, args))

        elif command == "core-get-vulnerabilities":
            return_results(get_vulnerabilities_command(client, args))

    except Exception as err:
        demisto.error(traceback.format_exc())
        return_error(str(err))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
