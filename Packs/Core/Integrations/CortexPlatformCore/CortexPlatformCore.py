import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CoreIRApiModule import *

# Disable insecure warnings
urllib3.disable_warnings()

TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
INTEGRATION_CONTEXT_BRAND = "Core"
INTEGRATION_NAME = "Cortex Platform Core"
MAX_GET_INCIDENTS_LIMIT = 100

WEBAPP_COMMANDS = ["core-get-vulnerabilities", "core-search-asset-groups"]
DATA_PLATFORM_COMMANDS = ["core-get-asset-details"]

ASSET_GROUP_FIELDS = {
    "asset_group_name": "XDM__ASSET_GROUP__NAME",
    "asset_group_type": "XDM__ASSET_GROUP__TYPE",
    "asset_group_description": "XDM__ASSET_GROUP__DESCRIPTION",
    "asset_group_id": "XDM__ASSET_GROUP__ID",
}


class FilterField:
    def __init__(self, field_name: str, operator: str, values: list):
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

    def get_webapp_data(self, request_data: dict) -> dict:
        reply = self._http_request(
            method="POST",
            url_suffix="/get_data",
            json_data=request_data,
        )

        return reply


def search_asset_groups_command(client: Client, args: dict) -> List[CommandResults]:
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

    Returns:
        CommandResults: Object containing the formatted asset groups,
                        raw response, and outputs for integration context.
    """
    limit = arg_to_number(args.get("limit")) or 1
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

    response = client.get_webapp_data(request_data).get("reply", {})
    groups = response.get("DATA", [])

    groups = [
        {(k.replace("XDM__ASSET_GROUP__", "") if k.startswith("XDM__ASSET_GROUP__") else k).lower(): v for k, v in item.items()}
        for item in groups
    ]
    
    command_results = []
    command_results.append(CommandResults(
        readable_output=tableToMarkdown("AssetGroups", groups, headerTransform=string_to_table_header),
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.AssetGroups.groups",
        outputs_key_field="id",
        outputs=groups,
        raw_response=response,
    ))
    
    filter_count = response.get("FILTER_COUNT")
    total_count = response.get("TOTAL_COUNT")

    metadata = f"fetched {min(filter_count,limit)} out of the {filter_count} available under this search filter, the total group count is {total_count}"
    
    command_results.append(CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.AssetGroups.returned_results_metadata",
        outputs=metadata,
        raw_response=response,
    ))
    
    return command_results


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

    except Exception as err:
        demisto.error(traceback.format_exc())
        return_error(str(err))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
