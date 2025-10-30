import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CoreIRApiModule import *
import dateparser
from enum import Enum

# Disable insecure warnings
urllib3.disable_warnings()

TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
INTEGRATION_CONTEXT_BRAND = "Core"
INTEGRATION_NAME = "Cortex Platform Core"
MAX_GET_INCIDENTS_LIMIT = 100

WEBAPP_COMMANDS = ["core-get-vulnerabilities", "core-search-asset-groups"]
DATA_PLATFORM_COMMANDS = ["core-get-asset-details"]

VULNERABLE_ISSUES_TABLE = "VULNERABLE_ISSUES_TABLE"
ASSET_GROUPS_TABLE = "UNIFIED_ASSET_MANAGEMENT_ASSET_GROUPS"

ASSET_GROUP_FIELDS = {
    "asset_group_name": "XDM__ASSET_GROUP__NAME",
    "asset_group_type": "XDM__ASSET_GROUP__TYPE",
    "asset_group_description": "XDM__ASSET_GROUP__DESCRIPTION",
    "asset_group_id": "XDM__ASSET_GROUP__ID",
}

VULNERABILITIES_SEVERITY_MAPPING = {
    "info": "SEV_030_INFO",
    "low": "SEV_040_LOW",
    "medium": "SEV_050_MEDIUM",
    "high": "SEV_060_HIGH",
    "critical": "SEV_070_CRITICAL",
}


class FilterBuilder:
    """
    Filter class for creating filter dictionary objects.
    """

    class FilterType(str, Enum):
        operator: str

        """
        Available type options for filter filtering.
        Each member holds its string value and its logical operator for multi-value scenarios.
        """

        def __new__(cls, value, operator):
            obj = str.__new__(cls, value)
            obj._value_ = value
            obj.operator = operator
            return obj

        EQ = ("EQ", "OR")
        RANGE = ("RANGE", "OR")
        CONTAINS = ("CONTAINS", "OR")
        GTE = ("GTE", "OR")
        ARRAY_CONTAINS = ("ARRAY_CONTAINS", "OR")
        JSON_WILDCARD = ("JSON_WILDCARD", "OR")
        IS_EMPTY = ("IS_EMPTY", "OR")
        NIS_EMPTY = ("NIS_EMPTY", "AND")

    AND = "AND"
    OR = "OR"
    FIELD = "SEARCH_FIELD"
    TYPE = "SEARCH_TYPE"
    VALUE = "SEARCH_VALUE"

    class Field:
        def __init__(self, field_name: str, filter_type: "FilterType", values: Any):
            self.field_name = field_name
            self.filter_type = filter_type
            self.values = values

    class MappedValuesField(Field):
        def __init__(self, field_name: str, filter_type: "FilterType", values: Any, mappings: dict[str, "FilterType"]):
            super().__init__(field_name, filter_type, values)
            self.mappings = mappings

    def __init__(self, filter_fields: list[Field] | None = None):
        self.filter_fields = filter_fields or []

    def add_field(self, name: str, type: "FilterType", values: Any, mapper: dict | None = None):
        """
        Adds a new field to the filter.
        Args:
            name (str): The name of the field.
            type (FilterType): The type to use for the field.
            values (Any): The values to filter for.
            mapper (dict | None): An optional dictionary to map values before filtering.
        """
        processed_values = values
        if mapper:
            if not isinstance(values, list):
                values = [values]
            processed_values = [mapper[v] for v in values if v in mapper]

        self.filter_fields.append(FilterBuilder.Field(name, type, processed_values))

    def add_field_with_mappings(self, name: str, type: "FilterType", values: Any, mappings: dict[str, "FilterType"]):
        """
        Adds a new field to the filter with special value mappings.
        Args:
            name (str): The name of the field.
            type (FilterType): The default filter type for non-mapped values.
            values (Any): The values to filter for.
            mappings (dict[str, FilterType]): A dictionary mapping special values to specific filter types.
                Example:
                    mappings = {
                        "unassigned": FilterType.IS_EMPTY,
                        "assigned": FilterType.NIS_EMPTY,
                    }
        """
        self.filter_fields.append(FilterBuilder.MappedValuesField(name, type, values, mappings))

    def add_time_range_field(self, name: str, start_time: str | None, end_time: str | None):
        """
        Adds a time range field to the filter.
        Args:
            name (str): The name of the field.
            start_time (str | None): The start time of the range.
            end_time (str | None): The end time of the range.
        """
        start, end = self._prepare_time_range(start_time, end_time)
        if start and end:
            self.add_field(name, FilterType.RANGE, {"from": start, "to": end})

    def to_dict(self) -> dict[str, list]:
        """
        Creates a filter dict from a list of Field objects.
        The filter will require each field to be one of the values provided.
        Returns:
            dict[str, list]: Filter object.
        """
        filter_structure: dict[str, list] = {FilterBuilder.AND: []}

        for field in self.filter_fields:
            if not isinstance(field.values, list):
                field.values = [field.values]

            search_values = []
            for value in field.values:
                if value is None:
                    continue

                current_filter_type = field.filter_type
                current_value = value

                if isinstance(field, FilterBuilder.MappedValuesField) and value in field.mappings:
                    current_filter_type = field.mappings[value]
                    if current_filter_type in [FilterType.IS_EMPTY, FilterType.NIS_EMPTY]:
                        current_value = "<No Value>"

                search_values.append(
                    {
                        FilterBuilder.FIELD: field.field_name,
                        FilterBuilder.TYPE: current_filter_type.value,
                        FilterBuilder.VALUE: current_value,
                    }
                )

            if search_values:
                search_obj = {field.filter_type.operator: search_values} if len(search_values) > 1 else search_values[0]
                filter_structure[FilterBuilder.AND].append(search_obj)

        if not filter_structure[FilterBuilder.AND]:
            filter_structure = {}

        return filter_structure

    @staticmethod
    def _prepare_time_range(start_time_str: str | None, end_time_str: str | None) -> tuple[int | None, int | None]:
        """Prepare start and end time from args, parsing relative time strings."""
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


FilterType = FilterBuilder.FilterType


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
        return self._http_request(
            method="POST",
            url_suffix="/get_data",
            json_data=request_data,
        )


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

    Returns:
        CommandResults: Object containing the formatted asset groups,
                        raw response, and outputs for integration context.
    """
    limit = arg_to_number(args.get("limit")) or 50
    filter_builder = FilterBuilder()
    filter_builder.add_field(ASSET_GROUP_FIELDS["asset_group_name"], FilterType.CONTAINS, argToList(args.get("name")))
    filter_builder.add_field(ASSET_GROUP_FIELDS["asset_group_type"], FilterType.EQ, args.get("type"))
    filter_builder.add_field(
        ASSET_GROUP_FIELDS["asset_group_description"], FilterType.CONTAINS, argToList(args.get("description"))
    )
    filter_builder.add_field(ASSET_GROUP_FIELDS["asset_group_id"], FilterType.EQ, argToList(args.get("id")))

    request_data = build_webapp_request_data(
        table_name=ASSET_GROUPS_TABLE,
        filter_dict=filter_builder.to_dict(),
        limit=limit,
        sort_field="XDM__ASSET_GROUP__LAST_UPDATE_TIME",
    )

    response = client.get_webapp_data(request_data)
    reply = response.get("reply", {})
    data = reply.get("DATA", [])

    data = [
        {(k.replace("XDM__ASSET_GROUP__", "") if k.startswith("XDM__ASSET_GROUP__") else k).lower(): v for k, v in item.items()}
        for item in data
    ]

    return CommandResults(
        readable_output=tableToMarkdown("AssetGroups", data, headerTransform=string_to_table_header),
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.AssetGroups",
        outputs_key_field="id",
        outputs=data,
        raw_response=response,
    )


def build_webapp_request_data(
    table_name: str,
    filter_dict: dict,
    limit: int,
    sort_field: str,
    on_demand_fields: list | None = None,
    sort_order: str = "DESC",
) -> dict:
    """
    Builds the request data for the generic /api/webapp/get_data endpoint.
    """
    filter_data = {
        "sort": [{"FIELD": sort_field, "ORDER": sort_order}],
        "paging": {"from": 0, "to": limit},
        "filter": filter_dict,
    }
    demisto.debug(f"{filter_data=}")

    if on_demand_fields is None:
        on_demand_fields = []

    return {"type": "grid", "table_name": table_name, "filter_data": filter_data, "jsons": [], "onDemandFields": on_demand_fields}


def get_vulnerabilities_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves vulnerabilities using the generic /api/webapp/get_data endpoint.
    """
    limit = arg_to_number(args.get("limit")) or 50
    sort_field = args.get("sort_field", "LAST_OBSERVED")
    sort_order = args.get("sort_order", "DESC")

    filter_builder = FilterBuilder()
    filter_builder.add_field("CVE_ID", FilterType.CONTAINS, argToList(args.get("cve_id")))
    filter_builder.add_field("CVSS_SCORE", FilterType.GTE, arg_to_number(args.get("cvss_score_gte")))
    filter_builder.add_field("EPSS_SCORE", FilterType.GTE, arg_to_number(args.get("epss_score_gte")))
    filter_builder.add_field("INTERNET_EXPOSED", FilterType.EQ, arg_to_bool_or_none(args.get("internet_exposed")))
    filter_builder.add_field("EXPLOITABLE", FilterType.EQ, arg_to_bool_or_none(args.get("exploitable")))
    filter_builder.add_field("HAS_KEV", FilterType.EQ, arg_to_bool_or_none(args.get("has_kev")))
    filter_builder.add_field("AFFECTED_SOFTWARE", FilterType.CONTAINS, argToList(args.get("affected_software")))
    filter_builder.add_field(
        "PLATFORM_SEVERITY", FilterType.EQ, argToList(args.get("severity")), VULNERABILITIES_SEVERITY_MAPPING
    )
    filter_builder.add_field("ISSUE_ID", FilterType.CONTAINS, argToList(args.get("issue_id")))
    filter_builder.add_time_range_field("LAST_OBSERVED", args.get("start_time"), args.get("end_time"))
    filter_builder.add_field_with_mappings(
        "ASSIGNED_TO",
        FilterType.CONTAINS,
        argToList(args.get("assignee")),
        {
            "unassigned": FilterType.IS_EMPTY,
            "assigned": FilterType.NIS_EMPTY,
        },
    )

    request_data = build_webapp_request_data(
        table_name=VULNERABLE_ISSUES_TABLE,
        filter_dict=filter_builder.to_dict(),
        limit=limit,
        sort_field=sort_field,
        sort_order=sort_order,
        on_demand_fields=argToList(args.get("on_demand_fields")),
    )
    response = client.get_webapp_data(request_data)
    reply = response.get("reply", {})
    data = reply.get("DATA", [])

    output_keys = [
        "ISSUE_ID",
        "CVE_ID",
        "CVE_DESCRIPTION",
        "ASSET_NAME",
        "PLATFORM_SEVERITY",
        "EPSS_SCORE",
        "CVSS_SCORE",
        "ASSIGNED_TO",
        "ASSIGNED_TO_PRETTY",
        "AFFECTED_SOFTWARE",
        "FIX_AVAILABLE",
        "INTERNET_EXPOSED",
        "HAS_KEV",
        "EXPLOITABLE",
        "ASSET_IDS",
    ]
    filtered_data = [{k: v for k, v in item.items() if k in output_keys} for item in data]

    readable_output = tableToMarkdown(
        "Vulnerabilities", filtered_data, headerTransform=string_to_table_header, sort_headers=False
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.VulnerabilityIssue",
        outputs_key_field="ISSUE_ID",
        outputs=filtered_data,
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

    webapp_api_url = "/api/webapp"
    public_api_url = f"{webapp_api_url}/public_api/v1"
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

        elif command == "core-get-vulnerabilities":
            return_results(get_vulnerabilities_command(client, args))

    except Exception as err:
        demisto.error(traceback.format_exc())
        return_error(str(err))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
