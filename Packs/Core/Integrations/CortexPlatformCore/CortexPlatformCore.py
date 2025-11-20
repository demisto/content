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
SEARCH_ASSETS_DEFAULT_LIMIT = 100
MAX_GET_CASES_LIMIT = 60

CASE_FIELDS = {
    "case_id_list": "CASE_ID",
    "case_domain": "INCIDENT_DOMAIN",
    "case_name": "NAME",
    "case_description": "DESCRIPTION",
    "status": "STATUS_PROGRESS",
    "severity": "SEVERITY",
    "creation_time": "CREATION_TIME",
    "asset_ids": "UAI_ASSET_IDS",
    "asset_groups": "UAI_ASSET_GROUP_IDS",
    "tags": "CURRENT_TAGS",
    "assignee": "ASSIGNED_USER_PRETTY",
    "name": "CONTAINS",
    "description": "DESCRIPTION",
    "last_updated": "LAST_UPDATE_TIME",
    "hosts": "HOSTS",
    "starred": "CASE_STARRED",
}

CASE_SEVERITY = {"low": "SEV_020_LOW", "medium": "SEV_030_MEDIUM", "high": "SEV_040_HIGH", "critical": "SEV_050_CRITICAL"}

CASE_STATUS = {
    "new": "STATUS_010_NEW",
    "under_investigation": "STATUS_020_UNDER_INVESTIGATION",
    "resolved": "STATUS_025_RESOLVED",
}

ASSET_FIELDS = {
    "asset_names": "xdm.asset.name",
    "asset_types": "xdm.asset.type.name",
    "asset_tags": "xdm.asset.tags",
    "asset_ids": "xdm.asset.id",
    "asset_providers": "xdm.asset.provider",
    "asset_realms": "xdm.asset.realm",
    "asset_group_ids": "xdm.asset.group_ids",
    "asset_categories": "xdm.asset.type.category",
}


WEBAPP_COMMANDS = ["core-get-vulnerabilities", "core-search-asset-groups", "core-get-issue-recommendations", "core-get-cases"]

DATA_PLATFORM_COMMANDS = ["core-get-asset-details"]
APPSEC_COMMANDS = ["core-enable-scanners"]
VULNERABLE_ISSUES_TABLE = "VULNERABLE_ISSUES_TABLE"
ASSET_GROUPS_TABLE = "UNIFIED_ASSET_MANAGEMENT_ASSET_GROUPS"
CASES_TABLE = "CASE_MANAGER_TABLE"

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

ALLOWED_SCANNERS = [
    "SCA",
    "IAC",
    "SECRETS",
]


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
        CASE_HOST_EQ = ("CASE_HOSTS_EQ", "OR")
        CONTAINS_IN_LIST = ("CONTAINS_IN_LIST", "OR")
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

    def get_webapp_data(self, request_data: dict) -> dict:
        return self._http_request(
            method="POST",
            url_suffix="/get_data",
            json_data=request_data,
        )

    def enable_scanners(self, payload: dict, repository_id: str) -> dict:
        return self._http_request(
            method="PUT",
            url_suffix=f"/v1/repositories/{repository_id}/scan-configuration",
            json_data=payload,
            headers={
                **self._headers,
                "Content-Type": "application/json",
            },
        )

    def get_playbook_suggestion_by_issue(self, issue_id):
        """
        Get playbook suggestions for a specific issue.
        Args:
            issue_id (str): The ID of the issue to get playbook suggestions for.
        Returns:
            dict: The response containing playbook suggestions.
        """
        reply = self._http_request(
            method="POST",
            json_data={"alert_internal_id": issue_id},
            headers=self._headers,
            url_suffix="/incident/get_playbook_suggestion_by_alert/",
        )

        return reply


def get_issue_recommendations_command(client: Client, args: dict) -> CommandResults:
    """
    Get comprehensive recommendations for an issue, including remediation steps and playbook suggestions.
    Retrieves issue data with remediation field using the generic /api/webapp/get_data endpoint.
    """
    issue_id = args.get("issue_id")
    if not issue_id:
        raise DemistoException("issue_id is required.")

    filter_builder = FilterBuilder()
    filter_builder.add_field("internal_id", FilterType.CONTAINS, issue_id)

    request_data = build_webapp_request_data(
        table_name="ALERTS_VIEW_TABLE",
        filter_dict=filter_builder.to_dict(),
        limit=1,
        sort_field="source_insert_ts",
        sort_order="DESC",
        on_demand_fields=[],
    )

    # Get issue data with remediation field
    response = client.get_webapp_data(request_data)
    reply = response.get("reply", {})
    issue_data = reply.get("DATA", [])

    if not issue_data:
        raise DemistoException(f"No issue found with ID: {issue_id}")

    issue = issue_data[0]

    # Get playbook suggestions
    playbook_response = client.get_playbook_suggestion_by_issue(issue_id)
    playbook_suggestions = playbook_response.get("reply", {})
    demisto.debug(f"{playbook_response=}")

    recommendation = {
        "issue_id": issue.get("internal_id") or issue_id,
        "issue_name": issue.get("alert_name"),
        "severity": issue.get("severity"),
        "description": issue.get("alert_description"),
        "remediation": issue.get("remediation"),
        "playbook_suggestions": playbook_suggestions,
    }

    headers = [
        "issue_id",
        "issue_name",
        "severity",
        "description",
        "remediation",
    ]

    readable_output = tableToMarkdown(
        f"Issue Recommendations for {issue_id}",
        [recommendation],
        headerTransform=string_to_table_header,
        headers=headers,
    )

    if playbook_suggestions:
        readable_output += "\n" + tableToMarkdown(
            "Playbook Suggestions",
            playbook_suggestions,
            headerTransform=string_to_table_header,
        )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.IssueRecommendations",
        outputs_key_field="issue_id",
        outputs=recommendation,
        raw_response=response,
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
    start_page: int = 0,
) -> dict:
    """
    Builds the request data for the generic /api/webapp/get_data endpoint.
    """
    filter_data = {
        "sort": [{"FIELD": sort_field, "ORDER": sort_order}],
        "paging": {"from": start_page, "to": limit},
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


def map_case_format(case_list):
    """
    Maps a list of case data from the API response format to a standardized internal format.

    Args:
        case_list (list): List of case dictionaries from the API response.
                         Each case should contain fields like CASE_ID, NAME, STATUS, etc.

    Returns:
        dict or list: Returns an empty dict if case_list is invalid or empty,
                     otherwise returns a list of mapped case dictionaries with
                     standardized field names and processed values.
    """
    if not case_list or not isinstance(case_list, list):
        return {}

    mapped_cases = []
    for case_data in case_list:
        mapped_case = {
            "case_id": str(case_data.get("CASE_ID")),
            "case_name": case_data.get("NAME"),
            "description": case_data.get("DESCRIPTION"),
            "creation_time": case_data.get("CREATION_TIME"),
            "modification_time": case_data.get("LAST_UPDATE_TIME"),
            "resolved_timestamp": case_data.get("RESOLVED_TIMESTAMP"),
            "status": case_data.get("STATUS", "").split("_")[-1].lower(),
            "severity": case_data.get("SEVERITY", "").split("_")[-1].lower(),
            "case_domain": case_data.get("INCIDENT_DOMAIN"),
            "original_tags": [tag.get("tag_name") for tag in case_data.get("ORIGINAL_TAGS", [])],
            "tags": [tag.get("tag_name") for tag in case_data.get("CURRENT_TAGS", [])],
            "issue_count": case_data.get("ACC_ALERT_COUNT"),
            "critical_severity_issue_count": case_data.get("CRITICAL_SEVERITY_ALERTS"),
            "high_severity_issue_count": case_data.get("HIGH_SEVERITY_ALERTS"),
            "med_severity_issue_count": case_data.get("MEDIUM_SEVERITY_ALERTS"),
            "low_severity_issue_count": case_data.get("LOW_SEVERITY_ALERTS"),
            "rule_based_score": case_data.get("CALCULATED_SCORE"),
            "aggregated_score": case_data.get("SCORE"),
            "manual_score": case_data.get("MANUAL_SCORE"),
            "predicted_score": case_data.get("SCORTEX"),
            "wildfire_hits": case_data.get("WF_HITS"),
            "assigned_user_pretty_name": case_data.get("ASSIGNED_USER_PRETTY"),
            "assigned_user_mail": case_data.get("ASSIGNED_USER"),
            "resolve_comment": case_data.get("RESOLVED_COMMENT"),
            "issues_grouping_status": case_data.get("CASE_GROUPING_STATUS", "").split("_")[-1],
            "starred": case_data.get("CASE_STARRED"),
            "case_sources": case_data.get("INCIDENT_SOURCES"),
            "custom_fields": case_data.get("EXTENDED_FIELDS"),
            "hosts": case_data.get("HOSTS") or [],
            "users": case_data.get("USERS") or [],
            "issue_categories": case_data.get("ALERT_CATEGORIES"),
            "mitre_techniques_ids_and_names": case_data.get("MITRE_TECHNIQUES"),
            "mitre_tactics_ids_and_names": case_data.get("MITRE_TACTICS"),
            "manual_severity": case_data.get("USER_SEVERITY"),
            "starred_manually": case_data.get("CASE_STARRED"),
            "host_count": len(case_data.get("HOSTS", []) or []),
            "user_count": len(case_data.get("USERS", []) or []),
            "asset_accounts": case_data.get("UAI_ASSET_ACCOUNTS", []),
            "asset_categories": case_data.get("UAI_ASSET_CATEGORIES", []),
            "asset_classes": case_data.get("UAI_ASSET_CLASSES", []),
            "asset_group_ids": case_data.get("UAI_ASSET_GROUP_IDS", []),
            "asset_ids": case_data.get("UAI_ASSET_IDS", []),
            "asset_names": case_data.get("UAI_ASSET_NAMES", []),
            "asset_providers": case_data.get("UAI_ASSET_PROVIDERS", []),
            "asset_regions": case_data.get("UAI_ASSET_REGIONS", []),
            "asset_types": case_data.get("UAI_ASSET_TYPES", []),
        }

        mapped_cases.append(mapped_case)

    return mapped_cases


def get_cases_command(client, args):
    """
    Retrieves cases from Cortex platform based on provided filtering criteria.

    Args:
        client: The Cortex platform client instance for making API requests.
        args (dict): Dictionary containing filter parameters including page number,
                    limits, time ranges, status, severity, and other case attributes.

    Returns:
        List of mapped case objects containing case details and metadata.
    """
    page = arg_to_number(args.get("page")) or 0
    limit = arg_to_number(args.get("limit")) or MAX_GET_CASES_LIMIT
    if limit > MAX_GET_CASES_LIMIT:
        limit = MAX_GET_CASES_LIMIT

    limit = page * MAX_GET_CASES_LIMIT + limit
    page = page * MAX_GET_CASES_LIMIT

    sort_by_modification_time = args.get("sort_by_modification_time")
    sort_by_creation_time = args.get("sort_by_creation_time")
    since_creation_start_time = args.get("since_creation_time")
    since_creation_end_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%S") if since_creation_start_time else None
    since_modification_start_time = args.get("since_modification_time")
    since_modification_end_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%S") if since_modification_start_time else None
    gte_creation_time = args.get("gte_creation_time")
    lte_creation_time = args.get("lte_creation_time")
    gte_modification_time = args.get("gte_modification_time")
    lte_modification_time = args.get("lte_modification_time")

    sort_field, sort_order = get_cases_sort_order(sort_by_creation_time, sort_by_modification_time)

    status_values = [CASE_STATUS[status] for status in argToList(args.get("status"))]
    severity_values = [CASE_SEVERITY[severity] for severity in argToList(args.get("severity"))]

    filter_builder = FilterBuilder()
    filter_builder.add_time_range_field(CASE_FIELDS["creation_time"], gte_creation_time, lte_creation_time)
    filter_builder.add_time_range_field(CASE_FIELDS["last_updated"], gte_modification_time, lte_modification_time)
    filter_builder.add_time_range_field(CASE_FIELDS["creation_time"], since_creation_start_time, since_creation_end_time)
    filter_builder.add_time_range_field(CASE_FIELDS["last_updated"], since_modification_start_time, since_modification_end_time)
    filter_builder.add_field(CASE_FIELDS["status"], FilterType.EQ, status_values)
    filter_builder.add_field(CASE_FIELDS["severity"], FilterType.EQ, severity_values)
    filter_builder.add_field(CASE_FIELDS["case_id_list"], FilterType.EQ, argToList(args.get("case_id_list")))
    filter_builder.add_field(CASE_FIELDS["case_domain"], FilterType.EQ, argToList(args.get("case_domain")))
    filter_builder.add_field(CASE_FIELDS["case_name"], FilterType.CONTAINS, argToList(args.get("case_name")))
    filter_builder.add_field(CASE_FIELDS["case_description"], FilterType.CONTAINS, argToList(args.get("case_description")))
    filter_builder.add_field(CASE_FIELDS["starred"], FilterType.EQ, argToList(args.get("starred")))
    filter_builder.add_field(CASE_FIELDS["asset_ids"], FilterType.CONTAINS_IN_LIST, argToList(args.get("asset_ids")))
    filter_builder.add_field(CASE_FIELDS["asset_groups"], FilterType.CONTAINS_IN_LIST, argToList(args.get("asset_groups")))
    filter_builder.add_field(CASE_FIELDS["hosts"], FilterType.EQ, argToList(args.get("hosts")))
    filter_builder.add_field(CASE_FIELDS["tags"], FilterType.EQ, argToList(args.get("tags")))
    filter_builder.add_field(CASE_FIELDS["assignee"], FilterType.CONTAINS, argToList(args.get("assignee")))

    request_data = build_webapp_request_data(
        table_name=CASES_TABLE,
        filter_dict=filter_builder.to_dict(),
        limit=limit,
        sort_field=sort_field,
        sort_order=sort_order,
        start_page=page,
    )
    demisto.info(f"{request_data=}")
    response = client.get_webapp_data(request_data)
    reply = response.get("reply", {})
    data = reply.get("DATA", [])
    demisto.debug(f"Raw case data retrieved from API: {data}")
    data = map_case_format(data)
    demisto.debug(f"Case data after mapping and formatting: {data}")

    return CommandResults(
        readable_output=tableToMarkdown("Cases", data, headerTransform=string_to_table_header),
        outputs_prefix="Core.Case",
        outputs_key_field="case_id",
        outputs=data,
        raw_response=data,
    )


def get_cases_sort_order(sort_by_creation_time, sort_by_modification_time):
    if sort_by_creation_time and sort_by_modification_time:
        raise ValueError("Should be provide either sort_by_creation_time or sort_by_modification_time. Can't provide both")

    if sort_by_creation_time:
        sort_field = "CREATION_TIME"
        sort_order = sort_by_creation_time
    elif sort_by_modification_time:
        sort_field = "LAST_UPDATE_TIME"
        sort_order = sort_by_modification_time
    else:
        sort_field = "LAST_UPDATE_TIME"
        sort_order = "DESC"
    return sort_field, sort_order


def get_extra_data_for_case_id_command(client: CoreClient, args):
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
    response = client.get_incident_data(case_id, issues_limit, full_alert_fields=True)
    mapped_response = preprocess_get_case_extra_data_outputs(response)
    return CommandResults(
        readable_output=tableToMarkdown("Case", mapped_response, headerTransform=string_to_table_header),
        outputs_prefix="Core.CaseExtraData",
        outputs=mapped_response,
        raw_response=mapped_response,
    )


def search_assets_command(client: Client, args):
    """
    Search for assets in XDR based on the provided filters.
    Args:
        client (Client): The client instance used to send the request.
        args (dict): Dictionary containing the arguments for the command.
                     Expected to include:
                         - asset_names (list[str]): List of asset names to search for.
                         - asset_types (list[str]): List of asset types to search for.
                         - asset_tags (list[str]): List of asset tags to search for.
                         - asset_ids (list[str]): List of asset IDs to search for.
                         - asset_providers (list[str]): List of asset providers to search for.
                         - asset_realms (list[str]): List of asset realms to search for.
                         - asset_group_names (list[str]): List of asset group names to search for.
    """
    asset_group_ids = get_asset_group_ids_from_names(client, argToList(args.get("asset_groups", "")))
    filter = FilterBuilder()
    filter.add_field(ASSET_FIELDS["asset_names"], FilterType.CONTAINS, argToList(args.get("asset_names", "")))
    filter.add_field(ASSET_FIELDS["asset_types"], FilterType.EQ, argToList(args.get("asset_types", "")))
    filter.add_field(ASSET_FIELDS["asset_tags"], FilterType.JSON_WILDCARD, safe_load_json(args.get("asset_tags", [])))
    filter.add_field(ASSET_FIELDS["asset_ids"], FilterType.EQ, argToList(args.get("asset_ids", "")))
    filter.add_field(ASSET_FIELDS["asset_providers"], FilterType.EQ, argToList(args.get("asset_providers", "")))
    filter.add_field(ASSET_FIELDS["asset_realms"], FilterType.EQ, argToList(args.get("asset_realms", "")))
    filter.add_field(ASSET_FIELDS["asset_group_ids"], FilterType.ARRAY_CONTAINS, asset_group_ids)
    filter.add_field(ASSET_FIELDS["asset_categories"], FilterType.EQ, argToList(args.get("asset_categories", "")))
    filter_str = filter.to_dict()

    demisto.debug(f"Search Assets Filter: {filter_str}")
    page_size = arg_to_number(args.get("page_size", SEARCH_ASSETS_DEFAULT_LIMIT))
    page_number = arg_to_number(args.get("page_number", 0))
    on_demand_fields = ["xdm.asset.tags"]
    raw_response = client.search_assets(filter_str, page_number, page_size, on_demand_fields).get("reply", {}).get("data", [])
    # Remove "xdm.asset." suffix from all keys in the response
    response = [
        {k.replace("xdm.asset.", "") if k.startswith("xdm.asset.") else k: v for k, v in item.items()} for item in raw_response
    ]
    return CommandResults(
        readable_output=tableToMarkdown("Assets", response, headerTransform=string_to_table_header),
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.Asset",
        outputs=response,
        raw_response=raw_response,
    )


def validate_scanner_name(scanner_name: str):
    """
    Validate that a scanner name is allowed.

    Args:
        scanner_name (str): The name of the scanner to validate.

    Returns:
        bool: True if the scanner name is valid.

    Raises:
        ValueError: If the scanner name is not in the list of allowed scanners.
    """
    if scanner_name.upper() not in ALLOWED_SCANNERS:
        raise ValueError(f"Invalid scanner '{scanner_name}'. Allowed scanners are: {', '.join(sorted(ALLOWED_SCANNERS))}")


def build_scanner_config_payload(args: dict) -> dict:
    """
    Build a scanner configuration payload for repository scanning.

    Args:
        args (dict): Dictionary containing configuration arguments.
                    Expected to include:
                        - enable_scanners (list): List of scanners to enable.
                        - disable_scanners (list): List of scanners to disable.
                        - pr_scanning (bool): Whether to enable PR scanning.
                        - block_on_error (bool): Whether to block on scanning errors.
                        - tag_resource_blocks (bool): Whether to tag resource blocks.
                        - tag_module_blocks (bool): Whether to tag module blocks.
                        - exclude_paths (list): List of paths to exclude from scanning.

    Returns:
        dict: Scanner configuration payload.

    Raises:
        ValueError: If the same scanner is specified in both enable and disabled lists.
    """
    enabled_scanners = argToList(args.get("enable_scanners", []))
    disabled_scanners = argToList(args.get("disable_scanners", []))
    secret_validation = argToBoolean(args.get("secret_validation", "False"))
    enable_pr_scanning = arg_to_bool_or_none(args.get("pr_scanning"))
    block_on_error = arg_to_bool_or_none(args.get("block_on_error"))
    tag_resource_blocks = arg_to_bool_or_none(args.get("tag_resource_blocks"))
    tag_module_blocks = arg_to_bool_or_none(args.get("tag_module_blocks"))
    exclude_paths = argToList(args.get("exclude_paths", []))

    overlap = set(enabled_scanners) & set(disabled_scanners)
    if overlap:
        raise ValueError(f"Cannot enable and disable the same scanner(s) simultaneously: {', '.join(overlap)}")

    # Build scanners configuration
    scanners = {}
    for scanner in enabled_scanners:
        validate_scanner_name(scanner)
        if scanner.upper() == "SECRETS":
            scanners["SECRETS"] = {"isEnabled": True, "scanOptions": {"secretValidation": secret_validation}}
        else:
            scanners[scanner.upper()] = {"isEnabled": True}

    for scanner in disabled_scanners:
        validate_scanner_name(scanner)
        scanners[scanner.upper()] = {"isEnabled": False}

    # Build scan configuration payload with only relevant arguments
    scan_configuration = {}

    if scanners:
        scan_configuration["scanners"] = scanners

    if args.get("pr_scanning") is not None:
        scan_configuration["prScanning"] = {
            "isEnabled": enable_pr_scanning,
            **({"blockOnError": block_on_error} if block_on_error is not None else {}),
        }

    if args.get("tag_resource_blocks") is not None or args.get("tag_module_blocks") is not None:
        scan_configuration["taggingBot"] = {
            **({"tagResourceBlocks": tag_resource_blocks} if tag_resource_blocks is not None else {}),
            **({"tagModuleBlocks": tag_module_blocks} if tag_module_blocks is not None else {}),
        }

    if exclude_paths:
        scan_configuration["excludedPaths"] = exclude_paths

    demisto.debug(f"{scan_configuration=}")

    return scan_configuration


def enable_scanners_command(client: Client, args: dict):
    """
    Updates repository scan configuration by enabling/disabling scanners and setting scan options.

    Args:
        client (Client): The client instance used to send the request.
        args (dict): Dictionary containing configuration arguments including repository_ids,
                    enabled_scanners, disabled_scanners, and other scan settings.

    Returns:
        CommandResults: Command results with readable output showing update status and raw response.
    """
    repository_ids = argToList(args.get("repository_ids"))
    payload = build_scanner_config_payload(args)

    # Send request to update repository scan configuration
    responses = []
    for repository_id in repository_ids:
        responses.append(client.enable_scanners(payload, repository_id))

    readable_output = f"Successfully updated repositories: {', '.join(repository_ids)}"

    return CommandResults(
        readable_output=readable_output,
        raw_response=responses,
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

    filter = FilterBuilder()
    filter.add_field("XDM.ASSET_GROUP.NAME", FilterType.EQ, group_names)
    filter_str = filter.to_dict()

    groups = client.search_asset_groups(filter_str).get("reply", {}).get("data", [])

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

    webapp_api_url = "/api/webapp"
    public_api_url = f"{webapp_api_url}/public_api/v1"
    data_platform_api_url = f"{webapp_api_url}/data-platform"
    appsec_api_url = f"{webapp_api_url}/public_api/appsec"
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
    elif command in APPSEC_COMMANDS:
        client_url = appsec_api_url

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

        elif command == "core-get-vulnerabilities":
            return_results(get_vulnerabilities_command(client, args))

        elif command == "core-get-issue-recommendations":
            return_results(get_issue_recommendations_command(client, args))
        elif command == "core-enable-scanners":
            return_results(enable_scanners_command(client, args))

    except Exception as err:
        demisto.error(traceback.format_exc())
        return_error(str(err))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
