from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CoreIRApiModule import *
import dateparser
from enum import Enum
import copy

from Packs.Core.Integrations.CortexPlatformCore.CommonServerPython import CommandResults

# Disable insecure warnings
urllib3.disable_warnings()

TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
INTEGRATION_CONTEXT_BRAND = "Core"
INTEGRATION_NAME = "Cortex Platform Core"
MAX_GET_INCIDENTS_LIMIT = 100
SEARCH_ASSETS_DEFAULT_LIMIT = 100
MAX_GET_CASES_LIMIT = 100
MAX_GET_ENDPOINTS_LIMIT = 100
AGENTS_TABLE = "AGENTS_TABLE"
MAX_GET_SYSTEM_USERS_LIMIT = 50
MAX_GET_EXCEPTION_RULES_LIMIT = 100

ASSET_FIELDS = {
    "asset_names": "xdm.asset.name",
    "asset_types": "xdm.asset.type.name",
    "asset_tags": "xdm.asset.tags",
    "asset_ids": "xdm.asset.id",
    "asset_providers": "xdm.asset.provider",
    "asset_realms": "xdm.asset.realm",
    "asset_group_ids": "xdm.asset.group_ids",
    "asset_categories": "xdm.asset.type.category",
    "asset_classes": "xdm.asset.type.class",
    "software_package_versions": "xdm.software_package.version",
    "kubernetes_cluster_versions": "xdm.kubernetes.cluster.version",
}

APPSEC_SOURCES = [
    "CAS_CVE_SCANNER",
    "CAS_IAC_SCANNER",
    "CAS_SECRET_SCANNER",
    "CAS_LICENSE_SCANNER",
    "CAS_SAST_SCANNER",
    "CAS_OPERATIONAL_RISK_SCANNER",
    "CAS_CI_CD_RISK_SCANNER",
    "CAS_DRIFT_SCANNER",
]
WEBAPP_COMMANDS = [
    "core-get-vulnerabilities",
    "core-search-asset-groups",
    "core-get-issue-recommendations",
    "core-get-cases",
    "core-update-issue",
    "core-get-asset-coverage",
    "core-get-asset-coverage-histogram",
    "core-create-appsec-policy",
    "core-get-appsec-issues",
    "core-update-case",
    "core-list-endpoints",
    "core-list-exception-rules",
    "core-update-case",
]
DATA_PLATFORM_COMMANDS = ["core-get-asset-details"]
APPSEC_COMMANDS = ["core-enable-scanners", "core-appsec-remediate-issue"]
XSOAR_COMMANDS = ["core-run-playbook"]

VULNERABLE_ISSUES_TABLE = "VULNERABLE_ISSUES_TABLE"
ASSET_GROUPS_TABLE = "UNIFIED_ASSET_MANAGEMENT_ASSET_GROUPS"
ASSET_COVERAGE_TABLE = "COVERAGE"
APPSEC_RULES_TABLE = "CAS_DETECTION_RULES"
CASES_TABLE = "CASE_MANAGER_TABLE"
DISABLE_PREVENTION_RULES_TABLE = "AGENT_EXCEPTION_RULES_TABLE_ADVANCED"
LEGACY_AGENT_EXCEPTIONS_TABLE = "AGENT_EXCEPTION_RULES_TABLE_LEGACY"


class CaseManagement:
    STATUS_RESOLVED_REASON = {
        "known_issue": "STATUS_040_RESOLVED_KNOWN_ISSUE",
        "duplicate": "STATUS_050_RESOLVED_DUPLICATE",
        "false_positive": "STATUS_060_RESOLVED_FALSE_POSITIVE",
        "true_positive": "STATUS_090_RESOLVED_TRUE_POSITIVE",
        "security_testing": "STATUS_100_RESOLVED_SECURITY_TESTING",
        "other": "STATUS_070_RESOLVED_OTHER",
    }

    FIELDS = {
        "case_id_list": "CASE_ID",
        "case_domain": "INCIDENT_DOMAIN",
        "case_name": "NAME",
        "case_description": "DESCRIPTION",
        "status": "STATUS_PROGRESS",
        "severity": "SEVERITY",
        "creation_time": "CREATION_TIME",
        "asset_ids": "UAI_ASSET_IDS",
        "asset_groups": "UAI_ASSET_GROUP_IDS",
        "assignee": "ASSIGNED_USER_PRETTY",
        "assignee_email": "ASSIGNED_USER",
        "name": "CONTAINS",
        "description": "DESCRIPTION",
        "last_updated": "LAST_UPDATE_TIME",
        "hosts": "HOSTS",
        "starred": "CASE_STARRED",
        "tags": "CURRENT_TAGS",
    }

    STATUS = {
        "new": "STATUS_010_NEW",
        "under_investigation": "STATUS_020_UNDER_INVESTIGATION",
        "resolved": "STATUS_025_RESOLVED",
    }

    SEVERITY = {
        "low": "SEV_020_LOW",
        "medium": "SEV_030_MEDIUM",
        "high": "SEV_040_HIGH",
        "critical": "SEV_050_CRITICAL",
    }

    TAGS = {
        "DOM:Security": "DOM:1",
        "DOM:Posture": "DOM:5",
    }


class Endpoints:
    ENDPOINT_TYPE = {
        "mobile": "AGENT_TYPE_MOBILE",
        "server": "AGENT_TYPE_SERVER",
        "workstation": "AGENT_TYPE_WORKSTATION",
        "containerized": "AGENT_TYPE_CONTAINERIZED",
        "serverless": "AGENT_TYPE_SERVERLESS",
    }
    ENDPOINT_STATUS = {
        "connected": "STATUS_010_CONNECTED",
        "lost": "STATUS_020_LOST",
        "disconnected": "STATUS_040_DISCONNECTED",
        "uninstalled": "STATUS_050_UNINSTALLED",
        "vdi pending login": "STATUS_060_VDI_PENDING_LOG_ON",
        "forensics offline": "STATUS_070_FORENSICS_OFFLINE",
    }
    ENDPOINT_PLATFORM = {
        "windows": "AGENT_OS_WINDOWS",
        "mac": "AGENT_OS_MAC",
        "linux": "AGENT_OS_LINUX",
        "android": "AGENT_OS_ANDROID",
        "ios": "AGENT_OS_IOS",
        "serverless": "AGENT_OS_SERVERLESS",
    }
    ENDPOINT_OPERATIONAL_STATUS = {
        "protected": "PROTECTED",
        "partially protected": "PARTIALLY_PROTECTED",
        "unprotected": "UNPROTECTED",
    }
    ASSIGNED_PREVENTION_POLICY = {
        "pcastro": "0a80deae95e84a90a26e0586a7a6faef",
        "Caas Default": "236a259c803d491484fc5f6d0c198676",
        "kris": "31987a7fb890406ca70287c1fc582cbf",
        "democloud": "44fa048803db4a8f989125a3887baf68",
        "Linux Default": "705e7aae722f45c5ab2926e2639b295f",
        "Android Default": "874e0fb9979c44459ca8f2dfdb3f03d9",
        "Serverless Function Default": "c68bb058bbf94bbcb78d748191978d3b",
        "macOS Default": "c9fd93fcee42486fb270ae0acbb7e0fb",
        "iOS Default": "dc2e804c147f4549a6118c96a5b0d710",
        "Windows Default": "e1f6b443a1e24b27955af39b4c425556",
        "bcpolicy": "f32766a625db4cc29b5dddbfb721fe58",
    }
    ENDPOINT_FIELDS = {
        "endpoint_name": "HOST_NAME",
        "endpoint_type": "AGENT_TYPE",
        "endpoint_status": "AGENT_STATUS",
        "platform": "OS_TYPE",
        "operating_system": "OS_DESC",
        "agent_version": "AGENT_VERSION",
        "agent_eol": "SUPPORTED_VERSION",
        "os_version": "OS_VERSION",
        "ip_address": "IP",
        "domain": "DOMAIN",
        "assigned_prevention_policy": "ACTIVE_POLICY",
        "tags": "TAGS",
        "endpoint_id": "AGENT_ID",
        "operational_status": "OPERATIONAL_STATUS",
        "cloud_provider": "CLOUD_PROVIDER",
        "cloud_region": "CLOUD_REGION",
    }


class AppsecIssues:
    class AppsecIssueType:
        def __init__(self, table_name: str, filters: set[str]):
            self.table_name: str = table_name
            self.filters: set = filters or set()

    ISSUE_TYPES = [
        AppsecIssueType(
            "ISSUES_IAC",
            {"urgency", "repository", "file_path", "automated_fix_available", "sla"},
        ),
        AppsecIssueType(
            "ISSUES_CVES",
            {
                "urgency",
                "repository",
                "file_path",
                "automated_fix_available",
                "sla",
                "cvss_score_gte",
                "epss_score_gte",
                "has_kev",
            },
        ),
        AppsecIssueType(
            "ISSUES_SECRETS",
            {"urgency", "repository", "file_path", "sla", "validation"},
        ),
        AppsecIssueType("ISSUES_WEAKNESSES", {"urgency", "repository", "file_path", "sla"}),
        AppsecIssueType("ISSUES_OPERATIONAL_RISK", {"repository", "file_path", "sla"}),
        AppsecIssueType("ISSUES_LICENSES", {"repository", "file_path", "sla"}),
        AppsecIssueType("ISSUES_CI_CD", {"sla"}),
    ]

    SPECIAL_FILTERS = {
        # List of filters that aren't a part of every Appsec table
        "urgency",
        "repository",
        "file_path",
        "automated_fix_available",
        "sla",
        "epss_score_gte",
        "cvss_score_gte",
        "has_kev",
        "validation",
    }

    SEVERITY_MAPPINGS = {
        "info": "SEV_010_INFO",
        "low": "SEV_020_LOW",
        "medium": "SEV_030_MEDIUM",
        "high": "SEV_040_HIGH",
        "critical": "SEV_050_CRITICAL",
        "unknown": "SEV_090_UNKNOWN",
    }

    SEVERITY_OUTPUT_MAPPINGS = {
        "SEV_010_INFO": "info",
        "SEV_020_LOW": "low",
        "SEV_030_MEDIUM": "medium",
        "SEV_040_HIGH": "high",
        "SEV_050_CRITICAL": "critical",
        "SEV_090_UNKNOWN": "unknown",
    }

    STATUS_MAPPINGS = {
        "New": "STATUS_010_NEW",
        "In Progress": "STATUS_020_UNDER_INVESTIGATION",
        "Resolved": "STATUS_025_RESOLVED",
    }

    STATUS_OUTPUT_MAPPINGS = {
        "STATUS_010_NEW": "New",
        "STATUS_020_UNDER_INVESTIGATION": "In Progress",
        "STATUS_025_RESOLVED": "Resolved",
    }

    SLA_MAPPING = {
        "Approaching": "APPROACHING",
        "On Track": "IN_SLA",
        "Overdue": "OVERDUE",
    }

    SLA_OUTPUT_MAPPING = {
        "APPROACHING": "Approaching",
        "IN_SLA": "On Track",
        "OVERDUE": "Overdue",
    }

    URGENCY_OUTPUT_MAPPING = {
        "NOT_URGENT": "Not Urgent",
        "N/A": "N/A",
        "TOP_URGENT": "Top Urgent",
        "URGENT": "Urgent",
    }


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

COVERAGE_API_FIELDS_MAPPING = {
    "vendor_name": "asset_provider",
    "asset_provider": "unified_provider",
}

EXCEPTION_RULES_TYPE_TO_TABLE_MAPPING = {
    "legacy_agent_exceptions": LEGACY_AGENT_EXCEPTIONS_TABLE,
    "disable_prevention_rules": DISABLE_PREVENTION_RULES_TABLE,
}
# Policy finding type mapping
POLICY_FINDING_TYPE_MAPPING = {
    "CI/CD Risk": "CAS_CI_CD_RISK_SCANNER",
    "Vulnerabilities": "CAS_CVE_SCANNER",
    "IaC Misconfiguration": "CAS_IAC_SCANNER",
    "Licenses": "CAS_LICENSE_SCANNER",
    "Operational Risk": "CAS_OPERATIONAL_RISK_SCANNER",
    "Secrets": "CAS_SECRET_SCANNER",
    "Weaknesses": "CAS_SAST_SCANNER",
}


# Policy category mapping
POLICY_CATEGORY_MAPPING = {
    "Application": "APPLICATION",
    "Repository": "REPOSITORY",
    "CI/CD Instance": "CICD_INSTANCE",
    "CI/CD Pipeline": "CICD_PIPELINE",
    "VCS Collaborator": "VCS_COLLABORATOR",
    "VCS Organization": "VCS_ORGANIZATION",
}

EXCEPTION_RULES_OUTPUT_FIELDS_TO_MAP = {"MODULES", "PROFILE_IDS"}


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
        ADVANCED_IP_MATCH_EXACT = ("ADVANCED_IP_MATCH_EXACT", "OR")
        RELATIVE_TIMESTAMP = ("RELATIVE_TIMESTAMP", "OR")

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
        def __init__(
            self,
            field_name: str,
            filter_type: "FilterType",
            values: Any,
            mappings: dict[str, "FilterType"],
        ):
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

    def add_field_with_mappings(
        self,
        name: str,
        type: "FilterType",
        values: Any,
        mappings: dict[str, "FilterType"],
    ):
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
        if start is not None and end is not None:
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
                    if current_filter_type in [
                        FilterType.IS_EMPTY,
                        FilterType.NIS_EMPTY,
                    ]:
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


def determine_assignee_filter_field(assignee_list: list) -> str:
    """
    Determine whether the assignee should be filtered by email or pretty name.

    Args:
        assignee (list): The assignee values to filter on.

    Returns:
        str: The appropriate field to filter on based on the input.
    """
    if not assignee_list:
        return CaseManagement.FIELDS["assignee"]

    assignee = assignee_list[0]

    if "@" in assignee:
        # If the assignee contains '@', use the email field
        return CaseManagement.FIELDS["assignee_email"]
    else:
        # Otherwise, use the pretty name field
        return CaseManagement.FIELDS["assignee"]


def process_case_response(resp):
    """
    Process case response by removing unnecessary fields.

    Args:
        resp (dict): Response dictionary to be processed

    Returns:
        dict: Cleaned response dictionary
    """
    fields_to_remove = ["layoutId", "layoutRuleName", "sourcesList"]

    reply = resp.get("reply", {})

    for field in fields_to_remove:
        reply.pop(field, None)

    # Remove nested score values
    if "score" in reply and isinstance(reply["score"], dict):
        reply["score"].pop("previous_score_source", None)
        reply["score"].pop("previous_score", None)

    if "incidentDomain" in reply:
        reply["caseDomain"] = reply.pop("incidentDomain")

    return reply


def issue_to_alert(args: dict | str) -> dict | str:
    return replace_substring(args, "issue", "alert")


def alert_to_issue(output: dict | str) -> dict | str:
    return replace_substring(output, "alert", "issue")


def incident_to_case(output: dict | str) -> dict | str:
    return replace_substring(output, "incident", "case")


def case_to_incident(args: dict | str) -> dict | str:
    return replace_substring(args, "case", "incident")


def arg_to_float(arg: Optional[str]):
    """
    Converts an XSOAR argument to a Python float
    """

    if arg is None or arg == "":
        return None

    arg = encode_string_results(arg)

    if isinstance(arg, str):
        try:
            return float(arg)
        except Exception:
            raise ValueError(f'"{arg}" is not a valid number')

    if isinstance(arg, int | float):
        return arg

    raise ValueError(f'"{arg}" is not a valid number')


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

    def update_issue(self, filter_data):
        return self._http_request(method="POST", json_data=filter_data, url_suffix="/alerts/update_alerts")

    def link_issue_to_cases(self, issue_id, case_ids: list) -> dict:
        """Link an issue to one or more cases.

        Args:
            issue_id: The issue ID to link
            case_ids: List of case IDs to link the issue to

        Returns:
            dict: API response
        """
        return self._http_request(
            method="POST", json_data={"issue_ids": [issue_id], "case_ids": case_ids}, url_suffix="/cases/link_issues"
        )

    def unlink_issue_from_cases(self, issue_id, case_ids: list) -> dict:
        """Unlink an issue from one or more cases.

        Args:
            issue_id: The issue ID to unlink
            case_ids: List of case IDs to unlink the issue from

        Returns:
            dict: API response
        """
        return self._http_request(
            method="POST", json_data={"issue_id": issue_id, "case_ids": case_ids}, url_suffix="/cases/unlink_issue"
        )

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
            full_url="/api/webapp/public_api/v1/asset-groups",
        )

        return reply

    def get_webapp_data(self, request_data: dict) -> dict:
        return self._http_request(
            method="POST",
            url_suffix="/get_data",
            json_data=request_data,
        )

    def get_webapp_view_def(self, request_data: dict) -> dict:
        return self._http_request(
            method="GET",
            url_suffix="/get_view_def",
            json_data=request_data,
        )

    def get_webapp_histograms(self, request_data: dict) -> dict:
        return self._http_request(
            method="POST",
            url_suffix="/get_histograms",
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
        return self._http_request(
            method="POST",
            json_data={"alert_internal_id": issue_id},
            headers=self._headers,
            url_suffix="/incident/get_playbook_suggestion_by_alert/",
        )

    def get_playbooks_metadata(self):
        return self._http_request(
            method="GET",
            headers=self._headers,
            full_url="/xsoar/playbooks/metadata",
        )

    def get_quick_actions_metadata(self):
        return self._http_request(
            method="GET",
            headers=self._headers,
            full_url="/xsoar/quickactions",
        )

    def appsec_remediate_issue(self, request_body):
        return self._http_request(
            method="POST",
            data=request_body,
            headers={**self._headers, "content-type": "application/json"},
            url_suffix="/v1/issues/fix/trigger_fix_pull_request",
        )

    def get_appsec_suggested_fix(self, issue_id: str) -> dict | None:
        reply = self._http_request(
            method="GET",
            headers=self._headers,
            full_url=f"/api/webapp/public_api/appsec/v1/issues/fix/{issue_id}/fix_suggestion",
        )
        return reply

    def create_policy(self, policy_payload: str) -> dict:
        """
        Creates a new policy in Cortex XDR.
        Args:
            policy_payload (str): The policy definition payload.
        Returns:
            dict: The response from the API.
        """
        demisto.debug(f"Policy creation payload: {policy_payload}")
        return self._http_request(
            method="POST",
            data=policy_payload,
            headers={**self._headers, "content-type": "application/json"},
            url_suffix="/public_api/appsec/v1/policies",
        )

    def update_case(self, case_update_payload, case_id):
        """
        Update a case with the provided data.

        Args:
            case_update_payload (dict): The data to update in the case.
            case_id (str): Case ID to update.

        Returns:
            dict: Response from the API for the case update.
        """
        request_data = {"request_data": {"newIncidentInterface": True, "case_id": case_id, **case_update_payload}}
        return self._http_request(
            method="POST",
            url_suffix="/case/set_data",
            json_data=request_data,
        )

    def run_playbook(self, issue_ids: list, playbook_id: str) -> dict:
        """
        Runs a specific playbook for a given investigation.

        Args:
            issue_ids: The IDs of the issues.
            playbook_id: The ID of the playbook to run.

        Returns:
            dict: The response from running the playbook.
        """
        return self._http_request(
            method="POST",
            url_suffix="/inv-playbook/new",
            headers={
                **self._headers,
                "Content-Type": "application/json",
            },
            json_data={"alertIds": issue_ids, "playbookId": playbook_id},
        )

    def unassign_case(self, case_id: str) -> dict:
        """
        Unassign a case by updating it with default unassignment data.

        Args:
            case_id (str): Case ID to unassign.

        Returns:
            dict: Response from the API for the case update.
        """
        request_data = {"request_data": {"newIncidentInterface": True, "case_id": case_id}}

        return self._http_request(
            method="POST",
            url_suffix="/case/un_assign_user",
            headers={
                **self._headers,
                "Content-Type": "application/json",
            },
            json_data=request_data,
        )

    def get_users(self):
        reply = self._http_request(
            method="POST",
            json_data={},
            headers=self._headers,
            url_suffix="/rbac/get_users",
        )

        return reply


def get_appsec_suggestion(client: Client, issue: dict, issue_id: str) -> dict:
    """
    Append Application Security - related suggestions to the recommendation data.

    Args:
        client (Client): Client instance used to send the request.
        headers (list): Headers for the readable output.
        issue (dict): Details of the issue.
        recommendation (dict): The base remediation recommendation.
        issue_id (str): The issue ID.

    Returns:
        tuple[list, dict]: Updated headers and recommendation including AppSec additions.
    """
    alert_source = issue.get("alert_source")
    if alert_source not in APPSEC_SOURCES:
        return {}

    recommendation = {}
    manual_fix = issue.get("extended_fields", {}).get("action")
    if manual_fix:
        recommendation["remediation"] = manual_fix

    fix_suggestion = client.get_appsec_suggested_fix(issue_id)
    demisto.debug(f"AppSec fix suggestion: {fix_suggestion}")

    if fix_suggestion and isinstance(fix_suggestion, dict) and fix_suggestion.get("suggestedCodeBlock"):
        recommendation.update(
            {
                "existing_code_block": fix_suggestion.get("existingCodeBlock", ""),
                "suggested_code_block": fix_suggestion.get("suggestedCodeBlock", ""),
            }
        )
    demisto.debug(f"{recommendation=} for {issue=}")

    return recommendation


def populate_playbook_and_quick_action_suggestions(
    client: Client, issue_id: str, pb_id_to_data: dict, qa_name_to_data: dict
) -> dict:
    """
    Fetches playbook and quick-action suggestions for a given issue
    and updates the recommendation dictionary accordingly.

    Returns:
        recommendation
    """
    recommendation = {}

    response = client.get_playbook_suggestion_by_issue(issue_id)
    suggestions = response.get("reply", {})
    demisto.debug(f"Playbooks and quick action {suggestions=} for {issue_id=}")

    if not suggestions:
        return {}

    # Playbook suggestion
    playbook_id = suggestions.get("playbook_id")
    suggestion_rule_id = suggestions.get("suggestion_rule_id")

    if playbook_id:
        recommendation["playbook_suggestions"] = {
            "playbook_id": playbook_id,
            "suggestion_rule_id": suggestion_rule_id,
        }
        pb_data = pb_id_to_data.get(playbook_id)
        if pb_data:
            recommendation["playbook_suggestions"].update(pb_data)

    # Quick action suggestion
    quick_action_id = suggestions.get("quick_action_id", None)
    quick_action_suggestion_rule_id = suggestions.get("quick_action_suggestion_rule_id", None)

    if quick_action_id:
        recommendation["quick_action_suggestions"] = {
            "name": quick_action_id,
            "suggestion_rule_id": quick_action_suggestion_rule_id,
        }
        qa_data = qa_name_to_data.get(quick_action_id)
        if qa_data:
            recommendation["quick_action_suggestions"].update(qa_data)

    return recommendation


def map_qa_name_to_data(qas_metadata) -> dict:
    """
    Maps each quick-action command name to its metadata, filtering hidden arguments
    and removing empty fields.

    Returns:
        dict: command_name → metadata.
    """
    if not isinstance(qas_metadata, list):
        return {}

    qa_name_to_data = {}

    for item in qas_metadata:
        brand = item.get("brand")
        category = item.get("category")

        for cmd in item.get("commands", []):
            cmd_name = cmd.get("name")
            arguments = cmd.get("arguments", [])
            filtered_args = [arg for arg in arguments if not arg.get("hidden", False)]
            qa_name_to_data[cmd_name] = remove_empty_elements(
                {
                    "brand": brand,
                    "category": category,
                    "description": cmd.get("description"),
                    "pretty_name": cmd.get("prettyName"),
                    "arguments": filtered_args,
                }
            )

    return qa_name_to_data


def map_pb_id_to_data(pbs_metadata) -> dict:
    """
    Maps each playbook ID to its corresponding data to enable fast lookups.

    Args:
        pbs_metadata: List of playbook metadata dictionaries.

    Returns:
        dict: Mapping of playbook ID to its data from the metadata list.
    """
    if not isinstance(pbs_metadata, list):
        return {}

    pb_id_to_data = {}
    for pb_metadata in pbs_metadata:
        pb_id = pb_metadata.get("id")
        if pb_id:
            pb_id_to_data[pb_id] = remove_empty_elements({"name": pb_metadata.get("name"), "comment": pb_metadata.get("comment")})

    return pb_id_to_data


def create_issue_recommendations_readable_output(issue_ids: list[str], all_recommendations: list[dict]) -> str:
    """
    Create readable output for issue recommendations with dynamic headers based on content.

    Args:
        issue_ids: List of issue IDs being processed
        all_recommendations: Complete recommendation data used to determine headers and create readable output

    Returns:
        str: Formatted markdown table string for readable output
    """
    # Base headers that are always present
    headers = [
        "issue_id",
        "issue_name",
        "severity",
        "description",
        "remediation",
    ]

    # Flags to track what headers we need to append
    append_appsec_headers = False
    append_playbook_suggestions_header = False
    append_quick_action_suggestions_header = False

    readable_recommendations = []

    # Single loop to both check for headers and create readable recommendations
    for recommendation in all_recommendations:
        # Check what headers we need to append
        if not append_appsec_headers and ("existing_code_block" in recommendation or "suggested_code_block" in recommendation):
            append_appsec_headers = True
        if not append_playbook_suggestions_header and "playbook_suggestions" in recommendation:
            append_playbook_suggestions_header = True
        if not append_quick_action_suggestions_header and "quick_action_suggestions" in recommendation:
            append_quick_action_suggestions_header = True

        # Create readable recommendation
        readable_rec = recommendation.copy()

        # Simplify playbook suggestions for readable output (show only name)
        if "playbook_suggestions" in readable_rec and isinstance(readable_rec["playbook_suggestions"], dict):
            pb_suggestions = readable_rec["playbook_suggestions"]
            readable_rec["playbook_suggestions"] = {
                "name": pb_suggestions.get("name", ""),
                "playbook_id": pb_suggestions.get("playbook_id", ""),
            }

        # Simplify quick action suggestions for readable output (show only pretty_name)
        if "quick_action_suggestions" in readable_rec and isinstance(readable_rec["quick_action_suggestions"], dict):
            qa_suggestions = readable_rec["quick_action_suggestions"]
            readable_rec["quick_action_suggestions"] = {
                "name": qa_suggestions.get("name", ""),
                "pretty_name": qa_suggestions.get("pretty_name", ""),
            }

        readable_recommendations.append(readable_rec)

    # Add conditional headers based on what we found
    if append_appsec_headers:
        headers.extend(["existing_code_block", "suggested_code_block"])

    if append_playbook_suggestions_header:
        headers.append("playbook_suggestions")

    if append_quick_action_suggestions_header:
        headers.append("quick_action_suggestions")

    # Create the readable output table
    issue_readable_output = tableToMarkdown(
        f"Issue Recommendations for {issue_ids}",
        readable_recommendations,
        headerTransform=string_to_table_header,
        headers=headers,
    )

    return issue_readable_output


def get_issue_recommendations_command(client: Client, args: dict) -> CommandResults:
    """
    Get comprehensive recommendations for an issue, including remediation steps and playbook suggestions.
    Retrieves issue data with remediation field using the generic /api/webapp/get_data endpoint.
    """
    issue_ids = argToList(args.get("issue_ids"))
    if len(issue_ids) > 10:
        raise DemistoException("Please provide a maximum of 10 issue IDs per request.")

    filter_builder = FilterBuilder()
    filter_builder.add_field("internal_id", FilterType.EQ, issue_ids)

    request_data = build_webapp_request_data(
        table_name="ALERTS_VIEW_TABLE",
        filter_dict=filter_builder.to_dict(),
        limit=10,
        sort_field="source_insert_ts",
        sort_order="DESC",
        on_demand_fields=[],
    )

    # Get issue data with remediation field
    response = client.get_webapp_data(request_data)
    reply = response.get("reply", {})
    issue_data = reply.get("DATA", [])

    if not issue_data:
        raise DemistoException(f"No issues found with IDs: {issue_ids}")

    # Call the endpoint here to avoid calling it for each issue.
    pbs_metadata = client.get_playbooks_metadata() or []
    qas_metadata = client.get_quick_actions_metadata() or []
    pb_id_to_data = map_pb_id_to_data(pbs_metadata)
    qa_name_to_data = map_qa_name_to_data(qas_metadata)
    all_recommendations = []

    for issue in issue_data:
        current_issue_id = issue.get("internal_id")

        # Base recommendation
        recommendation = {
            "issue_id": current_issue_id,
            "issue_name": issue.get("alert_name"),
            "severity": issue.get("severity"),
            "description": issue.get("alert_description"),
            "remediation": issue.get("remediation"),
        }

        # --- Playbook and Quick Action Suggestions ---
        recommendation_pb_qa = populate_playbook_and_quick_action_suggestions(
            client, current_issue_id, pb_id_to_data, qa_name_to_data
        )
        recommendation.update(recommendation_pb_qa)

        # --- AppSec ---
        appsec_recommendation = get_appsec_suggestion(client, issue, current_issue_id)
        if appsec_recommendation:
            recommendation.update(appsec_recommendation)

        all_recommendations.append(recommendation)

    # Final header adjustments
    issue_readable_output = create_issue_recommendations_readable_output(
        issue_ids=issue_ids, all_recommendations=all_recommendations
    )

    return CommandResults(
        readable_output=issue_readable_output,
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.IssueRecommendations",
        outputs_key_field="issue_id",
        outputs=all_recommendations,
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
    filter_builder.add_field(
        ASSET_GROUP_FIELDS["asset_group_name"],
        FilterType.CONTAINS,
        argToList(args.get("name")),
    )
    filter_builder.add_field(ASSET_GROUP_FIELDS["asset_group_type"], FilterType.EQ, args.get("type"))
    filter_builder.add_field(
        ASSET_GROUP_FIELDS["asset_group_description"],
        FilterType.CONTAINS,
        argToList(args.get("description")),
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
    sort_field: str | None,
    on_demand_fields: list | None = None,
    sort_order: str | None = "DESC",
    start_page: int = 0,
) -> dict:
    """
    Builds the request data for the generic /api/webapp/get_data endpoint.
    """
    sort = (
        [
            {
                "FIELD": COVERAGE_API_FIELDS_MAPPING.get(sort_field, sort_field),
                "ORDER": sort_order,
            }
        ]
        if sort_field
        else []
    )
    filter_data = {
        "sort": sort,
        "paging": {"from": start_page, "to": limit},
        "filter": filter_dict,
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


def build_histogram_request_data(table_name: str, filter_dict: dict, max_values_per_column: int, columns: list) -> dict:
    """
    Builds the request data for the generic /api/webapp//get_histograms endpoint.
    """
    filter_data = {
        "filter": filter_dict,
    }
    demisto.debug(f"{filter_data=}")

    return {
        "table_name": table_name,
        "filter_data": filter_data,
        "max_values_per_column": max_values_per_column,
        "columns": columns,
    }


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
    filter_builder.add_field(
        "INTERNET_EXPOSED",
        FilterType.EQ,
        arg_to_bool_or_none(args.get("internet_exposed")),
    )
    filter_builder.add_field("EXPLOITABLE", FilterType.EQ, arg_to_bool_or_none(args.get("exploitable")))
    filter_builder.add_field("HAS_KEV", FilterType.EQ, arg_to_bool_or_none(args.get("has_kev")))
    filter_builder.add_field(
        "AFFECTED_SOFTWARE",
        FilterType.CONTAINS,
        argToList(args.get("affected_software")),
    )
    filter_builder.add_field(
        "PLATFORM_SEVERITY",
        FilterType.EQ,
        argToList(args.get("severity")),
        VULNERABILITIES_SEVERITY_MAPPING,
    )
    filter_builder.add_field("FINDING_SOURCES", FilterType.CONTAINS_IN_LIST, argToList(args.get("finding_sources")))
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
        "FINDING_SOURCES",
    ]
    filtered_data = [{k: v for k, v in item.items() if k in output_keys} for item in data]

    readable_output = tableToMarkdown(
        "Vulnerabilities",
        filtered_data,
        headerTransform=string_to_table_header,
        sort_headers=False,
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


def extract_ids(case_extra_data: dict) -> list:
    """
    Extract a list of IDs from a command result.

    Args:
        command_res: The result of a command. It can be either a dictionary or a list.
        field_name: The name of the field that contains the ID.

    Returns:
        A list of the IDs extracted from the command result.
    """
    if not case_extra_data:
        return []

    field_name = "issue_id"
    issues = case_extra_data.get("issues", {})
    issues_data = issues.get("data", {}) if issues else {}
    issue_ids = [issue.get(field_name) for issue in issues_data if isinstance(issue, dict) and field_name in issue]
    demisto.debug(f"Extracted issue ids: {issue_ids}")
    return issue_ids


def get_case_extra_data(client, args):
    """
    Calls the core-get-case-extra-data command and parses the output to a standard structure.

    Args:
        args: The arguments to pass to the core-get-case-extra-data command.

    Returns:
        A dictionary containing the case data with the following keys:
            issue_ids: A list of IDs of issues in the case.
            network_artifacts: A list of network artifacts in the case.
            file_artifacts: A list of file artifacts in the case.
    """
    demisto.debug(f"Calling core-get-case-extra-data, {args=}")
    # Set the base URL for this API call to use the public API v1 endpoint
    client._base_url = "api/webapp/public_api/v1"
    case_extra_data = get_extra_data_for_case_id_command(client, args).outputs
    demisto.debug(f"After calling core-get-case-extra-data, {case_extra_data=}")
    issue_ids = extract_ids(case_extra_data)
    case_data = case_extra_data.get("case", {})
    notes = case_data.get("notes")
    xdr_url = case_data.get("xdr_url")
    starred_manually = case_data.get("starred_manually")
    manual_description = case_data.get("manual_description")
    detection_time = case_data.get("detection_time")
    manual_description = case_extra_data.get("manual_description")
    network_artifacts = case_extra_data.get("network_artifacts")
    file_artifacts = case_extra_data.get("file_artifacts")
    extra_data = {
        "issue_ids": issue_ids,
        "network_artifacts": network_artifacts,
        "file_artifacts": file_artifacts,
        "notes": notes,
        "detection_time": detection_time,
        "xdr_url": xdr_url,
        "starred_manually": starred_manually,
        "manual_description": manual_description,
    }
    return extra_data


def add_cases_extra_data(client, cases_list):
    # for each case id in the entry context, get the case extra data
    for case in cases_list:
        case_id = case.get("case_id")
        extra_data = get_case_extra_data(client, {"case_id": case_id, "limit": 1000})
        case.update({"CaseExtraData": extra_data})

    return cases_list


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
        demisto.debug(f"Processing case data: {case_data}")
        mapped_case = {
            "case_id": str(case_data.get("CASE_ID")),
            "case_name": case_data.get("NAME"),
            "description": case_data.get("DESCRIPTION"),
            "creation_time": case_data.get("CREATION_TIME"),
            "modification_time": case_data.get("LAST_UPDATE_TIME"),
            "resolved_timestamp": case_data.get("RESOLVED_TIMESTAMP"),
            "status": str(case_data.get("STATUS", case_data.get("STATUS_PROGRESS"))).split("_")[-1].lower(),
            "severity": str(case_data.get("SEVERITY")).split("_")[-1].lower(),
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
            "issues_grouping_status": str(case_data.get("CASE_GROUPING_STATUS")).split("_")[-1],
            "starred": case_data.get("CASE_STARRED"),
            "case_sources": case_data.get("INCIDENT_SOURCES"),
            "custom_fields": case_data.get("EXTENDED_FIELDS"),
            "hosts": case_data.get("HOSTS") or [],
            "users": case_data.get("USERS") or [],
            "host_count": len(case_data.get("HOSTS", []) or []),
            "user_count": len(case_data.get("USERS", []) or []),
            "issue_categories": case_data.get("ALERT_CATEGORIES"),
            "mitre_techniques_ids_and_names": case_data.get("MITRE_TECHNIQUES"),
            "mitre_tactics_ids_and_names": case_data.get("MITRE_TACTICS"),
            "manual_severity": case_data.get("USER_SEVERITY"),
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

    status_values = [CaseManagement.STATUS[status] for status in argToList(args.get("status"))]
    severity_values = [CaseManagement.SEVERITY[severity] for severity in argToList(args.get("severity"))]
    tag_values = [CaseManagement.TAGS.get(tag, tag) for tag in argToList(args.get("tag"))]
    filter_builder = FilterBuilder()
    filter_builder.add_time_range_field(CaseManagement.FIELDS["creation_time"], gte_creation_time, lte_creation_time)
    filter_builder.add_time_range_field(
        CaseManagement.FIELDS["last_updated"],
        gte_modification_time,
        lte_modification_time,
    )
    filter_builder.add_time_range_field(
        CaseManagement.FIELDS["creation_time"],
        since_creation_start_time,
        since_creation_end_time,
    )
    filter_builder.add_time_range_field(
        CaseManagement.FIELDS["last_updated"],
        since_modification_start_time,
        since_modification_end_time,
    )
    filter_builder.add_field(CaseManagement.FIELDS["status"], FilterType.EQ, status_values)
    filter_builder.add_field(CaseManagement.FIELDS["severity"], FilterType.EQ, severity_values)
    filter_builder.add_field(
        CaseManagement.FIELDS["case_id_list"],
        FilterType.EQ,
        argToList(args.get("case_id_list")),
    )
    filter_builder.add_field(
        CaseManagement.FIELDS["case_domain"],
        FilterType.EQ,
        argToList(args.get("case_domain")),
    )
    filter_builder.add_field(
        CaseManagement.FIELDS["case_name"],
        FilterType.CONTAINS,
        argToList(args.get("case_name")),
    )
    filter_builder.add_field(
        CaseManagement.FIELDS["case_description"],
        FilterType.CONTAINS,
        argToList(args.get("case_description")),
    )
    filter_builder.add_field(
        CaseManagement.FIELDS["starred"],
        FilterType.EQ,
        [argToBoolean(x) for x in argToList(args.get("starred"))],
    )
    filter_builder.add_field(
        CaseManagement.FIELDS["asset_ids"],
        FilterType.CONTAINS_IN_LIST,
        argToList(args.get("asset_ids")),
    )
    filter_builder.add_field(
        CaseManagement.FIELDS["asset_groups"],
        FilterType.CONTAINS_IN_LIST,
        argToList(args.get("asset_groups")),
    )
    filter_builder.add_field(
        CaseManagement.FIELDS["hosts"],
        FilterType.CASE_HOST_EQ,
        argToList(args.get("hosts")),
    )
    filter_builder.add_field(CaseManagement.FIELDS["tags"], FilterType.ARRAY_CONTAINS, tag_values)
    filter_builder.add_field_with_mappings(
        determine_assignee_filter_field(argToList(args.get("assignee"))),
        FilterType.CONTAINS,
        argToList(args.get("assignee")),
        {
            "unassigned": FilterType.IS_EMPTY,
            "assigned": FilterType.NIS_EMPTY,
        },
    )

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

    filter_count = int(reply.get("FILTER_COUNT", "0"))
    returned_count = len(data)

    command_results = []

    command_results.append(
        CommandResults(
            outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.CasesMetadata",
            outputs={"filter_count": filter_count, "returned_count": returned_count},
        )
    )

    get_enriched_case_data = argToBoolean(args.get("get_enriched_case_data", "false"))
    # In case enriched case data was requested
    if get_enriched_case_data and len(data) <= 10:
        if isinstance(data, dict):
            data = [data]

        case_extra_data = add_cases_extra_data(client, data)

        command_results.append(
            CommandResults(
                readable_output=tableToMarkdown("Cases", case_extra_data, headerTransform=string_to_table_header),
                outputs_prefix="Core.Case",
                outputs_key_field="case_id",
                outputs=case_extra_data,
                raw_response=case_extra_data,
            )
        )

    else:
        if get_enriched_case_data:
            command_results.append(
                CommandResults(
                    readable_output="Cannot retrieve enriched case data for more than 10 cases. "
                    "Only standard case data will be shown. "
                    "Try using a more specific query, "
                    "for example specific case IDs you want to get enriched data for.",
                    entry_type=4,
                )
            )

        command_results.append(
            CommandResults(
                readable_output=tableToMarkdown("Cases", data, headerTransform=string_to_table_header),
                outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.Case",
                outputs_key_field="case_id",
                outputs=data,
                raw_response=data,
            )
        )

    return command_results


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


def get_issue_id(args) -> str:
    """Retrieve the issue ID from either provided arguments or calling context.

    Args:
        args (dict): Arguments passed in the command, containing optional issue_id

    Returns:
        str: The extracted issue ID
    """
    issue_id = args.get("id", "")
    if not issue_id:
        issues = demisto.callingContext.get("context", {}).get("Incidents")
        if issues:
            issue = issues[0]
            issue_id = issue.get("id")

    return issue_id


def create_filter_data(issue_id: str, update_args: dict) -> dict:
    """Creates filter data for updating an issue with specified parameters.

    Args:
        issue_id (bool): Issue ID from args or context
        update_args (dict): Dictionary of fields to update

    Returns:
        dict: Object representing updated issue details
    """
    filter_builder = FilterBuilder()
    filter_builder.add_field("internal_id", FilterType.EQ, issue_id)

    filter_data = {
        "filter_data": {"filter": filter_builder.to_dict()},
        "filter_type": "static",
        "update_data": update_args,
    }
    return filter_data


def update_issue_command(client: Client, args: dict):
    """Updates an issue with specified parameters.

    Args:
        client (Client): Client instance to execute the request
        args (dict): Command arguments for updating an issue
    """
    issue_id = get_issue_id(args)
    if not issue_id:
        raise DemistoException("Issue ID is required for updating an issue.")

    status_map = {
        "New": "STATUS_010_NEW",
        "In Progress": "STATUS_020_UNDER_INVESTIGATION",
        "Resolved - Known Issue": "STATUS_040_RESOLVED_KNOWN_ISSUE",
        "Resolved - Duplicate Issue": "STATUS_050_RESOLVED_DUPLICATE",
        "Resolved - False Positive": "STATUS_060_RESOLVED_FALSE_POSITIVE",
        "Resolved - other": "STATUS_070_RESOLVED_OTHER",
        "Resolved - True Positive": "STATUS_090_RESOLVED_TRUE_POSITIVE",
        "Resolved - Security Testing": "STATUS_100_RESOLVED_SECURITY_TESTING",
        "Resolved - Dismissed": "STATUS_240_RESOLVED_DISMISSED",
        "Resolved - Fixed": "STATUS_250_RESOLVED_FIXED",
        "Resolved - Risk Accepted": "STATUS_130_RESOLVED_RISK_ACCEPTED",
    }
    severity_map = {
        "low": "SEV_020_LOW",
        "medium": "SEV_030_MEDIUM",
        "high": "SEV_040_HIGH",
        "critical": "SEV_050_CRITICAL",
    }
    severity_value = args.get("severity")
    status = args.get("status")
    link_cases = [int(case_id) for case_id in argToList(args.get("link_cases"))] if args.get("link_cases") else []
    unlink_cases = [int(case_id) for case_id in argToList(args.get("unlink_cases"))] if args.get("unlink_cases") else []

    update_args = {
        "assigned_user": args.get("assigned_user_mail"),
        "severity": severity_map.get(severity_value) if severity_value else None,
        "name": args.get("name"),
        "occurred": arg_to_timestamp(args.get("occurred"), ""),
        "phase": args.get("phase"),
        "type": args.get("type"),
        "description": args.get("description"),
        "resolution_status": status_map.get(status) if status else None,
    }

    # Remove None values before sending to API
    filtered_update_args = {k: v for k, v in update_args.items() if v is not None}

    if not filtered_update_args and not link_cases and not unlink_cases:
        raise DemistoException("Please provide arguments to update the issue.")

    if link_cases:
        client.link_issue_to_cases(int(issue_id), link_cases)
        demisto.debug(f"Linked issue {issue_id} to cases {link_cases}")

    if unlink_cases:
        client.unlink_issue_from_cases(int(issue_id), unlink_cases)
        demisto.debug(f"Unlinked issue {issue_id} from cases {unlink_cases}")

    if filtered_update_args:
        filter_data = create_filter_data(issue_id, filtered_update_args)
        demisto.debug(filter_data)
        client.update_issue(filter_data)

    return "done"


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


def normalize_key(key: str) -> str:
    """
    Strips the prefixes 'xdm.asset.' or 'xdm.' from the beginning of the key,
    if present, and returns the remaining key unchanged otherwise.

    Args:
        key (str): The original output key.

    Returns:
        str: The normalized key without XDM prefixes.
    """
    if key.startswith("xdm.asset."):
        return key.replace("xdm.asset.", "")

    if key.startswith("xdm."):
        return key.replace("xdm.", "")

    return key


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
    software_package_versions = args.get("software_package_versions", "")
    kubernetes_cluster_versions = args.get("kubernetes_cluster_versions", "")
    filter = FilterBuilder()
    filter.add_field(
        ASSET_FIELDS["asset_names"],
        FilterType.CONTAINS,
        argToList(args.get("asset_names", "")),
    )
    filter.add_field(
        ASSET_FIELDS["asset_types"],
        FilterType.EQ,
        argToList(args.get("asset_types", "")),
    )
    filter.add_field(
        ASSET_FIELDS["asset_tags"],
        FilterType.JSON_WILDCARD,
        safe_load_json(args.get("asset_tags", [])),
    )
    filter.add_field(ASSET_FIELDS["asset_ids"], FilterType.EQ, argToList(args.get("asset_ids", "")))
    filter.add_field(
        ASSET_FIELDS["asset_providers"],
        FilterType.EQ,
        argToList(args.get("asset_providers", "")),
    )
    filter.add_field(
        ASSET_FIELDS["asset_realms"],
        FilterType.EQ,
        argToList(args.get("asset_realms", "")),
    )
    filter.add_field(ASSET_FIELDS["asset_group_ids"], FilterType.ARRAY_CONTAINS, asset_group_ids)
    filter.add_field(
        ASSET_FIELDS["asset_categories"],
        FilterType.EQ,
        argToList(args.get("asset_categories", "")),
    )
    filter.add_field(ASSET_FIELDS["asset_classes"], FilterType.EQ, argToList(args.get("asset_classes", "")))
    filter.add_field(ASSET_FIELDS["software_package_versions"], FilterType.EQ, argToList(software_package_versions))
    filter.add_field(ASSET_FIELDS["kubernetes_cluster_versions"], FilterType.EQ, argToList(kubernetes_cluster_versions))
    filter_str = filter.to_dict()

    demisto.debug(f"Search Assets Filter: {filter_str}")
    page_size = arg_to_number(args.get("page_size", SEARCH_ASSETS_DEFAULT_LIMIT))
    page_number = arg_to_number(args.get("page_number", 0))
    on_demand_fields = ["xdm.asset.tags"]
    version_fields = [
        ("xdm.software_package.version", software_package_versions),
        ("xdm.kubernetes.cluster.version", kubernetes_cluster_versions),
    ]
    on_demand_fields.extend([field for field, condition in version_fields if condition])

    raw_response = client.search_assets(filter_str, page_number, page_size, on_demand_fields).get("reply", {}).get("data", [])
    # Remove "xdm.asset." suffix from all keys in the response
    response = [{normalize_key(k): v for k, v in item.items()} for item in raw_response]
    return CommandResults(
        readable_output=tableToMarkdown("Assets", response, headerTransform=string_to_table_header),
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.Asset",
        outputs_key_field="id",
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
            scanners["SECRETS"] = {
                "isEnabled": True,
                "scanOptions": {"secretValidation": secret_validation},
            }
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


def appsec_remediate_issue_command(client: Client, args: dict) -> CommandResults:
    """
    Create automated pull requests to fix multiple security issues in a single bulk operation.

    Args:
        client (Client): The client instance used to send the request.
        args (dict): Dictionary containing the arguments for the command.
                     Expected to include:
                         - issueIds (str): List of issue IDs to fix.
                         - title (str): Title of the PR triggered.

    Returns:
        CommandResults: Object containing the formatted extra data,
                        raw response, and outputs for integration context.
    """
    args = demisto.args()
    issue_ids = argToList(args.get("issue_ids"))
    if len(issue_ids) > 10:
        raise DemistoException("Please provide a maximum of 10 issue IDs per request.")

    triggered_prs = []
    for issue_id in issue_ids:
        request_body = {"issueIds": [issue_id], "title": args.get("title")}
        request_body = remove_empty_elements(request_body)
        current_response = client.appsec_remediate_issue(request_body)
        if current_response and isinstance(current_response, dict):
            current_triggered_prs = current_response.get("triggeredPrs")
            if isinstance(current_triggered_prs, list) and len(current_triggered_prs) > 0:
                triggered_prs.append(current_triggered_prs[0])

    return CommandResults(
        readable_output=tableToMarkdown(name="Triggered PRs", t=triggered_prs),
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.TriggeredPRs",
        outputs=triggered_prs,
        outputs_key_field="issueId",
        raw_response=triggered_prs,
    )


def build_asset_coverage_filter(args: dict) -> FilterBuilder:
    filter_builder = FilterBuilder()
    filter_builder.add_field("asset_id", FilterType.CONTAINS, argToList(args.get("asset_id")))
    filter_builder.add_field("asset_name", FilterType.CONTAINS, argToList(args.get("asset_name")))
    filter_builder.add_field(
        "business_application_names",
        FilterType.ARRAY_CONTAINS,
        argToList(args.get("business_application_names")),
    )
    filter_builder.add_field("status_coverage", FilterType.EQ, argToList(args.get("status_coverage")))
    filter_builder.add_field(
        "is_scanned_by_vulnerabilities",
        FilterType.EQ,
        argToList(args.get("is_scanned_by_vulnerabilities")),
    )
    filter_builder.add_field(
        "is_scanned_by_code_weakness",
        FilterType.EQ,
        argToList(args.get("is_scanned_by_code_weakness")),
    )
    filter_builder.add_field(
        "is_scanned_by_secrets",
        FilterType.EQ,
        argToList(args.get("is_scanned_by_secrets")),
    )
    filter_builder.add_field("is_scanned_by_iac", FilterType.EQ, argToList(args.get("is_scanned_by_iac")))
    filter_builder.add_field(
        "is_scanned_by_malware",
        FilterType.EQ,
        argToList(args.get("is_scanned_by_malware")),
    )
    filter_builder.add_field("is_scanned_by_cicd", FilterType.EQ, argToList(args.get("is_scanned_by_cicd")))
    filter_builder.add_field("last_scan_status", FilterType.EQ, argToList(args.get("last_scan_status")))
    filter_builder.add_field("asset_type", FilterType.EQ, argToList(args.get("asset_type")))
    filter_builder.add_field("unified_provider", FilterType.EQ, argToList(args.get("asset_provider")))
    filter_builder.add_field("asset_provider", FilterType.EQ, argToList(args.get("vendor_name")))

    return filter_builder


def build_exception_rules_filter(args: dict) -> FilterBuilder:
    filter_builder = FilterBuilder()
    filter_builder.add_field("ID", FilterType.CONTAINS, argToList(args.get("id")))
    filter_builder.add_field("NAME", FilterType.CONTAINS, argToList(args.get("rule_name")))
    filter_builder.add_field("PLATFORM", FilterType.EQ, argToList(args.get("platform")))
    filter_builder.add_field("CONDITIONS_PRETTY", FilterType.CONTAINS, argToList(args.get("conditions")))
    filter_builder.add_field("CREATED_BY", FilterType.CONTAINS, argToList(args.get("created_by")))
    filter_builder.add_field("USER_EMAIL", FilterType.CONTAINS, argToList(args.get("user_email")))
    start_modification_time_str, end_modification_time_str = (
        args.get("start_modification_time"),
        args.get("end_modification_time"),
    )
    if end_modification_time_str and not start_modification_time_str:
        start_modification_time_str = "0"
    filter_builder.add_time_range_field("MODIFICATION_TIME", start_modification_time_str, end_modification_time_str)
    filter_builder.add_field("STATUS", FilterType.EQ, argToList(args.get("status")))
    filter_builder.add_field("SUBTYPE", FilterType.EQ, argToList(args.get("rule_type")))
    return filter_builder


def get_asset_coverage_command(client: Client, args: dict):
    """
    Retrieves ASPM assets coverage using the generic /api/webapp/get_data endpoint.
    """

    request_data = build_webapp_request_data(
        table_name=ASSET_COVERAGE_TABLE,
        filter_dict=build_asset_coverage_filter(args).to_dict(),
        limit=arg_to_number(args.get("limit")) or 100,
        sort_field=args.get("sort_field"),
        sort_order=args.get("sort_order"),
    )
    response = client.get_webapp_data(request_data)
    reply = response.get("reply", {})
    data = reply.get("DATA", [])

    readable_output = tableToMarkdown(
        "ASPM Coverage",
        data,
        headerTransform=string_to_table_header,
        sort_headers=False,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.Coverage.Asset",
        outputs_key_field="asset_id",
        outputs=data,
        raw_response=response,
    )


def get_asset_coverage_histogram_command(client: Client, args: dict):
    """
    Retrieves ASPM assets coverage histogrm using the generic /api/webapp/get_histograms endpoint.
    """
    columns = argToList(args.get("columns"))
    columns = [COVERAGE_API_FIELDS_MAPPING.get(col, col) for col in columns]
    if not columns:
        raise ValueError("Please provide column value to create the histogram.")
    request_data = build_histogram_request_data(
        table_name=ASSET_COVERAGE_TABLE,
        filter_dict=build_asset_coverage_filter(args).to_dict(),
        columns=columns,
        max_values_per_column=arg_to_number(args.get("max_values_per_column")) or 100,
    )

    response = client.get_webapp_histograms(request_data)
    reply = response.get("reply", {})
    outputs = [{"column_name": column_name, "data": data} for column_name, data in reply.items()]

    readable_output = "\n".join(
        tableToMarkdown(
            f"ASPM Coverage {output['column_name']} Histogram",
            output["data"],
            headerTransform=string_to_table_header,
            sort_headers=False,
        )
        for output in outputs
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.Coverage.Histogram",
        outputs=outputs,
        raw_response=response,
    )


def get_appsec_rule_ids_from_names(client, rule_names: list[str]) -> list[str]:
    """
    Retrieves the IDs of AppSec rules based on their names using exact and partial matching.

    Args:
        client (Client): The client instance used to send the request.
        rule_names (list[str]): List of AppSec rule names to retrieve IDs for.

    Returns:
        list[str]: List of AppSec rule IDs.

    Raises:
        DemistoException: If any rule names cannot be found in the system.
    """
    if not rule_names:
        return []

    fb = FilterBuilder()
    fb.add_field("ruleName", FilterType.EQ, rule_names)
    data = (
        client.get_webapp_data(build_webapp_request_data(APPSEC_RULES_TABLE, fb.to_dict(), limit=200, sort_field="ruleName"))
        .get("reply", {})
        .get("DATA", [])
        or []
    )

    lookup = {r["ruleName"].lower(): r["ruleId"] for r in data if r.get("ruleId")}
    ids, found = [], set()

    for name in rule_names:
        n = name.lower()
        rid = lookup.get(n) or next((v for k, v in lookup.items() if n in k), None)
        if rid:
            ids.append(rid)
            found.add(name)

    missing = set(rule_names) - found
    if missing:
        raise DemistoException(f"Missing AppSec rules: {', '.join(missing)}")

    return ids


def create_policy_command(client: Client, args: dict) -> CommandResults:
    """
    Creates a new policy in Cortex Platform with defined conditions, scope, and triggers.
    Args:
        client: The Cortex Platform client instance.
        args: Dictionary containing policy configuration parameters including:
            - policy_name: Required name for the new policy
            - description: Optional policy description
            - asset_group_names: Asset groups to apply the policy to
            - conditions_*: Various condition parameters (finding type, severity, etc.)
            - scope_*: Policy scope configuration parameters
            - trigger_*: Policy trigger configuration (periodic, PR, CI/CD)

    Returns:
        CommandResults: Results object containing the created policy information with
        readable output, outputs prefix, and raw response data.

    Raises:
        DemistoException: If policy name is missing or no triggers are enabled.
    """
    policy_name = args.get("policy_name")
    if not policy_name:
        raise DemistoException("Policy name is required.")

    description = args.get("description", "")
    group_names = argToList(args.get("asset_group_names"))
    asset_group_ids = get_asset_group_ids_from_names(client, group_names)

    conditions = create_policy_build_conditions(client, args)
    scope = create_policy_build_scope(args)
    triggers = create_policy_build_triggers(args)

    # Ensure at least one trigger is enabled
    if not any(trigger.get("isEnabled") for trigger in triggers.values()):
        raise DemistoException("At least one trigger (periodic, PR, or CI/CD) must be enabled for the policy.")

    payload = {
        "name": policy_name,
        "description": description,
        "conditions": conditions,
        "scope": scope,
        "assetGroupIds": asset_group_ids,
        "triggers": triggers,
    }
    payload = json.dumps(payload)
    demisto.debug(f"{payload=}")

    client.create_policy(payload)

    return CommandResults(readable_output=f"AppSec policy '{policy_name}' created successfully.")


def create_policy_build_conditions(client: Client, args: dict) -> dict:
    """
    Build conditions for create-policy command based on provided arguments.

    Creates a filter structure for policy conditions including finding types, severity,
    developer suppression, backlog status, package information, AppSec rules, CVSS/EPSS scores,
    and various boolean conditions. If no finding types are specified, defaults to all types
    except "CI/CD Risk".

    Args:
        client: The Cortex Platform client instance
        args: Dictionary containing condition arguments from the command

    Returns:
        dict: Filter dictionary containing all specified conditions
    """
    builder = FilterBuilder()

    finding_types = argToList(args.get("conditions_finding_type"))
    if not finding_types:
        # Default to all finding types if none specified
        finding_types = [ft for ft in POLICY_FINDING_TYPE_MAPPING if ft != "CI/CD Risk"]

    builder.add_field("Finding Type", FilterType.EQ, finding_types, POLICY_FINDING_TYPE_MAPPING)

    # Severity
    if severities := argToList(args.get("conditions_severity")):
        builder.add_field("Severity", FilterType.EQ, severities)

    # Developer Suppression
    if dev_supp := arg_to_bool_or_none(args.get("conditions_respect_developer_suppression")):
        builder.add_field("Respect Developer Suppression", FilterType.EQ, dev_supp)

    # Backlog
    if backlog := args.get("conditions_backlog_status"):
        builder.add_field("Backlog Status", FilterType.EQ, backlog)

    # Packages
    for field in ["package_name", "package_version", "package_operational_risk"]:
        if val := args.get(f"conditions_{field}"):
            op = FilterType.CONTAINS if field == "package_name" else FilterType.EQ
            builder.add_field(field.replace("_", " ").title(), op, val)

    # AppSec Rules
    if rule_names := argToList(args.get("conditions_appsec_rule_names")):
        rule_ids = get_appsec_rule_ids_from_names(client, rule_names)
        builder.add_field("AppSec Rule", FilterType.EQ, rule_ids)

    # CVSS / EPSS
    for f, n in [("cvss", "CVSS"), ("epss", "EPSS")]:
        if val := arg_to_number(args.get(f"conditions_{f}")):
            builder.add_field(n, FilterType.GTE, val)

    # Boolean Conditions
    for key, label in {
        "has_a_fix": "HasAFix",
        "is_kev": "IsKev",
    }.items():
        if val := arg_to_bool_or_none(args.get(f"conditions_{key}")):
            builder.add_field(label, FilterType.EQ, val)

    # Secret Validity, License Type
    for key, label in {
        "secret_validity": "SecretValidity",
        "license_type": "LicenseType",
    }.items():
        if vals := argToList(args.get(f"conditions_{key}", [])):
            builder.add_field(label, FilterType.EQ, vals)

    return builder.to_dict()


def parse_custom_fields(custom_fields: str) -> dict:
    """
    Parse and sanitize custom fields from JSON string input.

    Args:
        custom_fields: JSON string containing array of custom field objects

    Returns:
        dict: Dictionary with sanitized alphanumeric keys and string values,
              duplicate keys are ignored (first occurrence wins)
    """
    custom_fields = safe_load_json(custom_fields)

    parsed_fields = {}

    for custom_field in custom_fields:
        for key, value in custom_field.items():
            # Sanitize key: remove non-alphanumeric characters
            sanitized_key = "".join(char for char in key if char.isalnum())
            if sanitized_key and sanitized_key not in parsed_fields:
                parsed_fields[sanitized_key] = str(value)

    return parsed_fields


def create_policy_build_scope(args: dict) -> dict:
    """
    Build scope filters for create-policy.
    Processes various scope parameters including categories, business applications,
    repository settings, and boolean filters like public repository status and
    security characteristics.

    Args:
        args: Dictionary containing scope filter parameters with keys like:
            - scope_category: List of categories to filter by
            - scope_business_application_names: Business application names
            - scope_application_business_criticality: Application criticality level
            - scope_repository_name: Repository name to filter
            - scope_is_public_repository: Boolean for public repository filter
            - scope_has_deployed_assets: Boolean for deployed assets filter
            - scope_has_internet_exposed_deployed_assets: Boolean for internet exposure filter
            - scope_has_sensitive_data_access: Boolean for sensitive data access filter
            - scope_has_privileged_capabilities: Boolean for privileged capabilities filter

    Returns:
        dict: Filter dictionary structure for policy scope, can be empty if no scope filters set
    """
    builder = FilterBuilder()

    # Category
    if categories := argToList(args.get("scope_category", [])):
        builder.add_field("category", FilterType.EQ, categories, POLICY_CATEGORY_MAPPING)

    # Business application names - use the exact field name
    if business_app_names := argToList(args.get("scope_business_application_names")):
        filter_type = FilterType.ARRAY_CONTAINS if len(business_app_names) > 1 else FilterType.CONTAINS
        builder.add_field("business_application_names", filter_type, business_app_names)

    # Application business criticality
    if app_criticality := args.get("scope_application_business_criticality"):
        builder.add_field("application_business_criticality", FilterType.CONTAINS, app_criticality)

    # Repository name
    if repo_name := args.get("scope_repository_name"):
        builder.add_field("repository_name", FilterType.CONTAINS, repo_name)

    # Boolean scope filters
    for key, label in {
        "scope_is_public_repository": "is_public_repository",
        "scope_has_deployed_assets": "has_deployed_assets",
        "scope_has_internet_exposed_deployed_assets": "has_internet_exposed",
        "scope_has_sensitive_data_access": "has_sensitive_data_access",
        "scope_has_privileged_capabilities": "has_privileged_capabilities",
    }.items():
        if val := arg_to_bool_or_none(args.get(key)):
            builder.add_field(label, FilterType.EQ, val)

    # Always return the filter dict (can be empty for scope)
    return builder.to_dict()


def create_policy_build_triggers(args: dict) -> dict:
    """
    Build triggers configuration for policy creation.

    Creates a complete triggers structure with periodic, PR, and CI/CD trigger types.
    Each trigger includes enabled status, actions, and optional severity overrides.

    Args:
        args (dict): Command arguments containing trigger configuration parameters:
            - triggers_periodic_report_issue: Enable periodic issue reporting
            - triggers_periodic_override_severity: Override severity for periodic triggers
            - triggers_pr_report_issue: Enable PR issue reporting
            - triggers_pr_block_pr: Enable PR blocking
            - triggers_pr_report_pr_comment: Enable PR comment reporting
            - triggers_pr_override_severity: Override severity for PR triggers
            - triggers_cicd_report_issue: Enable CI/CD issue reporting
            - triggers_cicd_block_cicd: Enable CI/CD blocking
            - triggers_cicd_report_cicd: Enable CI/CD reporting
            - triggers_cicd_override_severity: Override severity for CI/CD triggers

    Returns:
        dict: Triggers configuration with periodic, PR, and CI/CD sections.
              Each section contains isEnabled flag, actions dict, and overrideIssueSeverity.

    Raises:
        DemistoException: When no triggers are enabled (at least one must be set).

    Note:
        When an override severity is specified, reportIssue is automatically enabled
        for that trigger type.
    """
    # Periodic trigger
    periodic_report_issue = argToBoolean(args.get("triggers_periodic_report_issue", False))
    periodic_override = args.get("triggers_periodic_override_severity")

    # If override is set, reportIssue must be True
    if periodic_override:
        periodic_report_issue = True

    periodic_enabled = periodic_report_issue or bool(periodic_override)

    # PR trigger
    pr_report_issue = argToBoolean(args.get("triggers_pr_report_issue", False))
    pr_block_pr = argToBoolean(args.get("triggers_pr_block_pr", False))
    pr_report_comment = argToBoolean(args.get("triggers_pr_report_pr_comment", False))
    pr_override = args.get("triggers_pr_override_severity")

    # If override is set, reportIssue must be True
    if pr_override:
        pr_report_issue = True

    pr_enabled = pr_report_issue or pr_block_pr or pr_report_comment or bool(pr_override)

    # CI/CD trigger
    cicd_report_issue = argToBoolean(args.get("triggers_cicd_report_issue", False))
    cicd_block_cicd = argToBoolean(args.get("triggers_cicd_block_cicd", False))
    cicd_report_cicd = argToBoolean(args.get("triggers_cicd_report_cicd", False))
    cicd_override = args.get("triggers_cicd_override_severity")

    # If override is set, reportIssue must be True
    if cicd_override:
        cicd_report_issue = True

    cicd_enabled = cicd_report_issue or cicd_block_cicd or cicd_report_cicd or bool(cicd_override)

    triggers = {
        "periodic": {
            "isEnabled": periodic_enabled,
            "actions": {"reportIssue": periodic_report_issue},
        },
        "pr": {
            "isEnabled": pr_enabled,
            "actions": {
                "reportIssue": pr_report_issue,
                "blockPr": pr_block_pr,
                "reportPrComment": pr_report_comment,
            },
        },
        "cicd": {
            "isEnabled": cicd_enabled,
            "actions": {
                "reportIssue": cicd_report_issue,
                "blockCicd": cicd_block_cicd,
                "reportCicd": cicd_report_cicd,
            },
        },
    }

    # Add override severity if specified (and set to null if not specified)
    triggers["periodic"]["overrideIssueSeverity"] = periodic_override if periodic_override else None
    triggers["pr"]["overrideIssueSeverity"] = pr_override if pr_override else None
    triggers["cicd"]["overrideIssueSeverity"] = cicd_override if cicd_override else None

    # Ensure at least one trigger is enabled
    if not any(t["isEnabled"] for t in triggers.values()):
        raise DemistoException("At least one trigger (periodic, PR, or CI/CD) must be set.")

    return triggers


def create_appsec_issues_filter_and_tables(args: dict) -> dict[str, FilterBuilder]:
    """
    Generate a filter and determine applicable tables for fetching AppSec issues based on input filter arguments.

    Args:
        args (dict): Command input args for core-appsec-get-issues.

    Returns:
        tuple[list, FilterBuilder]: A tuple containing:
            - A list of applicable issue type table names
            - A FilterBuilder instance with configured filters
    """
    special_filter_args = {filter for filter in args if filter in AppsecIssues.SPECIAL_FILTERS}
    tables_filters = {}
    filter_builder = FilterBuilder()

    for issue_type in AppsecIssues.ISSUE_TYPES:
        if special_filter_args.issubset(issue_type.filters):
            tables_filters[issue_type.table_name] = filter_builder

    if not tables_filters:
        raise DemistoException(f"No matching issue type found for the given filter combination: {special_filter_args}")

    filter_builder.add_field(
        "cas_issues_cvss_score",
        FilterType.GTE,
        arg_to_float(args.get("cvss_score_gte")),
    )
    filter_builder.add_field(
        "cas_issues_epss_score",
        FilterType.GTE,
        arg_to_float(args.get("epss_score_gte")),
    )
    filter_builder.add_field("cas_issues_is_kev", FilterType.EQ, arg_to_bool_or_none(args.get("has_kev")))
    filter_builder.add_field(
        "cas_sla_status",
        FilterType.EQ,
        argToList(args.get("sla")),
        AppsecIssues.SLA_MAPPING,
    )
    filter_builder.add_field(
        "cas_issues_is_fixable",
        FilterType.EQ,
        arg_to_bool_or_none(args.get("automated_fix_available")),
    )
    filter_builder.add_field("cas_issues_validation", FilterType.EQ, argToList(args.get("validation")))
    filter_builder.add_field("urgency", FilterType.EQ, argToList(args.get("urgency")))
    filter_builder.add_field(
        "severity",
        FilterType.EQ,
        argToList(args.get("severity")),
        AppsecIssues.SEVERITY_MAPPINGS,
    )
    filter_builder.add_field("internal_id", FilterType.CONTAINS, argToList(args.get("issue_id")))
    filter_builder.add_field("alert_name", FilterType.CONTAINS, argToList(args.get("issue_name")))
    filter_builder.add_field("cas_issues_asset_name", FilterType.CONTAINS, argToList(args.get("asset_name")))
    filter_builder.add_field("cas_issues_repository", FilterType.CONTAINS, argToList(args.get("repository")))
    filter_builder.add_field("cas_issues_file_path", FilterType.CONTAINS, argToList(args.get("file_path")))
    filter_builder.add_field("cas_issues_git_user", FilterType.CONTAINS, argToList(args.get("collaborator")))
    filter_builder.add_field("status_progress", FilterType.EQ, argToList(args.get("status")))
    filter_builder.add_time_range_field("local_insert_ts", args.get("start_time"), args.get("end_time"))
    filter_builder.add_field_with_mappings(
        "assigned_to_pretty",
        FilterType.CONTAINS,
        argToList(args.get("assignee")),
        {
            "unassigned": FilterType.IS_EMPTY,
            "assigned": FilterType.NIS_EMPTY,
        },
    )

    if "backlog_status" in args and "ISSUES_CI_CD" in tables_filters:
        # backlog filter is different for the CI/CD issue table
        cicd_filter_builder = copy.deepcopy(filter_builder)
        cicd_filter_builder.add_field("issue_backlog_status", FilterType.EQ, argToList(args.get("backlog_status")))
        tables_filters["ISSUES_CI_CD"] = cicd_filter_builder

    filter_builder.add_field("backlog_status", FilterType.EQ, argToList(args.get("backlog_status")))

    return tables_filters


def normalize_and_filter_appsec_issue(issue: dict) -> dict:
    """
    Transforms raw issue data from the main issue table into the AppSec issues format.

    Args:
        raw_issue (dict): Raw issue data retrieved from the alerts view table.

    Returns:
        dict: issue with standard Appsec fields.
    """
    issue_all_fields = cast(dict, alert_to_issue(issue))

    filtered_output_keys: dict[str, dict] = {
        "internal_id": {"path": ["internal_id"]},
        "severity": {
            "path": ["severity"],
            "mapper": AppsecIssues.SEVERITY_OUTPUT_MAPPINGS,
        },
        "issue_name": {"path": ["issue_name"]},
        "issue_source": {"path": ["issue_source"]},
        "issue_category": {"path": ["issue_category"]},
        "issue_domain": {"path": ["issue_domain"]},
        "issue_description": {"path": ["issue_description"]},
        "status": {
            "path": ["status_progress"],
            "mapper": AppsecIssues.STATUS_OUTPUT_MAPPINGS,
        },
        "asset_name": {"path": ["cas_issues_asset_name"]},
        "assignee": {"path": ["assigned_to_pretty"]},
        "time_added": {"path": ["source_insert_ts"]},
        "epss_score": {"path": ["cas_issues_extended_fields", "epss_score"]},
        "cvss_score": {"path": ["cas_issues_normalized_fields", "xdm.vulnerability.cvss_score"]},
        "has_kev": {"path": ["cas_issues_is_kev"]},
        "urgency": {"path": ["urgency"], "mapper": AppsecIssues.URGENCY_OUTPUT_MAPPING},
        "sla_status": {
            "path": ["cas_sla_status"],
            "mapper": AppsecIssues.SLA_OUTPUT_MAPPING,
        },
        "secret_validation": {"path": ["secret_validation"]},
        "is_fixable": {"path": ["cas_issues_is_fixable"]},
        "repository_name": {"path": ["cas_issues_normalized_fields", "xdm.repository.name"]},
        "repository_organization": {"path": ["cas_issues_normalized_fields", "xdm.repository.organization"]},
        "file_path": {"path": ["cas_issues_normalized_fields", "xdm.file.path"]},
        "collaborator": {"path": ["cas_issues_normalized_fields", "xdm.code.git.commit.author.name"]},
        "is_deployed": {"path": ["cas_issues_extended_fields", "urgency", "metric", "is_deployed"]},
        "backlog_status": {"path": ["backlog_status"]},
    }
    appsec_issue = {}
    for output_key, output_info in filtered_output_keys.items():
        current_value = issue_all_fields
        path = output_info.get("path", {})
        for key in path:
            current_value = current_value.get(key, {})

        if current_value:
            value = current_value if "mapper" not in output_info else output_info.get("mapper", {}).get(current_value)
            appsec_issue[output_key] = value

    return appsec_issue


def get_appsec_issues_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves application security issues based on specified filters across multiple issue types.
    """
    limit = arg_to_number(args.get("limit")) or 50
    sort_field = args.get("sort_field", "severity")
    sort_order = args.get("sort_order", "DESC")

    tables_filters: dict[str, FilterBuilder] = create_appsec_issues_filter_and_tables(args)

    all_appsec_issues: list[dict] = []
    for table_name, filter_builder in tables_filters.items():
        request_data = build_webapp_request_data(
            table_name=table_name,
            filter_dict=filter_builder.to_dict(),
            limit=limit,
            sort_field=sort_field,
            sort_order=sort_order,
        )
        try:
            demisto.debug(f"Fetching issues from table {table_name}")
            response = client.get_webapp_data(request_data)
            reply = response.get("reply", {})
            data = reply.get("DATA", [])
            all_appsec_issues.extend(data)
        except Exception as e:
            raise DemistoException(f"Failed to retrieve issues from the {table_name} table: {e}")

    sorted_issues = sorted(
        all_appsec_issues,
        key=lambda issue: issue.get(sort_field, ""),
        reverse=(sort_order == "DESC"),
    )
    sorted_issues = sorted_issues[:limit]
    filtered_appsec_issues = [normalize_and_filter_appsec_issue(issue) for issue in sorted_issues]

    readable_output = tableToMarkdown(
        "Application Security Issues",
        filtered_appsec_issues,
        headerTransform=string_to_table_header,
        sort_headers=False,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.AppsecIssue",
        outputs_key_field="internal_id",
        outputs=filtered_appsec_issues,
        raw_response=all_appsec_issues,
    )


def update_case_command(client: Client, args: dict) -> CommandResults:
    """
    Updates one or more cases with the specified parameters such as name, description, assignee, status, and custom fields.

    Handles case status changes including resolution with proper validation, and supports bulk updates across multiple cases.
    Validates input parameters and returns appropriate error messages for invalid values.
    """
    case_ids = argToList(args.get("case_id"))
    case_name = args.get("case_name", "")
    description = args.get("description", "")
    assignee = args.get("assignee", "").lower()
    status = args.get("status", "")
    notes = args.get("notes", "")
    starred = args.get("starred", "")
    user_defined_severity = args.get("user_defined_severity", "")
    resolve_reason = args.get("resolve_reason", "")
    resolved_comment = args.get("resolved_comment", "")
    resolve_all_alerts = args.get("resolve_all_alerts", "")
    custom_fields = parse_custom_fields(args.get("custom_fields", []))
    if assignee == "unassigned":
        for case_id in case_ids:
            client.unassign_case(case_id)
        assignee = ""

    if status == "resolved" and (not resolve_reason or not CaseManagement.STATUS_RESOLVED_REASON.get(resolve_reason, False)):
        raise ValueError("In order to set the case to resolved, you must provide a resolve reason.")

    if (resolve_reason or resolve_all_alerts or resolved_comment) and not status == "resolved":
        raise ValueError(
            "In order to use resolve_reason, resolve_all_alerts, or resolved_comment, the case status must be set to "
            "'resolved.'"
        )

    if status and not CaseManagement.STATUS.get(status):
        raise ValueError(f"Invalid status '{status}'. Valid statuses are: {list(CaseManagement.STATUS.keys())}")

    if user_defined_severity and not CaseManagement.SEVERITY.get(user_defined_severity, False):
        raise ValueError(
            f"Invalid user_defined_severity '{user_defined_severity}'. Valid severities are: "
            f"{list(CaseManagement.SEVERITY.keys())}"
        )

    # Build request_data with mapped and filtered values
    case_update_payload = {
        "caseName": case_name if case_name else None,
        "description": description if description else None,
        "assignedUser": assignee if assignee else None,
        "notes": notes if notes else None,
        "starred": starred if starred else None,
        "status": CaseManagement.STATUS.get(status) if status else None,
        "userSeverity": CaseManagement.SEVERITY.get(user_defined_severity) if user_defined_severity else None,
        "resolve_reason": CaseManagement.STATUS_RESOLVED_REASON.get(resolve_reason) if resolve_reason else None,
        "caseResolvedComment": resolved_comment if resolved_comment else None,
        "resolve_all_alerts": resolve_all_alerts if resolve_all_alerts else None,
        "CustomFields": custom_fields if custom_fields else None,
    }
    remove_nulls_from_dictionary(case_update_payload)

    if not case_update_payload and args.get("assignee", "").lower() != "unassigned":
        raise ValueError("No valid update parameters provided for case update.")

    demisto.info(f"Executing case update for cases {case_ids} with request data: {case_update_payload}")
    responses = [client.update_case(case_update_payload, case_id) for case_id in case_ids]
    replies = []
    for resp in responses:
        replies.append(process_case_response(resp))

    return CommandResults(
        readable_output=tableToMarkdown("Cases", replies, headerTransform=string_to_table_header),
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.Case",
        outputs_key_field="case_id",
        outputs=replies,
        raw_response=replies,
    )


def run_playbook_command(client: Client, args: dict) -> CommandResults:
    """
    Executes a playbook command with specified arguments.

    Args:
        client (Client): The client instance for making API requests.
        args (dict): Arguments for running the playbook.

    Returns:
        CommandResults: Results of the playbook execution.
    """
    playbook_id = args.get("playbook_id", "")
    issue_ids = argToList(args.get("issue_ids", ""))

    response = client.run_playbook(issue_ids, playbook_id)

    # Process the response to determine success or failure
    if not response:
        # Empty response indicates success for all issues
        return CommandResults(
            readable_output=f"Playbook '{playbook_id}' executed successfully for all issue IDs: {', '.join(issue_ids)}",
        )

    error_messages = []

    for issue_id, error_message in response.items():
        error_messages.append(f"Issue ID {issue_id}: {error_message}")

    demisto.debug(f"Playbook run errors: {error_messages}")
    raise ValueError(f"Playbook '{playbook_id}' failed for following issues:\n" + "\n".join(error_messages))


def map_endpoint_format(endpoint_list: list) -> list:
    """
    Maps and prepares endpoints data for consistent output formatting.

    Args:
        endpoint_list (list): Raw endpoint list from client response.

    Returns:
        dict: Formatted endpoint results with markdown table and outputs.
    """
    map_output_endpoint_fields = {v: k for k, v in Endpoints.ENDPOINT_FIELDS.items()}

    map_output_endpoint_type = {v: k for k, v in Endpoints.ENDPOINT_TYPE.items()}

    map_output_endpoint_status = {v: k for k, v in Endpoints.ENDPOINT_STATUS.items()}

    map_output_endpoint_platform = {v: k for k, v in Endpoints.ENDPOINT_PLATFORM.items()}

    map_output_endpoint_operational_status = {v: k for k, v in Endpoints.ENDPOINT_OPERATIONAL_STATUS.items()}

    map_output_assigned_prevention_policy = {v: k for k, v in Endpoints.ASSIGNED_PREVENTION_POLICY.items()}

    # A dispatcher for easy lookup:
    nested_mappers = {
        "endpoint_type": map_output_endpoint_type,
        "endpoint_status": map_output_endpoint_status,
        "platform": map_output_endpoint_platform,
        "operational_status": map_output_endpoint_operational_status,
        "assigned_prevention_policy": map_output_assigned_prevention_policy,
    }
    mapped_list = []

    for outputs in endpoint_list:
        mapped_item = {}

        for raw_key, raw_value in outputs.items():
            # Step 1: map backend key → prettified_output_key
            if raw_key not in map_output_endpoint_fields:
                continue

            prettified_output_key = map_output_endpoint_fields[raw_key]

            # Step 2: map nested values (policy ID, status, etc.)
            if prettified_output_key in nested_mappers:
                mapper = nested_mappers[prettified_output_key]
                friendly_value = mapper.get(raw_value, raw_value)
            else:
                friendly_value = raw_value

            mapped_item[prettified_output_key] = friendly_value

        mapped_list.append(mapped_item)

    return mapped_list


def build_endpoint_filters(args: dict):
    """
    Build a FilterBuilder for endpoint queries from provided arguments.

    Args:
        args (dict): Command arguments.

    Returns:
        FilterBuilder: Object with filters applied.
    """
    operational_status = [
        Endpoints.ENDPOINT_OPERATIONAL_STATUS[operational_status]
        for operational_status in argToList(args.get("operational_status"))
    ]
    endpoint_type = [Endpoints.ENDPOINT_TYPE[endpoint_type] for endpoint_type in argToList(args.get("endpoint_type"))]
    endpoint_status = [Endpoints.ENDPOINT_STATUS[status] for status in argToList(args.get("endpoint_status"))]
    platform = [Endpoints.ENDPOINT_PLATFORM[platform] for platform in argToList(args.get("platform"))]
    assigned_prevention_policy = [
        Endpoints.ASSIGNED_PREVENTION_POLICY[assigned] for assigned in argToList(args.get("assigned_prevention_policy"))
    ]
    agent_eol = args.get("agent_eol")
    supported_version = arg_to_bool_or_none(agent_eol) if agent_eol else None

    filter_builder = FilterBuilder()
    filter_builder.add_field(Endpoints.ENDPOINT_FIELDS["endpoint_status"], FilterType.EQ, endpoint_status)
    filter_builder.add_field(Endpoints.ENDPOINT_FIELDS["operational_status"], FilterType.EQ, operational_status)
    filter_builder.add_field(Endpoints.ENDPOINT_FIELDS["endpoint_type"], FilterType.EQ, endpoint_type)
    filter_builder.add_field(Endpoints.ENDPOINT_FIELDS["platform"], FilterType.EQ, platform)
    filter_builder.add_field(Endpoints.ENDPOINT_FIELDS["assigned_prevention_policy"], FilterType.EQ, assigned_prevention_policy)
    filter_builder.add_field(Endpoints.ENDPOINT_FIELDS["endpoint_name"], FilterType.EQ, argToList(args.get("endpoint_name")))
    filter_builder.add_field(
        Endpoints.ENDPOINT_FIELDS["operating_system"], FilterType.CONTAINS, argToList(args.get("operating_system"))
    )
    filter_builder.add_field(Endpoints.ENDPOINT_FIELDS["agent_version"], FilterType.EQ, argToList(args.get("agent_version")))
    filter_builder.add_field(Endpoints.ENDPOINT_FIELDS["os_version"], FilterType.EQ, argToList(args.get("os_version")))
    filter_builder.add_field(
        Endpoints.ENDPOINT_FIELDS["ip_address"], FilterType.ADVANCED_IP_MATCH_EXACT, argToList(args.get("ip_address"))
    )
    filter_builder.add_field(Endpoints.ENDPOINT_FIELDS["domain"], FilterType.EQ, argToList(args.get("domain")))
    filter_builder.add_field(Endpoints.ENDPOINT_FIELDS["tags"], FilterType.EQ, argToList(args.get("tags")))
    filter_builder.add_field(Endpoints.ENDPOINT_FIELDS["endpoint_id"], FilterType.EQ, argToList(args.get("endpoint_id")))
    filter_builder.add_field(Endpoints.ENDPOINT_FIELDS["cloud_provider"], FilterType.EQ, argToList(args.get("cloud_provider")))
    filter_builder.add_field(Endpoints.ENDPOINT_FIELDS["cloud_region"], FilterType.EQ, argToList(args.get("cloud_region")))
    filter_builder.add_field(Endpoints.ENDPOINT_FIELDS["agent_eol"], FilterType.EQ, supported_version)
    filter_dict = filter_builder.to_dict()

    return filter_dict


def core_list_endpoints_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves a list of endpoints from the server, applies filters, maps the data, and returns
    it as CommandResults for Cortex XSOAR.

    Args:
        client (Client): The integration client used to fetch data.
        args (dict): Command arguments.

    Returns:
        CommandResults: Contains the formatted table, raw response, and outputs.
    """
    page = arg_to_number(args.get("page")) or 0
    limit = arg_to_number(args.get("page_size")) or MAX_GET_ENDPOINTS_LIMIT
    limit = min(limit, MAX_GET_ENDPOINTS_LIMIT)
    page_from = page * limit
    page_to = page * limit + limit
    filter_dict = build_endpoint_filters(args)

    request_data = build_webapp_request_data(
        table_name=AGENTS_TABLE,
        filter_dict=filter_dict,
        limit=page_to,
        sort_field="AGENT_NAME",
        sort_order="ASC",
        start_page=page_from,
    )
    demisto.info(f"{request_data=}")
    response = client.get_webapp_data(request_data)
    reply = response.get("reply", {})
    data = reply.get("DATA", [])
    data = map_endpoint_format(data)
    demisto.debug(f"Endpoint data after mapping and formatting: {data}")

    return CommandResults(
        readable_output=tableToMarkdown("Endpoints", data, headerTransform=string_to_table_header),
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.Endpoint",
        outputs_key_field="endpoint_id",
        outputs=data,
        raw_response=data,
    )


def build_column_mapping(column):
    """
    Extracts the mapping of module NAME (ugly name)
    to PRETTY_NAME from the column definitions metadata.
    """
    mapping = {}
    enum_values = column.get("FILTER_PARAMS", {}).get("ENUM_VALUES", [])
    for enum in enum_values:
        mapping[enum.get("NAME")] = enum.get("PRETTY_NAME")
    return mapping


def extract_mappings_from_view_def(view_def: dict, columns_to_map: set[str]):
    """
    Extracts the mapping of module listed in columns_to_map NAME (ugly name)
    to PRETTY_NAME from the column definitions metadata.
    """
    mapping = {}
    column_definitions = view_def.get("COLUMN_DEFINITIONS", [])
    for column in column_definitions:
        column_name = column.get("FIELD_NAME")
        if column_name in columns_to_map:
            mapping[column_name] = build_column_mapping(column)
    return mapping


def combine_pretty_names(list_of_criteria: list[list[dict[str, Any]]]) -> list[str]:
    """
    Takes a list of criteria (where each criterion is a list of dictionaries)
    and combines the 'pretty_name' values from the dictionaries in each criterion
    into a single string.

    Args:
        list_of_criteria: A list of lists, where the inner list contains
                          dictionaries with a 'pretty_name' key.

    Returns:
        A list of strings, where each string is the concatenation of the
        'pretty_name' values for one inner list.
    """
    result_strings = []
    for criterion in list_of_criteria:
        if isinstance(criterion, list):
            combined_string = "".join(item.get("pretty_name", "") for item in criterion)
            result_strings.append(combined_string)
        else:
            result_strings.append(criterion)
    return result_strings


def postprocess_exception_rules_response(view_def, data):
    view_def_data = view_def[0]
    mappings = extract_mappings_from_view_def(view_def_data, EXCEPTION_RULES_OUTPUT_FIELDS_TO_MAP)
    for record in data:
        for field in EXCEPTION_RULES_OUTPUT_FIELDS_TO_MAP:
            record[field] = [mappings.get(field, {}).get(val, val) for val in record.get(field, [])]
        record["ASSOCIATED_TARGETS"] = combine_pretty_names(record.get("ASSOCIATED_TARGETS", []))
        record["CONDITIONS"] = record.get("CONDITIONS_PRETTY")
        record["RULE_TYPE"] = record.get("SUBTYPE")
        record["CREATION_TIMESTAMP"] = record.get("CREATION_TIME")
        record["MODIFICATION_TIMESTAMP"] = record.get("MODIFICATION_TIME")
        record["MODIFICATION_TIME"] = timestamp_to_datestring(record["MODIFICATION_TIMESTAMP"])
        record["CREATION_TIME"] = timestamp_to_datestring(record["CREATION_TIMESTAMP"])
        record.pop("CONDITIONS_PRETTY", None)
        record.pop("SUBTYPE", None)

    readable_output = tableToMarkdown(
        view_def_data.get("TABLE_NAME"),
        data,
        headerTransform=string_to_table_header,
        sort_headers=False,
    )
    return readable_output


def get_webapp_data(
    client,
    table_name: str,
    filter_dict: Any,
    sort_field: str,
    sort_order: str,
    retrieve_all: bool,
    base_limit: int,
    max_limit: int,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    """
    Helper function to iteratively fetch records for a single table with optional pagination.
    """
    all_records = []
    raw_responses = []

    limit = max_limit if retrieve_all else base_limit
    paging_from = offset
    paging_to = offset + limit
    filter_count = 0
    while True:
        demisto.debug(f"get_webapp_data pagination: {paging_from}, {paging_to}")
        request_data = build_webapp_request_data(
            table_name=table_name,
            filter_dict=filter_dict.to_dict(),
            sort_field=sort_field,
            sort_order=sort_order,
            limit=paging_to,
            start_page=paging_from,
        )
        response = client.get_webapp_data(request_data)
        raw_responses.append(copy.deepcopy(response))

        reply = response.get("reply", {})
        data = reply.get("DATA", [])
        filter_count = int(reply.get("FILTER_COUNT", "0"))
        all_records.extend(data)

        if not retrieve_all or len(data) < limit:
            break

        paging_from += limit
        paging_to += limit

    return all_records, raw_responses, filter_count


def list_exception_rules_command(client, args: dict[str, Any]) -> list[CommandResults]:
    """
    Retrieves Disable Prevention Rules and Legacy Agent Exceptions using the
    generic /api/webapp/get_data endpoint, handling pagination.
    """

    exception_rule_type = args.get("type")
    sort_field = args.get("sort_field", "MODIFICATION_TIME")
    sort_order = args.get("sort_order", "DESC")

    default_limit = arg_to_number(args.get("page_size")) or MAX_GET_EXCEPTION_RULES_LIMIT
    page_number = arg_to_number(args.get("page", 0)) or 0
    offset = page_number * default_limit if args.get("page") else 0
    retrieve_all = argToBoolean(args.get("retrieve_all", False))

    base_limit = MAX_GET_EXCEPTION_RULES_LIMIT if retrieve_all else default_limit

    exception_rule_filter = build_exception_rules_filter(args)

    if exception_rule_type in EXCEPTION_RULES_TYPE_TO_TABLE_MAPPING:
        table_names = [EXCEPTION_RULES_TYPE_TO_TABLE_MAPPING.get(exception_rule_type)]
    else:
        table_names = [LEGACY_AGENT_EXCEPTIONS_TABLE, DISABLE_PREVENTION_RULES_TABLE]

    all_outputs = []
    all_raw_responses = []
    readable_output_lines = []
    total_filter_count = 0

    for table_name in table_names:
        demisto.debug(f"Retrieving {table_name}")
        records, raw_responses, filter_count = get_webapp_data(
            client=client,
            table_name=str(table_name),
            filter_dict=exception_rule_filter,
            sort_field=sort_field,
            sort_order=sort_order,
            retrieve_all=retrieve_all,
            base_limit=base_limit,
            max_limit=MAX_GET_EXCEPTION_RULES_LIMIT,
            offset=offset,
        )

        all_raw_responses.extend(raw_responses)
        total_filter_count += filter_count

        demisto.debug(f"Retrieved {len(records)} records")
        if records:
            view_def = client.get_webapp_view_def({"table_name": table_name})
            hr_output = postprocess_exception_rules_response(view_def, records)
            all_outputs.extend(records)
            readable_output_lines.append(hr_output)
        else:
            readable_output_lines.append(f"No data found for {table_name} matching the filter.")

    final_readable_output = "\n".join(readable_output_lines)

    return [
        CommandResults(
            readable_output=final_readable_output,
            outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.ExceptionRules",
            outputs_key_field="ID",
            outputs=all_outputs,
            raw_response=all_raw_responses,
        ),
        CommandResults(
            outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.ExceptionRulesMetadata",
            outputs={"filter_count": total_filter_count, "returned_count": len(all_outputs)},
        ),
    ]


def list_system_users_command(client, args):
    """
    Retrieves system user optionally filtered by email using the public api ep /public_api/v1/rbac/get_users
    This function calls the client to fetch all available system users. If specific
    emails are provided via the 'email' argument, it filters the results. If no
    emails are provided, it limits the results to 50.
    """
    emails = argToList(args.get("email", ""))
    if len(emails) > MAX_GET_SYSTEM_USERS_LIMIT:
        raise DemistoException("The maximum number of emails allowed is 50.")

    response = client.get_users()
    data = response.get("reply", {})
    if emails:
        data = [user for user in data if user.get("user_email") in emails]

    if len(data) > MAX_GET_SYSTEM_USERS_LIMIT:
        data = data[:MAX_GET_SYSTEM_USERS_LIMIT]

    return CommandResults(
        readable_output=tableToMarkdown("System Users", data, headerTransform=string_to_table_header),
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.User",
        outputs_key_field="user_email",
        outputs=data,
        raw_response=response,
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
    remove_nulls_from_dictionary(args)
    headers: dict = {}

    webapp_api_url = "/api/webapp"
    public_api_url = f"{webapp_api_url}/public_api/v1"
    data_platform_api_url = f"{webapp_api_url}/data-platform"
    appsec_api_url = f"{webapp_api_url}/public_api/appsec"
    xsoar_api_url = "/xsoar"
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
    elif command in XSOAR_COMMANDS:
        client_url = xsoar_api_url

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
            assignees = argToList(args.get("assignee", "").lower())
            if "assigned" in assignees or "unassigned" in assignees:
                if len(assignees) > 1:
                    raise DemistoException(
                        f"The assigned/unassigned options can not be used with additional assignees. Received: {assignees}"
                    )

                # Swap assignee arg with the requested special operation
                assignee_filter_option = args.pop("assignee", "")
                args[assignee_filter_option] = True

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

        elif command == "core-update-issue":
            return_results(update_issue_command(client, args))

        elif command == "core-get-issue-recommendations":
            return_results(get_issue_recommendations_command(client, args))

        elif command == "core-enable-scanners":
            return_results(enable_scanners_command(client, args))

        elif command == "core-appsec-remediate-issue":
            return_results(appsec_remediate_issue_command(client, args))

        elif command == "core-get-asset-coverage":
            return_results(get_asset_coverage_command(client, args))

        elif command == "core-get-asset-coverage-histogram":
            return_results(get_asset_coverage_histogram_command(client, args))
        elif command == "core-create-appsec-policy":
            return_results(create_policy_command(client, args))
        elif command == "core-get-appsec-issues":
            return_results(get_appsec_issues_command(client, args))
        elif command == "core-update-case":
            return_results(update_case_command(client, args))
        elif command == "core-run-playbook":
            return_results(run_playbook_command(client, args))
        elif command == "core-list-exception-rules":
            return_results(list_exception_rules_command(client, args))
        elif command == "core-list-system-users":
            return_results(list_system_users_command(client, args))
        elif command == "core-list-endpoints":
            return_results(core_list_endpoints_command(client, args))

    except Exception as err:
        demisto.error(traceback.format_exc())
        return_error(str(err))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
