from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CoreIRApiModule import *
import dateparser
import copy


# Disable insecure warnings
urllib3.disable_warnings()

TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
INTEGRATION_CONTEXT_BRAND = "Core"
INTEGRATION_NAME = "Cortex Platform Core"
MAX_GET_INCIDENTS_LIMIT = 100
SEARCH_ASSETS_DEFAULT_LIMIT = 100
MAX_GET_CASES_LIMIT = 100
MAX_SCRIPTS_LIMIT = 100
MAX_GET_ENDPOINTS_LIMIT = 100
MAX_COMPLIANCE_STANDARDS = 100
AGENTS_TABLE = "AGENTS_TABLE"
AGENT_POLICY_TABLE = "AGENT_POLICY_TABLE"
AGENT_PROFILES_TABLE = "AGENT_PROFILES_TABLE"
SECONDS_IN_DAY = 86400  # Number of seconds in one day
MIN_DIFF_SECONDS = 2 * 3600  # Minimum allowed difference = 2 hours
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
REMEDIATION_TECHNIQUES_SOURCES = ["CIEM_SCANNER", "DATA_POLICY", "AISPM_RULE_ENGINE"]
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
    "core-list-scripts",
    "core-run-script-agentix",
    "core-list-endpoints",
    "core-list-exception-rules",
    "core-get-endpoint-update-version",
    "core-update-endpoint-version",
    "core-create-endpoint-policy",
    "core-delete-endpoint-policy",
]
DATA_PLATFORM_COMMANDS = ["core-get-asset-details"]
APPSEC_COMMANDS = ["core-enable-scanners", "core-appsec-remediate-issue"]
ENDPOINT_COMMANDS = ["core-get-endpoint-support-file"]
XSOAR_COMMANDS = ["core-run-playbook", "core-get-case-resolution-statuses"]

VULNERABLE_ISSUES_TABLE = "VULNERABLE_ISSUES_TABLE"
ASSET_GROUPS_TABLE = "UNIFIED_ASSET_MANAGEMENT_ASSET_GROUPS"
ASSET_COVERAGE_TABLE = "COVERAGE"
APPSEC_RULES_TABLE = "CAS_DETECTION_RULES"
CASES_TABLE = "CASE_MANAGER_TABLE"
SCRIPTS_TABLE = "SCRIPTS_TABLE"


class ScriptManagement:
    FIELDS = {
        "script_name": "NAME",
        "supported_platforms": "PLATFORM",
    }

    PLATFORMS = {
        "windows": "AGENT_OS_WINDOWS",
        "linux": "AGENT_OS_LINUX",
        "macos": "AGENT_OS_MAC",
    }


DISABLE_PREVENTION_RULES_TABLE = "AGENT_EXCEPTION_RULES_TABLE_ADVANCED"
LEGACY_AGENT_EXCEPTIONS_TABLE = "AGENT_EXCEPTION_RULES_TABLE_LEGACY"


CUSTOM_FIELDS_TABLE = "CUSTOM_FIELDS_CASE_TABLE"


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
        "in_progress": "STATUS_020_UNDER_INVESTIGATION",
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


DAYS_MAPPING = {
    "sunday": 1,
    "monday": 2,
    "tuesday": 3,
    "wednesday": 4,
    "thursday": 5,
    "friday": 6,
    "saturday": 7,
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
    def platform_http_request(
        self,
        method,
        url_suffix="",
        json_data=None,
        params=None,
        data=None,
        timeout=None,
        ok_codes=None,
        error_handler=None,
        with_metrics=False,
    ):
        """A wrapper for the platformAPICall method to better handle requests and responses.

        Args:
            method (str): The HTTP method, for example: GET, POST, and so on.
            url_suffix (str): The API endpoint suffix to append to the base URL.
            json_data (dict, optional): Dictionary to send in the request body as JSON.
                Will be automatically serialized to JSON string.
            params (dict, optional): URL parameters to specify the query string.
            data (str, optional): Raw data to send in the request body.
                Used when json_data is not provided.
            timeout (float or tuple, optional): The amount of time (in seconds) that a request
                will wait for a client to establish a connection to a remote machine before
                a timeout occurs. Can be only float (Connection Timeout) or a tuple
                (Connection Timeout, Read Timeout).
            ok_codes (list, optional): List of HTTP status codes that are considered successful.
                If the response status is not in this list, an error will be raised.
            error_handler (callable, optional): Custom error handler function to process errors.
            with_metrics (bool): Whether to include metrics in error handling.

        Returns:
            dict or str: The parsed JSON response as a dictionary, or the raw response data
                if JSON parsing fails.

        Raises:
            DemistoException: If FORWARD_USER_RUN_RBAC is not enabled, indicating the integration
                is cloned or the server version is too low.
        """
        data = json.dumps(json_data) if json_data is not None else data

        response = demisto._platformAPICall(path=url_suffix, method=method, params=params, data=data, timeout=timeout)

        if ok_codes and response.get("status") not in ok_codes:
            self._handle_error(error_handler, response, with_metrics)
        try:
            return json.loads(response["data"])
        except json.JSONDecodeError:
            demisto.debug(f"Converting data to json was failed. Return it as is. The data's type is {type(response['data'])}")
            return response["data"]

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

    def get_endpoint_support_file(self, request_data: dict[str, Any]) -> dict:
        """
        Retrieve endpoint support file from Cortex XDR.
        Args:
            request_data (dict[str, Any]): The request data containing endpoint information.
        Returns:
            dict: The response containing the endpoint support file data.
        """
        demisto.debug(f"Endpoint support file request payload: {request_data}")
        return self._http_request(
            method="POST",
            data=request_data,
            headers=self._headers,
            url_suffix="/retrieve_endpoint_tsf",
        )

    def get_endpoint_update_version(self, request_data):
        reply = self._http_request(
            method="POST",
            json_data={"request_data": request_data},
            url_suffix="/agents/upgrade/details",
        )
        return reply

    def update_endpoint_version(self, request_data):
        reply = self._http_request(
            method="POST",
            json_data={"request_data": request_data},
            url_suffix="/agents/upgrade",
        )
        return reply

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

    def bulk_update_case(self, case_update_payload, case_ids):
        request_data = {
            "request_data": {
                "filter_data": {"filter": {"OR": [{"SEARCH_FIELD": "CASE_ID", "SEARCH_TYPE": "IN", "SEARCH_VALUE": case_ids}]}},
                "update_attrs": case_update_payload,
            }
        }
        return self._http_request(
            method="POST",
            url_suffix="/case/bulk_update_cases",
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

    def add_assessment_profile(self, profile_payload: dict) -> dict:
        """
        Add a new assessment profile to Cortex XDR.

        Args:
            profile_payload (dict): The assessment profile configuration payload.

        Returns:
            dict: The response from the API for adding the assessment profile.
        """
        return self._http_request(
            method="POST",
            url_suffix="/compliance/add_assessment_profile",
            json_data=profile_payload,
        )

    def list_compliance_standards_command(self, payload: dict) -> dict:
        """
        List compliance standards from Cortex XDR.

        Args:
            payload (dict): The request payload for listing compliance standards.

        Returns:
            dict: The response from the API containing compliance standards data.
        """
        return self._http_request(
            method="POST",
            url_suffix="/compliance/get_standards",
            json_data=payload,
        )

    def get_users(self):
        reply = self._http_request(
            method="POST",
            json_data={},
            headers=self._headers,
            url_suffix="/rbac/get_users",
        )

        return reply

    def get_case_resolution_statuses(self, case_id: str) -> dict:
        reply = self._http_request(
            method="GET",
            json_data={},
            headers={
                **self._headers,
                "Content-Type": "application/json",
            },
            url_suffix=f"case/{case_id}/resolution-plan/tasks",
        )
        return reply

    def get_custom_fields_metadata(self) -> dict[str, Any]:
        """
        Retrieve custom fields metadata from the CUSTOM_FIELDS_CASE_TABLE.

        Returns comprehensive metadata for all custom fields including:
        - CUSTOM_FIELD_NAME: Internal field identifier
        - CUSTOM_FIELD_PRETTY_NAME: User-friendly display name
        - CUSTOM_FIELD_IS_SYSTEM: Boolean flag (true = system field, false = custom field)
        - CUSTOM_FIELD_TYPE: Field data type

        Returns:
            dict: Response containing custom fields metadata in reply.DATA
        """
        request_data = {
            "type": "grid",
            "table_name": CUSTOM_FIELDS_TABLE,
            "filter_data": {
                "sort": [],
                "filter": {},
                "free_text": "",
                "visible_columns": None,
                "locked": None,
                "paging": {"from": 0, "to": 1000},
            },
            "jsons": [],
        }

        return self.get_webapp_data(request_data)

    def get_case_ai_summary(self, case_id: int) -> dict:
        """
        Retrieves AI-generated summary for a specific case ID.

        Args:
            case_id (int): The ID of the case to retrieve AI summary for.

        Returns:
            dict: API response containing case AI summary.
        """
        return self._http_request(
            method="POST",
            url_suffix="/cases/get_ai_case_details",
            json_data={"case_id": case_id},
        )

    def get_agent_policy_table(self) -> dict:
        """
        Retrieves the current agent policy table with policy hash.

        Returns:
            dict: API response containing policy table data and hash.
        """
        request_data = {
            "type": "grid",
            "table_name": AGENT_POLICY_TABLE,
            "filter_data": {"filter": {}},
        }
        return self.get_webapp_data(request_data)

    def update_agent_policy(self, update_data: dict) -> dict:
        """
        Updates the agent policy table with new or modified policies.

        Args:
            update_data (dict): The update payload containing policy data and hash.

        Returns:
            dict: API response from the policy update.
        """

        demisto.debug({"update_data": update_data})
        return self._http_request(
            method="POST",
            url_suffix="/agent/policy/update",
            json_data={"update_data": update_data},
        )


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


def get_remediation_techniques_suggestion(issue: dict, current_issue_id: str) -> list:
    """
    Get remediation techniques suggestions based on asset types.

    Args:
        issue (dict): The issue data.
        current_issue_id (str): The current issue ID.

    Returns:
        list: A list of filtered remediation techniques.
    """
    asset_types: list = issue.get("asset_types", [])
    normalized_asset_types = {t.upper().replace(" ", "_") for t in asset_types if t}
    remediation_techniques_response = issue.get("extended_fields", {}).get("remediationTechniques") or []
    filtered_techniques = [
        t
        for t in remediation_techniques_response
        if t.get("techniqueAssetType") and t.get("techniqueAssetType").upper() in normalized_asset_types
    ]
    demisto.debug(f"Remediation recommendation of {current_issue_id=}: {filtered_techniques}")
    return filtered_techniques


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
        alert_source = issue.get("alert_source")

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

        # --- Remediation Techniques ---
        elif alert_source in REMEDIATION_TECHNIQUES_SOURCES:
            filtered_techniques = get_remediation_techniques_suggestion(issue, current_issue_id)
            recommendation["remediation"] = filtered_techniques or recommendation.get("remediation")

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
    filter_builder.add_field("CORTEX_VULNERABILITY_RISK_SCORE", FilterType.GTE, arg_to_number(args.get("cvrs_gte")))
    filter_builder.add_field(
        "COMPENSATING_CONTROLS_DETECTED_COVERAGE", FilterType.EQ, argToList(args.get("compensating_controls_effective_coverage"))
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
        "COMPENSATING_CONTROLS_DETECTED_COVERAGE",
        "CORTEX_VULNERABILITY_RISK_SCORE",
        "FIX_VERSIONS",
        "ASSET_TYPES",
        "COMPENSATING_CONTROLS_DETECTED_CONTROLS",
        "EXPLOIT_LEVEL",
        "ISSUE_NAME",
        "PACKAGE_IN_USE",
        "PROVIDERS",
        "OS_FAMILY",
        "IMAGE",
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
    case_extra_data = get_extra_data_for_case_id_command(init_client("public"), args).outputs
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


def build_get_cases_filter(args: dict) -> FilterBuilder:
    since_creation_start_time = args.get("since_creation_time")
    since_creation_end_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%S") if since_creation_start_time else None
    since_modification_start_time = args.get("since_modification_time")
    since_modification_end_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%S") if since_modification_start_time else None
    gte_creation_time = args.get("gte_creation_time")
    lte_creation_time = args.get("lte_creation_time")
    gte_modification_time = args.get("gte_modification_time")
    lte_modification_time = args.get("lte_modification_time")

    not_status_values = [CaseManagement.STATUS.get(status) for status in argToList(args.get("not_status"))]
    status_values = [CaseManagement.STATUS.get(status) for status in argToList(args.get("status"))]
    severity_values = [CaseManagement.SEVERITY.get(severity) for severity in argToList(args.get("severity"))]
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
    filter_builder.add_field(CaseManagement.FIELDS["status"], FilterType.NEQ, not_status_values)
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

    return filter_builder


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

    sort_field, sort_order = get_cases_sort_order(args.get("sort_by_creation_time"), args.get("sort_by_modification_time"))
    request_data = build_webapp_request_data(
        table_name=CASES_TABLE,
        filter_dict=build_get_cases_filter(args).to_dict(),
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

    command_results = [
        CommandResults(
            outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.CasesMetadata",
            outputs={"filtered_count": filter_count, "returned_count": returned_count},
        )
    ]

    if (
        returned_count == 1 and int(data[0].get("issue_count") or 0) > 1
    ):  # AI summary supported in cases of a single case query with more than one issue
        case_id = data[0].get("case_id")
        try:  # if functionality isn't supported exception is raised and should be handled
            response = client.get_case_ai_summary(int(case_id))
            if response:
                reply = response.get("reply", {})
                if case_description := reply.get("case_description"):
                    data[0]["description"] = case_description
                if case_name := reply.get("case_name"):
                    data[0]["case_name"] = case_name
        except Exception as e:
            demisto.debug(f"Failed to retrieve case AI summary for case ID {case_id}: {str(e)}")

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
    case = mapped_response.get("case")
    if int(case.get("issue_count") or 0) > 1:
        try:  # if functionality isn't supported exception is raised and should be handled
            web_app_client = init_client("webapp")
            ai_response = web_app_client.get_case_ai_summary(int(case_id))
            if ai_response:
                reply = ai_response.get("reply", {})
                if case_description := reply.get("case_description"):
                    case["description"] = case_description
                if case_name := reply.get("case_name"):
                    case["case_name"] = case_name
        except Exception as e:
            demisto.debug(f"Failed to retrieve case AI summary for case ID {case_id}: {str(e)}")

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
        start_modification_time_str = (
            "1970-01-01"  # The standard "beginning of time" for most systems - beginning_of_unix = datetime.fromtimestamp(0)
        )
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


def get_endpoint_support_file_command(client: Client, args: dict) -> CommandResults:
    endpoint_ids = argToList(args.get("endpoint_ids"))

    filter_builder = FilterBuilder()
    filter_builder.add_field("AGENT_ID", FilterType.EQ, endpoint_ids)
    request_data = {
        "request_data": {
            "filter_data": {"filter": filter_builder.to_dict()},
            "filter_type": "static",
        }
    }

    response = client.get_endpoint_support_file(request_data)

    reply = response.get("reply", {})
    group_action_id = reply.get("group_action_id")

    if not group_action_id:
        raise DemistoException("No group_action_id found. Please ensure that valid endpoint IDs are provided.")

    readable_output = f"Endpoint support file request submitted successfully. Group Action ID: {group_action_id}"

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.EndpointSupportFile",
        outputs_key_field="group_action_id",
        outputs=reply,
        raw_response=response,
    )


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

    if status == "resolved" and (not resolve_reason or not CaseManagement.STATUS_RESOLVED_REASON.get(resolve_reason, False)):
        raise ValueError("In order to set the case to resolved, you must provide a resolve reason.")

    if (resolve_reason or resolve_all_alerts or resolved_comment) and not status == "resolved":
        raise ValueError(
            "In order to use resolve_reason, resolve_all_alerts, or resolved_comment, the case status must be set to "
            "'resolved'."
        )

    if status and not CaseManagement.STATUS.get(status):
        raise ValueError(f"Invalid status '{status}'. Valid statuses are: {list(CaseManagement.STATUS.keys())}")

    if user_defined_severity and not CaseManagement.SEVERITY.get(user_defined_severity, False):
        raise ValueError(
            f"Invalid user_defined_severity '{user_defined_severity}'. Valid severities are: "
            f"{list(CaseManagement.SEVERITY.keys())}"
        )

    valid_fields_to_update, error_messages = validate_custom_fields(custom_fields, client)

    # Build request_data with mapped and filtered values
    case_update_payload = {
        "caseName": case_name if case_name else None,
        "description": description if description else None,
        "assignedUser": assignee if assignee else None,
        "notes": notes if notes else None,
        "starred": argToBoolean(starred) if starred else None,
        "status": CaseManagement.STATUS.get(status) if status else None,
        "userSeverity": CaseManagement.SEVERITY.get(user_defined_severity) if user_defined_severity else None,
        "resolve_reason": CaseManagement.STATUS_RESOLVED_REASON.get(resolve_reason) if resolve_reason else None,
        "caseResolvedComment": resolved_comment if resolved_comment else None,
        "resolve_all_alerts": resolve_all_alerts if resolve_all_alerts else None,
        "CustomFields": valid_fields_to_update if valid_fields_to_update else None,
    }
    remove_nulls_from_dictionary(case_update_payload)

    if not case_update_payload:
        raise ValueError(f"No valid update parameters provided.\n{error_messages}")

    def is_bulk_update_allowed(case_update_payload: dict) -> bool:
        # Bulk update supports only those fields
        allowed_bulk_fields = {"userSeverity", "status", "starred", "assignedUser"}

        for field_name, field_value in case_update_payload.items():
            if (
                field_name == "status"
                and field_value == CaseManagement.STATUS["resolved"]
                or field_name not in allowed_bulk_fields
            ):
                return False
        return True

    def repackage_to_update_case_format(case_list):
        """
        Maps raw API case data to the Update Case Format,
        """
        if not case_list or not isinstance(case_list, list):
            return []

        reverse_tags = {v: k for k, v in CaseManagement.TAGS.items()}
        grouping_status_map = {"enabled": "GROUPING_STATUS_010_ENABLED", "disabled": "GROUPING_STATUS_020_DISABLED"}

        target = []
        for raw_case in case_list:
            raw_status = str(raw_case.get("STATUS", raw_case.get("STATUS_PROGRESS", ""))).split("_")[-1].lower()
            status_key = raw_status.replace("investigation", "under_investigation")
            raw_severity = str(raw_case.get("SEVERITY", "")).split("_")[-1].lower()
            raw_grouping = str(raw_case.get("CASE_GROUPING_STATUS", "")).split("_")[-1].lower()

            target.append(
                {
                    "id": str(raw_case.get("CASE_ID")),
                    "name": {"isUser": True, "value": raw_case.get("NAME")},
                    "score": {
                        "manual_score": raw_case.get("MANUAL_SCORE"),
                        "score": raw_case.get("SCORE"),
                        "score_source": raw_case.get("SCORE_SOURCE"),
                        "scoring_rules": raw_case.get("CALCULATED_SCORE"),
                        "scortex": raw_case.get("SCORTEX"),
                    },
                    "notes": None,
                    "description": {"isUser": True, "value": raw_case.get("DESCRIPTION")},
                    "caseDomain": raw_case.get("INCIDENT_DOMAIN"),
                    "creationTime": raw_case.get("CREATION_TIME"),
                    "lastUpdateTime": raw_case.get("LAST_UPDATE_TIME"),
                    "modifiedBy": None,
                    "starred": raw_case.get("CASE_STARRED"),
                    "status": {
                        "value": CaseManagement.STATUS.get(status_key),
                        "resolveComment": raw_case.get("RESOLVED_COMMENT"),
                        "resolve_reason": raw_case.get("RESOLVED_REASON"),
                    },
                    "severity": CaseManagement.SEVERITY.get(raw_severity),
                    "userSeverity": raw_case.get("USER_SEVERITY"),
                    "assigned": {"mail": raw_case.get("ASSIGNED_USER"), "pretty": raw_case.get("ASSIGNED_USER_PRETTY")},
                    "severityCounters": {
                        "SEV_020_LOW": raw_case.get("LOW_SEVERITY_ALERTS", 0),
                        "SEV_030_MEDIUM": raw_case.get("MEDIUM_SEVERITY_ALERTS", 0),
                        "SEV_040_HIGH": raw_case.get("HIGH_SEVERITY_ALERTS", 0),
                        "SEV_050_CRITICAL": raw_case.get("CRITICAL_SEVERITY_ALERTS", 0),
                    },
                    "topCounters": {
                        "HOSTS": len(raw_case.get("HOSTS", []) or []),
                        "MAL_ARTIFACTS": raw_case.get("WF_HITS", 0),
                        "USERS": len(raw_case.get("USERS", []) or []),
                    },
                    "tags": [
                        {"tag_id": reverse_tags.get(tag.get("tag_name")), "tag_name": tag.get("tag_name")}
                        for tag in (raw_case.get("CURRENT_TAGS", []) or [])
                    ],
                    "groupingStatus": {
                        "pretty": raw_grouping.capitalize(),
                        "raw": grouping_status_map.get(raw_grouping),
                        "reason": None,
                    },
                    "hasAttachment": raw_case.get("HAS_ATTACHMENT", False),
                    "internalStatus": raw_case.get("INTERNAL_STATUS", "STATUS_010_NONE"),
                }
            )

        return target

    demisto.info(f"Executing case update for cases {case_ids} with request data: {case_update_payload}")
    replies = []
    if is_bulk_update_allowed(case_update_payload):
        demisto.debug("Performing bulk case update")
        if case_update_payload.get("userSeverity"):
            case_update_payload["severity"] = case_update_payload.pop("userSeverity")
        if case_update_payload.get("assignedUser") == "unassigned":
            case_update_payload["assignedUser"] = None

        client.bulk_update_case(case_update_payload, case_ids)
        filter_builder = FilterBuilder()
        filter_builder.add_field(
            CaseManagement.FIELDS["case_id_list"],
            FilterType.EQ,
            case_ids,
        )
        request_data = build_webapp_request_data(
            table_name=CASES_TABLE,
            filter_dict=filter_builder.to_dict(),
            limit=len(case_ids),
            sort_field="CREATION_TIME",
        )
        demisto.debug(f"request_data to retrieve cases that were updated via bulk: {request_data}")
        response = client.get_webapp_data(request_data)
        reply = response.get("reply", {})
        data = reply.get("DATA", [])
        replies = repackage_to_update_case_format(data)

    else:
        demisto.debug("Performing iterative case update")
        if assignee == "unassigned":
            for case_id in case_ids:
                client.unassign_case(case_id)
        responses = [client.update_case(case_update_payload, case_id) for case_id in case_ids]
        replies = []
        for resp in responses:
            replies.append(process_case_response(resp))

    command_results = CommandResults(
        readable_output=tableToMarkdown("Cases", replies, headerTransform=string_to_table_header),
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.Case",
        outputs_key_field="case_id",
        outputs=replies,
        raw_response=replies,
    )

    if error_messages:
        return_results(command_results)
        return_error(f"The following fields could not be updated:\n{error_messages}")

    return command_results


def validate_custom_fields(fields_to_validate: dict, client: Client) -> tuple[dict, str]:
    """
    Validates custom fields against system metadata.

    Args:
        fields_to_validate: Dict of field names and values to validate.
        client: Client instance for API calls.

    Returns:
        Tuple of (valid_fields_dict, error_messages_str).
    """
    if not fields_to_validate:
        return {}, ""

    fields_data = client.get_custom_fields_metadata().get("reply", {}).get("DATA", [])

    if not fields_data:
        return {}, "No Fields are defined in the system."

    system_fields = {
        f["CUSTOM_FIELD_NAME"]: f.get("CUSTOM_FIELD_PRETTY_NAME", f["CUSTOM_FIELD_NAME"])
        for f in fields_data
        if f.get("CUSTOM_FIELD_NAME") and f.get("CUSTOM_FIELD_IS_SYSTEM")
    }
    custom_fields = {
        f["CUSTOM_FIELD_NAME"]: f.get("CUSTOM_FIELD_PRETTY_NAME", f["CUSTOM_FIELD_NAME"])
        for f in fields_data
        if f.get("CUSTOM_FIELD_NAME") and not f.get("CUSTOM_FIELD_IS_SYSTEM")
    }

    if not custom_fields:
        return {}, "No custom fields are defined in the system."

    demisto.debug(f"Available custom fields: {custom_fields=}")
    valid_fields, error_messages = {}, []
    for field_name, field_value in fields_to_validate.items():
        if field_name in system_fields:
            error_messages.append(
                f"Field '{field_name}' ({system_fields[field_name]}) is a system field and cannot"
                f" be set with custom_fields argument."
            )
        elif field_name in custom_fields:
            valid_fields[field_name] = field_value
        else:
            error_messages.append(f"Field '{field_name}' does not exist.")

    return valid_fields, "\n".join(f"- {e}" for e in error_messages)


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


def list_scripts_command(client: Client, args: dict) -> List[CommandResults]:
    """
    Retrieves a list of scripts from the platform with optional filtering.
    """
    page_number = arg_to_number(args.get("page_number")) or 0
    page_size = arg_to_number(args.get("page_size")) or MAX_SCRIPTS_LIMIT
    start_index = page_number * page_size
    end_index = start_index + page_size

    filter_builder = FilterBuilder()
    filter_builder.add_field(
        ScriptManagement.FIELDS["script_name"],
        FilterType.CONTAINS,
        argToList(args.get("script_name")),
    )

    platforms = [ScriptManagement.PLATFORMS[platform] for platform in argToList(args.get("supported_platforms"))]
    filter_builder.add_field(ScriptManagement.FIELDS["supported_platforms"], FilterType.CONTAINS, platforms)

    request_data = build_webapp_request_data(
        table_name=SCRIPTS_TABLE,
        filter_dict=filter_builder.to_dict(),
        limit=end_index,
        sort_field="MODIFICATION_TIME",
        start_page=start_index,
    )

    response = client.get_webapp_data(request_data)
    reply = response.get("reply", {})
    data = reply.get("DATA", [])

    mapped_scripts = []
    for script in data:
        mapped_script = {
            "name": script.get("NAME"),
            "description": script.get("DESCRIPTION"),
            "windows_supported": "AGENT_OS_WINDOWS" in str(script.get("PLATFORM", "")),
            "linux_supported": "AGENT_OS_LINUX" in str(script.get("PLATFORM", "")),
            "macos_supported": "AGENT_OS_MAC" in str(script.get("PLATFORM", "")),
            "script_uid": script.get("GUID"),
            "script_id": script.get("ID"),
            "script_inputs": script.get("ENTRY_POINT_DEFINITION", {}).get("input_params", []),
        }
        mapped_scripts.append(mapped_script)

    metadata = {
        "filtered_count": reply.get("FILTER_COUNT", 0),
        "returned_count": len(mapped_scripts),
    }

    command_results = []
    command_results.append(
        CommandResults(
            readable_output=tableToMarkdown("Scripts", mapped_scripts, headerTransform=string_to_table_header),
            outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.Scripts",
            outputs=mapped_scripts,
            outputs_key_field="script_id",
            raw_response=response,
        )
    )
    command_results.append(
        CommandResults(
            outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.ScriptsMetadata",
            outputs=metadata,
        )
    )

    return command_results


def run_script_agentix_command(client: Client, args: dict) -> PollResult:
    """
    Executes a script on agents with specified parameters.

    Args:
        client (Client): The client instance for making API requests.
        args (dict): Arguments for running the script.

    Returns:
        CommandResults: Results of the script execution.
    """
    script_uid = args.get("script_uid", "")
    script_name = args.get("script_name", "")
    endpoint_ids = argToList(args.get("endpoint_ids", ""))
    endpoint_names = argToList(args.get("endpoint_names", ""))
    parameters = args.get("parameters", "")
    if script_uid and script_name:
        raise ValueError("Please provide either script_uid or script_name, not both.")

    if not script_uid and not script_name:
        raise ValueError("You must specify either script_uid or script_name.")

    if endpoint_ids and endpoint_names:
        raise ValueError("Please provide either endpoint_ids or endpoint_names, not both.")

    if not endpoint_ids and not endpoint_names:
        raise ValueError("You must specify either endpoint_ids or endpoint_names.")

    if script_name:
        scripts_results = list_scripts_command(client, {"script_name": script_name})
        scripts = scripts_results[0].outputs.get("Scripts", [])  # type: ignore
        number_of_returned_scripts = len(scripts)
        demisto.debug(f"Scripts results: {scripts}")
        if number_of_returned_scripts > 1:
            error_message = (
                "Multiple scripts found. Please specify the exact script by providing one of the following script_uid:\n\n"
            )
            for script in scripts:
                error_message += (
                    f"Script UID: {script['script_uid']}\n"
                    f"Description: {script['description']}\n"
                    f"Name: {script['name']}\n"
                    f"Supported Platforms: Windows: {script['windows_supported']}, "
                    f"Linux: {script['linux_supported']}, "
                    f"MacOS: {script['macos_supported']}\n"
                    f"Script Inputs: {script['script_inputs']}\n\n"
                )
            raise ValueError(error_message)

        # If exactly one script is found, use its script_uid
        elif number_of_returned_scripts == 1:
            script = scripts[0]
            script_uid = script["script_uid"]
            script_inputs = script["script_inputs"]
            script_inputs_names = [input_param.get("name") for input_param in script_inputs]
            if script["script_inputs"] and not parameters:
                raise ValueError(
                    f"Script '{script_name}' requires the following input parameters: {', '.join(script_inputs_names)}, "
                    "but none were provided."
                )

        # If no scripts found, raise an error
        else:
            raise ValueError(f"No scripts found with the name: {script_name}")

    if endpoint_names:
        endpoint_results = core_list_endpoints_command(client, {"endpoint_name": endpoint_names})
        endpoints = endpoint_results.outputs or []
        demisto.debug(f"Endpoint results: {endpoints}")
        endpoint_ids = [endpoint["endpoint_id"] for endpoint in endpoints]  # type: ignore

    if not endpoint_ids:
        raise ValueError(f"No endpoints found with the specified names: {', '.join(endpoint_names)}")

    client._base_url = "/api/webapp/public_api/v1"
    return script_run_polling_command(
        {"endpoint_ids": endpoint_ids, "script_uid": script_uid, "parameters": parameters, "is_core": True}, client
    )


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


def parse_frequency(day: str | None, time: str | None) -> str:
    """
    Convert day and time to cron-style frequency string

    Cron format: Minute Hour Day-of-Month Month Day-of-Week
    Example: "0 12 * * 2" means:
    - Minute: 0 (The task starts at the 0th minute of the hour)
    - Hour: 12 (The task starts at the 12th hour - 12:00 PM in 24-hour time)
    - Day of Month: * (Every day of the month)
    - Month: * (Every month)
    - Day of Week: 2 (Tuesday)

    :param day: Day of month (optional)
    :param time: Time in HH:MM format
    :return: Cron-style frequency string
    """
    DAY_MAP = {"sunday": 0, "monday": 1, "tuesday": 2, "wednesday": 3, "thursday": 4, "friday": 5, "saturday": 6}

    target_time = time if time else "12:00"
    try:
        hours, minutes = map(int, target_time.split(":"))
        if not (0 <= hours < 24 and 0 <= minutes < 60):
            raise ValueError("Invalid time format. Use HH:MM in 24-hour format.")
    except ValueError:
        raise ValueError("Invalid time format. Use HH:MM.")

    if day is None:
        # If no day is provided -> Daily (represented by * in cron)
        cron_day = "*"
    else:
        # If day is provided -> Weekly (look up the day index)
        day_key = day.lower()
        if day_key not in DAY_MAP:
            raise ValueError(f"Invalid day. Must be one of {list(DAY_MAP.keys())}.")
        cron_day = str(DAY_MAP[day_key])

    return f"{minutes} {hours} * * {cron_day}"


def create_assessment_profile_payload(
    name: str,
    description: str,
    standard_id: str,
    asset_group_id: str,
    day: str | None,
    time: str | None,
    report_type: str = "ALL",
) -> Dict[str, Any]:
    """
    Prepare assessment profile payload

    :param name: Name of the assessment profile
    :param description: Description of the profile
    :param standard_id: ID of the compliance standard
    :param asset_group_id: ID of the asset group
    :param day: Day of evaluation (optional)
    :param time: Time of evaluation (optional)
    :param report_type: Type of report (default: ALL)
    :return: Assessment profile payload
    """

    report_frequency = parse_frequency(day, time)

    payload = {
        "request_data": {
            "profile_name": name,
            "asset_group_id": asset_group_id,
            "standard_id": standard_id,
            "description": description,
            "report_targets": [],
            "report_type": report_type,
            "evaluation_frequency": report_frequency,
        }
    }

    return payload


def list_compliance_standards_payload(
    name: str | None = None,
    created_by: str | None = None,
    labels: list[str] | None = None,
    page=0,
    page_size=MAX_COMPLIANCE_STANDARDS,
) -> Dict[str, Any]:
    """
    Prepare assessment profile payload

    :param name: Name of the assessment profile
    :param description: Description of the profile
    :param standard_id: ID of the compliance standard
    :param asset_group_id: ID of the asset group
    :param day: Day of evaluation (optional)
    :param time: Time of evaluation (optional)
    :param report_type: Type of report (default: ALL)
    :return: Assessment profile payload
    """

    start_index = page * page_size
    end_index = start_index + page_size
    payload: dict = {"request_data": {"filters": []}}

    if name:
        payload["request_data"]["filters"].append({"field": "name", "operator": "contains", "value": name})

    if created_by:
        payload["request_data"]["filters"].append(
            {"field": "IS_CUSTOM", "operator": "in", "value": ["yes" if created_by == "Custom" else "no"]}
        )

    if labels:
        for label in labels:
            payload["request_data"]["filters"].append({"field": "labels", "operator": "contains", "value": label})

    payload["request_data"]["sort"] = {"field": "insertion_time", "keyword": "desc"}

    payload["request_data"]["pagination"] = {
        "search_from": start_index,
        "search_to": end_index,
    }

    return payload


def core_add_assessment_profile_command(client: Client, args: dict) -> CommandResults:
    """
    Adds a new assessment profile to the Cortex Platform.

    Args:
        client (Client): The integration client used to add the assessment profile.
        args (dict): Command arguments containing profile details.

    Returns:
        CommandResults: Contains the result of adding the assessment profile.
    """
    profile_name = args.get("profile_name", "")
    profile_description = args.get("profile_description", "")
    standard_name = args.get("standard_name", "")
    asset_group_name = args.get("asset_group_name", "")
    day = args.get("day")
    time = args.get("time", "12:00")

    payload = list_compliance_standards_payload(
        name=standard_name,
    )
    demisto.debug(f"Listing compliance standards with payload: {payload}")
    response = client.list_compliance_standards_command(payload)
    reply = response.get("reply", {})
    standards = reply.get("standards")
    demisto.debug(f"{standards=}")

    if not standards:
        return_error("No compliance standards found matching the provided name.")

    if len(standards) > 1:
        standard_names = [standard.get("name") for standard in standards]
        new_line = "\n"
        return_error(
            f"The name you provided matches more than one standard:\n\n{new_line.join(standard_names)}\n\n"
            "Please provide a more specific name."
        )

    standard_id = standards[0].get("id")

    filter = FilterBuilder()
    filter.add_field("XDM.ASSET_GROUP.NAME", FilterType.CONTAINS, asset_group_name)
    filter_str = filter.to_dict()
    groups = client.search_asset_groups(filter_str).get("reply", {}).get("data", [])
    group_ids = [group.get("XDM.ASSET_GROUP.ID") for group in groups if group.get("XDM.ASSET_GROUP.ID")]
    group_names = [group.get("XDM.ASSET_GROUP.NAME") for group in groups if group.get("XDM.ASSET_GROUP.NAME")]

    if not group_ids:
        return_error("No asset group found matching the provided name.")

    if len(group_ids) > 1:
        new_line = "\n"
        return_error(
            f"The name you provided matches more than one asset group:\n\n{new_line.join(group_names)}\n\n"
            "Please provide a more specific name."
        )
    demisto.debug(f"{group_ids=}")
    asset_group_id = group_ids[0]

    payload = create_assessment_profile_payload(
        name=profile_name,
        description=profile_description,
        standard_id=str(standard_id),
        asset_group_id=asset_group_id,
        day=day,
        time=time,
        report_type="ALL",
    )
    demisto.debug(f"Creating assessment profile with payload: {payload}")

    reply = client.add_assessment_profile(payload)
    assessment_profile_id = reply.get("assessment_profile_id")
    return CommandResults(
        readable_output=f"Assessment Profile {assessment_profile_id} successfully added",
        outputs_prefix="Core.AssessmentProfile",
        outputs_key_field="assessment_profile_id",
        outputs=assessment_profile_id,
        raw_response=reply,
    )


def core_list_compliance_standards_command(client: Client, args: dict) -> list[CommandResults]:
    """
    Lists compliance standards with optional filtering.

    Args:
        client (Client): The client instance for API communication.
        args (dict): Command arguments containing optional filters:
            - name (str): Filter by standard name
            - created_by (str): Filter by creator
            - labels (list): Filter by labels (converts "Alibaba Cloud" to "alibaba_cloud" and "On Prem" to "on_prem")
            - page (int): Page number for pagination (default: 0)
            - page_size (int): Number of results per page (default: MAX_COMPLIANCE_STANDARDS)

    Returns:
        list[CommandResults]: List containing:
            - CommandResults with filtered compliance standards data and metadata
            - CommandResults with pagination metadata (filtered_count, returned_count)
    """
    name = args.get("name", "")
    created_by = args.get("created_by", "")
    labels = argToList(args.get("labels", ""))
    labels = ["alibaba_cloud" if label == "Alibaba Cloud" else "on_prem" if label == "On Prem" else label for label in labels]
    page = arg_to_number(args.get("page", "0"))
    page_size = arg_to_number(args.get("page_size", MAX_COMPLIANCE_STANDARDS))

    payload = list_compliance_standards_payload(
        name=name,
        created_by=created_by,
        labels=labels,
        page=page,
        page_size=page_size,
    )

    response = client.list_compliance_standards_command(payload)
    reply = response.get("reply", {})
    standards = reply.get("standards")
    demisto.debug(f"{standards=}")
    filtered_count = reply.get("result_count")
    returned_count = len(standards)

    filtered_standards = [
        {
            "id": s.get("id"),
            "name": s.get("name"),
            "description": s.get("description"),
            "controls_count": len(s.get("controls_ids", [])),
            "assessments_profiles_count": s.get("assessments_profiles_count", 0),
            "labels": s.get("labels", []),
        }
        for s in standards
    ]

    demisto.debug(f"{filtered_standards=}")
    command_results = []
    command_results.append(
        CommandResults(
            readable_output=tableToMarkdown("Compliance Standards", filtered_standards),
            outputs_prefix="Core.ComplianceStandards",
            outputs_key_field="id",
            outputs=filtered_standards,
            raw_response=reply,
        )
    )
    command_results.append(
        CommandResults(
            outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.ComplianceStandardsMetadata",
            outputs={"filtered_count": filtered_count, "returned_count": returned_count},
        )
    )

    return command_results


def validate_start_end_times(start_time, end_time):
    """
    Validate that start_time and end_time are provided correctly and represent
    a time range of at least two hours.

    Args:
        start_time (str | None): Start time in "HH:MM" format.
        end_time (str | None): End time in "HH:MM" format.

    Raises:
        DemistoException: If only one of the times is provided or the time range is less than two hours.
    """
    if (start_time and not end_time) or (end_time and not start_time):
        raise DemistoException("Both start_time and end_time must be provided together.")

    if start_time and end_time:
        start_dt = datetime.strptime(start_time, "%H:%M")
        end_dt = datetime.strptime(end_time, "%H:%M")
        diff = (end_dt - start_dt).total_seconds()
        if diff < 0:
            diff += SECONDS_IN_DAY

        if diff < MIN_DIFF_SECONDS:
            raise DemistoException("Start and end times must be at least two hours apart (midnight crossing is supported).")


def transform_distributions(response):
    """
    Takes the full API response and replaces `distributions` dict
    with a single flattened list while keeping everything else the same.
    """
    flattened = []
    distributions = response.get("distributions", {})
    total_count = arg_to_number(response.get("total_count"))

    for platform, items in distributions.items():
        for item in items:
            unsupported_os = arg_to_number(item.get("unsupported_os"))
            if item.get("is_beta") or item.get("less") == 0 or (unsupported_os != 0 and unsupported_os == total_count):
                continue

            new_item = remove_empty_elements(
                {
                    "platform": platform,
                    "endpoints_with_lower_version_count": item.get("less"),
                    "endpoints_with_higher_version_count": item.get("greater"),
                    "endpoints_with_same_version_count": item.get("equal"),
                    "version": item.get("version"),
                }
            )
            flattened.append(new_item)

    new_response = {"platform_count": response.get("platform_count"), "total_count": total_count, "distributions": flattened}
    return new_response


def get_endpoint_update_version_command(client, args):
    """
    Get the endpoint update version for specified endpoints.

    Args:
        client (Client): Integration client.
        args (dict): Command arguments containing endpoint list.

    Returns:
        CommandResults: Formatted results of endpoint update versions.
    """
    filter_builder = FilterBuilder()
    endpoint_ids = argToList(args.get("endpoint_ids", ""))
    filter_builder.add_field("AGENT_ID", FilterType.EQ, endpoint_ids)
    filter_data = {
        "filter": filter_builder.to_dict(),
    }
    request_data = {"filter_data": filter_data, "filter_type": "static"}
    demisto.debug(f"{request_data=}")
    response = client.get_endpoint_update_version(request_data)
    flattened_response = transform_distributions(response)
    return CommandResults(
        readable_output=tableToMarkdown(
            "Endpoint Update Versions", flattened_response.get("distributions"), headerTransform=string_to_table_header
        ),
        outputs=flattened_response,
        outputs_prefix="Core.EndpointUpdateVersion",
    )


def update_endpoint_version_command(client, args):
    """
    Update the agent version on one or more endpoints, optionally scheduling
    the update by days and time window.

    Args:
        client: API client used to communicate with the backend service.
        args (dict): Command arguments provided by the user.

    Returns:
        CommandResults: Object containing a human-readable summary and outputs
        with the endpoint IDs and the resulting group action ID (if created).
    """
    filter_builder = FilterBuilder()
    endpoint_ids = argToList(args.get("endpoint_ids", ""))
    filter_builder.add_field("AGENT_ID", FilterType.EQ, endpoint_ids)
    versions = {args.get("platform"): args.get("version")}
    days_arg = argToList(args.get("days", ""))

    if days_arg:
        days = [DAYS_MAPPING.get(day.lower()) for day in days_arg]
        if any(d is None for d in days):
            raise DemistoException("Please provide valid days.")
    else:
        days = None

    start_time = args.get("start_time")
    end_time = args.get("end_time")
    validate_start_end_times(start_time, end_time)

    filter_data = {
        "filter": filter_builder.to_dict(),
    }
    request_data = {
        "filter_data": filter_data,
        "filter_type": "static",
        "versions": versions,
        "upgrade_to_pkg_manager": False,
        "schedule_data": {"START_TIME": start_time, "END_TIME": end_time, "DAYS": days},
    }
    demisto.debug(f"Request data of the command core-update-endpoint-version: {request_data}")
    response = client.update_endpoint_version(request_data)
    demisto.debug(f"Response of the command core-update-endpoint-version: {response}")
    group_action_id = response.get("reply", {}).get("group_action_id")
    if not group_action_id:
        summary = "The update to the target versions was unsuccessful."
    else:
        summary = f"The update to the target versions was successful. Action ID: {group_action_id}"

    return CommandResults(
        readable_output=summary,
        outputs={"endpoint_ids": endpoint_ids, "action_id": group_action_id},
        outputs_prefix="Core.EndpointUpdate",
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


def convert_timeframe_string_to_json(time_to_convert: str) -> Dict[str, int]:
    """Convert a timeframe string to a json required for XQL queries.

    Args:
        time_to_convert (str): The time frame string to convert (supports seconds, minutes, hours, days, months, years, between).

    Returns:
        dict: The timeframe parameters in JSON.
    """
    try:
        time_to_convert_lower = time_to_convert.strip().lower()
        if time_to_convert_lower.startswith("between "):
            tokens = time_to_convert_lower[len("between ") :].split(" and ")
            if len(tokens) == 2:
                time_from = dateparser.parse(tokens[0], settings={"TIMEZONE": "UTC"})
                time_to = dateparser.parse(tokens[1], settings={"TIMEZONE": "UTC"})
                if time_from is None or time_to is None:
                    raise DemistoException(
                        "Failed to parse timeframe argument, please use a valid format."
                        " (e.g. '1 day', '3 weeks ago', 'between 2021-01-01 12:34:56 +02:00 and 2021-02-01 12:34:56 +02:00')"
                    )
                return {"from": int(time_from.timestamp() * 1000), "to": int(time_to.timestamp() * 1000)}
        else:
            relative = dateparser.parse(time_to_convert, settings={"TIMEZONE": "UTC"})
            now_date = datetime.utcnow()
            if relative is None or now_date is None:
                raise DemistoException(
                    "Failed to parse timeframe argument, please use a valid format."
                    " (e.g. '1 day', '3 weeks ago', 'between 2021-01-01 12:34:56 +02:00 and 2021-02-01 12:34:56 +02:00')"
                )
            return {"relativeTime": int((now_date - relative).total_seconds() * 1000)}

        raise ValueError(f"Invalid timeframe: {time_to_convert}")
    except Exception as exc:
        raise DemistoException(
            f"Please enter a valid time frame (seconds, minutes, hours, days, weeks, months, years, between).\n{exc!s}"
        )


def get_xql_query_results_platform(client: Client, execution_id: str) -> dict:
    """Retrieve results of an executed XQL query using Platform API.

    Args:
        client (Client): The XDR Client.
        execution_id (str): The execution ID of the query to retrieve.

    Returns:
        dict: The query results including status, execution_id, and results if completed.
    """
    data: dict[str, Any] = {
        "query_id": execution_id,
    }

    # Call the Client function and get the raw response
    demisto.debug(f"Calling get_query_results with {data=}")
    response = client.platform_http_request(
        method="POST", json_data=data, url_suffix="/xql_queries/results/info/", ok_codes=[200]
    )

    response["execution_id"] = execution_id
    stream_id = response.get("stream_id")
    if response.get("status") != "PENDING" and stream_id:
        data = {
            "stream_id": stream_id,
        }
        demisto.debug(f"Requesting query results using {data=}")
        query_data = client.platform_http_request(
            method="POST", json_data=data, url_suffix="/xql_queries/results/", ok_codes=[200]
        )
        if isinstance(query_data, str):
            response["results"] = [json.loads(line) for line in query_data.split("\n") if line.strip()]
        else:
            response["results"] = query_data

    if response.get("status") == "FAIL":
        # Get full error details using PAPI
        data = {
            "request_data": {
                "query_id": execution_id,
                "pending_flag": True,
                "format": "json",
            }
        }
        res = client._http_request(method="POST", url_suffix="/xql/get_query_results", json_data=data)
        response["error_details"] = res.get("reply", "")

    return response


def get_xql_query_results_platform_polling(client: Client, execution_id: str, timeout: int) -> dict:
    """Retrieve results of an executed XQL query using Platform API with polling.

    Args:
        client (Client): The XDR Client.
        execution_id (str): The execution ID of the query to fetch.
        timeout (int): The polling timeout in seconds.

    Returns:
        dict: The query results after polling completes or timeout is reached.
    """
    interval_in_secs = 10

    # Block execution until the execution status isn't pending or we time out
    polling_start_time = datetime.now()
    while (datetime.now() - polling_start_time).total_seconds() < timeout:
        outputs = get_xql_query_results_platform(client, execution_id)
        if outputs.get("status") != "PENDING":
            break

        t_to_timeout = (datetime.now() - polling_start_time).total_seconds()
        demisto.debug(
            f"Got status 'PENDING' for {execution_id}, next poll in {interval_in_secs} seconds. Timeout in {t_to_timeout}"
        )
        time.sleep(interval_in_secs)  # pylint: disable=E9003

    return outputs


def handle_xql_limit(query: str, max_limit: int) -> str:
    """Ensure the given query does not exceed the max limit.
    Overrides the limit if it exceeds the maximum or if a limit clause isn't present.

    Args:
        query (str): The XQL query string to process.
        max_limit (int): The max limit value.

    Returns:
        str: The original query if it already contains a valid limit clause, or the query
            with a max limit clause appended or the limit value replaced if it exceeds max_limit.
    """
    if not query or not query.strip():
        return query

    # Pattern to match limit keyword with number, skipping over comments and quotes
    # The pattern uses alternation: first try to match things to skip (comments/quotes),
    # then try to match the actual limit clause. This ensures we don't match "limit"
    # inside comments or quoted strings.
    limit_pattern = re.compile(
        r"""
        (?P<skip>                           # Group for things to skip (not replace)
            /\*.*?\*/                       # Block comments
            |//[^\n]*                       # Line comments
            |"(?:[^"\\]|\\.)*"              # Double-quoted strings
            |'(?:[^'\\]|\\.)*'              # Single-quoted strings
        )
        |(?P<limit>limit\s+)(?P<num>\d+)    # Or match limit keyword with number
        """,
        re.IGNORECASE | re.DOTALL | re.VERBOSE,
    )

    limit_found = False

    def replace_limit(match):
        """Replace limit value if it exceeds max_limit, skip comments/quotes."""
        nonlocal limit_found
        # We matched a limit clause
        if match.group("limit"):
            limit_found = True
            current_limit = int(match.group("num"))
            if current_limit > max_limit:
                return f"{match.group('limit')}{max_limit}"

        return match.group(0)

    result = limit_pattern.sub(replace_limit, query)

    # Add a max limit clause if no limit was found anywhere in the query
    if not limit_found:
        result = f"{result}\n| limit {max_limit}"

    return result


def start_xql_query_platform(client: Client, query: str, timeframe: dict) -> str:
    """Execute an XQL query using Platform API.

    Args:
        client (Client): The XDR Client.
        query (str): The XQL query string to execute.
        timeframe (dict): The timeframe for the query.

    Returns:
        str: The query execution ID.
    """
    data: Dict[str, Any] = {
        "query": query,
        "timeframe": timeframe,
    }

    demisto.debug(f"Calling xql_queries/submit with {data=}")
    res = client.platform_http_request(url_suffix="/xql_queries/submit/", method="POST", json_data=data, ok_codes=[200])
    return str(res)


def xql_query_platform_command(client: Client, args: dict) -> CommandResults:
    """Execute an XQL query using Platform API and poll for results.

    Args:
        client (Client): The XDR Client.
        args (dict): Command arguments including query, timeframe, wait_for_results, and timeout_in_seconds.

    Returns:
        CommandResults: The command results with execution_id, query_url, and optionally status and results.
    """
    query = args.get("query", "")
    if not query:
        raise ValueError("query is not specified")

    MAX_QUERY_LIMIT = 1000
    query_with_limit = handle_xql_limit(query, MAX_QUERY_LIMIT)
    timeframe = convert_timeframe_string_to_json(args.get("timeframe", "24 hours") or "24 hours")

    execution_id = start_xql_query_platform(client, query_with_limit, timeframe)

    if not execution_id:
        raise DemistoException("Failed to start query\n")

    query_url = "/".join([demisto.demistoUrls().get("server", ""), "xql/xql-search", execution_id])
    outputs = {
        "execution_id": execution_id,
        "query_url": query_url,
    }
    if query != query_with_limit:
        outputs["query_limit_modified"] = (
            f"Limit clauses larger than {MAX_QUERY_LIMIT} are currently not supported and have been reduced to {MAX_QUERY_LIMIT}"
        )

    if argToBoolean(args.get("wait_for_results", True)):
        demisto.debug(f"Polling query execution with {execution_id=}")
        timeout_in_secs = int(args.get("timeout_in_seconds", 180))
        outputs.update(get_xql_query_results_platform_polling(client, execution_id, timeout_in_secs))

    return CommandResults(
        outputs_prefix="GenericXQLQuery", outputs_key_field="execution_id", outputs=outputs, raw_response=outputs
    )


def init_client(api_type: str) -> Client:
    """
    Initializes the Client for a specific API type.

    Args:
        api_type (str): The category of the API (e.g., 'public', 'webapp', 'data_platform', etc.)
    """
    params = demisto.params()

    # Connection parameters
    proxy = params.get("proxy", False)
    verify_cert = not params.get("insecure", False)

    try:
        timeout = int(params.get("timeout", 120))
    except (ValueError, TypeError):
        timeout = 120

    # Base URL Mapping logic based on api_type
    webapp_root = "/api/webapp"

    url_map = {
        "webapp": webapp_root,
        "public": f"{webapp_root}/public_api/v1",
        "data_platform": f"{webapp_root}/data-platform",
        "appsec": f"{webapp_root}/public_api/appsec",
        "xsoar": "/xsoar",
        "agents": f"{webapp_root}/agents",
    }

    # Fallback to public API if the type isn't recognized
    client_url = url_map.get(api_type, url_map["public"])

    headers: dict = {"Authorization": params.get("api_key"), "Content-Type": "application/json"}

    return Client(
        base_url=client_url,
        proxy=proxy,
        verify=verify_cert,
        headers=headers,
        timeout=timeout,
    )


def enhance_with_pb_details(pb_id_to_data: dict, playbook: dict):
    related_pb = pb_id_to_data.get(playbook.get("id"))
    if related_pb:
        playbook["name"] = related_pb.get("name")
        playbook["description"] = related_pb.get("comment")


def postprocess_case_resolution_statuses(client, response: dict):
    response = copy.deepcopy(response)
    pbs_metadata = client.get_playbooks_metadata() or []
    pb_id_to_data = map_pb_id_to_data(pbs_metadata)

    all_items = []
    categories = ["done", "inProgress", "pending", "recommended"]

    for category in categories:
        tasks = response.get(category, {}).get("caseTasks", [])
        for task in tasks:
            # Add category field to identify which list this came from
            task["category"] = category
            if category in ["done", "inProgress", "recommended"]:
                task["itemType"] = "playbook"
            else:
                task["itemType"] = "playbookTask"

            if category in ["done", "inProgress"]:
                enhance_with_pb_details(pb_id_to_data, task)
            elif category == "pending":
                enhance_with_pb_details(pb_id_to_data, task.get("parentdetails"))
                task["parentPlaybook"] = task.pop("parentdetails")

            all_items.append(task)

    return all_items


def get_case_resolution_statuses(client, args):
    case_ids = argToList(args.get("case_id"))
    raw_responses = []
    outputs = []
    for case_id in case_ids:
        response = client.get_case_resolution_statuses(case_id)
        raw_responses.append(response)
        outputs.append(postprocess_case_resolution_statuses(client, response))
    return CommandResults(
        readable_output=tableToMarkdown("Case Resolution Statuses", outputs, headerTransform=string_to_table_header),
        outputs_prefix="Core.CaseResolutionStatus",
        outputs=outputs,
        raw_response=raw_responses,
    )


def build_target_filter_from_endpoint_ids(endpoint_ids: list[str]) -> dict:
    """
    Build a TARGET_FILTER object from endpoint names.

    Args:
        endpoint_names: List of endpoint names to target.

    Returns:
        dict: Filter object for targeting specific endpoints.
    """
    if len(endpoint_ids) == 1:
        # Single endpoint
        return {"filter": {"AND": [{"SEARCH_FIELD": "AGENT_ID", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": endpoint_ids[0]}]}}
    else:
        # Multiple endpoints - use OR logic
        or_conditions = [
            {"SEARCH_FIELD": "AGENT_ID", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": endpoint_id} for endpoint_id in endpoint_ids
        ]
        return {"filter": {"AND": [{"OR": or_conditions}]}}


def validate_profile_platform_compatibility(platform: str, profile_args: dict[str, str | None]) -> None:
    """
    Validate that the provided profiles are supported by the specified platform.

    Platform-specific profile restrictions:
    - serverless: Only 'restrictions' profile allowed
    - Android, iOS: Only 'malware' and 'agent_settings' profiles allowed
    - Linux, macOS, Windows: All profiles allowed

    Args:
        platform: The platform type (e.g., AGENT_OS_WINDOWS, AGENT_OS_SERVERLESS).
        profile_args: Dictionary of profile argument names to their values.
                     Keys should be profile types (e.g., 'exploit_profile', 'malware_profile').

    Raises:
        DemistoException: If a profile is provided that is not supported by the platform.
    """
    # Define allowed profiles per platform
    PLATFORM_ALLOWED_PROFILES: dict[str, list[str]] = {
        "serverless": ["restrictions"],
        "android": ["malware", "agent_settings"],
        "ios": ["malware", "agent_settings"],
        "linux": ["exploit", "malware", "agent_settings", "restrictions", "exceptions"],
        "mac": ["exploit", "malware", "agent_settings", "restrictions", "exceptions"],
        "windows": ["exploit", "malware", "agent_settings", "restrictions", "exceptions"],
    }

    allowed_profiles: list[str] = PLATFORM_ALLOWED_PROFILES.get(platform) or []

    # Check each provided profile
    unsupported_profiles = []
    for profile_name, profile_value in profile_args.items():
        # Skip if profile is not provided
        if not profile_value:
            continue

        # profile_name is the key like 'exploit', 'malware', etc.
        if profile_name not in allowed_profiles:
            unsupported_profiles.append(f"{profile_name} (value: {profile_value})")

    if unsupported_profiles:
        allowed_list = ", ".join(sorted(allowed_profiles))
        unsupported_list = ", ".join(unsupported_profiles)

        raise DemistoException(
            f"The following profiles are not supported for platform '{platform}': {unsupported_list}. "
            f"Allowed profiles for this platform: {allowed_list}."
        )


def get_profile_ids(client: Client, platform: str, profile_args: dict[str, str | None]) -> dict[str, dict[str, Any]]:
    """
    Get profile IDs for multiple profiles from AGENT_PROFILES_TABLE using OR filters.

    Args:
        client: The Cortex Platform client instance.
        platform: The platform type (e.g., AGENT_OS_WINDOWS, AGENT_OS_LINUX).
        profile_args: Dictionary mapping profile type (lowercase) to profile name or ID.
                     Example: {'exploit': 'Default', 'malware': 'Default'}

    Returns:
        dict: Dictionary mapping 'PROFILE_TYPE' (uppercase) to profile data.
              Example: {'EXPLOIT': {'id': 11, 'name': 'Default'}, 'MALWARE': {'id': 10, 'name': 'Default'}}

    Raises:
        DemistoException: If multiple profiles with the same name exist for a profile type,
                         or if a requested profile doesn't exist.
    """
    or_filters = []
    for profile_type_lower, profile_name_or_id in profile_args.items():
        if not profile_name_or_id:  # Skip profiles without values
            continue

        profile_type = profile_type_lower.upper()

        # Create AND condition for each profile (name OR id + type)
        and_condition = [
            {
                "OR": [
                    {"SEARCH_FIELD": "PROFILE_NAME", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": profile_name_or_id},
                    {"SEARCH_FIELD": "PROFILE_ID", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": profile_name_or_id},
                ]
            },
            {"SEARCH_FIELD": "PROFILE_TYPE", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": profile_type},
        ]
        or_filters.append({"AND": and_condition})

    # Build the complete filter structure with platform at the top level
    combined_filter = {
        "AND": [
            {"SEARCH_FIELD": "PROFILE_PLATFORM", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": Endpoints.ENDPOINT_PLATFORM[platform]},
            {"OR": or_filters},
        ]
    }

    request_data = {
        "type": "grid",
        "table_name": AGENT_PROFILES_TABLE,
        "filter_data": {
            "sort": [],
            "filter": combined_filter,
        },
    }

    demisto.debug(f"Querying profiles with filter: {combined_filter}")

    response = client.get_webapp_data(request_data)
    profiles_data = response.get("reply", {})

    # Group profiles by type to detect duplicates
    profiles_by_type: dict[str, list[dict]] = {}
    for profile in profiles_data:
        profile_type = profile.get("PROFILE_TYPE")
        if profile_type:
            if profile_type not in profiles_by_type:
                profiles_by_type[profile_type] = []
            profiles_by_type[profile_type].append(profile)

    # Build mapping and check for duplicates
    profile_map: dict[str, dict[str, Any]] = {}

    for profile_type_lower, profile_name_or_id in profile_args.items():
        if not profile_name_or_id:  # Skip profiles without values
            continue

        profile_type = profile_type_lower.upper()
        matching_profiles = profiles_by_type.get(profile_type, [])

        # Check if profile exists
        if not matching_profiles:
            raise DemistoException(
                f"Profile '{profile_name_or_id}' of type '{profile_type}' not found for platform '{platform}'. "
                f"Please verify the profile name or ID exists."
            )

        # Check for multiple profiles with the same name
        if len(matching_profiles) > 1:
            profile_details = "\n".join(
                [f"  - Name: {p.get('PROFILE_NAME')}, ID: {p.get('PROFILE_ID')}" for p in matching_profiles]
            )
            raise DemistoException(
                f"Multiple profiles found with name '{profile_name_or_id}' for type '{profile_type}':\n{profile_details}\n"
                f"Please use the profile ID instead to specify which one you want."
            )

        # Single profile found - add to map
        profile = matching_profiles[0]
        profile_id = profile.get("PROFILE_ID")
        profile_name = profile.get("PROFILE_NAME")
        profile_map[profile_type] = {"id": profile_id, "name": profile_name}

    demisto.debug(f"Retrieved profile IDs for platform {platform}: {profile_map}")
    return profile_map


def fetch_policy_table(client: Client) -> tuple[list[dict], str]:
    """
    Fetch the current agent policy table and hash.

    Returns:
        tuple: (policies_list, policy_hash)

    Raises:
        DemistoException: If policy hash cannot be retrieved.
    """
    demisto.debug("Fetching current agent policy table")
    policy_response = client.get_agent_policy_table()
    reply = policy_response.get("reply", {})
    current_policies = reply.get("DATA", [])
    policy_hash = reply.get("POLICY_HASH", "")

    if not policy_hash:
        raise DemistoException("Failed to retrieve policy hash from the current policy table.")

    demisto.debug(f"Current policy hash: {policy_hash}")
    demisto.debug(f"Current policies count: {len(current_policies)}")

    return current_policies, policy_hash


def resolve_platform_name(platform: str) -> str:
    """
    Resolve platform name.

    Args:
        platform: Platform name (e.g., 'windows', 'linux')

    Returns:
        str: Platform value (e.g., 'AGENT_OS_WINDOWS')

    Raises:
        DemistoException: If platform is invalid.
    """
    platform_value = Endpoints.ENDPOINT_PLATFORM.get(platform)
    if not platform_value:
        raise DemistoException(
            f"Invalid platform '{platform}'. Valid platforms are: {', '.join(Endpoints.ENDPOINT_PLATFORM.keys())}"
        )
    return platform_value


def resolve_endpoint_names_to_ids(client: Client, endpoint_names: list[str]) -> list[str]:
    """Resolve endpoint names to IDs and validate no duplicates exist."""
    demisto.debug(f"Resolving endpoint names to IDs: {endpoint_names}")

    filter_builder = FilterBuilder()
    filter_builder.add_field(Endpoints.ENDPOINT_FIELDS["endpoint_name"], FilterType.EQ, endpoint_names)

    request_data = build_webapp_request_data(
        table_name=AGENTS_TABLE,
        filter_dict=filter_builder.to_dict(),
        limit=MAX_GET_ENDPOINTS_LIMIT,
        sort_field="AGENT_NAME",
        sort_order="ASC",
    )

    response = client.get_webapp_data(request_data)
    reply = response.get("reply", {})
    raw_endpoints = reply.get("DATA", [])

    if not raw_endpoints:
        raise DemistoException(f'No endpoints found with the specified names: {", ".join(endpoint_names)}')

    endpoints = map_endpoint_format(raw_endpoints)

    # Check for duplicate endpoint names
    endpoint_name_to_ids: dict[str, list[str]] = {}
    for endpoint in endpoints:
        endpoint_name = endpoint.get("endpoint_name")
        endpoint_id = endpoint.get("endpoint_id")

        if endpoint_name and endpoint_id:
            if endpoint_name not in endpoint_name_to_ids:
                endpoint_name_to_ids[endpoint_name] = []
            endpoint_name_to_ids[endpoint_name].append(endpoint_id)

    duplicates = {name: ids for name, ids in endpoint_name_to_ids.items() if len(ids) > 1}

    if duplicates:
        error_message = "Multiple endpoints found with the same name. Please use target_endpoint_ids instead:\n\n"
        for endpoint_name, endpoint_ids in duplicates.items():
            error_message += f'Endpoint Name: "{endpoint_name}"\n'
            for endpoint_id in endpoint_ids:
                error_message += f"  - ID: {endpoint_id}\n"
            error_message += "\n"
        raise DemistoException(error_message.strip())

    endpoint_ids = [endpoint["endpoint_id"] for endpoint in endpoints if endpoint.get("endpoint_id")]
    demisto.debug(f"Resolved endpoint IDs: {endpoint_ids}")
    return endpoint_ids


def create_endpoint_policy_command(client: Client, args: dict) -> CommandResults:
    """
    Creates a new endpoint policy and applies it to specified endpoints.

    This command handles the complex logic of:
    1. Fetching the current policy table and hash
    2. Managing priority conflicts (shifting existing policies if needed)
    3. Creating the new policy with proper schema (TARGET, TARGET_FILTER, profile IDs, etc.)
    4. Updating the policy table with the complete data

    Policy Priority Specifications:
    - Default Policy: Fixed at priority 0 (system-level constant). This is a system-level constant
    and cannot be assigned to user-defined policies.
    - Priority Ranking: Higher numbers = higher precedence
    - UI Display: Policies sorted descending (highest priority first)

    Args:
        client: The Cortex Platform client instance.
        args: Dictionary containing policy configuration parameters:
            - policy_name (required): Name for the new policy
            - target_endpoint_names (optional): Comma-separated list of endpoint names
            - target_endpoint_ids (optional): Comma-separated list of endpoint IDs
            - platform (required): Platform type (AGENT_OS_WINDOWS, AGENT_OS_MAC, etc.)
            - description (optional): Policy description
            - priority (optional): Policy priority (default: auto-assigned)
            - exploit_profile (optional): Exploit protection profile name
            - malware_profile (optional): Malware protection profile name
            - agent_settings_profile (optional): Agent settings profile name


    Returns:
        CommandResults: Results object with success message and created policy details.

    Raises:
        DemistoException: If required parameters are missing or policy creation fails.
    """

    def calculate_policy_priority(current_policies: list[dict], platform_value: str, requested_priority: int | None) -> int:
        """Calculate and validate policy priority, handling auto-assignment."""
        MIN_USER_POLICY_PRIORITY = 1
        platform_policies = [p for p in current_policies if p.get("PLATFORM") == platform_value]

        if not platform_policies:
            priority = MIN_USER_POLICY_PRIORITY
        else:
            max_existing_priority = max(p.get("PRIORITY", 0) for p in platform_policies)

            if requested_priority is None:
                priority = max_existing_priority + 1
            elif requested_priority > max_existing_priority:
                demisto.debug(
                    f"Priority {requested_priority} is higher than max ({max_existing_priority}). "
                    f"Setting to {max_existing_priority + 1}."
                )
                priority = max_existing_priority + 1
            else:
                priority = requested_priority

        if priority < MIN_USER_POLICY_PRIORITY:
            raise DemistoException(f"Priority must be at least {MIN_USER_POLICY_PRIORITY}.")

        return priority

    def shift_policy_priorities(current_policies: list[dict], platform_value: str, new_priority: int) -> None:
        """Shift existing policies with priority >= new_priority up by 1 (modifies in-place)."""
        existing_priority_policy = next(
            (p for p in current_policies if p.get("PLATFORM") == platform_value and p.get("PRIORITY") == new_priority), None
        )

        if not existing_priority_policy:
            return

        demisto.debug(f"Priority {new_priority} exists. Shifting policies.")

        policies_to_shift = sorted(
            [p for p in current_policies if p.get("PLATFORM") == platform_value and p.get("PRIORITY", 0) >= new_priority],
            key=lambda p: p.get("PRIORITY", 0),
            reverse=True,
        )

        for policy in policies_to_shift:
            current_priority = policy.get("PRIORITY", 0)
            new_priority_value = current_priority + 1
            policy["PRIORITY"] = new_priority_value
            demisto.debug(f"Shifted '{policy.get('NAME')}' from {current_priority} to {new_priority_value}")

    def get_identity_and_web_api_profile_defaults(platform_value: str) -> dict[str, Any]:
        """
        Get platform-specific default profile IDs for identity and web_and_api.
        Note: identity and web_and_api are currently not supported, but the api expect to get them in the request.
        """
        WINDOWS_IDENTITY_PROFILE_ID = 17
        LINUX_WEB_AND_API_PROFILE_ID = 12
        if platform_value == "AGENT_OS_WINDOWS":
            return {
                "identity": "Default",
                "identity_id": WINDOWS_IDENTITY_PROFILE_ID,
                "web_and_api": None,
                "web_and_api_id": None,
            }
        elif platform_value == "AGENT_OS_LINUX":
            return {
                "identity": None,
                "identity_id": None,
                "web_and_api": "Default",
                "web_and_api_id": LINUX_WEB_AND_API_PROFILE_ID,
            }
        else:
            return {
                "identity": None,
                "identity_id": None,
                "web_and_api": None,
                "web_and_api_id": None,
            }

    def get_platform_specific_profile_defaults(platform: str, args: dict) -> dict[str, str | None]:
        """
        Get platform-specific default profile values.

        Platform-specific default values:
        - serverless: restrictions = 'Default', all others = None
        - android, ios: malware, agent_settings = 'Default', all others = None
        - linux, mac, windows: exceptions = 'Default (No Exceptions)', all others = 'Default'

        Args:
            platform: The platform type (e.g., 'serverless', 'android', 'linux')
            args: Command arguments containing user-provided profile values

        Returns:
            dict: Profile arguments with platform-specific defaults applied
        """
        # Get user-provided values (None if not provided)
        user_exploit = args.get("exploit_profile")
        user_malware = args.get("malware_profile")
        user_agent_settings = args.get("agent_settings_profile")
        user_restrictions = args.get("restrictions_profile")
        user_exceptions = args.get("exceptions_profile")

        # Set platform-specific defaults
        if platform == "serverless":
            return {
                "exploit": user_exploit,
                "malware": user_malware,
                "agent_settings": user_agent_settings,
                "restrictions": user_restrictions or "Default",
                "exceptions": user_exceptions,
            }
        elif platform in ["android", "ios"]:
            return {
                "exploit": user_exploit,
                "malware": user_malware or "Default",
                "agent_settings": user_agent_settings or "Default",
                "restrictions": user_restrictions,
                "exceptions": user_exceptions,
            }
        else:  # linux, mac, windows
            return {
                "exploit": user_exploit or "Default",
                "malware": user_malware or "Default",
                "agent_settings": user_agent_settings or "Default",
                "restrictions": user_restrictions or "Default",
                "exceptions": user_exceptions or "Default (No Exceptions)",
            }

    def build_policy_object(
        policy_name: str,
        platform_value: str,
        priority: int,
        target_endpoint_ids: list[str],
        profile_map: dict[str, dict[str, Any]],
        description: str,
    ) -> dict[str, Any]:
        """Build the complete policy object with all required fields."""
        identity_and_web_api_profiles = get_identity_and_web_api_profile_defaults(platform_value)
        target_filter = build_target_filter_from_endpoint_ids(target_endpoint_ids)

        # Extract profile data
        policy = {
            "IS_ANY": False,
            "PLATFORM": platform_value,
            "NAME": policy_name,
            "IS_ENABLED": True,
            "TARGET_FILTER": target_filter,
            "TARGET_GROUP_TYPE": "STATIC",
            "EXPLOIT": profile_map.get("EXPLOIT", {}).get("name"),
            "EXPLOIT_ID": profile_map.get("EXPLOIT", {}).get("id"),
            "MALWARE": profile_map.get("MALWARE", {}).get("name"),
            "MALWARE_ID": profile_map.get("MALWARE", {}).get("id"),
            "AGENT_SETTINGS": profile_map.get("AGENT_SETTINGS", {}).get("name"),
            "AGENT_SETTINGS_ID": profile_map.get("AGENT_SETTINGS", {}).get("id"),
            "RESTRICTIONS": profile_map.get("RESTRICTIONS", {}).get("name"),
            "RESTRICTIONS_ID": profile_map.get("RESTRICTIONS", {}).get("id"),
            "EXCEPTIONS": profile_map.get("EXCEPTIONS", {}).get("name"),
            "EXCEPTIONS_ID": profile_map.get("EXCEPTIONS", {}).get("id"),
            "IDENTITY_ID": identity_and_web_api_profiles["identity_id"],
            "IDENTITY": identity_and_web_api_profiles["identity"],
            "WEB_AND_API_ID": identity_and_web_api_profiles["web_and_api_id"],
            "WEB_AND_API": identity_and_web_api_profiles["web_and_api"],
            "TARGET": [],
            "PRIORITY": priority,
            "DESCRIPTION": description,
        }

        return policy

    # 1. Parse and validate arguments
    policy_name = args.get("policy_name", "")
    target_endpoint_names = argToList(args.get("target_endpoint_names", ""))
    target_endpoint_ids = argToList(args.get("target_endpoint_ids", ""))
    platform = args.get("platform", "")
    description = args.get("description", "")
    requested_priority = arg_to_number(args.get("priority"))

    if target_endpoint_names and target_endpoint_ids:
        raise DemistoException(
            "Cannot provide both target_endpoint_names and target_endpoint_ids. " "Please use one or the other."
        )

    if not target_endpoint_names and not target_endpoint_ids:
        raise DemistoException("Either target_endpoint_names or target_endpoint_ids must be provided.")

    platform_value = resolve_platform_name(platform)

    if target_endpoint_names:
        target_endpoint_ids = resolve_endpoint_names_to_ids(client, target_endpoint_names)

    current_policies, policy_hash = fetch_policy_table(client)

    priority = calculate_policy_priority(current_policies, platform_value, requested_priority)
    shift_policy_priorities(current_policies, platform_value, priority)

    profile_args = get_platform_specific_profile_defaults(platform, args)

    # Validate that user isn't trying to set profiles not allowed for the platform
    # This will raise an error if incompatible profiles are provided
    validate_profile_platform_compatibility(platform, profile_args)
    profile_map = get_profile_ids(client, platform, profile_args)

    new_policy = build_policy_object(
        policy_name=policy_name,
        platform_value=platform_value,
        priority=priority,
        target_endpoint_ids=target_endpoint_ids,
        profile_map=profile_map,
        description=description,
    )

    demisto.debug(f"New policy to be created: {new_policy}")

    updated_policies = current_policies + [new_policy]
    update_payload = {
        "DATA": updated_policies,
        "POLICY_HASH": policy_hash,
    }

    demisto.debug("Updating agent policy table")
    response = client.update_agent_policy(update_payload)

    readable_output = (
        f"Successfully created endpoint policy '{policy_name}' with priority {priority} "
        f"for platform {platform}.\n"
        f"Target endpoints (by ID): {', '.join(target_endpoint_ids)}"
    )

    outputs = {
        "PolicyName": policy_name,
        "Platform": platform,
        "Priority": priority,
        "TargetEndpointIds": target_endpoint_ids,
        "ExploitProfile": profile_args["exploit"],
        "MalwareProfile": profile_args["malware"],
        "AgentSettingsProfile": profile_args["agent_settings"],
        "RestrictionsProfile": profile_args["restrictions"],
        "ExceptionsProfile": profile_args["exceptions"],
        "Description": description,
    }
    remove_nulls_from_dictionary(outputs)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.EndpointPolicy",
        outputs_key_field="PolicyName",
        outputs=outputs,
        raw_response=response,
    )


def find_policies_to_delete(
    platform_policies: list[dict],
    policy_names: list[str],
    policy_ids: list[str],
    platform: str,
) -> list[dict]:
    """Find the policies to delete based on names or IDs."""
    policies_to_delete = []

    if policy_ids:
        # Delete by IDs
        for policy_id in policy_ids:
            matching_policies = [p for p in platform_policies if str(p.get("ID")) == str(policy_id)]

            if not matching_policies:
                raise DemistoException(f"No policy found with ID '{policy_id}' for platform '{platform}'.")

            policies_to_delete.append(matching_policies[0])
    else:
        # Delete by names
        for policy_name in policy_names:
            matching_policies = [p for p in platform_policies if p.get("NAME") == policy_name]

            if not matching_policies:
                raise DemistoException(f"No policy found with name '{policy_name}' for platform '{platform}'.")

            if len(matching_policies) > 1:
                policy_details = "\n".join(
                    [f"  - Name: {p.get('NAME')}, ID: {p.get('ID')}, Priority: {p.get('PRIORITY')}" for p in matching_policies]
                )
                raise DemistoException(
                    f"Multiple policies found with name '{policy_name}' for platform '{platform}':\n{policy_details}\n"
                    f"Please use policy_id to specify which one to delete."
                )

            policies_to_delete.append(matching_policies[0])

    return policies_to_delete


def validate_policy_deletable(policy: dict, platform: str) -> None:
    """Validate that a policy can be deleted."""
    DEFAULT_POLICY_PRIORITY = 0  # System default, cannot be deleted
    priority = policy.get("PRIORITY")

    if priority == DEFAULT_POLICY_PRIORITY:
        policy_name = policy.get("NAME")
        raise DemistoException(
            f"Cannot delete the default policy '{policy_name}' "
            f"(priority {DEFAULT_POLICY_PRIORITY}) for platform '{platform}'. "
            f"Default policies are system-level and cannot be removed."
        )


def delete_endpoint_policy_command(client: Client, args: dict) -> CommandResults:
    """
    Deletes one or more existing endpoint policies from the policy table.

    This command:
    1. Fetches the current policy table and hash
    2. Identifies policies to delete by names or IDs
    3. Validates policies can be deleted (not default policies)
    4. Removes the policies and updates the table

    Args:
        client: The Cortex Platform client instance.
        args: Dictionary containing policy identification parameters.

    Returns:
        CommandResults: Results object with success message and deleted policy details.

    Raises:
        DemistoException: If required parameters are missing, policies not found,
                         or multiple policies match the criteria.
    """
    policy_names = argToList(args.get("policy_name"))
    policy_ids = argToList(args.get("policy_id"))
    platform = args.get("platform", "")

    if not policy_names and not policy_ids:
        raise DemistoException("Either policy_name or policy_id must be provided to identify the policy to delete.")

    if policy_names and policy_ids:
        raise DemistoException("Cannot provide both policy_name and policy_id. Please use one or the other.")

    platform_value = resolve_platform_name(platform)

    current_policies, policy_hash = fetch_policy_table(client)

    platform_policies = [p for p in current_policies if p.get("PLATFORM") == platform_value]
    demisto.debug(f"Found {len(platform_policies)} policies for platform '{platform}'")

    if not platform_policies:
        raise DemistoException(f"No policies found for platform '{platform}'.")

    policies_to_delete = find_policies_to_delete(platform_policies, policy_names, policy_ids, platform)

    for policy in policies_to_delete:
        validate_policy_deletable(policy, platform)

    deleted_policies_info = []
    for policy in policies_to_delete:
        policy_info = {
            "PolicyName": policy.get("NAME"),
            "PolicyID": policy.get("ID"),
            "Platform": platform,
            "Priority": policy.get("PRIORITY"),
            "Deleted": True,
        }
        deleted_policies_info.append(policy_info)
        demisto.debug(
            f"Deleting policy: Name='{policy_info['PolicyName']}', "
            f"ID={policy_info['PolicyID']}, Priority={policy_info['Priority']}"
        )

    policies_to_delete_set = {p.get("ID") for p in policies_to_delete}
    updated_policies = [p for p in current_policies if p.get("ID") not in policies_to_delete_set]
    demisto.debug(f"Policies count after deletion: {len(updated_policies)} (removed {len(policies_to_delete)})")

    update_payload = {
        "DATA": updated_policies,
        "POLICY_HASH": policy_hash,
    }

    demisto.debug("Updating agent policy table")
    response = client.update_agent_policy(update_payload)

    readable_output = "Successfully deleted the following endpoint policies:\n\n"
    for policy_info in deleted_policies_info:
        readable_output += (
            f"- Name: {policy_info['PolicyName']}, ID: {policy_info['PolicyID']}, Priority: {policy_info['Priority']}\n"
        )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{INTEGRATION_CONTEXT_BRAND}.DeletedEndpointPolicy",
        outputs_key_field="PolicyID",
        outputs=deleted_policies_info,
        raw_response=response,
    )


def verify_platform_version(version: str = "8.13.0"):
    if not is_demisto_version_ge(version):
        raise DemistoException("This command is not available for this platform version")


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
    # Logic to determine which API type the current command belongs to
    if command in WEBAPP_COMMANDS:
        api_type = "webapp"
    elif command in DATA_PLATFORM_COMMANDS:
        api_type = "data_platform"
    elif command in APPSEC_COMMANDS:
        api_type = "appsec"
    elif command in ENDPOINT_COMMANDS:
        api_type = "agents"
    elif command in XSOAR_COMMANDS:
        api_type = "xsoar"
    else:
        api_type = "public"

    client = init_client(api_type)

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
        elif command == "core-list-scripts":
            return_results(list_scripts_command(client, args))
        elif command == "core-run-script-agentix":
            return_results(run_script_agentix_command(client, args))

        elif command == "core-get-endpoint-support-file":
            return_results(get_endpoint_support_file_command(client, args))

        elif command == "core-list-exception-rules":
            return_results(list_exception_rules_command(client, args))
        elif command == "core-list-system-users":
            return_results(list_system_users_command(client, args))
        elif command == "core-list-endpoints":
            return_results(core_list_endpoints_command(client, args))
        elif command == "core-add-assessment-profile":
            return_results(core_add_assessment_profile_command(client, args))
        elif command == "core-list-compliance-standards":
            return_results(core_list_compliance_standards_command(client, args))

        elif command == "core-get-endpoint-update-version":
            return_results(get_endpoint_update_version_command(client, args))

        elif command == "core-update-endpoint-version":
            return_results(update_endpoint_version_command(client, args))

        elif command == "core-get-case-resolution-statuses":
            verify_platform_version()
            return_results(get_case_resolution_statuses(client, args))

        elif command == "core-xql-generic-query-platform":
            verify_platform_version()
            return_results(xql_query_platform_command(client, args))

        elif command == "core-create-endpoint-policy":
            return_results(create_endpoint_policy_command(client, args))

        elif command == "core-delete-endpoint-policy":
            return_results(delete_endpoint_policy_command(client, args))

    except Exception as err:
        demisto.error(traceback.format_exc())
        return_error(str(err))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
