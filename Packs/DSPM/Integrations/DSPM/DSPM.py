import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401

import urllib3
from typing import Any
import re


# Disable insecure warnings
urllib3.disable_warnings()
""" CONSTANTS """
MAX_PAGE_SIZE: int = 50
DEFAULT_LIMIT: str = "50"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
GET_RISK_FINDINGS_ENDPOINT = "/v1/risk-findings"
GET_ASSET_LISTS = "/v1/assets"
GET_ASSET_DETAILS = "/v1/assets/id?id="
GET_ASSET_FILES = "/v1/classification/asset-files/id"
GET_ASSET_FIELDS = "/v1/classification/asset-fields/id"
GET_DATA_TYPES_ENDPOINT: str = "/v1/classification/data-types"
GET_DATA_TYPE_FINDINGS_ENDPOINT: str = "/v1/data-type-findings"
GET_ALERTS_LIST: str = "/v1/alerts"
GET_LABELS: str = "/v1/labels"
GET_RISK_FINDING_BY_ID: str = "/v1/risk-findings/id/"

SUPPORTED_CLOUD_PROVIDERS = ["AWS", "AZURE", "GCP", "SNOWFLAKE", "FILE_SHARE", "O365"]
SUPPORTED_CATEGORIES = [
    "SECURITY",
    "COMPLIANCE",
    "GOVERNANCE",
    "SECURITY_AND_COMPLIANCE",
    "SECURITY_AND_GOVERNANCE",
    "COMPLIANCE_AND_GOVERNANCE",
    "SECURITY_AND_COMPLIANCE_AND_GOVERNANCE",
]
SUPPORTED_SERVICE_TYPES = [
    "ATHENA",
    "AURORA",
    "AWS_BACKUP",
    "DOCUMENTDB",
    "DYNAMODB",
    "DAX",
    "EMR",
    "EBS",
    "EFS",
    "ELASTICACHE",
    "FSX",
    "KINESIS_DELIVERY_STREAM",
    "MEMORYDB",
    "NEPTUNE",
    "QLDB",
    "RDS",
    "REDSHIFT",
    "S3",
    "TIMESTREAM",
    "OPENSEARCH",
    "COSMOS_DB",
    "SYNAPSE",
    "CACHE_FOR_REDIS",
    "MARIA_DB",
    "MYSQL_SERVER",
    "POSTGRESQL_SERVER",
    "SQL_SERVER",
    "STORAGE_ACCOUNT",
    "SQL_MANAGED_INSTANCE",
    "ANF",
    "CLOUD_STORAGE",
    "CLOUD_SQL",
    "BIG_QUERY",
    "FILE_STORE",
    "CLOUD_SPANNER",
    "MEMORY_STORE",
    "BIG_TABLE",
    "FIRE_STORE",
    "UNMANAGED_AWS_MYSQL",
    "UNMANAGED_AWS_ORACLE_SERVER",
    "UNMANAGED_AWS_MONGO_DB",
    "UNMANAGED_AWS_POSTGRESQL",
    "UNMANAGED_AWS_REDIS",
    "UNMANAGED_AWS_SQLITE",
    "UNMANAGED_AWS_MS_SQL",
    "UNMANAGED_AWS_MARIA_DB",
    "UNMANAGED_AWS_NEO4_J",
    "UNMANAGED_AWS_ELASTIC",
    "UNMANAGED_AWS_COCKROACH_DB",
    "UNMANAGED_AWS_AEROSPIKE",
    "UNMANAGED_AWS_SCYLLA_DB",
    "UNMANAGED_AZURE_MYSQL",
    "UNMANAGED_AZURE_ORACLE_SERVER",
    "UNMANAGED_AZURE_MONGO_DB",
    "UNMANAGED_AZURE_POSTGRESQL",
    "UNMANAGED_AZURE_REDIS",
    "UNMANAGED_AZURE_SQLITE",
    "UNMANAGED_AZURE_MS_SQL",
    "UNMANAGED_AZURE_MARIA_DB",
    "UNMANAGED_AZURE_NEO4_J",
    "UNMANAGED_AZURE_ELASTIC",
    "UNMANAGED_AZURE_COCKROACH_DB",
    "UNMANAGED_AZURE_AEROSPIKE",
    "UNMANAGED_AZURE_SCYLLA_DB",
    "UNMANAGED_GCP_MYSQL",
    "UNMANAGED_GCP_ORACLE_SERVER",
    "UNMANAGED_GCP_MONGO_DB",
    "UNMANAGED_GCP_POSTGRESQL",
    "UNMANAGED_GCP_REDIS",
    "UNMANAGED_GCP_SQLITE",
    "UNMANAGED_GCP_MS_SQL",
    "UNMANAGED_GCP_MARIA_DB",
    "UNMANAGED_GCP_NEO4_J",
    "UNMANAGED_GCP_ELASTIC",
    "UNMANAGED_GCP_COCKROACH_DB",
    "UNMANAGED_GCP_AEROSPIKE",
    "UNMANAGED_GCP_SCYLLA_DB",
    "SNOWFLAKE_DB",
    "FILE_SHARE",
    "ONE_DRIVE",
    "SHARE_POINT",
    "AZURE_OPEN_AI_DEPLOYMENT",
    "VERTEX_ENDPOINT",
]
SUPPORTED_LIFECYCLE = ["RUNNING", "STOPPED", "DELETED"]
SUPPORTED_STATUSES = [
    "OPEN",
    "CLOSED",
    "UNIMPORTANT",
    "WRONG",
    "HANDLED",
    "INVESTIGATING",
]
SUPPORTED_CLOUD_ENVIRONMENTS = ["UNKNOWN", "DEVELOPMENT", "STAGING", "TESTING", "PRODUCTION"]
SUPPORTED_POLICY_SEVERITIES = ["HIGH", "MEDIUM", "LOW"]
SUPPORTED_CATEGORY_TYPES = ["FIRST_MOVE", "ATTACK", "COMPLIANCE", "ASSET_AT_RISK", "RECONNAISSANCE"]

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API"""

    def __init__(self, base_url, api_key, verify=True, proxy=False):
        headers = {"dig-api-key": api_key, "Accept": "application/json"}
        super().__init__(base_url, verify=verify, headers=headers, proxy=proxy)

    def get_labels(self):
        return self._http_request(
            method="GET", url_suffix=f"{GET_LABELS}"
        )

    def fetch_risk_findings(self, params: dict[str, Any]):
        demisto.debug(f"all params : {params}")
        return self._http_request(
            method="GET", url_suffix=f"{GET_RISK_FINDINGS_ENDPOINT}", params=params
        )

    def get_asset_files(self, params: dict[str, Any]):
        return self._http_request(
            method="POST", url_suffix=f"{GET_ASSET_FILES}", params=params
        )

    def get_asset_details(self, asset_id: str):
        return self._http_request(
            method="GET", url_suffix=f"{GET_ASSET_DETAILS}{asset_id}"
        )

    def get_asset_lists(self, params: dict[str, Any]):
        return self._http_request(
            method="GET", url_suffix=f"{GET_ASSET_LISTS}", params=params
        )

    def get_data_types(self):
        return self._http_request(
            method="GET",
            url_suffix=f"{GET_DATA_TYPES_ENDPOINT}",
        )

    def get_data_type_findings(self, params: dict[str, Any]):
        return self._http_request(
            method="GET", url_suffix=f"{GET_DATA_TYPE_FINDINGS_ENDPOINT}", params=params
        )

    def get_risk_information(self, risk_id: str):
        """
        Retrieve a risk finding by its ID from Dig Security.

        :param incident_id: The ID of the incident to retrieve.
        :return: The incident data as a dictionary.
        """
        return self._http_request(
            method="GET", url_suffix=f"{GET_RISK_FINDING_BY_ID}{risk_id}"
        )

    def update_risk_status(self, risk_id: str, updated_status: str):
        return self._http_request(
            method="PATCH",
            url_suffix=f"/v1/risk-findings/id/{risk_id}/status/{updated_status}",
        )

    def get_alerts_list(self, params: dict[str, Any]):
        return self._http_request(
            method="GET",
            url_suffix=f"{GET_ALERTS_LIST}",
            params=params
        )

    def update_alert_status(self, alert_id: str, updated_status: str):
        return self._http_request(
            method="PATCH",
            url_suffix=f"/v1/alerts/id/{alert_id}/status/{updated_status}",
        )

    def get_list_of_asset_fields(self, params):
        return self._http_request(
            method="POST",
            url_suffix=f"{GET_ASSET_FIELDS}",
            params=params
        )


""" HELPER FUNCTIONS """


def validate_parameter(
    param_name: str, param_in: str, param_equal: str, supported_list: list[str]
):
    if param_in:
        param_list = [item.strip() for item in param_in.split(",") if item.strip()]
        for param in param_list:
            if param not in supported_list:
                raise ValueError(f'This "{param}" {param_name} is not supported')

    if param_equal and param_equal not in supported_list:
        raise ValueError(f'This "{param_equal}" {param_name} is not supported')


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication"""
    try:
        # validate dspm creds
        client.get_data_types()
        return "ok"

    except DemistoException as e:
        if "Forbidden" in str(e) or "Authorization" in str(e):
            return "Authorization Error: make sure DSPM API Key is correctly set"
        else:
            return f"Error: An unknown exception occurred: {e}"


def get_list_risk_findings(
    client: Client, args: dict[str, Any], page: int
) -> list[dict]:
    """Fetch list of DSPM Risk findings"""
    # Validate and process cloudProvider parameters
    cloud_provider_in = args.get("cloud_provider_in", "")
    cloud_provider_equal = args.get("cloud_provider_equal", "")
    validate_parameter(
        "cloudProvider", cloud_provider_in, cloud_provider_equal, SUPPORTED_CLOUD_PROVIDERS
    )

    # Check supported affects
    affects_in = args.get("affects_in", "")
    affects_equal = args.get("affects_equal", "")
    validate_parameter(
        "affects", affects_in, affects_equal, SUPPORTED_CATEGORIES
    )

    # Check supported Status
    status_in = args.get("status_in", "")
    status_equal = args.get("status_equal", "")
    validate_parameter("status", status_in, status_equal, SUPPORTED_STATUSES)

    # Check supported sorting order
    sort_order = args.get("sort")
    if sort_order:
        pattern = r"^.*,(ASC|DESC)$"
        matches = re.findall(pattern, sort_order, re.IGNORECASE)  # type: ignore
        if not matches:
            raise ValueError(f'This "{sort_order}" sorting order is not supported')

    params = {
        "ruleName.in": args.get("rule_name_in"),
        "ruleName.equals": args.get("rule_name_equal"),
        "dspmTagKey.in": args.get("dspm_tag_key_in"),
        "dspmTagKey.equals": args.get("dspm_tag_key_equal"),
        "dspmTagValue.in": args.get("dspm_tag_value_in"),
        "dspmTagValue.equals": args.get("dspm_tag_value_equal"),
        "projectId.in": args.get("projectId_in"),
        "projectId.equals": args.get("projectId_equal"),
        "cloudProvider.in": args.get("cloud_provider_in"),
        "cloudProvider.equals": args.get("cloud_provider_equal"),
        "affects.in": args.get("affects_in"),
        "affects.equals": args.get("affects_equal"),
        "status.in": args.get("status_in"),
        "status.equals": args.get("status_equal"),
        "sort": args.get("sort"),
        "page": page,
        "size": MAX_PAGE_SIZE,
    }
    # Remove None values from params
    params = {k: v for k, v in params.items() if v is not None}
    demisto.debug(f"params : {params}")

    # Fetch data from client
    findings = client.fetch_risk_findings(params)

    if not findings:
        return []  # No more findings to fetch

    return findings


def get_risk_finding_by_id(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    risk_id = args.get("finding_id")
    if not risk_id:
        raise ValueError("finding_id argument is required")

    # Fetch data from client using the get_risk_information method
    response = client.get_risk_information(risk_id)

    if not response:
        raise ValueError(f"No risk found with id {risk_id}")

    finding = response if isinstance(response, dict) else response[0]

    readable_output = tableToMarkdown("Risk Finding", finding, headerTransform=pascalToSpace)

    return CommandResults(
        outputs_prefix="DSPM.RiskFinding",
        outputs_key_field="id",
        outputs=finding,
        readable_output=readable_output,
        raw_response=finding
    )


def get_list_of_assets(client: Client, args: dict[str, Any], page: int) -> list[dict]:
    # Validate and process cloudProvider parameters
    cloud_provider_in = args.get("cloud_provider_in", "")
    cloud_provider_equal = args.get("cloud_provider_equal", "")
    validate_parameter(
        "cloudProvider", cloud_provider_in, cloud_provider_equal, SUPPORTED_CLOUD_PROVIDERS
    )

    # Validate and process serviceType parameters
    service_Type_In = args.get("service_type_in", "")
    service_Type_Equal = args.get("service_type_equal", "")
    validate_parameter(
        "serviceType", service_Type_In, service_Type_Equal, SUPPORTED_SERVICE_TYPES
    )

    # Validate and process lifecycle parameters
    lifecycle_In = args.get("lifecycle_in", "")
    lifecycle_Equal = args.get("lifecycle_equal", "")
    validate_parameter(
        "lifecycle", lifecycle_In, lifecycle_Equal, SUPPORTED_LIFECYCLE
    )

    # Check supported sorting order
    sort_order = args.get("sort")
    if sort_order:
        pattern = r"^.*,(ASC|DESC)$"
        matches = re.findall(pattern, sort_order, re.IGNORECASE)  # type: ignore
        if not matches:
            raise ValueError(f'This "{sort_order}" sorting order is not supported')

    params = {
        "region.in": args.get("region_in"),
        "region.equals": args.get("region_equal"),
        "cloudProvider.in": args.get("cloud_provider_in"),
        "cloudProvider.equals": args.get("cloud_provider_equal"),
        "serviceType.in": args.get("service_type_in"),
        "serviceType.equals": args.get("service_type_equal"),
        "digTagKey.contains": args.get("dig_tag_key_contains"),
        "digTagValue.contains": args.get("dig_tag_value_contains"),
        "lifecycle.in": args.get("lifecycle_in"),
        "lifecycle.equals": args.get("lifecycle_equal"),
        "sort": args.get("sort"),
        "page": page,
        "size": MAX_PAGE_SIZE,
    }
    # Remove None values from params
    params = {k: v for k, v in params.items() if v is not None}

    # Fetch data from client
    response = client.get_asset_lists(params)

    assets = response.get("assets", []) if isinstance(response, dict) else response

    if not assets:
        return []  # No more assets to fetch

    return assets


def get_asset_details(client: Client, args: dict[str, Any]) -> CommandResults:
    asset_id = args.get("asset_id", None)
    if not asset_id:
        raise ValueError("asset_id not specified")

    asset_details = client.get_asset_details(asset_id)

    readable_output = tableToMarkdown("Asset Details", asset_details, headerTransform=pascalToSpace)
    return CommandResults(
        outputs_prefix="DSPM.AssetDetails",
        outputs_key_field="id",
        outputs=asset_details,
        readable_output=readable_output,
        raw_response=asset_details
    )


def get_asset_files_by_id(client: Client, args: dict[str, Any]) -> CommandResults:
    asset_id = args.get("asset_id", None)
    if not asset_id:
        raise ValueError("Asset ID not specified")

    page_number = 1
    all_files = []

    while True:
        params = {
            "id": asset_id,
            "page": page_number,
            "size": MAX_PAGE_SIZE
        }

        # Fetch the asset files for the current page
        response = client.get_asset_files(params)
        files = response.get("files", [])

        if not files:
            break  # Stop when there are no more files to retrieve

        # Append the files to the total list of files
        all_files.extend(files)

        # Increment page number for the next fetch
        page_number += 1

    files_count = len(all_files)

    # Return the result without formatting the files structure
    readable_output = tableToMarkdown("Asset Files", all_files, headerTransform=pascalToSpace)
    return CommandResults(
        outputs_prefix="DSPM.AssetFiles",
        outputs_key_field="filename",
        outputs={"files": all_files, "filesCount": files_count},
        readable_output=readable_output,
        raw_response=all_files
    )


def get_data_types(client: Client) -> CommandResults:
    """Command to fetch data types."""
    data_types = client.get_data_types()
    data_types_formatted = [
        {"No": index + 1, "Key": dt} for index, dt in enumerate(data_types)
    ]

    table_name = "Data Types"
    headers = ['No', 'Key']
    readable_output = tableToMarkdown(table_name, data_types_formatted, headers=headers)

    return CommandResults(
        outputs_prefix="DSPM.DataTypes",
        outputs_key_field="Key",
        outputs=data_types_formatted,
        readable_output=readable_output,
        raw_response=data_types
    )


def get_data_type_findings(
    client: Client, args: dict[str, Any], page: int
) -> list[dict]:
    """Fetch data type findings for a specific page."""
    # check supported cloud providers
    cloud_provider_in = args.get("cloud_provider_in", "")
    cloud_provider_equal = args.get("cloud_provider_equal", "")
    validate_parameter(
        "cloudProvider", cloud_provider_in, cloud_provider_equal, SUPPORTED_CLOUD_PROVIDERS
    )

    # check supported service type
    service_type_in = args.get("service_type_in", "")
    service_type_equal = args.get("service_type_equal", "")
    validate_parameter(
        "serviceType", service_type_in, service_type_equal, SUPPORTED_SERVICE_TYPES
    )

    # check supported lifecycle
    lifecycle_in = args.get("lifecycle_in", "")
    lifecycle_equal = args.get("lifecycle_equal", "")
    validate_parameter(
        "lifecycle", lifecycle_in, lifecycle_equal, SUPPORTED_LIFECYCLE
    )

    # Check supported sorting order
    sort_order = args.get("sort")
    if sort_order:
        pattern = r"^.*,(ASC|DESC)$"
        matches = re.findall(pattern, sort_order, re.IGNORECASE)  # type: ignore
        if not matches:
            raise ValueError(f'This "{sort_order}" sorting order is not supported')

    params = {
        "region.in": args.get("region_in"),
        "region.equals": args.get("region_equal"),
        "projectId.in": args.get("projectId_in"),
        "projectId.equals": args.get("projectId_equal"),
        "cloudProvider.in": args.get("cloud_provider_in"),
        "cloudProvider.equals": args.get("cloud_provider_equal"),
        "serviceType.in": args.get("service_type_in"),
        "serviceType.equals": args.get("service_type_equal"),
        "lifecycle.in": args.get("lifecycle_in"),
        "lifecycle.equals": args.get("lifecycle_equal"),
        "sort": args.get("sort"),
        "page": page,
        "size": MAX_PAGE_SIZE,
    }

    # Remove None values from params
    params = {k: v for k, v in params.items() if v is not None}

    data_type_findings = client.get_data_type_findings(params)
    return data_type_findings


def update_risk_finding_status(client, args):
    finding_id = args.get("risk_finding_id")
    status = args.get("status")
    if status and status not in SUPPORTED_STATUSES:
        raise ValueError(f'This "{status}" status is not supported')

    try:
        response = client.update_risk_status(finding_id, status)
        # Format the response for display
        markdown = tableToMarkdown("Risk Status Update", [response], headerTransform=pascalToSpace)

        return CommandResults(
            readable_output=markdown,
            outputs_prefix="DSPM.RiskFindingStatusUpdate",
            outputs_key_field="riskFindingId",
            outputs=response,
            raw_response=response
        )
    except Exception as e:
        return_error(
            f"Failed to update risk finding {finding_id} to status {status}. Error: {str(e)}"
        )


def get_list_of_alerts(
    client: Client, args: dict[str, Any], page: int
) -> list[dict]:
    """fetch list of dspm alerts"""
    # check supported cloud providers
    cloud_provider_in = args.get("cloud_provider_in", "")
    cloud_provider_equal = args.get("cloud_provider_equal", "")
    validate_parameter(
        "cloudProvider", cloud_provider_in, cloud_provider_equal, SUPPORTED_CLOUD_PROVIDERS
    )

    # check supported cloud environments
    cloud_environment_in = args.get("cloud_environment_in", "")
    cloud_environment_equal = args.get("cloud_environment_equal", "")
    validate_parameter(
        "cloudEnvironment", cloud_environment_in, cloud_environment_equal, SUPPORTED_CLOUD_ENVIRONMENTS
    )

    # check supported policy severity
    policy_severity_in = args.get("policy_severity_in", "")
    policy_severity_equal = args.get("policy_severity_equal", "")
    validate_parameter(
        "policySeverity", policy_severity_in, policy_severity_equal, SUPPORTED_POLICY_SEVERITIES
    )

    # check supported category type
    category_type_in = args.get("category_type_in", "")
    category_type_equal = args.get("category_type_equal", "")
    validate_parameter(
        "categoryType", category_type_in, category_type_equal, SUPPORTED_CATEGORY_TYPES
    )

    # check supported category type
    status_in = args.get("status_in", "")
    status_equal = args.get("status_equal", "")
    validate_parameter(
        "status", status_in, status_equal, SUPPORTED_STATUSES
    )

    # Check supported sorting order
    sort_order = args.get("sort")
    if sort_order:
        pattern = r"^.*,(ASC|DESC)$"
        matches = re.findall(pattern, sort_order, re.IGNORECASE)  # type: ignore
        if not matches:
            raise ValueError(f'This "{sort_order}" sorting order is not supported')

    params = {
        "detectionTime.equals": args.get("detection_time_equals"),
        "detectionTime.greaterThanOrEqual": args.get("detection_time_greater_than_or_equal"),
        "detectionTime.greaterThan": args.get("detection_time_greater_than"),
        "detectionTime.lessThanOrEqual": args.get("detection_time_less_than_or_equal"),
        "detectionTime.lessThan": args.get("detection_time_less_than"),
        "policyName.in": args.get("policy_name_in"),
        "policyName.equals": args.get("policy_name_equals"),
        "assetName.in": args.get("asset_name_in"),
        "assetName.equals": args.get("asset_name_equals"),
        "cloudProvider.in": args.get("cloud_provider_in"),
        "cloudProvider.equals": args.get("cloud_provider_equals"),
        "destinationProjectVendorName.in": args.get("destination_project_vendor_name_in"),
        "destinationProjectVendorName.equals": args.get("destination_project_vendor_name_equals"),
        "cloudEnvironment.in": args.get("cloud_environment_in"),
        "cloudEnvironment.equals": args.get("cloud_environment_equals"),
        "policySeverity.in": args.get("policy_severity_in"),
        "policySeverity.equals": args.get("policy_severity_equals"),
        "categoryType.in": args.get("category_type_in"),
        "categoryType.equals": args.get("category_type_equals"),
        "status.in": args.get("status_in"),
        "status.equals": args.get("status_equals"),
        "sort": args.get("sort"),
        "page": page,
        "size": MAX_PAGE_SIZE
    }

    # Remove None values from params
    params = {k: v for k, v in params.items() if v is not None}

    alerts_list = client.get_alerts_list(params)
    return alerts_list


def update_dspm_alert_status(client, args):
    alert_id = args.get("alert_id")
    status = args.get("status")
    if status and status not in SUPPORTED_STATUSES:
        raise ValueError(f'This "{status}" status is not supported')

    try:
        response = client.update_alert_status(alert_id, status)
        # Format the response for display

        markdown = tableToMarkdown("Alert Status Update", [response], headerTransform=pascalToSpace)

        return CommandResults(
            readable_output=markdown,
            outputs_prefix="DSPM.AlertStatusUpdate",
            outputs_key_field="alertId",
            outputs=response,
            raw_response=response
        )
    except Exception as e:
        return_error(
            f"Failed to update alert '{alert_id}' to status '{status}'. Error: {str(e)}"
        )


def get_list_of_labels(client: Client):
    """Command to fetch list of label names based on company"""
    labels = client.get_labels()
    labels_formatted = [
        {"No": index + 1, "Key": dt} for index, dt in enumerate(labels)
    ]

    table_name = "Labels"
    headers = ['No', 'Key']
    readable_output = tableToMarkdown(table_name, labels_formatted, headers=headers)

    return CommandResults(
        outputs_prefix="DSPM.Label",
        outputs_key_field="Key",
        outputs=labels_formatted,
        readable_output=readable_output,
        raw_response=labels
    )


def dspm_list_risk_findings_command(client, args):
    limit = args.get("limit", DEFAULT_LIMIT)
    if not limit.isdigit():
        raise ValueError("The 'limit' parameter must be an integer.")
    limit = int(limit)
    page = 0
    findings_collected: list = []

    while len(findings_collected) < limit:
        findings = get_list_risk_findings(client, args, page)
        if not findings:
            if page == 0 and not findings_collected:
                demisto.info("No risks were fetched")

                return CommandResults(
                    readable_output="No Risk Findings found."
                )

            break  # No more findings to fetch

        findings_collected.extend(findings)
        if len(findings_collected) >= limit:
            break

        page += 1

    # Trim findings to match the limit
    findings_collected = findings_collected[:limit]

    # Prepare the readable output
    readable_output = tableToMarkdown("Risk Findings", findings_collected, headerTransform=pascalToSpace)

    # Return a single CommandResults with all findings
    return CommandResults(
        outputs_prefix="DSPM.RiskFinding",
        outputs_key_field="id",
        outputs=findings_collected,
        readable_output=readable_output,
        raw_response=findings_collected
    )


def dspm_list_assets_command(client, args):
    limit = args.get("limit", DEFAULT_LIMIT)
    if not limit.isdigit():
        raise ValueError("The 'limit' parameter must be an integer.")
    limit = int(limit)
    page = 0
    collected_assets: list = []

    while len(collected_assets) < limit:
        assets = get_list_of_assets(client, args, page)
        if not assets:
            if page == 0 and not collected_assets:
                return CommandResults(
                    readable_output="No assets found."
                )

            break

        collected_assets.extend(assets)
        if len(collected_assets) >= limit:
            break

        page += 1

    # Trim the results to match the limit
    collected_assets = collected_assets[:limit]

    # Generate readable output
    readable_output = tableToMarkdown("List of Assets", collected_assets, headerTransform=pascalToSpace)

    # Return the collected assets directly without parsing
    return CommandResults(
        outputs_prefix="DSPM.Asset",
        outputs_key_field="id",
        outputs=collected_assets,
        readable_output=readable_output,
        raw_response=collected_assets
    )


def dspm_list_data_types_findings_command(client, args):
    limit = args.get("limit", DEFAULT_LIMIT)
    if not limit.isdigit():
        raise ValueError("The 'limit' parameter must be an integer.")
    limit = int(limit)
    page = 0
    collected_data_types: list = []

    while len(collected_data_types) < limit:
        data_type_findings = get_data_type_findings(
            client, args, page
        )
        if not data_type_findings:
            if page == 0 and not collected_data_types:
                return CommandResults(
                    readable_output="No Data Types findings found.",
                )

            break

        collected_data_types.extend(data_type_findings)
        if len(collected_data_types) >= limit:
            break

        page += 1

    # Trim the results to match the limit
    collected_data_types = collected_data_types[:limit]

    readable_output = tableToMarkdown("Data Types Finding", collected_data_types, headerTransform=pascalToSpace)
    return CommandResults(
        outputs_prefix="DSPM.DataTypesFinding",
        outputs_key_field="dataTypeName",
        outputs=collected_data_types,
        readable_output=readable_output,
        raw_response=collected_data_types
    )


def dspm_list_alerts_command(client, args):
    limit = args.get("limit", DEFAULT_LIMIT)
    if not limit.isdigit():
        raise ValueError("The 'limit' parameter must be an integer.")
    limit = int(limit)
    page = 0
    collected_alerts: list = []

    while len(collected_alerts) < limit:
        alerts = get_list_of_alerts(client, args, page)
        if not alerts:
            if page == 0 and not collected_alerts:
                return CommandResults(
                    readable_output="No alerts found.",
                )

            break

        collected_alerts.extend(alerts)
        if len(collected_alerts) >= limit:
            break
        page += 1

    # Trim the results to match the limit
    collected_alerts = collected_alerts[:limit]

    readable_output = tableToMarkdown("List Of Alerts", collected_alerts, headerTransform=pascalToSpace)
    return CommandResults(
        outputs_prefix="DSPM.Alert",
        outputs_key_field="id",
        outputs=collected_alerts,
        readable_output=readable_output,
        raw_response=collected_alerts
    )


def dspm_get_list_of_asset_fields_command(client: Client, args: dict[str, Any]) -> CommandResults:
    asset_id = args.get("assetId", None)
    if not asset_id:
        raise ValueError("Asset ID not specified")

    page_number = 1
    all_fields = []
    try:
        while True:
            params = {
                "id": asset_id,
                "page": page_number,
                "size": MAX_PAGE_SIZE
            }

            # Fetch the asset fields for the current page
            response = client.get_list_of_asset_fields(params)
            if isinstance(response, list) and len(response) > 0:
                fields = response[0].get("fields", [])
            else:
                fields = response.get("fields", [])
            # fields = response[0].get("fields", [])

            if not fields:
                break

            # Append the fields to the total list of fields
            all_fields.extend(fields)

            # Increment page number for the next fetch
            page_number += 1

        fields_count = len(all_fields)

        # Return the result without formatting the fields structure
        headers = ["name", "dataTypes", "path", "tableName", "tableSize", "databaseName", "collectionName", "type", "schemaName"]
        readable_output = tableToMarkdown("Asset Field", all_fields, headers=headers, headerTransform=pascalToSpace)
        return CommandResults(
            outputs_prefix="DSPM.AssetFields",
            outputs_key_field="name",
            outputs={"fields": all_fields, "fieldsCount": fields_count},
            readable_output=readable_output
        )
    except Exception as e:
        error = str(e)
        if '"status": 400' in error:
            message = f"Provided assetID:- '{asset_id}' does not supported. Please check the command description for more details"
        elif '"status": 404' in error:
            message = f"Incorrect assetID:- '{asset_id}' provided. Please confirm the assetID"
        else:
            message = f"Failed to get asset fields for assetId:- '{asset_id}'. Error: {str(e)}"
        raise Exception(message)


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # get the service API url
    base_url = demisto.params().get("dspmBaseUrl")
    api_key = demisto.params().get("dspmApiKey", {}).get("password")
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)

    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        client = Client(
            base_url=base_url, api_key=api_key, verify=verify_certificate, proxy=proxy
        )

        if demisto.command() == "test-module":
            result = test_module(client)
            return_results(result)

        #
        # labels-resource
        #
        elif demisto.command() == "dspm-list-labels":
            return_results(get_list_of_labels(client))

        #
        # risk-resource
        #
        elif demisto.command() == "dspm-list-risk-findings":
            return_results(dspm_list_risk_findings_command(client, demisto.args()))
        elif demisto.command() == "dspm-get-risk-finding-by-id":
            return_results(get_risk_finding_by_id(client, demisto.args()))
        elif demisto.command() == "dspm-update-risk-finding-status":
            return_results(update_risk_finding_status(client, demisto.args()))

        #
        # asset-resource
        #

        elif demisto.command() == "dspm-list-assets":
            return_results(dspm_list_assets_command(client, demisto.args()))
        elif demisto.command() == "dspm-get-asset-details":
            return_results(get_asset_details(client, demisto.args()))

        #
        # classification-resource
        #
        elif demisto.command() == "dspm-get-data-types":
            return_results(get_data_types(client))
        elif demisto.command() == "dspm-get-asset-files-by-id":
            return_results(get_asset_files_by_id(client, demisto.args()))
        elif demisto.command() == "dspm-get-list-of-asset-fields-by-id":
            return_results(dspm_get_list_of_asset_fields_command(client, demisto.args()))

        #
        # data-type-findings-resource
        #
        elif demisto.command() == "dspm-list-data-types-findings":
            return_results(dspm_list_data_types_findings_command(client, demisto.args()))

        #
        # alert-resource
        #
        elif demisto.command() == "dspm-update-alert-status":
            return_results(update_dspm_alert_status(client, demisto.args()))
        elif demisto.command() == "dspm-list-alerts":
            return_results(dspm_list_alerts_command(client, demisto.args()))

    except Exception as e:
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}"
        )


""" ENTRY POINT """
if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
