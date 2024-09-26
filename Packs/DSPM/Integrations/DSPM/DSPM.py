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
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
GET_RISK_FINDINGS_ENDPOINT = "/v1/risk-findings"
GET_ASSET_LISTS = "/v1/assets"
GET_ASSET_DETAILS = "/v1/assets/id?id="
GET_ASSET_FILES = "/v1/classification/asset-files/id"
GET_DATA_TYPES_ENDPOINT: str = "/v1/classification/data-types"
GET_DATA_TYPE_FINDINGS_ENDPOINT: str = "/v1/data-type-findings"
GET_ALERTS_LIST: str = "/v1/alerts"
GET_RISK_FINDING_BY_ID: str = "/v1/risk-findings/id/"
INCIDENT_STATUS = {"OPEN": 1, "INVESTIGATING": 2, "HANDLED": 2, "CLOSED": 2}
RISK_STATUS = {"Active": "OPEN", "Closed": "INVESTIGATING", "Pending": "INVESTIGATING"}

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
SUPPORTED_STATUSES = [
    "OPEN",
    "CLOSED",
    "UNIMPORTANT",
    "WRONG",
    "HANDLED",
    "INVESTIGATING",
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
SORTING_ORDER = ["ASC", "DESC"]
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


""" HELPER FUNCTIONS """


def map_status(status: str):
    mapped_status = INCIDENT_STATUS.get(
        status, 1
    )  # Default to 'Active' if the status is not found
    demisto.debug(f"Mapping status '{status}' to '{mapped_status}'")
    return mapped_status


def severity_to_dbot_score(severity):
    if severity == "LOW":
        return 1
    if severity == "MEDIUM":
        return 2
    if severity == "HIGH":
        return 3
    if severity == "CRITICAL":
        return 4
    return 0


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


def dspm_get_risk_findings(
    client: Client, args: dict[str, Any], page: int
) -> list[dict]:
    """Fetch list of DSPM Risk findings"""
    # Validate and process cloudProvider parameters
    cloudProviderIn = args.get("cloudProviderIn", "")
    cloudProviderEqual = args.get("cloudProviderEqual", "")
    validate_parameter(
        "cloudProvider", cloudProviderIn, cloudProviderEqual, SUPPORTED_CLOUD_PROVIDERS
    )

    # Check supported affects
    affectsIn = args.get("affectsIn", "")
    affectsEqual = args.get("affectsEqual", "")
    validate_parameter(
        "affects", affectsIn, affectsEqual, SUPPORTED_CATEGORIES
    )

    # Check supported Status
    statusIn = args.get("statusIn", "")
    statusEqual = args.get("statusEqual", "")
    validate_parameter("status", statusIn, statusEqual, SUPPORTED_STATUSES)

    # Check supported sorting order
    sort_order = args.get("sort")
    if sort_order:
        pattern = r"^.*,(ASC|DESC)$"
        matches = re.findall(pattern, sort_order, re.IGNORECASE)  # type: ignore
        if not matches:
            raise ValueError(f'This "{sort_order}" sorting order is not supported')

    params = {
        "ruleName.in": args.get("ruleNameIn"),
        "ruleName.equals": args.get("ruleNameEqual"),
        "dspmTagKey.in": args.get("dspmTagKeyIn"),
        "dspmTagKey.equals": args.get("dspmTagKeyEqual"),
        "dspmTagValue.in": args.get("dspmTagValueIn"),
        "dspmTagValue.equals": args.get("dspmTagValueEqual"),
        "projectId.in": args.get("projectIdIn"),
        "projectId.equals": args.get("projectIdEqual"),
        "cloudProvider.in": args.get("cloudProviderIn"),
        "cloudProvider.equals": args.get("cloudProviderEqual"),
        "affects.in": args.get("affectsIn"),
        "affects.equals": args.get("affectsEqual"),
        "status.in": args.get("statusIn"),
        "status.equals": args.get("statusEqual"),
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

    parsed_findings = [
        {
            "ID": finding.get("id", ""),
            "Rule Name": finding.get("ruleName", ""),
            "Severity": finding.get("severity", ""),
            "Asset Name": finding.get("asset", {}).get("name", ""),
            "Asset ID": finding.get("asset", {}).get("assetId", ""),
            "Status": finding.get("status", ""),
            "Project ID": finding.get("projectId", ""),
            "Cloud Provider": finding.get("cloudProvider", ""),
            "Cloud Environment": finding.get("cloudEnvironment", ""),
            "First Discovered": finding.get("firstDiscovered", ""),
            "Compliance Standards": finding.get("complianceStandards", {}),
        }
        for finding in findings
    ]
    return parsed_findings


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

    parsed_finding = {
        "ID": finding.get("id", ""),
        "Rule Name": finding.get("ruleName", ""),
        "Severity": finding.get("severity", ""),
        "Asset Name": finding.get("asset", {}).get("name", ""),
        "Asset ID": finding.get("asset", {}).get("assetId", ""),
        "Status": finding.get("status", ""),
        "Project ID": finding.get("projectId", ""),
        "Cloud Provider": finding.get("cloudProvider", ""),
        "Cloud Environment": finding.get("cloudEnvironment", ""),
        "First Discovered": finding.get("firstDiscovered", ""),
        "Compliance Standards": finding.get("complianceStandards", {}),
    }

    headers = parsed_finding.keys()
    readable_output = tableToMarkdown("Risk Finding", parsed_finding, headers=headers, headerTransform=pascalToSpace)

    return CommandResults(
        outputs_prefix="DSPM.RiskFinding",
        outputs_key_field="id",
        outputs=parsed_finding,
        readable_output=readable_output
    )


def get_list_of_assets(client: Client, args: dict[str, Any], page: int) -> list[dict]:
    # Validate and process cloudProvider parameters
    cloudProviderIn = args.get("cloudProviderIn", "")
    cloudProviderEqual = args.get("cloudProviderEqual", "")
    validate_parameter(
        "cloudProvider", cloudProviderIn, cloudProviderEqual, SUPPORTED_CLOUD_PROVIDERS
    )

    # Validate and process serviceType parameters
    service_Type_In = args.get("serviceTypeIn", "")
    service_Type_Equal = args.get("serviceTypeEqual", "")
    validate_parameter(
        "serviceType", service_Type_In, service_Type_Equal, SUPPORTED_SERVICE_TYPES
    )

    # Validate and process lifecycle parameters
    lifecycle_In = args.get("lifecycleIn", "")
    lifecycle_Equal = args.get("lifecycleEqual", "")
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
        "region.in": args.get("regionIn"),
        "region.equals": args.get("regionEqual"),
        "cloudProvider.in": args.get("cloudProviderIn"),
        "cloudProvider.equals": args.get("cloudProviderEqual"),
        "serviceType.in": args.get("serviceTypeIn"),
        "serviceType.equals": args.get("serviceTypeEqual"),
        "digTagKey.contains": args.get("digTagKeyContains"),
        "digTagValue.contains": args.get("digTagValueContains"),
        "lifecycle.in": args.get("lifecycleIn"),
        "lifecycle.equals": args.get("lifecycleEqual"),
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

    parsed_assets = [
        {
            "ID": asset.get("id", ""),
            "Project ID": asset.get("projectId", ""),
            "Project Name": asset.get("projectName", ""),
            "Name": asset.get("name", ""),
            "Cloud Provider": asset.get("cloudProvider", ""),
            "Cloud Environment": asset.get("cloudEnvironment", ""),
            "Service Type": asset.get("serviceType", ""),
            "Lifecycle": asset.get("lifecycle", ""),
            "Open Risks Count": asset.get("openRisksCount", 0),
            "Open Alerts Count": asset.get("openAlertsCount", 0),
            "Encrypted": asset.get("encrypted", False),
            "Open To World": asset.get("openToWorld", False),
            "Tags": asset.get("tags", {}),
            "Asset Dig Tags": asset.get("assetDigTags", []),
        }
        for asset in assets
    ]
    return parsed_assets


def get_asset_details(client: Client, args: dict[str, Any]) -> CommandResults:
    asset_id = args.get("asset_id", None)
    if not asset_id:
        raise ValueError("asset_id not specified")

    asset_details = client.get_asset_details(asset_id)
    demisto.debug(f"Asset details of : {asset_id}")
    demisto.debug(asset_details)

    headers = ["assetDigTags", "cloudEnvironment", "cloudProvider", "dataTypeGroups", "dataTypes", "encrypted", "id",
               "lifecycle", "name", "openAlertsCount", "openRisksCount", "openToWorld", "projectId",
               "projectName", "serviceType", "tags"]
    readable_output = tableToMarkdown("Asset Details", asset_details, headers=headers, headerTransform=pascalToSpace)
    return CommandResults(
        outputs_prefix="DSPM.AssetDetails",
        outputs_key_field="id",
        outputs=asset_details,
        readable_output=readable_output,
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
    headers = ["filename", "path", "type", "size", "openToWorld", "isDeleted", "isMalicious", "dataTypes", "labels", "isDbDump"]
    readable_output = tableToMarkdown("Asset Files", all_files, headers=headers, headerTransform=pascalToSpace)
    return CommandResults(
        outputs_prefix="DSPM.AssetFiles",
        outputs_key_field="filename",
        outputs={"files": all_files, "filesCount": files_count},
        readable_output=readable_output
    )


def get_data_types(client: Client) -> CommandResults:
    """Command to fetch data types."""
    data_types = client.get_data_types()
    data_types_formatted = [
        {"No": index + 1, "Key": dt} for index, dt in enumerate(data_types)
    ]

    table_name = "Data Types"
    headers = ['No', 'Key']
    if data_types_formatted:
        readable_output = tableToMarkdown(table_name, data_types_formatted, headers=headers)
    else:
        readable_output = tableToMarkdown(table_name, [], headers=headers)

    return CommandResults(
        outputs_prefix="DSPM.DataTypes",
        outputs_key_field="Key",
        outputs=data_types_formatted,
        readable_output=readable_output,
    )


def get_data_type_findings(
    client: Client, args: dict[str, Any], page: int
) -> list[dict]:
    """Fetch data type findings for a specific page."""
    # check supported cloud providers
    cloudProviderIn = args.get("cloudProviderIn", "")
    cloudProviderEqual = args.get("cloudProviderEqual", "")
    validate_parameter(
        "cloudProvider", cloudProviderIn, cloudProviderEqual, SUPPORTED_CLOUD_PROVIDERS
    )

    # check supported service type
    serviceTypeIn = args.get("serviceTypeIn", "")
    serviceTypeEqual = args.get("serviceTypeEqual", "")
    validate_parameter(
        "serviceType", serviceTypeIn, serviceTypeEqual, SUPPORTED_SERVICE_TYPES
    )

    # check supported lifecycle
    lifecycleIn = args.get("lifecycleIn", "")
    lifecycleEqual = args.get("lifecycleEqual", "")
    validate_parameter(
        "lifecycle", lifecycleIn, lifecycleEqual, SUPPORTED_LIFECYCLE
    )

    # Check supported sorting order
    sort_order = args.get("sort")
    if sort_order:
        pattern = r"^.*,(ASC|DESC)$"
        matches = re.findall(pattern, sort_order, re.IGNORECASE)  # type: ignore
        if not matches:
            raise ValueError(f'This "{sort_order}" sorting order is not supported')

    params = {
        "region.in": args.get("regionIn"),
        "region.equals": args.get("regionEqual"),
        "projectId.in": args.get("projectIdIn"),
        "projectId.equals": args.get("projectIdEqual"),
        "cloudProvider.in": args.get("cloudProviderIn"),
        "cloudProvider.equals": args.get("cloudProviderEqual"),
        "serviceType.in": args.get("serviceTypeIn"),
        "serviceType.equals": args.get("serviceTypeEqual"),
        "lifecycle.in": args.get("lifecycleIn"),
        "lifecycle.equals": args.get("lifecycleEqual"),
        "sort": args.get("sort"),
        "page": page,
        "size": MAX_PAGE_SIZE,
    }

    data_type_findings = client.get_data_type_findings(params)
    return data_type_findings


def update_risk_finding_status(client, args):
    finding_id = args.get("riskFindingId")
    status = args.get("status")
    if status and status not in SUPPORTED_STATUSES:
        raise ValueError(f'This "{status}" status is not supported')

    try:
        response = client.update_risk_status(finding_id, status)
        # Format the response for display
        headers = ["Risk Finding ID", "Old Status", "New Status"]
        data = {
            "Risk Finding ID": response.get("riskFindingId"),
            "Old Status": response.get("oldStatus"),
            "New Status": response.get("newStatus"),
        }

        markdown = tableToMarkdown("Risk Status Update", [data], headers=headers, headerTransform=pascalToSpace)

        return CommandResults(
            readable_output=markdown,
            outputs_prefix="DSPM.RiskFindingStatusUpdate",
            outputs_key_field="riskFindingId",
            outputs=data,
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
    cloudProviderIn = args.get("cloudProviderIn", "")
    cloudProviderEqual = args.get("cloudProviderEqual", "")
    validate_parameter(
        "cloudProvider", cloudProviderIn, cloudProviderEqual, SUPPORTED_CLOUD_PROVIDERS
    )

    # check supported cloud environments
    cloudEnvironmentIn = args.get("cloudEnvironmentIn", "")
    cloudEnvironmentEqual = args.get("cloudEnvironmentEqual", "")
    validate_parameter(
        "cloudEnvironment", cloudEnvironmentIn, cloudEnvironmentEqual, SUPPORTED_CLOUD_ENVIRONMENTS
    )

    # check supported policy severity
    policySeverityIn = args.get("policySeverityIn", "")
    policySeverityEqual = args.get("policySeverityEqual", "")
    validate_parameter(
        "policySeverity", policySeverityIn, policySeverityEqual, SUPPORTED_POLICY_SEVERITIES
    )

    # check supported category type
    categoryTypeIn = args.get("categoryTypeIn", "")
    categoryTypeEqual = args.get("categoryTypeEqual", "")
    validate_parameter(
        "categoryType", categoryTypeIn, categoryTypeEqual, SUPPORTED_CATEGORY_TYPES
    )

    # check supported category type
    statusIn = args.get("statusIn", "")
    statusEqual = args.get("statusEqual", "")
    validate_parameter(
        "status", statusIn, statusEqual, SUPPORTED_STATUSES
    )

    # Check supported sorting order
    sort_order = args.get("sort")
    if sort_order:
        pattern = r"^.*,(ASC|DESC)$"
        matches = re.findall(pattern, sort_order, re.IGNORECASE)  # type: ignore
        if not matches:
            raise ValueError(f'This "{sort_order}" sorting order is not supported')

    params = {
        "detectionTime.equals": args.get("detectionTimeEquals"),
        "detectionTime.greaterThanOrEqual": args.get("detectionTimeGreaterThanOrEqual"),
        "detectionTime.greaterThan": args.get("detectionTimeGreaterThan"),
        "detectionTime.lessThanOrEqual": args.get("detectionTimeLessThanOrEqual"),
        "detectionTime.lessThan": args.get("detectionTimeLessThan"),
        "policyName.in": args.get("policyNameIn"),
        "policyName.equals": args.get("policyNameEquals"),
        "assetName.in": args.get("assetNameIn"),
        "assetName.equals": args.get("assetNameEquals"),
        "cloudProvider.in": args.get("cloudProviderIn"),
        "cloudProvider.equals": args.get("cloudProviderEquals"),
        "destinationProjectVendorName.in": args.get("destinationProjectVendorNameIn"),
        "destinationProjectVendorName.equals": args.get("destinationProjectVendorNameEquals"),
        "cloudEnvironment.in": args.get("cloudEnvironmentIn"),
        "cloudEnvironment.equals": args.get("cloudEnvironmentEquals"),
        "policySeverity.in": args.get("policySeverityIn"),
        "policySeverity.equals": args.get("policySeverityEquals"),
        "categoryType.in": args.get("categoryTypeIn"),
        "categoryType.equals": args.get("categoryTypeEquals"),
        "status.in": args.get("statusIn"),
        "status.equals": args.get("statusEquals"),
        "sort": args.get("sort"),
        "page": page,
        "size": MAX_PAGE_SIZE
    }

    # Remove None values from params
    params = {k: v for k, v in params.items() if v is not None}

    alerts_list = client.get_alerts_list(params)
    return alerts_list


def update_dspm_alert_status(client, args):
    alert_id = args.get("alertId")
    status = args.get("status")
    if status and status not in SUPPORTED_STATUSES:
        raise ValueError(f'This "{status}" status is not supported')

    try:
        response = client.update_alert_status(alert_id, status)
        # Format the response for display
        headers = ["Alert ID", "Old Status", "New Status"]
        data = {
            "Alert ID": response.get("alertId"),
            "Old Status": response.get("oldStatus"),
            "New Status": response.get("newStatus"),
        }

        markdown = tableToMarkdown("Alert Status Update", [data], headers=headers, headerTransform=pascalToSpace)

        return CommandResults(
            readable_output=markdown,
            outputs_prefix="DSPM.AlertStatusUpdate",
            outputs_key_field="alertId",
            outputs=data,
        )
    except Exception as e:
        return_error(
            f"Failed to update alert '{alert_id}' to status '{status}'. Error: {str(e)}"
        )


def get_integration_config():

    integration_config = {
        "dspmApiKey": demisto.params().get("dspmApiKey", {}).get("password"),
        "slackMsgLifetime": demisto.params().get("slackMsgLifetime"),
        "defaultSlackUser": demisto.params().get("defaultSlackUser"),
    }
    demisto.debug(f" integration config : ${integration_config}")

    # Prepare data for table format
    table_data = [
        {"Key": key, "Value": value} for key, value in integration_config.items()
    ]

    # Convert dictionary to table format
    markdown = tableToMarkdown(
        "Integration Configuration", table_data, headers=["Key", "Value"]
    )

    # Return CommandResults with the integration config
    return CommandResults(
        readable_output=markdown,
        outputs_prefix="DSPM.IntegrationConfig",
        outputs_key_field="config",
        outputs={"integration_config": integration_config},
    )


def dspm_get_risk_findings_command(client, args):
    page = 0
    headers = ["ID", "Rule Name", "Severity", "Asset Name", "Asset ID", "Status", "Project ID",
               "Cloud Provider", "Cloud Environment", "First Discovered", "Compliance Standards"]
    while True:
        findings = dspm_get_risk_findings(client, args, page)
        if not findings:
            if page == 0:
                demisto.info("No risks were fetched")
                readable_output = tableToMarkdown("Risk Findings", [], headers=headers, headerTransform=pascalToSpace)

                return_results(
                    CommandResults(
                        outputs_prefix="DSPM.RiskFindings",
                        outputs_key_field="id",
                        readable_output=readable_output,
                    )
                )
            break  # No more findings to fetch

        readable_output = tableToMarkdown("Risk Findings", findings, headers=headers, headerTransform=pascalToSpace)
        return_results(
            CommandResults(
                outputs_prefix="DSPM.RiskFindings",
                outputs_key_field="id",
                outputs=findings,
                readable_output=readable_output,
            )
        )
        page += 1


def dspm_get_list_of_assets_command(client, args):
    page = 0
    headers = ["ID", "Project ID", "Project Name", "Name", "Cloud Provider", "Cloud Environment", "Service Type",
               "Lifecycle", "Open Risks Count", "Open Alerts Count", "Encrypted", "Open To World",
               "Tags", "Asset Dig Tags"]
    while True:
        assets = get_list_of_assets(client, args, page)
        if not assets:
            if page == 0:
                readable_output = tableToMarkdown("List of assets", [], headers=headers, headerTransform=pascalToSpace)

                return_results(
                    CommandResults(
                        outputs_prefix="DSPM.Assets",
                        outputs_key_field="id",
                        outputs=[],
                        readable_output=readable_output,
                    )
                )
            break

        readable_output = tableToMarkdown("List of assets", assets, headers=headers, headerTransform=pascalToSpace)

        return_results(
            CommandResults(
                outputs_prefix="DSPM.Assets",
                outputs_key_field="id",
                outputs=assets,
                readable_output=readable_output,
            )
        )
        page += 1


def dspm_get_data_types_findings_command(client, args):
    page = 0
    all_data_type_findings = []
    headers = ['No', 'Key']

    while True:
        data_type_findings = get_data_type_findings(
            client, args, page
        )

        if not data_type_findings:
            if page == 0:
                readable_output = tableToMarkdown("Data Types", [], headers=headers)
                return_results(
                    CommandResults(
                        outputs_prefix="DSPM.DataTypesFindings",
                        outputs_key_field="Key",
                        outputs=[],
                        readable_output=readable_output,
                    )
                )
            break

        all_data_type_findings.extend(data_type_findings)

        data_type_findings_formatted = [
            {
                "No": index + 1 + (page * MAX_PAGE_SIZE),
                "Key": dt["dataTypeName"],
            }
            for index, dt in enumerate(data_type_findings)
        ]

        readable_output = tableToMarkdown("Data Types", data_type_findings_formatted, headers=headers)
        return_results(
            CommandResults(
                outputs_prefix="DSPM.DataTypesFindings",
                outputs_key_field="Key",
                outputs=data_type_findings_formatted,
                readable_output=readable_output,
            )
        )
        page += 1


def dspm_get_list_of_alerts_command(client, args):
    page = 0
    headers = ["id", "detectionTime", "policyName", "assetName", "assetLabels", "cloudProvider", "destinationProjects",
               "cloudEnvironment", "policySeverity", "policyCategoryType", "status", "eventActor", "eventUserAgent",
               "eventActionMedium", "eventSource", "policyFrameWorks", "eventRawData"]
    while True:
        alerts = get_list_of_alerts(client, args, page)
        if not alerts:
            if page == 0:
                readable_output = tableToMarkdown("List Of Alerts", [], headers=headers, headerTransform=pascalToSpace)

                return_results(
                    CommandResults(
                        outputs_prefix="DSPM.Alerts",
                        outputs_key_field="id",
                        outputs=[],
                        readable_output=readable_output,
                    )
                )
            break

        readable_output = tableToMarkdown("List Of Alerts", alerts, headers=headers, headerTransform=pascalToSpace)
        return_results(
            CommandResults(
                outputs_prefix="DSPM.Alerts",
                outputs_key_field="id",
                outputs=alerts,
                readable_output=readable_output,
            )
        )
        page += 1


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
        elif demisto.command() == "dspm-get-integration-config":
            return_results(get_integration_config())
        elif demisto.command() == "dspm-get-risk-findings":
            return_results(dspm_get_risk_findings_command(client, demisto.args()))
        elif demisto.command() == "dspm-get-risk-finding-by-id":
            return_results(get_risk_finding_by_id(client, demisto.args()))
        elif demisto.command() == "dspm-get-list-of-assets":
            return_results(dspm_get_list_of_assets_command(client, demisto.args()))
        elif demisto.command() == "dspm-get-asset-details":
            return_results(get_asset_details(client, demisto.args()))
        elif demisto.command() == "dspm-get-asset-files-by-id":
            return_results(get_asset_files_by_id(client, demisto.args()))
        elif demisto.command() == "dspm-get-data-types":
            return_results(get_data_types(client))
        elif demisto.command() == "dspm-get-data-types-findings":
            return_results(dspm_get_data_types_findings_command(client, demisto.args()))
        elif demisto.command() == "dspm-update-risk-finding-status":
            return_results(update_risk_finding_status(client, demisto.args()))
        elif demisto.command() == "dspm-update-alert-status":
            return_results(update_dspm_alert_status(client, demisto.args()))
        elif demisto.command() == "dspm-get-list-of-alerts":
            return_results(dspm_get_list_of_alerts_command(client, demisto.args()))

    except Exception as e:
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}"
        )


""" ENTRY POINT """
if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
