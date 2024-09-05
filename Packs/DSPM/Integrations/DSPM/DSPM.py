import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401
import json
from datetime import datetime
import requests  # type: ignore
from requests.auth import HTTPBasicAuth  # type: ignore

import urllib3
from typing import Any
import re
import hashlib
import time
import hmac
import base64
from requests.exceptions import ConnectionError
from google.oauth2 import service_account
from google.auth.transport.requests import Request

# Disable insecure warnings
urllib3.disable_warnings()
""" CONSTANTS """
# RISK_FINDINGS = []
MAX_PAGE_SIZE: int = 50
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
GET_RISK_FINDINGS_ENDPINT = "/v1/risk-findings"
GET_ASSET_LISTS = "/v1/assets"
GET_ASSET_DETAILS = "/v1/assets/id?id="
GET_ASSET_FILES = "/v1/classification/asset-files/id"
GET_DATA_TYPES_ENDPOINT: str = "/v1/classification/data-types"
GET_DATA_TYPE_FINDINGS_ENDPOINT: str = "/v1/data-type-findings"
GET_CURRENT_JIRA_USER_ENDPOINT: str = "/rest/api/2/myself"
INCIDENT_STATUS = {"OPEN": 1, "INVESTIGATING": 2, "HANDLED": 2, "CLOSED": 2}
RISK_STATUS = {"Active": "OPEN", "Closed": "INVESTIGATING", "Pending": "INVESTIGATING"}
MIRROR_DIRECTION = {
    "None": None,
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}

SUPPORTED_CLOUD_PROVIDERS = ["AWS", "AZURE", "GCP", "SNOWFLAKE", "FILE_SHARE", "O365"]
SUPPORTED_AFFECTS = [
    "SECURITY",
    "COMPLIANCE",
    "GOVERNANCE",
    "SECURITY_AND_COMPLIANCE",
    "SECURITY_AND_GOVERNANCE",
    "COMPLIANCE_AND_GOVERNANCE",
    "SECURITY_AND_COMPLIANCE_AND_GOVERNANCE",
]
SUPPORTED_STATUS = [
    "OPEN",
    "CLOSED",
    "UNIMPORTANT",
    "WRONG",
    "HANDLED",
    "INVESTIGATING",
]
SUPPORTED_SERVICES_TYPE = [
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
SUPPORTED_STATUS = [
    "OPEN",
    "CLOSED",
    "UNIMPORTANT",
    "WRONG",
    "HANDLED",
    "INVESTIGATING",
]

# Define remediation steps for specific findings
ASSET_REMEDIATION_DESCRIPTION = {
    "Sensitive asset open to world": (
        "To remediate this, 'aws-s3-put-public-access-block' command will be executed. "
        "This will block public access to the specified S3 bucket containing sensitive data.\n\n"
        #   "This will prevent unauthorized access and ensure data security.\n\n"
    )
}
ASSET_REMEDIATION_STEPS = {
    "Sensitive asset open to world": (
        "If you prefer to remediate manually, follow these steps:\n"
        "1. Log in to the AWS Management Console.\n"
        "2. Navigate to the S3 service.\n"
        "3. Select the bucket with sensitive data.\n"
        "4. Go to the 'Permissions' tab.\n"
        "5. Under 'Public access settings for this bucket', click 'Edit'.\n"
        "6. Turn on 'Block all public access' and save the changes.\n"
        "7. Review and confirm the changes to ensure the bucket is no longer publicly accessible."
    ),
    "Empty storage asset": "To remediate, consider deleting the asset to reduce the attack surface.",
    "Sensitive asset without storage versioning": (
        "To remediate, ensure all sensitive storage assets have versioning policies in place for "
        "disaster recovery purposes. These policies can be configured on the asset level in the cloud provider console."
    ),
    "Stale Assets With Sensitive Data": (
        "To remediate this risk, consider implementing a data retention policy for the asset. If it is feasible, "
        "enable automatic deletion of data that has not been read or written to in the last 90 days. "
        "If such a policy cannot be applied, we recommend to manually remove stale objects. "
        "Not only does this approach helps maintaining compliance with data protection regulations, "
        "it also minimizes the attack surface by reducing the amount of potentially exploitable data."
    ),
}
""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API"""

    def __init__(self, base_url, api_key, verify=True, proxy=False):
        headers = {"dig-api-key": api_key, "Accept": "application/json"}
        super().__init__(base_url, verify=verify, headers=headers, proxy=proxy)

    def fetch_risk_findings(self, params: dict[str, Any]):
        demisto.debug(f"all params : {params}")
        return self._http_request(
            method="GET", url_suffix=GET_RISK_FINDINGS_ENDPINT, params=params
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
            method="GET", url_suffix=GET_ASSET_LISTS, params=params
        )

    def get_data_types(self):
        return self._http_request(
            method="GET",
            url_suffix=GET_DATA_TYPES_ENDPOINT,
        )

    def get_data_type_findings(self, params: dict[str, Any]):
        return self._http_request(
            method="GET", url_suffix=GET_DATA_TYPE_FINDINGS_ENDPOINT, params=params
        )

    def get_risk_information(self, risk_id: str):
        """
        Retrieve a risk finding by its ID from Dig Security.

        :param incident_id: The ID of the incident to retrieve.
        :return: The incident data as a dictionary.
        """
        return self._http_request(
            method="GET", url_suffix=f"/v1/risk-findings/id/{risk_id}"
        )

    def update_risk_status(self, risk_id: str, updated_status: str):
        return self._http_request(
            method="PATCH",
            url_suffix=f"/v1/risk-findings/id/{risk_id}/status/{updated_status}",
        )


""" HELPER FUNCTIONS """


def map_status(status: str):
    mapped_status = INCIDENT_STATUS.get(
        status, 1
    )  # Default to 'Active' if the status is not found
    demisto.debug(f"Mapping status '{status}' to '{mapped_status}'")
    return mapped_status


# def map_to_third_party_status(status: str) -> str:
#     mapped_status = RISK_STATUS.get(status, 'open')  # Default to 'open' if the status is not found
#     demisto.debug(f"Mapping local status '{status}' to third-party status '{mapped_status}'")
#     return mapped_status


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


def check_jira_credentials():
    try:
        jira_server_url = demisto.params().get("jiraServerUrl", "")
        url = f"https://{jira_server_url}{GET_CURRENT_JIRA_USER_ENDPOINT}"
        jira_email = demisto.params().get("jiraEmail")
        api_token = demisto.params().get("jiraApiToken", {}).get("password")
        auth = HTTPBasicAuth(jira_email, api_token)
        headers = {"Accept": "application/json"}

        response = requests.request(method="GET", url=url, headers=headers, auth=auth)

        return response
        demisto.debug("Jira validation response :", response)
        if response.status_code != 200:
            raise Exception("Invalid Jira credentials")
        else:
            demisto.debug(f"jira validation response : {response}")
            return None
    except Exception as e:
        demisto.debug("Got exception check_jira_credentials")
        demisto.debug(e)


def check_azure_credentials():
    try:
        account_name = str(demisto.params().get("azureStorageName"))
        account_key = str(demisto.params().get("azureSharedKey", {}).get("password"))
        api_version = "2024-11-04"
        request_url = f"https://{account_name}.blob.core.windows.net/?comp=list"
        request_date = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")

        # string for API signature
        string_to_sign = (
            f"GET\n"  # HTTP Verb
            f"\n"  # Content-Encoding
            f"\n"  # Content-Language
            f"\n"  # Content-Length
            f"\n"  # Content-MD5
            f"\n"  # Content-Type
            f"\n"  # Date
            f"\n"  # If-Modified-Since
            f"\n"  # If-Match
            f"\n"  # If-None-Match
            f"\n"  # If-Unmodified-Since
            f"\n"  # Range
            f"x-ms-date:{request_date}\n"
            f"x-ms-version:{api_version}\n"
            f"/{account_name}/\n"
            "comp:list"
        )

        # create signature token for API auth
        decoded_key = base64.b64decode(account_key)
        signature = hmac.new(
            decoded_key, string_to_sign.encode("utf-8"), hashlib.sha256
        ).digest()
        encoded_signature = base64.b64encode(signature).decode("utf-8")

        authorization_header = f"SharedKey {account_name}:{encoded_signature}"
        headers = {
            "x-ms-date": request_date,
            "x-ms-version": api_version,
            "Authorization": authorization_header,
        }
        response = requests.get(request_url, headers=headers)

        if response.status_code == 200:
            return True
        else:
            return_error(
                f"The provided Azure shared Key is invalid, Status Code '{response.status_code}'."
            )
    except ConnectionError:
        return_error(
            f"The provided Azure Storage account name - '{account_name}' is invalid."
        )
    except Exception:
        return_error("The provided Azure shared Key is invalid.")


def create_gcp_access_token(gcp_service_account_json):
    # Remove extra escape char
    gcp_service_account_json = gcp_service_account_json.encode().decode(
        "unicode_escape"
    )

    # Parse the JSON string into a dictionary
    service_account_info = json.loads(gcp_service_account_json, strict=False)

    # Create credentials from the JSON dictionary
    credentials = service_account.Credentials.from_service_account_info(
        service_account_info
    )

    # Set the scope for the token
    scoped_credentials = credentials.with_scopes(
        ["https://www.googleapis.com/auth/cloud-platform"]
    )

    # Request an access token
    scoped_credentials.refresh(Request())

    # Get the access token
    access_token = scoped_credentials.token

    return access_token


def validate_gcp_access_token(access_token):
    validation_url = (
        f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={access_token}"
    )
    response = requests.get(validation_url)
    return response.status_code == 200


def check_gcp_json_credentials():
    try:
        # create GCP access token
        gcp_service_account_json = demisto.params().get("serviceAccountJson")
        gcp_access_token = create_gcp_access_token(gcp_service_account_json)

        # validate the GCP access token
        is_access_token_valid = validate_gcp_access_token(gcp_access_token)
        return is_access_token_valid

    except Exception as err:
        return_error(f"Failed to validate the GCP credentials, Err: {err}")
        return False


def check_slack_notification_lifetime():
    max_lifetime = 48
    try:
        slackMsgLifetime = int(demisto.params().get("slackMsgLifetime"))  # type: ignore
        if slackMsgLifetime > max_lifetime:
            return_error(
                f"Provided Slack Notification lifetime '{slackMsgLifetime}' is more than {max_lifetime} hours"
            )
    except Exception as err:
        return_error(f"Failed to validate Slack Notification lifetime, Err: {err}")


def validate_parameter_list_and_equal(
    param_name: str, param_in: str, param_equal: str, supported_list: list[str]
):
    if param_in:
        param_list = [item.strip() for item in param_in.split(",") if item.strip()]
        for param in param_list:
            if param not in supported_list:
                raise ValueError(f'This "{param}" {param_name} does not supported')

    if param_equal and param_equal not in supported_list:
        raise ValueError(f'This "{param_equal}" {param_name} does not supported')


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication"""
    try:
        # validate dspm creds
        client.get_data_types()

        # validate jira creds
        response = check_jira_credentials()
        if response.status_code != 200:
            raise Exception("Invalid Jira credentials")

        # validate Azure creds
        is_azure_creds_valid = check_azure_credentials()
        if not is_azure_creds_valid:
            raise Exception("Invalid Azure credentials")

        # validate GCP creds
        is_gcp_creds_valid = check_gcp_json_credentials()
        if not is_gcp_creds_valid:
            raise Exception("Invalid GCP credentials")

        check_slack_notification_lifetime()

        return "ok"

    except DemistoException as e:
        if "Forbidden" in str(e) or "Authorization" in str(e):
            return "Authorization Error: make sure DSPM API Key is correctly set"
        elif "Jira" in str(e):
            return "Authorization Error: make sure Jira creds Key is correctly set"
        else:
            return "Error"


def get_risk_findings_command(
    client: Client, args: dict[str, Any], page: int
) -> list[dict]:
    # Validate and process cloudProvider parameters
    cloudProviderIn = args.get("cloudProviderIn", "")
    cloudProviderEqual = args.get("cloudProviderEqual", "")
    validate_parameter_list_and_equal(
        "cloudProvider", cloudProviderIn, cloudProviderEqual, SUPPORTED_CLOUD_PROVIDERS
    )

    # Check supported affects
    affectsIn = args.get("affectsIn", "")
    affectsEqual = args.get("affectsEqual", "")
    validate_parameter_list_and_equal(
        "affects", affectsIn, affectsEqual, SUPPORTED_AFFECTS
    )

    # Check supported Status
    statusIn = args.get("statusIn", "")
    statusEqual = args.get("statusEqual", "")
    validate_parameter_list_and_equal("status", statusIn, statusEqual, SUPPORTED_STATUS)

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


def get_risk_finding_by_id_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    risk_id = args.get("finding_id")
    if not risk_id:
        raise ValueError("finding_id argument is required")

    # Fetch data from client using the get_risk_information method
    response = client.get_risk_information(risk_id)

    if not response:
        raise ValueError(f"No finding found with id {risk_id}")

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

    return CommandResults(
        outputs_prefix="DSPM.RiskFinding",
        outputs_key_field="id",
        outputs=parsed_finding,
    )


def get_list_of_assets(client: Client, args: dict[str, Any], page: int) -> list[dict]:
    # Validate and process cloudProvider parameters
    cloudProviderIn = args.get("cloudProviderIn", "")
    cloudProviderEqual = args.get("cloudProviderEqual", "")
    validate_parameter_list_and_equal(
        "cloudProvider", cloudProviderIn, cloudProviderEqual, SUPPORTED_CLOUD_PROVIDERS
    )

    # Validate and process serviceType parameters
    service_Type_In = args.get("serviceTypeIn", "")
    service_Type_Equal = args.get("serviceTypeEqual", "")
    validate_parameter_list_and_equal(
        "serviceType", service_Type_In, service_Type_Equal, SUPPORTED_SERVICES_TYPE
    )

    # Validate and process lifecycle parameters
    lifecycle_In = args.get("lifecycleIn", "")
    lifecycle_Equal = args.get("lifecycleEqual", "")
    validate_parameter_list_and_equal(
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


def get_asset_details_command(client: Client, args: dict[str, Any]) -> CommandResults:
    asset_id = args.get("asset_id", None)
    if not asset_id:
        raise ValueError("asset_id not specified")

    asset_details = client.get_asset_details(asset_id)
    demisto.debug(f"Asset details of : {asset_id}")
    demisto.debug(asset_details)
    return CommandResults(
        outputs_prefix="DSPM.AssetDetails",
        outputs_key_field="id",
        outputs=asset_details,
    )


def get_asset_files_by_id(client: Client, args: dict[str, Any]) -> CommandResults:
    asset_id = args.get("asset_id", None)
    if not asset_id:
        raise ValueError("Asset ID not specified")

    page_number = 1
    page_size = 50  # You can adjust the page size as needed
    all_files = []

    while True:
        params = {
            "id": asset_id,
            "page": page_number,
            "size": page_size
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
    return CommandResults(
        outputs_prefix="DSPM.AssetFiles",
        outputs_key_field="filename",
        outputs={"files": all_files, "filesCount": files_count},
        readable_output=f"Total Files: {files_count}\nFiles: {all_files}"
    )


def get_data_types_command(client: Client) -> CommandResults:
    """Command to fetch data types."""
    data_types = client.get_data_types()
    data_types_formatted = [
        {"No": index + 1, "Key": dt} for index, dt in enumerate(data_types)
    ]

    if data_types_formatted:
        readable_output = "### Data Types\n | No | Key  |\n |----|------|\n"
        for item in data_types_formatted:
            readable_output += f"| {item['No']}  | {item['Key']} |\n"
    else:
        readable_output = (
            "### Data Types\n | No | Key |\n |----|-----|\n **No entries.**\n"
        )

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
    validate_parameter_list_and_equal(
        "cloudProvider", cloudProviderIn, cloudProviderEqual, SUPPORTED_CLOUD_PROVIDERS
    )

    # check supported service type
    serviceTypeIn = args.get("serviceTypeIn", "")
    serviceTypeEqual = args.get("serviceTypeEqual", "")
    validate_parameter_list_and_equal(
        "serviceType", serviceTypeIn, serviceTypeEqual, SUPPORTED_SERVICES_TYPE
    )

    # check supported lifecycle
    lifecycleIn = args.get("lifecycleIn", "")
    lifecycleEqual = args.get("lifecycleEqual", "")
    validate_parameter_list_and_equal(
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


def update_risk_finding_status_command(client, args):
    finding_id = args.get("riskFindingId")
    status = args.get("status")
    if status and status not in SUPPORTED_STATUS:
        raise ValueError(f'This "{status}" cloud provider does not supported')

    # Validate status
    # if status not in INCIDENT_STATUS:
    #     raise ValueError(f"Invalid status. Choose from: {', '.join(INCIDENT_STATUS)}")

    try:
        response = client.update_risk_status(finding_id, status)
        # Format the response for display
        headers = ["Risk Finding ID", "Old Status", "New Status"]
        data = {
            "Risk Finding ID": response.get("riskFindingId"),
            "Old Status": response.get("oldStatus"),
            "New Status": response.get("newStatus"),
        }

        markdown = tableToMarkdown("Risk Status Update", [data], headers=headers)

        return CommandResults(
            readable_output=markdown,
            outputs_prefix="DSPM.RiskFindingStatusUpdate",
            outputs_key_field="riskFindingId",
            outputs=response,
        )
    except Exception as e:
        return_error(
            f"Failed to update risk finding {finding_id} to status {status}. Error: {str(e)}"
        )


""" FETCH INCIDENTS FUNCTION"""

# def get_mirroring_fields(mirror_direction):
#     """
#     Get tickets mirroring.
#     """

#     return {
#         "mirror_direction": MIRROR_DIRECTION.get(mirror_direction),
#         "mirror_instance": demisto.integrationInstance(),
#         "incident_type": "DSPM Risk Findings",
#     }


def fetch_incidents(client: Client, mirror_direction):
    last_run = demisto.getLastRun()
    last_fetch = last_run.get("last_fetch")
    processed_ids = last_run.get("processed_ids", [])

    if last_fetch is None:
        last_fetch = "1970-01-01T00:00:00Z"

    incidents = []
    page = 0
    size = 1  # 50 is max size we can provide.
    findings = []

    while True:
        response = client.fetch_risk_findings(
            {
                "page": page,
                "size": size,
                "ruleName.equals": "Sensitive asset open to world",
            }
        )
        new_findings = response
        if not new_findings or page == 1:
            break
        findings.extend(new_findings)
        page += 1

    demisto.debug(f"Total number of findings fetched: {len(findings)}")

    for finding in findings:
        finding_id = finding.get("id")
        occurred_time = datetime.utcnow().strftime(DATE_FORMAT)
        # finding.update(get_mirroring_fields(mirror_direction))

        if finding_id not in processed_ids:
            asset_id = finding.get("asset", {}).get("assetId", "")
            asset_details = {}
            if asset_id:
                try:
                    asset_details = client.get_asset_details(asset_id)
                    demisto.debug("asset details :", asset_details)
                    finding["asset"]["details"] = asset_details
                except Exception as e:
                    demisto.error(
                        f"Failed to fetch asset details for asset ID {asset_id}: {str(e)}"
                    )
                # Define custom fields for the incident
                custom_fields = {
                    "assetdetails": asset_details,
                    "remediationDescription": ASSET_REMEDIATION_DESCRIPTION.get(
                        finding.get("ruleName"), "N/A"
                    ),
                    "remediateSteps": ASSET_REMEDIATION_STEPS.get(
                        finding.get("ruleName"), "N/A"
                    ),
                    "riskFindingId": finding.get("id"),
                }
                incident = {
                    "name": finding.get("ruleName"),
                    "type": "DSPM Risk Findings",
                    "occurred": occurred_time,
                    "details": finding.get("asset", {}).get("name", ""),
                    "severity": severity_to_dbot_score(finding.get("severity")),
                    "status": map_status(finding.get("status")),
                    "assetDetails": json.dumps(asset_details),
                    "CustomFields": custom_fields,
                    "rawJSON": json.dumps(finding),
                }
                demisto.debug(f"incident details : {incident}")
                # RISK_FINDINGS.append(
                #     {
                #         'risk_id': finding.get('id'),
                #         'ruleName': finding.get('ruleName'),
                #         'asset_id': finding.get('asset', {}).get('assetId', ''),
                #         'asset_name': finding.get('asset', {}).get('name', ''),
                #         'status': finding.get('status'),
                #         'remediation_status': 'N/A',
                #         'remediation_step': REMEDIATE_STEPS.get(finding.get('ruleName'), 'N/A'),
                #         'cloudProvider': finding.get('cloudProvider')
                #     }
                # )
                incidents.append(incident)
            processed_ids.append(finding_id)  # type: ignore

    demisto.debug(f"Number of incidents created: {len(incidents)}")
    demisto.debug(f"Incident details: {incidents}")

    try:
        demisto.incidents(incidents)
        demisto.debug("Incidents successfully sent to demisto.incidents()")
    except Exception as e:
        demisto.error(f"Failed to create incidents: {str(e)}")

    if incidents:
        last_finding_time = incidents[-1]["occurred"]
        demisto.setLastRun(
            {"last_fetch": last_finding_time, "processed_ids": processed_ids}
        )
        demisto.debug(f"New last fetch time set: {last_finding_time}")
    else:
        demisto.setLastRun({"last_fetch": last_fetch, "processed_ids": processed_ids})
        demisto.debug("No new incidents created")


def get_integration_config_command():
    # create GCP access token
    gcp_service_account_json = demisto.params().get("serviceAccountJson")
    gcp_access_token = create_gcp_access_token(gcp_service_account_json)

    integration_config = {
        "jiraEmail": demisto.params().get("jiraEmail"),
        "jiraServerUrl": demisto.params().get("jiraServerUrl"),
        "jiraApiToken": demisto.params().get("jiraApiToken", {}).get("password"),
        "azureStorageName": demisto.params().get("azureStorageName"),
        "azureSharedKey": demisto.params().get("azureSharedKey", {}).get("password"),
        "dspmApiKey": demisto.params().get("dspmApiKey", {}).get("password"),
        "GCPAccessToken": gcp_access_token,
        "slackMsgLifetime": demisto.params().get("slackMsgLifetime"),
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


def get_slack_msg_lifetime(client, sleep_time):
    in_seconds = int(sleep_time) * 3600
    # time.sleep(int(in_seconds))
    time.sleep(10)
    return in_seconds


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
    mirror_direction = demisto.params().get("mirror_direction", None)

    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        client = Client(
            base_url=base_url, api_key=api_key, verify=verify_certificate, proxy=proxy
        )

        if demisto.command() == "test-module":
            result = test_module(client)
            return_results(result)
        elif demisto.command() == "dspm-get-integration-cofig":
            return_results(get_integration_config_command())
        elif demisto.command() == "fetch-incidents":
            fetch_incidents(client, mirror_direction)
        elif demisto.command() == "dspm-get-risk-findings":
            # get_risk_findings_command(client, demisto.args())
            page = 0
            while True:
                findings = get_risk_findings_command(client, demisto.args(), page)
                if not findings:
                    if page == 0:
                        readable_output = "### Risk Findings\n **No entries.**\n"
                        return_results(
                            CommandResults(
                                outputs_prefix="DSPM.RiskFindings",
                                outputs_key_field="id",
                                readable_output=readable_output,
                            )
                        )
                    break  # No more findings to fetch

                return_results(
                    CommandResults(
                        outputs_prefix="DSPM.RiskFindings",
                        outputs_key_field="id",
                        outputs=findings,
                    )
                )
                page += 1
        elif demisto.command() == "dspm-get-risk-finding-by-id":
            return_results(get_risk_finding_by_id_command(client, demisto.args()))
        elif demisto.command() == "dspm-get-list-of-assets":
            page = 0
            while True:
                assets = get_list_of_assets(client, demisto.args(), page)
                if not assets:
                    if page == 0:
                        readable_output = "### List of assets\n **No entries.**\n"
                        return_results(
                            CommandResults(
                                outputs_prefix="DSPM.Assets",
                                outputs_key_field="id",
                                outputs=[],
                                readable_output=readable_output,
                            )
                        )
                    break

                return_results(
                    CommandResults(
                        outputs_prefix="DSPM.Assets",
                        outputs_key_field="id",
                        outputs=assets,
                    )
                )
                page += 1
        elif demisto.command() == "dspm-get-asset-details":
            return_results(get_asset_details_command(client, demisto.args()))
        elif demisto.command() == "dspm-get-asset-files-by-id":
            return_results(get_asset_files_by_id(client, demisto.args()))
        elif demisto.command() == "dspm-get-data-types":
            return_results(get_data_types_command(client))
        elif demisto.command() == "dspm-get-data-types-findings":
            page = 0
            all_data_type_findings = []

            while True:
                data_type_findings = get_data_type_findings(
                    client, demisto.args(), page
                )
                if not data_type_findings:
                    if page == 0:
                        readable_output = (
                            "### Data Types\n"
                            "| No | Key |\n"
                            "|----|-----|\n"
                            "**No entries.**\n"
                        )
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

                readable_output = "### Data Types\n | No | Key  |\n |----|------|\n"
                for item in data_type_findings_formatted:
                    readable_output += f"| {item['No']}  | {item['Key']} |\n"

                return_results(
                    CommandResults(
                        outputs_prefix="DSPM.DataTypesFindings",
                        outputs_key_field="Key",
                        outputs=data_type_findings_formatted,
                        readable_output=readable_output,
                    )
                )

                page += 1
        elif demisto.command() == "dspm-update-risk-finding-status":
            return_results(update_risk_finding_status_command(client, demisto.args()))
        elif demisto.command() == "dspm-get-lifetime-for-slack":
            sleep_time = demisto.params().get("slackMsgLifetime", "")
            in_seconds = get_slack_msg_lifetime(client, sleep_time)
            return_results(f"Sleep for {in_seconds} seconds")

    except Exception as e:
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}"
        )


""" ENTRY POINT """
if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
