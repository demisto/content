import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401
import json
from datetime import datetime
from requests.auth import HTTPBasicAuth

import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''
RISK_FINDINGS = []
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
GET_RISK_FINDINGS_ENDPINT = '/v1/risk-findings'
GET_ASSET_LISTS = "/v1/assets"
GET_ASSET_DETAILS = "/v1/assets/id?id="
GET_ASSET_FILES = "/v1/classification/asset-files/id?id="
GET_DATA_TYPES_ENDPOINT: str = "/v1/classification/data-types"
GET_DATA_TYPE_FINDINGS_ENDPOINT: str = "/v1/data-type-findings"
GET_CURRENT_JIRA_USER_ENDPOINT: str = "/rest/api/2/myself"
INCIDENT_STATUS = {
    'OPEN': 1,
    'INVESTIGATING': 2,
    'HANDLED': 2,
    'CLOSED': 2
}
RISK_STATUS = {
    'Active': 'OPEN',
    'Closed': 'INVESTIGATING',
    'Pending': 'INVESTIGATING'
}
MIRROR_DIRECTION = {
    "None": None,
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}

SUPPORTED_CLOUD_PROVIDERS = ['AWS', 'AZURE', 'GCP', 'SNOWFLAKE', 'FILE SHARE', 'O365']
SUPPORTED_AFFECTS = ['SECURITY', 'COMPLIANCE', 'GOVERNANCE', 'SECURITY_AND_COMPLIANCE',
                     'SECURITY_AND_GOVERNANCE', 'COMPLIANCE_AND_GOVERNANCE', 'SECURITY_AND_COMPLIANCE_AND_GOVERNANCE']
SUPPORTED_STATUS = ['OPEN', 'CLOSED', 'UNIMPORTANT', 'WRONG', 'HANDLED', 'INVESTIGATING']
SUPPORTED_SERVICES_TYPE = [
    'ATHENA', 'AURORA', 'AWS_BACKUP', 'DOCUMENTDB', 'DYNAMODB', 'DAX', 'EMR',
    'EBS', 'EFS', 'ELASTICACHE', 'FSX', 'KINESIS_DELIVERY_STREAM', 'MEMORYDB',
    'NEPTUNE', 'QLDB', 'RDS', 'REDSHIFT', 'S3', 'TIMESTREAM', 'OPENSEARCH',
    'COSMOS_DB', 'SYNAPSE', 'CACHE_FOR_REDIS', 'MARIA_DB', 'MYSQL_SERVER',
    'POSTGRESQL_SERVER', 'SQL_SERVER', 'STORAGE_ACCOUNT', 'SQL_MANAGED_INSTANCE',
    'ANF', 'CLOUD_STORAGE', 'CLOUD_SQL', 'BIG_QUERY', 'FILE_STORE', 'CLOUD_SPANNER',
    'MEMORY_STORE', 'BIG_TABLE', 'FIRE_STORE', 'UNMANAGED_AWS_MYSQL',
    'UNMANAGED_AWS_ORACLE_SERVER', 'UNMANAGED_AWS_MONGO_DB', 'UNMANAGED_AWS_POSTGRESQL',
    'UNMANAGED_AWS_REDIS', 'UNMANAGED_AWS_SQLITE', 'UNMANAGED_AWS_MS_SQL',
    'UNMANAGED_AWS_MARIA_DB', 'UNMANAGED_AWS_NEO4_J', 'UNMANAGED_AWS_ELASTIC',
    'UNMANAGED_AWS_COCKROACH_DB', 'UNMANAGED_AWS_AEROSPIKE', 'UNMANAGED_AWS_SCYLLA_DB',
    'UNMANAGED_AZURE_MYSQL', 'UNMANAGED_AZURE_ORACLE_SERVER', 'UNMANAGED_AZURE_MONGO_DB',
    'UNMANAGED_AZURE_POSTGRESQL', 'UNMANAGED_AZURE_REDIS', 'UNMANAGED_AZURE_SQLITE',
    'UNMANAGED_AZURE_MS_SQL', 'UNMANAGED_AZURE_MARIA_DB', 'UNMANAGED_AZURE_NEO4_J',
    'UNMANAGED_AZURE_ELASTIC', 'UNMANAGED_AZURE_COCKROACH_DB', 'UNMANAGED_AZURE_AEROSPIKE',
    'UNMANAGED_AZURE_SCYLLA_DB', 'UNMANAGED_GCP_MYSQL', 'UNMANAGED_GCP_ORACLE_SERVER',
    'UNMANAGED_GCP_MONGO_DB', 'UNMANAGED_GCP_POSTGRESQL', 'UNMANAGED_GCP_REDIS',
    'UNMANAGED_GCP_SQLITE', 'UNMANAGED_GCP_MS_SQL', 'UNMANAGED_GCP_MARIA_DB',
    'UNMANAGED_GCP_NEO4_J', 'UNMANAGED_GCP_ELASTIC', 'UNMANAGED_GCP_COCKROACH_DB',
    'UNMANAGED_GCP_AEROSPIKE', 'UNMANAGED_GCP_SCYLLA_DB', 'SNOWFLAKE_DB', 'FILE_SHARE',
    'ONE_DRIVE', 'SHARE_POINT', 'AZURE_OPEN_AI_DEPLOYMENT', 'VERTEX_ENDPOINT'
]
SUPPORTED_LIFECYCLE = ['RUNNING', 'STOPPED', 'DELETED']
SORTING_ORDER = ['ASC', 'DESC']


# Define remediation steps for specific findings
REMEDIATE_STEPS = {
    'Sensitive asset open to world': (
        "Change the S3 PublicAccessBlock settings to block public "
        "access control lists (ACLs) for the bucket"
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
    )
}
''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API"""

    def __init__(self, base_url, api_key, verify=True, proxy=False):
        headers = {
            'dig-api-key': api_key,
            'Accept': 'application/json'
        }
        super().__init__(base_url, verify=verify, headers=headers, proxy=proxy)

    def fetch_risk_findings(self, params: dict[str, Any]):
        return self._http_request(
            method='GET',
            url_suffix=GET_RISK_FINDINGS_ENDPINT,
            params=params
        )

    def get_asset_files(self, params: dict[str, Any], body: dict[str, Any]):
        return self._http_request(
            method='POST',
            url_suffix=f"{GET_ASSET_FILES}",
            params=params,
            body=body
        )

    def get_asset_details(self, asset_id: str):
        return self._http_request(
            method='GET',
            url_suffix=f"{GET_ASSET_DETAILS}{asset_id}"
        )

    def get_asset_lists(self, params: dict[str, Any]):
        return self._http_request(
            method='GET',
            url_suffix=GET_ASSET_LISTS,
            params=params
        )

    def get_data_types(self, params: dict[str, Any]):
        return self._http_request(
            method='GET',
            url_suffix=GET_DATA_TYPES_ENDPOINT,
            params=params
        )

    def get_data_type_findings(self, params: dict[str, Any]):
        return self._http_request(
            method='GET',
            url_suffix=GET_DATA_TYPE_FINDINGS_ENDPOINT,
            params=params
        )

    def get_risk_information(self, risk_id: str):
        """
        Retrieve a risk finding by its ID from Dig Security.

        :param incident_id: The ID of the incident to retrieve.
        :return: The incident data as a dictionary.
        """
        return self._http_request(
            method='GET',
            url_suffix=f"/v1/risk-findings/id/{risk_id}"
        )

    def update_risk_status(self, risk_id: str, updated_status: str):
        return self._http_request(
            method='PATCH',
            url_suffix=f"/v1/risk-findings/id/{risk_id}/status/{updated_status}"
        )


''' HELPER FUNCTIONS '''


def map_status(status: str):
    mapped_status = INCIDENT_STATUS.get(status, 1)  # Default to 'Active' if the status is not found
    demisto.debug(f"Mapping status '{status}' to '{mapped_status}'")
    return mapped_status


def map_to_third_party_status(status: str) -> str:
    mapped_status = RISK_STATUS.get(status, 'open')  # Default to 'open' if the status is not found
    demisto.debug(f"Mapping local status '{status}' to third-party status '{mapped_status}'")
    return mapped_status


def severity_to_dbot_score(severity):
    if severity == 'LOW':
        return 1
    elif severity == 'MEDIUM':
        return 2
    elif severity == 'HIGH':
        return 3
    elif severity == 'CRITICAL':
        return 4
    return 0


def check_jira_credentials():
    jira_server_url = demisto.params().get('jiraServerUrl', '')
    jira_getUser_api = f"https://{jira_server_url}{GET_CURRENT_JIRA_USER_ENDPOINT}"
    jira_email = demisto.params().get('jiraEmail')
    api_token = demisto.params().get('jiraApiToken')

    auth = HTTPBasicAuth(jira_email, api_token)
    headers = {
        "Accept": "application/json"
    }
    response = requests.request("GET", jira_getUser_api, headers=headers, auth=auth)
    if response.status_code != 200:
        raise Exception("Invalid Jira credentials")


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication"""
    try:
        client.fetch_risk_findings({})
        check_jira_credentials()
        return 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e


def get_risk_findings_command(client: Client, args: dict[str, Any]) -> CommandResults:
    # check supported cloud providers
    cloud_provider_in = args.get('cloudProviderIn')
    if cloud_provider_in and cloud_provider_in not in SUPPORTED_CLOUD_PROVIDERS:
        raise ValueError(f'This "{cloud_provider_in}" cloud provider does not supported')

    cloud_provider_equal = args.get('cloudProviderEqual')
    if cloud_provider_equal and cloud_provider_equal not in SUPPORTED_CLOUD_PROVIDERS:
        raise ValueError(f'This "{cloud_provider_equal}" cloud provider does not supported')

    # check supported affects
    affects_In = args.get('affectsIn')
    if affects_In and affects_In not in SUPPORTED_AFFECTS:
        raise ValueError(f'This "{affects_In}" Affect does not supported')

    affects_Equal = args.get('affectsEqual')
    if affects_Equal and affects_Equal not in SUPPORTED_AFFECTS:
        raise ValueError(f'This "{affects_Equal}" Affect does not supported')

    # check supported Status
    status_In = args.get('statusIn')
    if status_In and status_In not in SUPPORTED_STATUS:
        raise ValueError(f'This "{status_In}" Status does not supported')

    status_Equal = args.get('statusEqual')
    if status_Equal and status_Equal not in SUPPORTED_STATUS:
        raise ValueError(f'This "{status_Equal}" Status does not supported')

    # check supported sorting order
    sort_order = args.get('sort')
    if sort_order and sort_order.upper() not in SORTING_ORDER:
        raise ValueError(f'This "{sort_order}" sorting order does not supported')
    page = 0
    params = {
        "ruleName.in": args.get('ruleNameIn'),
        "ruleName.equals": args.get('ruleNameEqual'),
        "dspmTagKey.in": args.get('dspmTagKeyIn'),
        "dspmTagKey.equals": args.get('dspmTagKeyEqual'),
        "dspmTagValue.in": args.get('dspmTagValueIn'),
        "dspmTagValue.equals": args.get('dspmTagValueEqual'),
        "projectId.in": args.get('projectIdIn'),
        "projectId.equals": args.get('projectIdEqual'),
        "cloudProvider.in": args.get('cloudProviderIn'),
        "cloudProvider.equals": args.get('cloudProviderEqual'),
        "affects.in": args.get('affectsIn'),
        "affects.equals": args.get('affectsEqual'),
        "status.in": args.get('statusIn'),
        "status.equals": args.get('statusEqual'),
        "page": args.get('page'),
        "sort": args.get('sort'),
        "size": args.get('size')
    }
    # Remove None values from params
    params = {k: v for k, v in params.items() if v is not None}

    all_findings: List[dict] = []

    for _ in range(5):  # Limiting to 5 pages to avoid infinite loop
        # Fetch data from client
        response = client.fetch_risk_findings(params)

        findings = response.get('findings', []) if isinstance(response, dict) else response

        if not findings:
            break  # No more findings to fetch

        all_findings.extend(findings)

        # Increment page number for the next iteration
        page += 1
        params['page'] = page

    parsed_findings = [
        {
            'ID': finding.get('id', ''),
            'Rule Name': finding.get('ruleName', ''),
            'Severity': finding.get('severity', ''),
            'Asset Name': finding.get('asset', {}).get('name', ''),
            'Asset ID': finding.get('asset', {}).get('assetId', ''),
            'Status': finding.get('status', ''),
            'Project ID': finding.get('projectId', ''),
            'Cloud Provider': finding.get('cloudProvider', ''),
            'Cloud Environment': finding.get('cloudEnvironment', ''),
            'First Discovered': finding.get('firstDiscovered', ''),
            'Compliance Standards': finding.get('complianceStandards', {})
        }
        for finding in all_findings
    ]

    return CommandResults(
        outputs_prefix='DSPM.RiskFindings',
        outputs_key_field='id',
        outputs=parsed_findings
    )


def get_risk_finding_by_id_command(client: Client, args: dict[str, Any]) -> CommandResults:
    risk_id = args.get('id')
    if not risk_id:
        raise ValueError('id argument is required')

    # Fetch data from client using the get_risk_information method
    response = client.get_risk_information(risk_id)

    if not response:
        raise ValueError(f'No finding found with id {risk_id}')

    finding = response if isinstance(response, dict) else response[0]

    parsed_finding = {
        'ID': finding.get('id', ''),
        'Rule Name': finding.get('ruleName', ''),
        'Severity': finding.get('severity', ''),
        'Asset Name': finding.get('asset', {}).get('name', ''),
        'Asset ID': finding.get('asset', {}).get('assetId', ''),
        'Status': finding.get('status', ''),
        'Project ID': finding.get('projectId', ''),
        'Cloud Provider': finding.get('cloudProvider', ''),
        'Cloud Environment': finding.get('cloudEnvironment', ''),
        'First Discovered': finding.get('firstDiscovered', ''),
        'Compliance Standards': finding.get('complianceStandards', {})
    }

    return CommandResults(
        outputs_prefix='DSPM.RiskFinding',
        outputs_key_field='id',
        outputs=parsed_finding
    )


def get_list_of_assets(client: Client, args: dict[str, Any]) -> CommandResults:
    # check supported cloud providers
    cloud_provider_in = args.get('cloudProviderIn')
    if cloud_provider_in and cloud_provider_in not in SUPPORTED_CLOUD_PROVIDERS:
        raise ValueError(f'This "{cloud_provider_in}" cloud provider does not supported')

    cloud_provider_equal = args.get('cloudProviderEqual')
    if cloud_provider_equal and cloud_provider_equal not in SUPPORTED_CLOUD_PROVIDERS:
        raise ValueError(f'This "{cloud_provider_equal}" cloud provider does not supported')

    # check supported service type
    service_Type_In = args.get('serviceTypeIn')
    if service_Type_In and service_Type_In not in SUPPORTED_SERVICES_TYPE:
        raise ValueError(f'This "{service_Type_In}" service type does not supported')

    service_Type_Equal = args.get('serviceTypeEqual')
    if service_Type_Equal and service_Type_Equal not in SUPPORTED_SERVICES_TYPE:
        raise ValueError(f'This "{service_Type_Equal}" service type does not supported')

    # check supported lifecycle
    lifecycle_In = args.get('lifecycleIn')
    if lifecycle_In and lifecycle_In not in SUPPORTED_LIFECYCLE:
        raise ValueError(f'This "{lifecycle_In}" lifecycle does not supported')

    lifecycle_Equal = args.get('lifecycleEqual')
    if lifecycle_Equal and lifecycle_Equal not in SUPPORTED_LIFECYCLE:
        raise ValueError(f'This "{lifecycle_Equal}" lifecycle does not supported')

    # check supported sorting order
    sort_order = args.get('sort')
    if sort_order and sort_order.upper() not in SORTING_ORDER:
        raise ValueError(f'This "{sort_order}" sorting order does not supported')
    page = 0
    params = {
        "region.in": args.get('regionIn'),
        "region.equals": args.get('regionEqual'),
        "cloudProvider.in": args.get('cloudProviderIn'),
        "cloudProvider.equals": args.get('cloudProviderEqual'),
        "serviceType.in": args.get('serviceTypeIn'),
        "serviceType.equals": args.get('serviceTypeEqual'),
        "digTagKey.contains": args.get('digTagKeyContains'),
        "digTagValue.contains": args.get('digTagValueContains'),
        "lifecycle.in": args.get('lifecycleIn'),
        "lifecycle.equals": args.get('lifecycleEqual'),
        "sort": args.get('sort'),
        "page": args.get('page'),
        "size": args.get('size')
    }
    # Remove None values from params
    params = {k: v for k, v in params.items() if v is not None}

    all_assets: List[dict] = []

    for _ in range(5):  # Limiting to 5 pages to avoid infinite loop
        # Fetch data from client
        response = client.get_asset_lists(params)

        assets = response.get('assets', []) if isinstance(response, dict) else response

        if not assets:
            break  # No more assets to fetch

        all_assets.extend(assets)

        # Increment page number for the next iteration
        page += 1
        params['page'] = page

    parsed_assets = [
        {
            'ID': asset.get('id', ''),
            'Project ID': asset.get('projectId', ''),
            'Project Name': asset.get('projectName', ''),
            'Name': asset.get('name', ''),
            'Cloud Provider': asset.get('cloudProvider', ''),
            'Cloud Environment': asset.get('cloudEnvironment', ''),
            'Service Type': asset.get('serviceType', ''),
            'Lifecycle': asset.get('lifecycle', ''),
            'Open Risks Count': asset.get('openRisksCount', 0),
            'Open Alerts Count': asset.get('openAlertsCount', 0),
            'Encrypted': asset.get('encrypted', False),
            'Open To World': asset.get('openToWorld', False),
            'Tags': asset.get('tags', {}),
            'Asset Dig Tags': asset.get('assetDigTags', [])
        }
        for asset in all_assets
    ]

    return CommandResults(
        outputs_prefix='DSPM.Assets',
        outputs_key_field='id',
        outputs=parsed_assets
    )


def get_asset_details_command(client: Client, args: dict[str, Any]) -> CommandResults:
    asset_id = args.get('asset_id', None)
    if not asset_id:
        raise ValueError('asset_id not specified')

    asset_details = client.get_asset_details(asset_id)
    demisto.debug(f"Asset details of : {asset_id}")
    demisto.debug(asset_details)
    return CommandResults(
        outputs_prefix='DSPM.AssetDetails',
        outputs_key_field='id',
        outputs=asset_details
    )


def get_asset_files_by_id(client: Client, args: dict[str, Any]) -> CommandResults:
    asset_id = args.get('id', None)
    types = args.get('types', [])
    params = {
        "id": asset_id,
        "page": args.get('page', 1),
        "size": args.get('size', 20)
    }

    if not asset_id:
        raise ValueError("Asset ID not specified")

    request_body = {
        "type": {
            "in": types
        }
    }

    response = client.get_asset_files(params, request_body)

    files = response.get('files', [])
    files_count = response.get('filesCount', 0)

    return CommandResults(
        outputs_prefix='DSPM.AssetFiles',
        outputs_key_field='filename',
        outputs={
            'files': files,
            'filesCount': files_count
        }
    )


def get_data_types_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Command to fetch data types."""
    # check supported cloud providers
    cloud_provider_in = args.get('cloudProviderIn')
    if cloud_provider_in and cloud_provider_in not in SUPPORTED_CLOUD_PROVIDERS:
        raise ValueError(f'This "{cloud_provider_in}" cloud provider does not supported')

    cloud_provider_equal = args.get('cloudProviderEqual')
    if cloud_provider_equal and cloud_provider_equal not in SUPPORTED_CLOUD_PROVIDERS:
        raise ValueError(f'This "{cloud_provider_equal}" cloud provider does not supported')

    # check supported service type
    service_Type_In = args.get('serviceTypeIn')
    if service_Type_In and service_Type_In not in SUPPORTED_SERVICES_TYPE:
        raise ValueError(f'This "{service_Type_In}" service type does not supported')

    service_Type_Equal = args.get('serviceTypeEqual')
    if service_Type_Equal and service_Type_Equal not in SUPPORTED_SERVICES_TYPE:
        raise ValueError(f'This "{service_Type_Equal}" service type does not supported')

    # check supported lifecycle
    lifecycle_In = args.get('lifecycleIn')
    if lifecycle_In and lifecycle_In not in SUPPORTED_LIFECYCLE:
        raise ValueError(f'This "{lifecycle_In}" lifecycle does not supported')

    lifecycle_Equal = args.get('lifecycleEqual')
    if lifecycle_Equal and lifecycle_Equal not in SUPPORTED_LIFECYCLE:
        raise ValueError(f'This "{lifecycle_Equal}" lifecycle does not supported')

    # check supported sorting order
    sort_order = args.get('sort')
    if sort_order and sort_order.upper() not in SORTING_ORDER:
        raise ValueError(f'This "{sort_order}" sorting order does not supported')

    params = {
        "region.in": args.get('regionIn'),
        "region.equals": args.get('regionEqual'),
        "projectId.in": args.get('projectIdIn'),
        "projectId.equals": args.get('projectIdEqual'),
        "cloudProvider.in": args.get('cloudProviderIn'),
        "cloudProvider.equals": args.get('cloudProviderEqual'),
        "serviceType.in": args.get('serviceTypeIn'),
        "serviceType.equals": args.get('serviceTypeEqual'),
        "lifecycle.in": args.get('lifecycleIn'),
        "lifecycle.equals": args.get('lifecycleEqual'),
        "page": args.get('page'),
        "sort": args.get('sort'),
        "size": args.get('size')
    }
    data_types = client.get_data_types(params)
    data_types_formatted = [{'No': index + 1, 'Key': dt} for index, dt in enumerate(data_types)]

    if data_types_formatted:
        readable_output = (
            "### Data Types\n"
            "| No | Key  |\n"
            "|----|------|\n"
        )
        for item in data_types_formatted:
            readable_output += f"| {item['No']}  | {item['Key']} |\n"
    else:
        readable_output = (
            "### Data Types\n"
            "| No | Key |\n"
            "|----|-----|\n"
            "**No entries.**\n"
        )

    return CommandResults(
        outputs_prefix='DSPM.DataTypes',
        outputs_key_field='Key',
        outputs=data_types_formatted,
        readable_output=readable_output
    )


def get_data_type_findings_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Command to fetch data types and format them for the XSOAR command results."""
    # check supported cloud providers
    cloud_provider_in = args.get('cloudProviderIn')
    if cloud_provider_in and cloud_provider_in not in SUPPORTED_CLOUD_PROVIDERS:
        raise ValueError(f'This "{cloud_provider_in}" cloud provider does not supported')

    cloud_provider_equal = args.get('cloudProviderEqual')
    if cloud_provider_equal and cloud_provider_equal not in SUPPORTED_CLOUD_PROVIDERS:
        raise ValueError(f'This "{cloud_provider_equal}" cloud provider does not supported')

    # check supported service type
    service_Type_In = args.get('serviceTypeIn')
    if service_Type_In and service_Type_In not in SUPPORTED_SERVICES_TYPE:
        raise ValueError(f'This "{service_Type_In}" service type does not supported')

    service_Type_Equal = args.get('serviceTypeEqual')
    if service_Type_Equal and service_Type_Equal not in SUPPORTED_SERVICES_TYPE:
        raise ValueError(f'This "{service_Type_Equal}" service type does not supported')

    # check supported lifecycle
    lifecycle_In = args.get('lifecycleIn')
    if lifecycle_In and lifecycle_In not in SUPPORTED_LIFECYCLE:
        raise ValueError(f'This "{lifecycle_In}" lifecycle does not supported')

    lifecycle_Equal = args.get('lifecycleEqual')
    if lifecycle_Equal and lifecycle_Equal not in SUPPORTED_LIFECYCLE:
        raise ValueError(f'This "{lifecycle_Equal}" lifecycle does not supported')

    # check supported sorting order
    sort_order = args.get('sort')
    if sort_order and sort_order.upper() not in SORTING_ORDER:
        raise ValueError(f'This "{sort_order}" sorting order does not supported')

    params = {
        "region.in": args.get('regionIn'),
        "region.equals": args.get('regionEqual'),
        "projectId.in": args.get('projectIdIn'),
        "projectId.equals": args.get('projectIdEqual'),
        "cloudProvider.in": args.get('cloudProviderIn'),
        "cloudProvider.equals": args.get('cloudProviderEqual'),
        "serviceType.in": args.get('serviceTypeIn'),
        "serviceType.equals": args.get('serviceTypeEqual'),
        "lifecycle.in": args.get('lifecycleIn'),
        "lifecycle.equals": args.get('lifecycleEqual'),
        "page": args.get('page'),
        "sort": args.get('sort'),
        "size": args.get('size')
    }
    data_type_findings = client.get_data_type_findings(params)

    if not data_type_findings:  # Check if the list is empty
        readable_output = (
            "### Data Types\n"
            "| No | Key |\n"
            "|----|-----|\n"
            "**No entries.**\n"
        )
        return CommandResults(
            outputs_prefix='DSPM.DataTypesFindings',
            outputs_key_field='Key',
            outputs=[],
            readable_output=readable_output
        )

    if isinstance(data_type_findings[0], str):  # Handle case where the data is a list of strings
        data_type_findings_formatted = [{'No': index + 1, 'Key': dt} for index, dt in enumerate(data_type_findings)]
    else:  # Handle case where the data is a list of dictionaries
        data_type_findings_formatted = [{'No': index + 1, 'Key': dt['dataTypeName']}
                                        for index, dt in enumerate(data_type_findings)]

    readable_output = (
        "### Data Types\n"
        "| No | Key  |\n"
        "|----|------|\n"
    )
    for item in data_type_findings_formatted:
        readable_output += f"| {item['No']}  | {item['Key']} |\n"

    return CommandResults(
        outputs_prefix='DSPM.DataTypesFindings',
        outputs_key_field='Key',
        outputs=data_type_findings_formatted,
        readable_output=readable_output
    )


def update_risk_finding_status_command(client, args):
    finding_id = args.get('findingId')
    status = args.get('status')

    # Validate status
    if status not in INCIDENT_STATUS:
        raise ValueError(f"Invalid status. Choose from: {', '.join(INCIDENT_STATUS)}")

    try:
        response = client.update_risk_status(finding_id, status)
        if response.get('status') == status:
            return_results(f'Risk finding {finding_id} updated to status {status}')
        else:
            raise Exception(f"Unexpected response: {response}")
    except Exception as e:
        return_error(f"Failed to update risk finding {finding_id} to status {status}. Error: {str(e)}")


''' FETCH INCIDENTS FUNCTION'''


def get_mirroring_fields(mirror_direction):
    """
    Get tickets mirroring.
    """

    return {
        "mirror_direction": MIRROR_DIRECTION.get(mirror_direction),
        "mirror_instance": demisto.integrationInstance(),
        "incident_type": "DSPM Risk Findings",
    }


def fetch_incidents(client: Client, mirror_direction):
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('last_fetch')
    processed_ids = last_run.get('processed_ids', [])

    if last_fetch is None:
        last_fetch = '1970-01-01T00:00:00Z'

    incidents = []
    page = 0
    size = 50  # 50 is max size we can provide.
    findings = []

    while True:
        response = client.fetch_risk_findings({'page': page, 'size': size, 'ruleName.equals': 'Sensitive asset open to world'})
        new_findings = response
        if not new_findings:
            break
        findings.extend(new_findings)
        page += 1

    demisto.debug(f"Total number of findings fetched: {len(findings)}")

    for finding in findings:
        finding_id = finding.get('id')
        occurred_time = datetime.utcnow().strftime(DATE_FORMAT)
        finding.update(get_mirroring_fields(mirror_direction))

        if finding_id not in processed_ids:
            asset_id = finding.get('asset', {}).get('assetId', '')
            asset_details = {}
            if asset_id:
                try:
                    asset_details = client.get_asset_details(asset_id)
                    demisto.debug("asset details :", asset_details)
                    finding['asset']['details'] = asset_details
                except Exception as e:
                    demisto.error(f"Failed to fetch asset details for asset ID {asset_id}: {str(e)}")
                # Define custom fields for the incident
                custom_fields = {
                    "assetdetails": asset_details,
                    "remediatestep": REMEDIATE_STEPS.get(finding.get('ruleName'), 'N/A')
                }
                incident = {
                    'name': finding.get('ruleName'),
                    'dbotMirrorId': finding.get('id'),
                    "type": "DSPM Risk Findings",
                    'occurred': occurred_time,
                    'details': finding.get('asset', {}).get('name', ''),
                    'severity': severity_to_dbot_score(finding.get('severity')),
                    'status': map_status(finding.get('status')),
                    'assetDetails': json.dumps(asset_details),
                    "CustomFields": custom_fields,
                    'rawJSON': json.dumps(finding)
                }
                RISK_FINDINGS.append(
                    {
                        'risk_id': finding.get('id'),
                        'ruleName': finding.get('ruleName'),
                        'asset_id': finding.get('asset', {}).get('assetId', ''),
                        'asset_name': finding.get('asset', {}).get('name', ''),
                        'status': finding.get('status'),
                        'remediation_status': 'N/A',
                        'remediation_step': REMEDIATE_STEPS.get(finding.get('ruleName'), 'N/A'),
                        'cloudProvider': finding.get('cloudProvider')
                    }
                )
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
        last_finding_time = incidents[-1]['occurred']
        demisto.setLastRun({'last_fetch': last_finding_time, 'processed_ids': processed_ids})
        demisto.debug(f"New last fetch time set: {last_finding_time}")
    else:
        demisto.setLastRun({'last_fetch': last_fetch, 'processed_ids': processed_ids})
        demisto.debug("No new incidents created")


def get_integration_config_command():
    integration_config = {
        "jiraEmail": demisto.params().get('jiraEmail'),
        "jiraServerUrl": demisto.params().get('jiraServerUrl'),
        "jiraApiToken": demisto.params().get('jiraApiToken', {}).get('password'),
        "xsoarServerUrl": demisto.params().get('xsoarUrl'),
        "xsoarApiKey": demisto.params().get('xsoarApiKey', {}).get('password')
    }
    demisto.debug(f" integration config : ${integration_config}")

    return CommandResults(
        outputs_prefix='DSPM.integration_config',
        outputs_key_field='config',
        outputs={'integration_conf': integration_config}
    )

# def find_existing_incident(dbot_mirror_id: str) -> bool:
#     query = f'dbotMirrorId:"{dbot_mirror_id}"'
#     result = demisto.execute_command("getIncidents", {"query": query, "limit": 1})
#     if is_error(result):
#         return False
#     incidents = result[0].get('Contents', {}).get('data', [])
#     return len(incidents) > 0


# def fetch_handler(client: Client):
#     last_run = demisto.getLastRun()
#     last_fetch = last_run.get('last_fetch')

#     if last_fetch is None:
#         last_fetch = '1970-01-01T00:00:00Z'

#     incidents = []
#     page = 0
#     page_size = 50

#     while True:
#         findings_response = client.fetch_risk_findings({'page': page, 'size': page_size})
#         new_findings = findings_response

#         if not new_findings:
#             break

#         for finding in new_findings:
#             finding_id = finding.get('id')
#             occurred_time = datetime.utcnow().strftime(DATE_FORMAT)

#             if not find_existing_incident(finding_id):
#                 # Fetch asset details for the current finding
#                 asset_id = finding.get('asset', {}).get('assetId')
#                 if asset_id:
#                     asset_details = client.get_asset_details(asset_id)
#                     finding['asset'].append(asset_details)

#                 incident = {
#                     'name': finding.get('ruleName'),
#                     'dbotMirrorId': finding.get('id'),
#                     'occurred': occurred_time,
#                     'details': finding.get('asset', {}).get('name', ''),
#                     'severity': severity_to_dbot_score(finding.get('severity')),
#                     'status': map_status(finding.get('status')),
#                     'rawJSON': json.dumps(finding)
#                 }
#                 incidents.append(incident)

#         page += 1

#     try:
#         demisto.incidents(incidents)
#         demisto.debug("Incidents successfully sent to demisto.incidents()")
#     except Exception as e:
#         demisto.error(f"Failed to create incidents: {str(e)}")

#     if incidents:
#         last_finding_time = incidents[-1]['occurred']
#         demisto.setLastRun({'last_fetch': last_finding_time})
#         demisto.debug(f"New last fetch time set: {last_finding_time}")
#     else:
#         demisto.setLastRun({'last_fetch': last_fetch})
#         demisto.debug("No new incidents created")

''' Mirroring Functions '''


def get_remote_incident_data(client: Client, remote_incident_id: str, last_update) -> dict[str, Any]:
    """
    Called every time get-remote-data command runs on an incident.
    Gets the relevant incident entity from the remote system (DSPM). The remote system returns the incident
    entity as a dictionary. We take from this entity only the relevant incoming mirroring fields, in order to do the mirroring.

    :param client: The client object with an authenticated session.
    :param remote_incident_id: The ID of the remote incident.
    :return: The incident data to be mirrored.
    """
    mirrored_data = client.get_risk_information(remote_incident_id)
    mirrored_data["incident_type"] = "DSPM Risk Findings"
    return mirrored_data


def get_remote_data_command(client: Client, args: dict, params: dict) -> GetRemoteDataResponse:
    """
    get-remote-data command: Returns an updated remote incident.
    Args:
        args:
            id: incident id to retrieve.
            lastUpdate: when was the last time we retrieved data.

    Returns:
        GetRemoteDataResponse object, which contains the incident data to update.
    """
    demisto.debug("inside get_remote_data_command")
    remote_args = GetRemoteDataArgs(args)
    remote_incident_id = remote_args.remote_incident_id
    last_update = remote_args.last_update
    mirrored_data = {}
    entries: list = []
    try:
        demisto.debug(
            f"Performing get-remote-data command with incident id: {remote_incident_id} "
            f"and last_update: {remote_args.last_update}"
        )
        mirrored_data = get_remote_incident_data(client, remote_incident_id, last_update)
        demisto.debug("mirror data fetch ")
        demisto.debug(mirrored_data)
        if mirrored_data:
            demisto.debug("Successfully fetched the remote incident data")
            close_xsoar_incident = params.get("close_xsoar_incident", False)
            entries = set_xsoar_incident_entries(mirrored_data, entries, remote_incident_id, close_xsoar_incident)
        else:
            demisto.debug(f"No delta was found for incident {remote_incident_id}.")

        return GetRemoteDataResponse(mirrored_object=mirrored_data, entries=entries)

    except Exception as e:
        demisto.debug(
            f"Error in DSPM incoming mirror for incident: {remote_incident_id}\n"
            f"Error message: {str(e)}"
        )

        if not mirrored_data:
            mirrored_data = {"id": remote_incident_id}
        mirrored_data["in_mirror_error"] = str(e)

        return GetRemoteDataResponse(mirrored_object=mirrored_data, entries=[])


def set_xsoar_incident_entries(mirrored_data: dict[str, Any], entries: list, incident_id: str, close_incident: bool) -> list:
    """
    Process the mirrored data and set XSOAR incident entries accordingly.

    :param mirrored_data: The data fetched from the remote incident.
    :param entries: The current list of entries.
    :param incident_id: The ID of the incident.
    :param close_incident: Boolean flag to close the incident if needed.
    :return: Updated list of entries.
    """
    demisto.debug(f"Setting XSOAR incident entries for incident ID {incident_id} with mirrored data: {mirrored_data}")

    # fields_to_update = {
    #     'Name': mirrored_data.get('ruleName', ''),
    #     'Severity': mirrored_data.get('severity', ''),
    #     'Asset Name': mirrored_data.get('asset', {}).get('name', ''),
    #     'Asset ID': mirrored_data.get('asset', {}).get('assetId', ''),
    #     'Status': map_status(mirrored_data.get('status', '')),
    #     'Project ID': mirrored_data.get('projectId', ''),
    #     'Cloud Provider': mirrored_data.get('cloudProvider', ''),
    #     'Cloud Environment': mirrored_data.get('cloudEnvironment', ''),
    #     'First Discovered': mirrored_data.get('firstDiscovered', ''),
    #     'Compliance Standards': mirrored_data.get('complianceStandards', {}),
    #     'dbotMirrorId': mirrored_data.get('id', ''),
    #     'Details': mirrored_data.get('asset', {}).get('name', '')
    # }
    demisto.debug(f"Mirror id {mirrored_data.get('id', '')} and status is : {mirrored_data.get('status', '')}")
    if (mirrored_data.get('status') == "CLOSED"
        or mirrored_data.get('status') == "INVESTIGATING"
            or mirrored_data.get('status') == "HANDLED"):
        demisto.debug(f"Incident is closed: {incident_id}")
        entries.append(
            {
                "Type": EntryType.NOTE,
                "Contents": {
                    "dbotIncidentClose": True,
                    "closeReason": "Incident was closed on DSPM",
                },
                "Tags": ["closed"],
                "ContentsFormat": EntryFormat.JSON,
            }
        )
        return entries

    entry = {
        "Type": 1,  # Note type
        "Contents": f"Mirrored data fetched for incident ID {incident_id}.",
        "ContentsFormat": "json",
        "Tags": ["mirrored"],
        "Note": True
    }

    # for key, value in fields_to_update.items():
    #     entry[key] = value

    entries.append(entry)

    # if close_incident:
    #     entries.append({
    #         "Type": 1,
    #         "Contents": f"Incident {incident_id} closed as per remote status.",
    #         "ContentsFormat": "text",
    #         "Tags": ["closed"],
    #         "Note": True
    #     })

    return entries


def update_remote_system_command(client: Client, args: dict) -> str:
    """update-remote-system command: pushes local changes to the remote system
    :type client: ``Client``
    :param client: XSOAR client to use
    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['data']`` the data to send to the remote system
        ``args['entries']`` the entries to send to the remote system
        ``args['incidentChanged']`` boolean telling us if the local incident indeed changed or not
        ``args['remoteId']`` the remote incident id
    :return:
        ``str`` containing the remote incident id - really important if the incident is newly created remotely
    :rtype: ``str``
    """
    parsed_args = UpdateRemoteSystemArgs(args)
    delta = parsed_args.delta
    remote_incident_id = parsed_args.remote_incident_id
    demisto.debug(f'Got the following data {parsed_args.data}, and delta {delta}.')

    try:
        if parsed_args.incident_changed:
            status = delta.get("status", None)
            if status:
                third_party_status = map_to_third_party_status(status)
                client.update_risk_status(remote_incident_id, third_party_status)
    except Exception as e:
        demisto.error(f'Error updating incident {remote_incident_id} on the remote system. '
                      f'Error message: {str(e)}')

    return remote_incident_id


def get_modified_remote_data_command(client: Client, args: dict) -> GetModifiedRemoteDataResponse:
    """
    Gets the modified remote incidents.
    Args:
        args:
            last_update: the last time we retrieved modified incidents.

    Returns:
        GetModifiedRemoteDataResponse object, which contains a list of the retrieved incidents IDs.
    """
    demisto.debug("inside get_modified_remote_data_command :")
    remote_args = GetModifiedRemoteDataArgs(args)

    last_update_utc = dateparser.parse(
        remote_args.last_update, settings={"TIMEZONE": "UTC"}
    )  # convert to utc format
    assert last_update_utc is not None, f"could not parse {remote_args.last_update}"

    demisto.debug(f"Remote arguments last_update in UTC is {last_update_utc}")
    modified_ids_to_mirror = []
    last_update_utc = last_update_utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    demisto.debug("On line 582 , last_update_utc :", last_update_utc)
    raw_risks = client.fetch_risk_findings({})

    for finding in raw_risks:
        modified_ids_to_mirror.append(finding.get("id"))

    demisto.debug(f"All ids to mirror in are: {modified_ids_to_mirror}")

    return GetModifiedRemoteDataResponse(modified_ids_to_mirror)


def get_mapping_fields() -> dict[str, Any]:
    mapping_fields: dict[str, Any] = {}
    # Pull the remote schema for incident types and their fields
    # Example:
    # mapping_fields = query_mapping_fields()
    return mapping_fields


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # get the service API url
    base_url = demisto.params().get('url')
    api_key = demisto.params().get('credentials', {}).get('password')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    mirror_direction = demisto.params().get('mirror_direction', None)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            api_key=api_key,
            verify=verify_certificate,
            proxy=proxy
        )

        if demisto.command() == 'test-module':
            result = test_module(client)
            demisto.results(result)
        elif demisto.command() == "dspm-get-integration-cofig":
            return_results(get_integration_config_command())
        elif demisto.command() == 'fetch-incidents':
            fetch_incidents(client, mirror_direction)
        elif demisto.command() == 'dspm-get-risk-findings':
            page_size: int = int(demisto.args().get('size', 50))
            if page_size <= 0:
                raise ValueError("items_per_page should be a positive non-zero value.")
            return_results(get_risk_findings_command(client, demisto.args()))
        elif demisto.command() == 'dspm-get-risk-finding-by-id':
            return_results(get_risk_finding_by_id_command(client, demisto.args()))
        elif demisto.command() == 'dspm-get-list-of-assets':
            return_results(get_list_of_assets(client, demisto.args()))
        elif demisto.command() == 'dspm-get-asset-details':
            return_results(get_asset_details_command(client, demisto.args()))
        elif demisto.command() == 'dspm-get-asset-files-by-id':
            return_results(get_asset_files_by_id(client, demisto.args()))
        elif demisto.command() == 'dspm-get-data-types':
            return_results(get_data_types_command(client, demisto.args()))
        elif demisto.command() == 'dspm-get-data-types-findings':
            return_results(get_data_type_findings_command(client, demisto.args()))
        elif demisto.command() == 'dspm-update-risk-finding-status':
            return_results(update_risk_finding_status_command(client, demisto.args()))
        elif demisto.command() == 'get-modified-remote-data':
            modified_incidents = get_modified_remote_data_command(client, demisto.args())
            return_results(modified_incidents)
        elif demisto.command() == 'get-remote-data':
            remote_data = get_remote_data_command(client, demisto.args(), demisto.params())
            return_results(remote_data)
        elif demisto.command() == 'update-remote-system':
            update_remote_system_command(client, demisto.args())
        elif demisto.command() == 'get-mapping-fields':
            mapping_fields = get_mapping_fields()
            return_results(mapping_fields)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
