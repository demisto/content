import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401
import json
from datetime import datetime

import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''
RISK_FINDINGS = []
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
GET_RISK_FINDINGS_ENDPINT = '/v1/risk-findings'
GET_ASSET_DETAILS = "/v1/assets/id?id="
GET_DATA_TYPES_ENDPOINT: str = "/v1/classification/data-types"
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

    def get_asset_details(self, asset_id: str):
        return self._http_request(
            method='GET',
            url_suffix=f"{GET_ASSET_DETAILS}{asset_id}"
        )

    def get_data_types(self):
        return self._http_request(
            method='GET',
            url_suffix=GET_DATA_TYPES_ENDPOINT
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


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication"""
    try:
        client.fetch_risk_findings({})
        return 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e


def get_risk_findings_command(client: Client, args: dict[str, Any]) -> CommandResults:
    page: int = 0
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
        "page": page,
        "sort": args.get('sort'),
        "size": args.get('size')
    }
    # Remove None values from params
    params = {k: v for k, v in params.items() if v is not None}

    # Initialize list to store all findings
    all_findings: List[dict] = []

    while True:
        # Fetch data from client
        response = client.fetch_risk_findings(params)

        if isinstance(response, list):
            findings = response
        else:
            findings = response.get('findings', [])

        if not findings:
            break  # No more findings to fetch

        # Append findings to the list
        all_findings.extend(findings)

        # Increment page number for the next iteration
        page += 1
        params['page'] = page

    parsed_findings = []
    for finding in all_findings:
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
        parsed_findings.append(parsed_finding)

    return CommandResults(
        outputs_prefix='DSPM.RiskFindings',
        outputs_key_field='id',
        outputs=all_findings
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
        outputs_key_field='asset.id',
        outputs=asset_details
    )


def get_data_types_command(client: Client) -> CommandResults:
    dataTypes = client.get_data_types()

    # Log the dataTypes structure for debugging
    demisto.debug(f"dataTypes: {dataTypes}")

    formatted_data = [{"No": idx + 1, "Key": item} for idx, item in enumerate(dataTypes)]

    headers = ["No", "Key"]
    human_readable = tableToMarkdown("Data Types", formatted_data, headers=headers)

    return CommandResults(
        outputs_prefix='DSPM.DataTypes',
        outputs_key_field='Key',
        outputs=formatted_data,
        readable_output=human_readable
    )


def update_risk_finding_status_command(client, args):
    finding_id = args.get('findingId')
    status = args.get('status')

    if status not in INCIDENT_STATUS.keys():
        raise ValueError(f"Invalid status. Choose from: {', '.join(INCIDENT_STATUS.keys())}")

    response = client.update_risk_status(finding_id, status)

    if response.status_code != 200:
        return_error(f"Failed to update risk finding status: {response.text}")

    return_results(f"Risk finding {finding_id} updated to status {status}")


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
            processed_ids.append(finding_id)

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
        elif demisto.command() == 'dspm-get_risk_findings':
            page_size: int = int(demisto.args().get('size', 50))
            if page_size <= 0:
                raise ValueError("items_per_page should be a positive non-zero value.")
            return_results(get_risk_findings_command(client, demisto.args()))
        elif demisto.command() == 'dspm-get_asset_details':
            return_results(get_asset_details_command(client, demisto.args()))
        elif demisto.command() == 'dspm-get-data-types':
            return_results(get_data_types_command(client))
        elif demisto.command() == 'dspm-update_risk_finding_status':
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
