import json

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import traceback
from typing import Dict, Any, Tuple

# Disable insecure warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'  # ISO8601 format with UTC, default in XSOAR
CategoryToIncidentType = {
    'Access': 'Alert',
    'Admin': 'Alert',
    'Audit': 'Alert',
    'Data': 'Alert',
    'Policy': 'Alert',
    'Vulnerability': 'Alert',
    'CompromisedAccount': 'Threat',
    'InsiderThreat': 'Threat',
    'PrivilegeAccess': 'Threat',
}

''' CLIENT CLASS '''


class Client(BaseClient):
    def test(self):
        self.incident_query(1, (arg_to_datetime('3 days') or datetime.now() - timedelta(days=3)).strftime(DATE_FORMAT))

    def incident_query(self, limit: Optional[int], start_time: str = '', end_time: str = '', actor_ids: list[str] = None,
                       service_names: list[str] = None, categories: list[str] = None) -> Dict[str, Any]:
        url_suffix = '/external/api/v1/queryIncidents'
        params = {'limit': limit or 50}
        data = assign_params(
            startTime=start_time,
            endTime=end_time,
            actorIds=actor_ids,
            serviceNames=service_names,
            incidentCriteria=assign_params(
                categories=categories
            ),
        )
        return self._http_request('POST', url_suffix, params=params, json_data=data, raise_on_status=True)

    def status_update(self, incident_ids: List, status: str) -> Dict[str, str]:
        url_suffix = '/external/api/v1/modifyIncidents'
        data = [
            {'incidentId': incident_id, "changeRequests": {"WORKFLOW_STATUS": status}} for incident_id in incident_ids
        ]
        return self._http_request('POST', url_suffix, json_data=data, raise_on_status=True)

    def anomaly_activity_list(self, incident_id: Optional[int]) -> Dict[str, str]:
        url_suffix = '/external/api/v1/queryActivities'
        data = {"incident_id": incident_id}
        return self._http_request('POST', url_suffix, json_data=data)

    def policy_dictionary_list(self) -> List[Dict]:
        url_suffix = '/dlp/dictionary'
        return self._http_request('GET', url_suffix, raise_on_status=True)

    def policy_dictionary_update(self, dict_id: Optional[int], name: str, content: str) -> Dict[str, str]:
        url_suffix = '/dlp/dictionary'
        data = {
            "id": dict_id,
            "name": name,
            "content": content
        }
        return self._http_request('PUT', url_suffix, data=json.dumps(data), raise_on_status=True)


''' HELPER FUNCTIONS '''


def calculate_offset_and_limit(**kwargs) -> Tuple[int, int]:
    if limit := arg_to_number(kwargs.get('limit')):  # 'limit' is stronger than pagination ('page', and 'page_size').
        return 0, limit
    if (page := arg_to_number(kwargs.get('page'))) and (page_size := arg_to_number(kwargs.get('page_size'))):
        page -= 1  # First page means list in index zero.
        return page * page_size, page * page_size + page_size
    return 0, 50


def convert_to_xsoar_severity(severity: str) -> float:
    """Maps Skyhigh Security severity to Cortex XSOAR severity

    Converts the Skyhigh Security incident severity level to Cortex XSOAR incident severity (1 to 4)
    for mapping.

    :type severity: ``str``
    :param severity: severity as returned from the Skyhigh Security API ('info', 'low', 'medium', 'high')

    :return: Cortex XSOAR Severity (int: 1 to 4)
    :rtype: ``float``
    """
    return {
        'info': IncidentSeverity.INFO,
        'low': IncidentSeverity.LOW,
        'medium': IncidentSeverity.MEDIUM,
        'high': IncidentSeverity.HIGH,
    }[severity]


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    type client: ``Client``
    :param client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        client.test()
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise
    return message


def fetch_incidents(client: Client, params: dict) -> Tuple[dict, list]:
    last_run = demisto.getLastRun()
    xsoar_incidents = []

    limit = arg_to_number(params.get('max_fetch', 50))
    if not (start_time := last_run.get('start_time')):  # in the first interval.
        default_first_time = datetime.now() - timedelta(days=3)
        start_time = (arg_to_datetime(params.get('first_fetch')) or default_first_time).strftime(DATE_FORMAT)

    result = client.incident_query(limit, start_time)

    if incidents := result.get('body', {}).get('incidents', []):
        ids = set(last_run.get('ids', set()))

        for incident in incidents:
            # Since the API returns the incidents in ascending time modified order.
            # As mentioned here:
            # https://success.myshn.net/Skyhigh_CASB/Skyhigh_CASB_APIs/Incidents_API/02_Incidents_API_Paths#_responses_3
            # We need to verify no duplicates are pushed to xsoar.
            if (incident_id := incident.get('incidentId')) not in ids:
                xsoar_incidents.append(
                    {
                        'name': f'Skyhigh Security Incident {incident_id}',
                        'occurred': incident.get('timeModified'),
                        'rawJSON': json.dumps(incident),
                        'dbotMirrorId': incident_id,
                        'severity': convert_to_xsoar_severity(incident.get('incidentRiskSeverity', 'low'))
                    }
                )

                ids.add(incident_id)

        last_run = {
            'start_time': result.get('body', {}).get('responseInfo', {}).get('nextStartTime', ''),
            'ids': list(ids)
        }

    return last_run, xsoar_incidents


def incident_query_command(client: Client, args: Dict) -> CommandResults:
    limit = arg_to_number(args.get('limit', 50))
    start_time = (arg_to_datetime(args.get('start_time')) or datetime.now() - timedelta(days=3)).strftime(DATE_FORMAT)
    end_time = (arg_to_datetime(args.get('end_time')) or datetime.now()).strftime(DATE_FORMAT)
    actor_ids = argToList(args.get('actor_ids'))
    service_names = argToList(args.get('service_names'))
    if categories := argToList(args.get('categories')):
        categories = [
            {"incidentType": CategoryToIncidentType.get(category), "category": category} for category in categories
        ]
    elif incident_types := argToList(args.get('incident_types')):
        categories = [{"incidentType": incident_type} for incident_type in incident_types]

    if not (page_number := arg_to_number(args.get('page_number'))) or \
            not (page_size := arg_to_number(args.get('page_size'))):
        result = client.incident_query(limit, start_time, end_time, actor_ids, service_names, categories)
    else:
        result = {}
        for _ in range(page_number):
            result = client.incident_query(page_size, start_time, end_time, actor_ids, service_names, categories)
            start_time = result.get('body', {}).get('responseInfo', {}).get('nextStartTime', {})

    if incidents := result.get('body', {}).get('incidents'):
        readable_dict = []

        for incident in incidents:
            readable_dict.append({
                'IncidentID': incident.get('incidentId'),
                'Time(UTC)': incident.get('timeCreated'),
                'Status': incident.get('status'),
                'Alert Action': incident.get('remediationResponse'),
                'Service Name': incident.get('serviceNames'),
                'Alert Severity': incident.get('incidentRiskSeverity'),
                'User Name': incident.get('actorId'),
                'Policy Name': incident.get('policyName'),
            })

        readable_output = tableToMarkdown(
            'Skyhigh Security Incidents', readable_dict, headerTransform=pascalToSpace, removeNull=True
        )

        return CommandResults(
            outputs=incidents,
            outputs_prefix='SkyhighSecurity.Incident',
            outputs_key_field='incidentId',
            readable_output=readable_output,
            raw_response=incidents,
        )
    else:
        return CommandResults(
            readable_output='No Incidents were found with the requested filters.',
        )


def status_update_command(client: Client, args: Dict) -> CommandResults:
    incident_ids = argToList(args.get('incident_ids'))
    status = str(args.get('status'))

    result = client.status_update(incident_ids, status)
    readable_output = 'Status updated for user'

    return CommandResults(
        readable_output=readable_output,
        raw_response=result,
    )


def anomaly_activity_list_command(client: Client, args: Dict) -> CommandResults:
    anomaly_id = arg_to_number(args.get('anomaly_id'))

    result = client.anomaly_activity_list(anomaly_id)

    return CommandResults(
        outputs=result,
        outputs_prefix='SkyhighSecurity.Dictionaries',
        outputs_key_field='ID',
        readable_output=tableToMarkdown('', result),
        raw_response=result
    )


def policy_dictionary_list_command(client: Client, args: Dict) -> CommandResults:
    offset, limit = calculate_offset_and_limit(**args)
    names = argToList(args.get('name'))

    result = client.policy_dictionary_list()
    policies = result[offset:limit]

    filtered_policies = []
    for policy in policies:
        if names and policy.get('name') in names or not names:
            filtered_policies.append(
                {
                    'ID': policy.get('id'),
                    'Name': policy.get('name'),
                    'LastModified': policy.get('last_modified_time'),
                }
            )

    readable_output = tableToMarkdown(
        'List of Skyhigh Security Policies', filtered_policies, headerTransform=pascalToSpace, removeNull=True
    )

    return CommandResults(
        outputs=filtered_policies,
        outputs_prefix='SkyhighSecurity.Dictionaries',
        outputs_key_field='ID',
        readable_output=readable_output,
        raw_response=filtered_policies,
    )


def policy_dictionary_update_command(client: Client, args: Dict) -> CommandResults:
    dict_id = arg_to_number(args.get('dictionary_id'))
    name = str(args.get('name'))
    content = str(args.get('content'))

    result = client.policy_dictionary_update(dict_id, name, content)

    return CommandResults(
        readable_output=f'Dictionary id: {dict_id} was updated.',
        raw_response=result
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    params = demisto.params()
    base_url = urljoin(params['url'].removesuffix('/'), '/shnapi/rest')
    verify_certificate = not params.get('insecure', False)
    credentials = params.get('credentials', {})
    handle_proxy()
    command = demisto.command()

    demisto.debug(f'Command being called is {command}')

    try:
        commands: Dict = {
            'skyhigh-security-incident-query': incident_query_command,
            'skyhigh-security-incident-status-update': status_update_command,
            'skyhigh-security-anomaly-activity-list': anomaly_activity_list_command,
            'skyhigh-security-policy-dictionary-list': policy_dictionary_list_command,
            'skyhigh-security-policy-dictionary-update': policy_dictionary_update_command,
        }

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            auth=(credentials.get('identifier'), credentials.get('password')),
            proxy=params.get('proxy')
        )

        if command == 'test-module':
            result = test_module(client)
            return_results(result)

        if command == 'fetch-incidents':
            last_run, incidents = fetch_incidents(client, params)
            demisto.setLastRun(last_run)
            demisto.incidents(incidents)

        elif command in commands:
            return_results(commands[command](client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
