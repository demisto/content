import datetime
import json

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
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
        self.incident_query(1)

    def incident_query(self, limit: int, start_time: str = '', end_time: str = '', actor_ids: list[str] = None,
                       service_names: list[str] = None, categories: list[str] = None) -> Dict[str, Any]:
        url_suffix = '/external/api/v1/queryIncidents'
        params = {'limit': limit}
        data = assign_params(
            startTime=start_time,
            endTime=end_time,
            actorIds=actor_ids,
            serviceNames=service_names,
            incidentCriteria=assign_params(
                categories=categories
            ),
        )
        return self._http_request('POST', url_suffix, params=params, json_data=data).json()

    def status_update(self, incident_ids: List[str], status: str) -> Dict[str, str]:
        url_suffix = '/external/api/v1/modifyIncidents'
        data = [
            {'incidentId': incident_id, "changeRequests": {"WORKFLOW_STATUS": status}} for incident_id in incident_ids
        ]
        return self._http_request('POST', url_suffix, json_data=data).json()

    def anomaly_activity_list(self, incident_id: str) -> Dict[str, str]:
        url_suffix = '/external/api/v1/queryActivities'
        data = {"incident_id": incident_id}
        return self._http_request('POST', url_suffix, json_data=data).json()

    def policy_dictionary_list(self) -> List[Dict[str, str]]:
        url_suffix = '/dlp/dictionary'
        return self._http_request('GET', url_suffix).json()

    def policy_dictionary_update(self, dict_id: int, name: str, content: List[str]) -> Dict[str, str]:
        url_suffix = '/dlp/dictionary'
        data = {
            "id": dict_id,
            "name": name,
            "content": content
        }
        return self._http_request('PUT', url_suffix, json_data=data).json()


''' HELPER FUNCTIONS '''


def calculate_offset_and_limit(**kwargs) -> [int, int]:
    if limit := arg_to_number(kwargs.get('limit')):  # 'limit' is stronger than pagination ('page', and 'page_size').
        return 0, limit
    if arg_to_number(kwargs.get('page')) and arg_to_number(kwargs.get('page_size')):
        page = kwargs.get('page') - 1  # First page means list in index zero.
        page_size = kwargs.get('page_size')
        return page * page_size, page * page_size + page_size
    return 0, 50


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
            raise e
    return message


def incident_query_command(client: Client, args: Dict) -> CommandResults:
    offset, limit = calculate_offset_and_limit(**args)
    start_time = args.get('start_time') or (datetime.now() - datetime.timedelta(days=3)).strftime(DATE_FORMAT)
    end_time = args.get('end_time')
    actor_ids = argToList(args.get('actor_ids'))
    service_names = argToList(args.get('service_names'))
    if categories := argToList(args.get('categories')):
        categories = [
            {"incidentType": CategoryToIncidentType.get(category), "category": category} for category in categories
        ]
    elif incident_types := argToList(args.get('incident_types')):
        categories = [{"incidentType": incident_type} for incident_type in incident_types]

    result = client.incident_query(limit, start_time, end_time, actor_ids, service_names, categories)

    if incidents := result.get('incidents'):
        readable_dict = {
            'IncidentID': incidents.get('incidentId'),
            'Time(UTC)': incidents.get('timeCreated'),
            'Status': incidents.get('status'),
            'Alert Action': incidents.get('remediationResponse'),
            'Service Name': incidents.get('serviceNames'),
            'Alert Severity': incidents.get('Incident risk severity'),
            'Policy Name': incidents.get('policyName'),
            'User Name': incidents.get('actorID'),
        }
        readable_output = tableToMarkdown(
            'MVISION CASB Incidents', readable_dict, headerTransform=pascalToSpace, removeNull=True
        )

        return CommandResults(
            outputs=incidents,
            outputs_prefix='MVisionCASB.Incident',
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
    status = args.get('status')

    result = client.status_update(incident_ids, status)
    readable_output = 'Status updated for user'

    return CommandResults(
        readable_output=readable_output,
        raw_response=result,
    )


def anomaly_activity_list_command(client: Client, args: Dict) -> CommandResults:
    return CommandResults()


def policy_dictionary_list_command(client: Client, args: Dict) -> CommandResults:
    offset, limit = calculate_offset_and_limit(**args)

    result = client.policy_dictionary_list()
    list_of_policies = result[offset:limit]

    if name := argToList(args.get('name')):
        list_of_policies[:] = [policy for policy in list_of_policies if policy.get('name') in name]
    readable_output = tableToMarkdown('', list_of_policies, headerTransform=pascalToSpace, removeNull=True)

    return CommandResults(
        outputs=None,
        outputs_prefix='',
        outputs_key_field='',
        readable_output=readable_output,
        raw_response=result,
    )


def policy_dictionary_update_command(client: Client, args: Dict) -> CommandResults:

    return CommandResults()


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    base_url = urljoin(demisto.params()['url'].removesuffix('/'), '/shnapi/rest')
    api_key = demisto.params().get('credentials', {}).get('password')
    verify_certificate = not demisto.params().get('insecure', False)
    handle_proxy()

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        commands: Dict = {
            'mvision-casb-incident-query': incident_query_command,
            'mvision-casb-incident-status-update': status_update_command,
            'mvision-casb-anomaly-activity-list': anomaly_activity_list_command,
            'mvision-casb-policy-dictionary-list': policy_dictionary_list_command,
            'mvision-casb-policy-dictionary-update': policy_dictionary_update_command,
        }

        headers: Dict = {"Authorization": api_key}

        client = Client(
            base_url=base_url,
            headers=headers,
            verify=verify_certificate
        )

        if demisto.command() == 'test-module':
            result = test_module(client)
            return_results(result)

        # TODO: REMOVE the following dummy command case:
        elif demisto.command() == 'baseintegration-dummy':
            return_results(baseintegration_dummy_command(client, demisto.args()))
        # TODO: ADD command cases for the commands you will implement

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
