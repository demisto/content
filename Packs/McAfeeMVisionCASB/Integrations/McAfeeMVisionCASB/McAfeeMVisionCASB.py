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

''' CLIENT CLASS '''


class Client(BaseClient):
    def test(self):
        return

    def incident_query(self, limit: Optional[int], start_time: str, end_time: str, actor_ids: list[str],
                       service_names: list[str], incident_types: list[str], categories: list[str]) -> Dict[str, str]:
        url_suffix = '/external/api/v1/queryIncidents'
        params = {'limit': limit or 500}
        data = assign_params(
            start_time=start_time,
            end_time=end_time,
            actor_ids=actor_ids,
            service_names=service_names,
            incidentCriteria=assign_params(
                incident_types=incident_types,
                categories=categories,
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

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

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
    if limit := arg_to_number(args.get('limit')):
        pass
    else:
        page = arg_to_number(args.get('page', 1)) - 1
        page_size = arg_to_number(args.get('page_size', 50))
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    actor_ids = args.get('actor_ids')
    service_names = args.get('service_names')
    incident_types = args.get('incident_types')
    categories = args.get('categories')

    result = client.incident_query(limit, start_time, end_time, actor_ids, service_names, incident_types, categories)
    readable_dict = {
        'IncidentID': result.get('incidentId'),
        'Time(UTC)': result.get('timeCreated'),
        'Status': result.get('status'),
        'Alert Action': result.get('remediationResponse'),
        'Service Name': result.get('serviceNames'),
        'Alert Severity': result.get('Incident risk severity'),
        'Policy Name': result.get('policyName'),
        'User Name': result.get('actorID'),
    }
    readable_output = tableToMarkdown(
        'MVISION CASB Incidents', readable_dict, headerTransform=pascalToSpace, removeNull=True
    )

    return CommandResults(
        outputs=result,
        outputs_prefix='MVisionCASB.Incident',
        outputs_key_field='incidentId',
        readable_output=readable_output,
        raw_response=result,
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
    if limit := arg_to_number(args.get('limit')):
        offset = 0
    else:
        page = arg_to_number(args.get('page', 1)) - 1
        page_size = arg_to_number(args.get('page_size', 50))
        offset = page * page_size

    result = client.policy_dictionary_list()
    if name := args.get('name'):
        readable_list = [item for item in result if item.get('name') in name][offset:limit]
    else:
        readable_list = result[offset:limit]
    readable_output = tableToMarkdown('', readable_list, headerTransform=pascalToSpace, removeNull=True)

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
