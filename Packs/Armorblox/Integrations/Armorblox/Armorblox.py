import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any

from armorblox.client import Client as AbxBaseClient
import dateparser
import urllib3
import json
import collections

# disable insecure warnings
urllib3.disable_warnings()

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MAX_INCIDENTS_TO_FETCH = demisto.params().get('max_fetch')
FIRST_FETCH = demisto.params().get('first_fetch')
TENANT_NAME = demisto.params().get('tenantName')
INSECURE = demisto.params().get('insecure')
PROXY = demisto.params().get('proxy')
API_KEY = demisto.params().get('apikey')
verify_certificate = not demisto.params().get('insecure', False)
proxy = demisto.params().get('proxy', False)


class Client(AbxBaseClient):
    """Client class to interact with the service API
    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    """

    def get_incidents(self, orderBy='ASC', pageSize=None, pageToken=None, first_fetch=None):
        request_params = {'orderBy': orderBy}

        if pageToken == -1 and first_fetch:
            request_params['timeFilter'] = first_fetch
        elif pageToken and first_fetch:
            request_params['timeFilter'] = first_fetch
            request_params['pageToken'] = pageToken

        if pageSize:
            request_params['pageSize'] = pageSize

        response_json, next_page_token, total_count = self.incidents.list(params=request_params)
        return response_json, next_page_token

    def get_incident_details(self, incident_id):
        return self.incidents.get(incident_id)


def makehash():
    return collections.defaultdict(makehash)


def test_module(client: Client) -> str:  # pragma: no coverage
    """Tests API connectivity and authentication'
    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.
    :type client: ``Client``
    :param Client: Armorblox client to use
    :type name: ``str``
    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        client.get_incidents(pageSize=1)

    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def get_incidents_list(client, pageToken, first_fetch):
    """
    Hits the Armorblox API and returns the list of fetched incidents.
    """
    results, next_page_token = client.get_incidents(pageSize=MAX_INCIDENTS_TO_FETCH, pageToken=pageToken,
                                                    first_fetch=first_fetch)
    # For each incident, get the details and extract the message_id
    for result in results:
        result['message_ids'] = get_incident_message_ids(client, result["id"])
    return results, next_page_token


def get_incident_message_ids(client, incident_id):
    """
    Returns the message ids for all the events for the input incident.
    """

    detail_response = client.get_incident_details(incident_id)
    message_ids = []
    # loop through all the events of this incident and collect the message ids
    if 'events' in detail_response.keys():
        for event in detail_response['events']:
            message_ids.append(event['message_id'])

    if 'abuse_events' in detail_response.keys():
        for event in detail_response['abuse_events']:
            message_ids.append(event['message_id'])
    return message_ids


def get_remediation_action(client, incident_id):
    """
    Returns the remediation action(s) for the input incident.
    """

    detail_response = client.get_incident_details(incident_id)
    remediation_actions = None
    if 'remediation_actions' in detail_response.keys():
        remediation_actions = detail_response['remediation_actions'][0]
    else:
        remediation_actions = None
    contxt = makehash()
    human_readable = makehash()
    human_readable['incident_id'] = incident_id
    human_readable['remediation_actions'] = remediation_actions
    contxt['incident_id'] = incident_id
    contxt['remediation_actions'] = remediation_actions
    return CommandResults(outputs_prefix='Armorblox.Threat', outputs=contxt)


def fetch_incidents_command(client):
    last_run = demisto.getLastRun()
    start_time: Any
    # pageToken fetched from demisto lastRun
    pageToken = int()
    incidents = []
    if 'start_time' not in last_run.keys():
        pageToken = -1
        response, next_page_token = client.get_incidents(pageSize=1, pageToken=pageToken, first_fetch=FIRST_FETCH)
        if response:
            response = response[0]
            start_time = response.get('date')
            start_time = dateparser.parse(start_time)
            message_ids = get_incident_message_ids(client, response.get('id'))
            response['message_ids'] = message_ids
            curr_incident = {'rawJSON': json.dumps(response), 'details': json.dumps(response)}
            incidents.append(curr_incident)

    if last_run and 'pageToken' in last_run.keys():
        pageToken = last_run.get('pageToken')

    if last_run and 'start_time' in last_run.keys():
        start_time = dateparser.parse(last_run.get('start_time'))

    start_time = start_time.timestamp()
    incidents_data, pageToken = get_incidents_list(client, pageToken=pageToken, first_fetch=FIRST_FETCH)
    last_time = start_time

    for incident in incidents_data:
        dt = incident.get('date')
        parsed_date = dateparser.parse(dt)
        assert parsed_date is not None, f'failed parsing {dt}'
        dt = int(parsed_date.timestamp())
        # Update last run and add incident if the incident is newer than last fetch
        if dt > int(start_time):
            curr_incident = {'rawJSON': json.dumps(incident), 'details': json.dumps(incident)}
            last_time = dt
            incidents.append(curr_incident)
    # Save the next_run as a dict with the start_time key to be stored
    demisto.setLastRun({'start_time': str(last_time), 'pageToken': pageToken})
    return incidents


def main():  # pragma: no coverage
    ''' EXECUTION '''
    demisto.info(f'Command being called is {demisto.command()}')
    try:

        client = Client(
            api_key=API_KEY,
            instance_name=TENANT_NAME
        )
        if demisto.command() == "fetch-incidents":
            incident_results = fetch_incidents_command(client)
            demisto.incidents(incident_results)
            return_results("Incidents fetched successfully!!")
            # return_results(fetch_incidents_command(client))
        if demisto.command() == "armorblox-check-remediation-action":
            incident_id = demisto.args().get('incident_id')
            return_results(get_remediation_action(client, incident_id))

        elif demisto.command() == 'test-module':
            result = test_module(client)
            return_results(result)
    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
