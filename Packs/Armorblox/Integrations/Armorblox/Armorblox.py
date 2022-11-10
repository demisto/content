import collections
import json
from datetime import timedelta

import requests
from CommonServerPython import *  # noqa: F401
from armorblox.client import Client as AbxBaseClient

import demistomock as demisto  # noqa: F401

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

ARMORBLOX_INCIDENT_API_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
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

    def get_incidents(self, orderBy='ASC', pageSize=None, pageToken=None, first_fetch=None,
                      from_date=None,
                      to_date=None):
        request_params = {'orderBy': orderBy}

        if pageToken == -1 and first_fetch:
            request_params['timeFilter'] = first_fetch
        elif pageToken and first_fetch:
            request_params['timeFilter'] = first_fetch
            request_params['pageToken'] = pageToken

        if pageSize:
            request_params['pageSize'] = pageSize

        if from_date:
            request_params['from_date'] = from_date

        if to_date:
            request_params['to_date'] = to_date

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


def get_incidents_list(client, pageToken, first_fetch, from_date=None, to_date=None):
    """
    Hits the Armorblox API and returns the list of fetched incidents.
    """
    results, next_page_token = client.get_incidents(pageSize=MAX_INCIDENTS_TO_FETCH,
                                                    pageToken=pageToken,
                                                    first_fetch=first_fetch,
                                                    from_date=from_date,
                                                    to_date=to_date)
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


def fetch_incidents_command(client):  # pragma: no coverage
    last_run = demisto.getLastRun()
    demisto.debug(str(last_run))
    current_time = datetime.utcnow().replace(second=0)
    last_fetch_time = last_run.get("last_fetch_time", None)
    incidents = []
    incidents_data = []
    mapping = {
        "lastDay": 1,
        "last3Days": 3
    }
    if last_fetch_time is None:
        last_fetch_time = (current_time - timedelta(days=mapping[FIRST_FETCH])).strftime(
            ARMORBLOX_INCIDENT_API_TIME_FORMAT)

    current_time = current_time.strftime(ARMORBLOX_INCIDENT_API_TIME_FORMAT)
    next_page_token = None
    while True:
        response, next_page_token = get_incidents_list(client, pageToken=next_page_token,
                                                       from_date=last_fetch_time,
                                                       to_date=current_time,
                                                       first_fetch=FIRST_FETCH)
        incidents_data.extend(response)
        if not next_page_token:
            break
    last_fetch_time = current_time

    for incident in incidents_data:
        curr_incident = {'rawJSON': json.dumps(incident), 'details': json.dumps(incident)}
        incidents.append(curr_incident)
    # Save the next_run as a dict with the start_time key to be stored
    demisto.setLastRun({'last_fetch_time': last_fetch_time})
    demisto.debug(str(len(incidents)))
    return incidents


def get_threat_incidents(client, params):
    threats_incidents, next_page_token, total_count = client.threats.list(params=params)
    return threats_incidents


def get_dlp_incidents(client, params):
    dlp_incidents, next_page_token, total_count = client.dlp_incidents.list(params=params)
    return dlp_incidents


def get_abuse_incidents(client, params):
    abuse_incidents, next_page_token, total_count = client.abuse_incidents.list(params=params)
    return abuse_incidents


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
        if demisto.command() == "armorblox-check-remediation-action":
            incident_id = demisto.args().get('incident_id')
            return_results(get_remediation_action(client, incident_id))
        if demisto.command() == "armorblox-get-incident":
            incident_id = demisto.args().get('incident_id')
            return_results(client.get_incident_details(incident_id))
        if demisto.command() == "armorblox-get-threats-incidents":
            return_results(get_threat_incidents(client, demisto.args()))
            # return_results(demisto.args())
        if demisto.command() == "armorblox-get-dlp-incidents":
            return_results(get_dlp_incidents(client, demisto.args()))
        if demisto.command() == "armorblox-get-abuse-incidents":
            return_results(get_abuse_incidents(client, demisto.args()))
        elif demisto.command() == 'test-module':
            result = test_module(client)
            return_results(result)
    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
