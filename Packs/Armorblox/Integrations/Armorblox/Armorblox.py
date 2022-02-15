import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import dateparser
import requests
import json
import collections

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MAX_INCIDENTS_TO_FETCH = demisto.params().get('max_fetch')
FIRST_FETCH = demisto.params().get('first_fetch')
TENANT_NAME = demisto.params().get('tenantName')
INSECURE = demisto.params().get('insecure')
PROXY = demisto.params().get('proxy')
API_KEY = demisto.params().get('apikey')
verify_certificate = not demisto.params().get('insecure', False)
proxy = demisto.params().get('proxy', False)
BASE_URL = f"https://{TENANT_NAME}.armorblox.io/api/v1beta1/organizations/{TENANT_NAME}"

payload: Dict = {}
headers = {
    'x-ab-authorization': f'{API_KEY}'
}


class Client(BaseClient):
    """Client class to interact with the service API
    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def get_incidents(self, orderBy="ASC", pageSize=None, pageToken=None, first_fetch=None) -> List[Dict[str, Any]]:
        request_params: Dict[str, Any] = {}

        request_params['orderBy'] = orderBy
        if pageToken == -1 and first_fetch:
            request_params['timeFilter'] = first_fetch
        elif pageToken and first_fetch:
            request_params['timeFilter'] = first_fetch
            request_params['pageToken'] = pageToken
        if pageSize:
            request_params['pageSize'] = pageSize
        return self._http_request(
            method='GET',
            url_suffix='/incidents',
            params=request_params
        )

    def get_incident_details(self, incident_id):
        request_params: Dict[str, Any] = {}
        return self._http_request(
            method='GET',
            url_suffix='/incidents/{}'.format(incident_id),
            params=request_params
        )


def makehash():
    return collections.defaultdict(makehash)


def test_module(client: Client) -> str:
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


def get_page_token(client, pageToken=None):
    response = client.get_incidents(pageSize=MAX_INCIDENTS_TO_FETCH, pageToken=pageToken, first_fetch=FIRST_FETCH)
    if 'next_page_token' in response.keys():
        return response['next_page_token']
    else:
        return None


def get_incidents_list(client, pageToken, first_fetch):
    """
    Hits the Armorblox API and returns the list of fetched incidents.
    """
    response = client.get_incidents(pageSize=MAX_INCIDENTS_TO_FETCH, pageToken=pageToken, first_fetch=first_fetch)
    results = []
    if 'incidents' in response.keys():
        results = response['incidents']

    # For each incident, get the details and extract the message_id
    for result in results:
        result['message_ids'] = get_incident_message_ids(client, result["id"])
    return results


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
    response = {}
    incidents = []
    if 'start_time' not in last_run.keys():
        pageToken = -1
        response = client.get_incidents(pageSize=1, pageToken=pageToken, first_fetch=FIRST_FETCH)
        if 'incidents' in response.keys():
            start_time = response['incidents'][0]['date']
            start_time = dateparser.parse(start_time)
            message_ids = get_incident_message_ids(client, response['incidents'][0]['id'])
            response['incidents'][0]['message_ids'] = message_ids
            curr_incident = {'rawJSON': json.dumps(response['incidents'][0]), 'details': json.dumps(response['incidents'][0])}
            incidents.append(curr_incident)

    if last_run and 'pageToken' in last_run.keys():
        pageToken = last_run.get('pageToken')

    if last_run and 'start_time' in last_run.keys():
        start_time = dateparser.parse(last_run.get('start_time'))

    start_time = start_time.timestamp()
    incidents_data = get_incidents_list(client, pageToken=pageToken, first_fetch=FIRST_FETCH)
    pageToken = get_page_token(client, pageToken=pageToken)
    last_time = start_time

    for incident in incidents_data:
        dt = incident['date']
        dt = dateparser.parse(dt).timestamp()
        # Update last run and add incident if the incident is newer than last fetch
        if dt > start_time:

            curr_incident = {'rawJSON': json.dumps(incident), 'details': json.dumps(incident)}
            last_time = dt
            incidents.append(curr_incident)
    # Save the next_run as a dict with the start_time key to be stored
    demisto.setLastRun({'start_time': str(last_time), 'pageToken': pageToken})
    return incidents


def main():
    ''' EXECUTION '''
    LOG('command is %s' % (demisto.command(), ))
    try:

        client = Client(
            base_url=BASE_URL,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

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
