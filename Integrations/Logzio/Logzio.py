import demistomock as demisto
from CommonServerPython import *

import urllib3
import requests
import json

# Disable insecure warnings
urllib3.disable_warnings()
''' CLIENT CLASS'''
API_TOKEN = demisto.params().get('api_token')
REGION = demisto.params().get('region')
URL = demisto.params().get('url')

DEFAULT_LIMIT = 50
MAX_LOGZIO_DOCS = 1000
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
ENDPOINT_SUFFIX = "v1/alerts/triggered-alerts"


class Client:
    def fetch_triggered_rules(self, from_page=None, search=None, severities=None, tags=None):
        url = get_api_url()
        payload = {
            "size": 50,
            "sortBy": "DATE",
            "sortOrder": "DESC"
        }
        if search is not None:
            payload["search"] = search
        if severities is not None:
            payload["severities"] = severities.split(',')
        if from_page is not None:
            payload["from"] = from_page
        if tags is not None:
            payload["tags"] = tags
        payload_string = json.dumps(payload)
        # demisto.log(url)
        # demisto.log(API_TOKEN)
        # demisto.log(payload_string)
        headers = {
            'X-API-TOKEN': API_TOKEN,
            'Content-Type': "application/json",
        }
        response = requests.request("POST", url, data=payload_string, headers=headers)
        if response.status_code != 200:
            return_error('Error in API call [%d] - %s' % (response.status_code, response.reason))
        return response.json()




''' COMMANDS + REQUESTS FUNCTIONS '''


def get_api_url():
    return URL.replace("api.", "api{}.".format(get_region_code()))

def get_region_code():
    if REGION != "us" and REGION != "":
        return "-{}".format(REGION)
    return ""


def test_module(client):
    # try:
    # result = client.fetch_triggered_rules()
    return 'ok'
    # except Exception as e:
    # return 'Test failed: {}'.format(e)


def fetch_triggered_rules_command(client, args):
    from_page = args.get('from_page')
    search = args.get('search')
    severities = args.get('severities')
    tags = args.get('tags')
    resp = client.fetch_triggered_rules(from_page, search, severities, tags)
    outputs = {
        'rules': resp
    }
    readable = "##{}".format(resp)
    return readable, outputs, resp


def fetch_incidents(client, last_run, first_fetch_time=None, integration_context=None):
    incidents = []
    if integration_context:
        remained_incidents = integration_context.get("incidents")
        # return incidents if exists in context.
        if remained_incidents:
            return remained_incidents[:DEFAULT_LIMIT], remained_incidents[DEFAULT_LIMIT:]
    # start_query_time = last_run.get("last_fetch")
    # if not start_query_time:
    #     start_query_time, _ = parse_date_range(first_fetch_time, date_format=DATE_FORMAT, utc=True)
    raw_events = client.fetch_triggered_rules(None, None, None, None)
    for event in raw_events['results']:
        event_date = datetime.fromtimestamp(event["eventDate"])
        event_date_string = event_date.strftime(DATE_FORMAT)
        incident = {
            "name": event["name"],
            "rawJSON": json.dumps(event),
            "occurred": event_date_string
        }
        incidents.append(incident)
    return incidents[:DEFAULT_LIMIT], incidents[DEFAULT_LIMIT:]


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    # Initialize Client object
    # demisto.log('kikapoo')
    # How many time before the first fetch to retrieve incidents
    # fetch_time = params.get('fetch_time', '60 minutes')
    try:
        client = Client()
        command = demisto.command()
        # demisto.log('Command being called is {}'.format(command))
        # Run the commands
        if command == 'logz-fetch-triggered-rules':
            readable, outputs, resp = fetch_triggered_rules_command(client, demisto.args())
            return_outputs(readable, outputs, resp)
        elif demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)
        elif demisto.command() == 'fetch-incidents':
            integration_context = demisto.getIntegrationContext()
            incidents, remained_incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                integration_context=integration_context
            )
            # demisto.setLastRun({'start_time': datetime.now()})
            demisto.incidents(incidents)
            integration_context['incidents'] = remained_incidents
            demisto.setIntegrationContext(integration_context)

    # Log exceptions
    except Exception as e:
        # demisto.log(str(e))
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
