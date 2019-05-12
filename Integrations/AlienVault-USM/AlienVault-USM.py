import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
from distutils.util import strtobool

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

CLIENT_ID = demisto.params().get('client_id')
CLIENT_SECRET = demisto.params().get('client_secret')
# Remove trailing slash to prevent wrong URL path to service
SERVER = demisto.params()['url'][:-1] \
    if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
API_VERSION = demisto.params().get('api_version')

TIME_ZONE = demisto.params().get('time_zone', '+0000')
# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)
# How many time before the first fetch to retrieve incidents
FETCH_TIME = demisto.params().get('fetch_time', '3 days')
# Service base URL
BASE_URL = SERVER + '/api/{}'.format(API_VERSION)
# Headers to be sent in requests
HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}
AUTH_TOKEN = ''


''' HELPER FUNCTIONS '''


@logger
def http_request(method, url_suffix, params=None, headers=None, data=None, **kwargs):
    data = data if data else {}
    if not headers:
        headers = HEADERS
        headers['Authorization'] = 'Bearer ' + AUTH_TOKEN
    # A wrapper for requests lib to send our requests and handle requests and responses better
    res = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        params=params,
        data=data,
        headers=headers,
        **kwargs
    )
    # Handle error responses gracefully
    if res.status_code not in {200}:
        return_error('Error in API call to Example Integration [%d] - %s' % (res.status_code, res.reason))

    return res.json()

@logger
def get_token():
    basic_auth_credentials = (CLIENT_ID, CLIENT_SECRET)

    res = http_request('POST', '/oauth/token',
                       params={'grant_type': 'client_credentials'},
                       headers={'Content-Type': 'application/www-form-urlencoded'},
                       auth=basic_auth_credentials)

    return res['access_token']


def parse_alarm(alarm_data):
    return {
        'ID': alarm_data['uuid'],
        'Priority': alarm_data['priority_label'],
        'DestinationAsset': alarm_data['destinations'][0]['address'],
        'RuleAttackId': alarm_data['rule_attack_id'],
        'RuleAttackTactic': alarm_data['rule_attack_tactic'][0],
        'RuleAttackTechnique': alarm_data['rule_attack_technique'],
        'Sensor': alarm_data['events'][0]['received_from'],
        'Source': {
            'IpAddress': alarm_data['destinations'][0]['address'],
            'Organization': alarm_data['sources'][0]['organisation'],
            'Country': alarm_data['sources'][0]['country'],
        },
        'Destination': {
            'IpAddress': alarm_data['destinations'][0]['address'],
            'FQDN': alarm_data['destinations'][0]['fqdn']
        }
    }


def parse_alarms(alarms_data):
    alarms = []
    for alarm in alarms_data:
        alarms.append({
            'ID': alarm['uuid'],
            'Priority': alarm['priority_label'],
            'DestinationAsset': alarm['events'][0]['message']['destination_address'],
            'RuleAttackId': alarm['rule_attack_id'],
            'RuleAttackTactic': alarm['rule_attack_tactic'][0],
            'RuleAttackTechnique': alarm['rule_attack_technique'],
            'Sensor': alarm['events'][0]['message']['received_from'],
            'Source': {
                'IpAddress': alarm['events'][0]['message']['source_address'],
                'Organization': alarm['events'][0]['message']['source_organisation'],
                'Country': alarm['events'][0]['message']['source_country'],
            },
            'Destination': {
                'IpAddress': alarm['events'][0]['message']['destination_address'],
                'FQDN': alarm['events'][0]['message']['destination_fqdn'],
            }
        })

    return alarms


def item_to_incident(item):
    incident = {
        'Type': 'AlienVault USM',
        'name': 'Example Incident: ' + item.get('name'),
        'occurred': item.get('createdDate'),
        'rawJSON': json.dumps(item),
    }

    return incident


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    http_request('GET', '')
    demisto.results('ok')


def get_alarm_command():
    """
    Gets alarm details by ID
    """
    args = demisto.args()
    alarm_id = args['id']

    # Make request and get raw response
    response = get_alarm(alarm_id)

    # Parse response into context & content entries
    alarm_details = parse_alarm(response)

    return_outputs(tableToMarkdown('Alarm {}'.format(alarm_id), alarm_details), alarm_details, response)



def get_alarm(alarm_id):
    res = http_request('GET', '/alarms/' + alarm_id)

    return res


def search_alerts_command():
    args = demisto.args()
    start_time = args.get('start_time', 'now-7d')
    end_time = args.get('end_time', 'now')
    show_suppressed = args.get('show_suppressed', 'false')
    limit = int(args.get('limit', 100))

    result = search_alerts(start_time, end_time, show_suppressed, limit)
    alarms = parse_alarms(result)

    return_outputs(tableToMarkdown('Alarms:', alarms),
                   {'AlienVault.Alarm(val.ID && val.ID == obj.ID': alarms}, result)


@logger
def search_alerts(start_time, end_time, show_suppressed, limit):
    data = {
        "page": 1,
        "size": limit,
        "find": {
            "alarm.suppressed": [
                show_suppressed
            ]
        },
        "sort": {
            "alarm.timestamp_occured": "desc"
        },
        "range": {
            "alarm.timestamp_occured": {
                "gte": start_time,
                "lte": end_time,
                "timeZone": TIME_ZONE
            }
        }
    }
    res = http_request('GET', '/alarms/', data=data)

    return res['_embedded']['alarms']


def fetch_incidents():
    last_run = demisto.getLastRun()
    # Get the last fetch time, if exists
    last_fetch = last_run.get('time')

    # Handle first time fetch, fetch incidents retroactively
    if last_fetch is None:
        last_fetch, _ = parse_date_range(FETCH_TIME, to_timestamp=True)

    incidents = []
    items = search_alerts()
    for item in items:
        incident = item_to_incident(item)
        incident_date = date_to_timestamp(incident['occurred'], '%Y-%m-%dT%H:%M:%S.%fZ')
        # Update last run and add incident if the incident is newer than last fetch
        if incident_date > last_fetch:
            last_fetch = incident_date
            incidents.append(incident)

    demisto.setLastRun({'time': last_fetch})
    demisto.incidents(incidents)


''' COMMANDS MANAGER / SWITCH PANEL '''
COMMANDS = {
    'test-module': test_module,
    'fetch-incidents': fetch_incidents,
    'alienvault-search-alerts': search_alerts_command,
    'alienvault-get-alarm': get_alarm_command,
}


def main():
    global AUTH_TOKEN
    cmd = demisto.command()
    LOG('Command being called is %s' % (cmd))

    try:
        AUTH_TOKEN = get_token()
        handle_proxy()

        if cmd in COMMANDS:
            COMMANDS[cmd]()

    # Log exceptions
    except Exception as e:
        if demisto.command() == 'fetch-incidents':
            LOG(e.message)
            LOG.print_log()
            raise
        else:
            return_error('An error occurred: {}'.format(str(e)))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
