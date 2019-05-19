import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
import dateparser

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

CLIENT_ID = demisto.params().get('client_id')
CLIENT_SECRET = demisto.params().get('client_secret')
# Remove trailing slash to prevent wrong URL path to service
SERVER = demisto.params()['url'][:-1] \
    if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']

# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)
# How many time before the first fetch to retrieve incidents
FETCH_TIME = demisto.params().get('fetch_time', '3 days')
# Service base URL
BASE_URL = SERVER + '/api/2.0'
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


def get_time_range(time_frame=None, start_time=None, end_time=None):
    if time_frame is None:
        return None, None

    if time_frame == 'Custom':
        if start_time is None and end_time is None:
            raise ValueError('invalid custom time frame: need to specify one of start_time, end_time')
        if start_time is not None:
            start_time = dateparser.parse(start_time)
        if end_time is not None:
            end_time = dateparser.parse(end_time)

        return date_to_timestamp(start_time), date_to_timestamp(end_time)

    end_time = datetime.now()
    if time_frame == 'Today':
        start_time = dateparser.parse(time_frame)

    elif time_frame == 'Yesterday':
        start_time = dateparser.parse(time_frame)

    elif time_frame == 'Last Hour':
        start_time = end_time - timedelta(hours=1)
    elif time_frame == 'Last 24 Hours':
        start_time = end_time - timedelta(hours=24)
    elif time_frame == 'Last 48 Hours':
        start_time = end_time - timedelta(hours=48)
    elif time_frame == 'Last 7 Days':
        start_time = end_time - timedelta(days=7)
    elif time_frame == 'Last 30 Days':
        start_time = end_time - timedelta(days=30)
    else:
        raise ValueError('Could not parse time frame: {}'.format(time_frame))

    return date_to_timestamp(start_time), date_to_timestamp(end_time)


@logger
def parse_alarm(alarm_data):
    return {
        'ID': alarm_data['uuid'],
        'Priority': alarm_data['priority_label'],
        'OccurredTime': alarm_data['timestamp_occured_iso8601'],
        'ReceivedTime': alarm_data['timestamp_received_iso8601'],

        'RuleAttackID': alarm_data['rule_attack_id'],
        'RuleAttackTactic': alarm_data['rule_attack_tactic'],
        'RuleAttackTechnique': alarm_data['rule_attack_technique'],
        'RuleDictionary': alarm_data.get('rule_dictionary'),
        'RuleID': alarm_data.get('rule_id'),
        'RuleIntent': alarm_data.get('rule_intent'),
        'RuleMethod': alarm_data.get('rule_method'),
        'RuleStrategy': alarm_data.get('rule_strategy'),

        'Source': {
            'IPAddress': alarm_data['alarm_source_names'],
            'Organization': alarm_data['alarm_source_organisations'],
            'Country': alarm_data['alarm_source_countries'],
        },
        'Destination': {
            'IPAddress': alarm_data['alarm_destination_names'],
        },
        'Event': [{
            'ID': event['uuid'],
            'OccurredTime': event['timestamp_occured_iso8601'],
            'ReceivedTime': event['timestamp_received_iso8601'],
        } for event in alarm_data.get('events', [])]
    }


@logger
def parse_alarms(alarms_data):
    alarms = []
    for alarm in alarms_data:
        alarms.append({
            'ID': alarm['uuid'],
            'Priority': alarm['priority_label'],
            'OccurredTime': alarm['timestamp_occured_iso8601'],
            'ReceivedTime': alarm['timestamp_received_iso8601'],

            'RuleAttackID': alarm.get('rule_attack_id'),
            'RuleAttackTactic': alarm.get('rule_attack_tactic'),
            'RuleAttackTechnique': alarm.get('rule_attack_technique'),
            'RuleDictionary': alarm.get('rule_dictionary'),
            'RuleID': alarm.get('rule_id'),
            'RuleIntent': alarm.get('rule_intent'),
            'RuleMethod': alarm.get('rule_method'),
            'RuleStrategy': alarm.get('rule_strategy'),

            'Source': {
                'IPAddress': alarm['alarm_source_names'],
                'Organization': alarm['alarm_source_organisations'],
                'Country': alarm['alarm_source_countries'],
            },
            'Destination': {
                'IPAddress': alarm['alarm_destination_names'],
            },
            'Event': [{
                'ID': event['message']['uuid'],
                'OccurredTime': event['message']['timestamp_occured_iso8601'],
                'ReceivedTime': event['message']['timestamp_received_iso8601'],
            } for event in alarm.get('events', [])]
        })

    return alarms


def item_to_incident(item):
    incident = {
        'Type': 'AlienVault USM',
        'name': 'Alarm: ' + item.get('uuid'),
        'occurred': item.get('timestamp_occured_iso8601'),
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

    return_outputs(tableToMarkdown('Alarm {}'.format(alarm_id), alarm_details),
                   {'AlienVault.Alarm(val.ID && val.ID == obj.ID)': alarm_details},
                   response)


def get_alarm(alarm_id):
    res = http_request('GET', '/alarms/' + alarm_id)

    return res


def search_alerts_command():
    args = demisto.args()
    time_frame = args.get('time_frame')
    start_time = args.get('start_time', 'now-7d')
    end_time = args.get('end_time', 'now')
    show_suppressed = args.get('show_suppressed', 'false')
    limit = int(args.get('limit', 100))

    start_time, end_time = get_time_range(time_frame, start_time, end_time)

    result = search_alerts(start_time=start_time, end_time=end_time, show_suppressed=show_suppressed, limit=limit)
    alarms = parse_alarms(result)

    return_outputs(tableToMarkdown('Alarms:', alarms),
                   {'AlienVault.Alarm(val.ID && val.ID == obj.ID)': alarms}, result)


@logger
def search_alerts(start_time=None, end_time=None, status=None, priority=None, show_suppressed=None,
                  limit=100, rule_intent=None, rule_method=None, rule_strategy=None, direction='desc'):
    params = {
        'page': 1,
        'size': limit,
        'sort': 'timestamp_occured,{}'.format(direction),
        'suppressed': show_suppressed
    }

    if status:
        params['status'] = status
    if priority:
        params['priority_label'] = priority
    if rule_intent:
        params['rule_intent'] = rule_intent
    if rule_method:
        params['rule_method'] = rule_method
    if rule_strategy:
        params['rule_strategy'] = rule_strategy

    if start_time:
        params['timestamp_occured_gte'] = start_time
    if end_time:
        params['timestamp_occured_lte'] = end_time

    res = http_request('GET', '/alarms/', params=params)
    if res['page']['totalElements'] == 0:
        return []

    return res['_embedded']['alarms']


def fetch_incidents():
    last_run = demisto.getLastRun()
    # Get the last fetch time, if exists
    last_fetch = last_run.get('time')

    # Handle first time fetch, fetch incidents retroactively
    if last_fetch is None:
        last_fetch, _ = parse_date_range(FETCH_TIME, date_format='%Y-%m-%dT%H:%M:%S.%fZ')

    incidents = []
    items = search_alerts(last_fetch, 'now', 'false', 100, direction='asc')
    for item in items:
        incident = item_to_incident(item)
        incidents.append(incident)

    if incidents:
        #  updating according to latest incident
        last_fetch = incidents[-1]['occurred']

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
