import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
import dateparser
from typing import Dict

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

CLIENT_ID = demisto.params().get('client_id')
CLIENT_SECRET = demisto.params().get('client_secret')
# Remove trailing slash to prevent wrong URL path to service
SERVER = demisto.params().get('url', '').strip('/')

# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)
IS_FETCH = demisto.params().get('isFetch')
# How much time before the first fetch to retrieve incidents
FETCH_TIME = demisto.params().get('fetch_time', '3 days')
# Service base URL
BASE_URL = SERVER + '/api/2.0'
# Headers to be sent in requests
HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}
TIME_FORMAT = demisto.params().get('time_format', 'auto-discovery')
AUTH_TOKEN = ''


''' HELPER FUNCTIONS '''


def parse_time(time_str):
    if TIME_FORMAT != 'auto-discovery':
        return TIME_FORMAT

    regex_to_format = {
        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z': '%Y-%m-%dT%H:%M:%SZ',
        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z': '%Y-%m-%dT%H:%M:%S.%fZ'
    }

    selected_format = '%Y-%m-%dT%H:%M:%SZ'
    for regex, date_format in regex_to_format.items():
        if re.match(regex, time_str):
            selected_format = date_format
            break

    return selected_format


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
    if res.status_code == 401:
        raise Exception('UnauthorizedError: please validate your credentials.')
    if res.status_code not in {200}:
        raise Exception('Error in API call to Example Integration [{}] - {}'.format(res.status_code, res.reason))

    return res.json()


@logger
def get_token():
    basic_auth_credentials = (CLIENT_ID, CLIENT_SECRET)

    res = http_request('POST', '/oauth/token',
                       params={'grant_type': 'client_credentials'},
                       headers={'Content-Type': 'application/www-form-urlencoded'},
                       auth=basic_auth_credentials)

    return res.get('access_token')


@logger
def get_time_range(time_frame=None, start_time=None, end_time=None):
    if time_frame is None:
        return None, None

    if time_frame == 'Custom':
        if start_time is None and end_time is None:
            raise ValueError('invalid custom time frame: need to specify one of start_time, end_time')

        if start_time is None:
            start_time = datetime.now()
        else:
            start_time = dateparser.parse(start_time)

        if end_time is None:
            end_time = datetime.now()
        else:
            end_time = dateparser.parse(end_time)

        return date_to_timestamp(start_time), date_to_timestamp(end_time)

    end_time = datetime.now()
    if time_frame == 'Today':
        start_time = datetime.now().date()

    elif time_frame == 'Yesterday':
        start_time = (end_time - timedelta(days=1)).date()

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
def parse_alarms(alarms_data):
    if not isinstance(alarms_data, list):
        alarms_data = [alarms_data]

    alarms = []
    for alarm in alarms_data:
        events = []
        for event in alarm.get('events', []):
            # search command return the event object under sub-key message
            if 'message' in event:
                event = event['message']

            events.append({
                'ID': event['uuid'],
                'OccurredTime': event['timestamp_occured_iso8601'],
                'ReceivedTime': event['timestamp_received_iso8601'],
            })

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
                'IPAddress': alarm.get('alarm_source_names') or alarm.get('source_name'),
                'Organization': alarm.get('alarm_source_organisations') or alarm.get('source_organisation'),
                'Country': alarm.get('alarm_source_countries') or alarm.get('source_country'),
            },
            'Destination': {
                'IPAddress': alarm.get('alarm_destination_names') or alarm.get('destination_name'),
            },
            'Event': events,
            'Status': alarm.get('status'),
        })

    return alarms


@logger
def parse_events(events_data):
    regex = re.compile(r'.*"signature": "([\w\s]*)"')
    events = []
    for event in events_data:
        event_name = ''
        match = regex.match(event.get('log', ''))
        if match:
            event_name = match.group(1)

        events.append({
            'ID': event.get('uuid'),
            'Name': event_name,
            'OccurredTime': event.get('timestamp_occured_iso8601'),
            'ReceivedTime': event.get('timestamp_received_iso8601'),
            'Suppressed': event.get('suppressed'),

            'AccessControlOutcome': event.get('access_control_outcome'),
            'Category': event.get('event_category'),
            'Severity': event.get('event_severity'),
            'Subcategory': event.get('event_subcategory'),

            'Source': {
                'IPAddress': event.get('source_name'),
                'Port': event.get('source_port'),
            },
            'Destination': {
                'IPAddress': event.get('destination_name'),
                'Port': event.get('destination_port')
            },
        })

    return events


def dict_value_to_int(target_dict: Dict, key: str):
    """
    :param target_dict: A dictionary which has the key param
    :param key: The key that we need to convert it's value to integer
    :return: The integer representation of the key's value in the dict params
    """
    try:
        if target_dict:
            value = target_dict.get(key)
            if value:
                target_dict[key] = int(value)
                return target_dict[key]
    except ValueError:
        raise ValueError(f'The value for {key} must be an integer.')


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
    Performs basic get request to get alarm samples
    """
    # the login is executed in the switch panel code
    if IS_FETCH:
        # just check the correctness of the parameter
        parse_date_range(FETCH_TIME)
    search_alarms(limit=2)
    demisto.results('ok')


def get_alarm_command():
    """
    Gets alarm details by ID
    """
    args = demisto.args()
    alarm_id = args['alarm_id']

    # Make request and get raw response
    response = get_alarm(alarm_id)

    # Parse response into context & content entries
    alarm_details = parse_alarms(response)

    return_outputs(tableToMarkdown('Alarm {}'.format(alarm_id), alarm_details),
                   {'AlienVault.Alarm(val.ID && val.ID == obj.ID)': alarm_details},
                   response)


def get_alarm(alarm_id):
    res = http_request('GET', '/alarms/' + alarm_id)

    return res


def search_alarms_command():
    args = demisto.args()
    time_frame = args.get('time_frame')
    start_time = args.get('start_time', 'now-7d')
    end_time = args.get('end_time', 'now')
    show_suppressed = args.get('show_suppressed', 'false')
    limit = int(args.get('limit', 100))
    status = args.get('status')
    priority = args.get('priority')
    rule_intent = args.get('rule_intent')
    rule_method = args.get('rule_method')
    rule_strategy = args.get('rule_strategy')

    start_time, end_time = get_time_range(time_frame, start_time, end_time)

    result = search_alarms(start_time=start_time, end_time=end_time, show_suppressed=show_suppressed, limit=limit,
                           status=status, priority=priority, rule_intent=rule_intent, rule_method=rule_method,
                           rule_strategy=rule_strategy)

    alarms = parse_alarms(result)

    return_outputs(tableToMarkdown('Alarms:', alarms),
                   {'AlienVault.Alarm(val.ID && val.ID == obj.ID)': alarms}, result)


@logger
def search_alarms(start_time=None, end_time=None, status=None, priority=None, show_suppressed=None,
                  limit=100, rule_intent=None, rule_method=None, rule_strategy=None, direction='desc'):
    params = {
        'page': 0,
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

    res = http_request('GET', '/alarms', params=params)
    if res['page']['totalElements'] == 0:
        return []

    return res.get('_embedded', {}).get('alarms', [])


def search_events_command():
    args = demisto.args()
    time_frame = args.get('time_frame')
    start_time = args.get('start_time', 'now-7d')
    end_time = args.get('end_time', 'now')
    account_name = args.get('account_name')
    event_name = args.get('event_name')
    source_name = args.get('source_name')
    limit = int(args.get('limit', 100))

    start_time, end_time = get_time_range(time_frame, start_time, end_time)

    result = search_events(start_time=start_time, end_time=end_time, account_name=account_name, event_name=event_name,
                           source_name=source_name, limit=limit)
    events = parse_events(result)

    return_outputs(tableToMarkdown('Events:', events),
                   {'AlienVault.Event(val.ID && val.ID == obj.ID)': events},
                   result)


@logger
def search_events(start_time=None, end_time=None, account_name=None, event_name=None, source_name=None, limit=100,
                  direction='desc'):
    params = {
        'page': 1,
        'size': limit,
        'sort': 'timestamp_occured,{}'.format(direction),
    }

    if account_name:
        params['account_name'] = account_name
    if event_name:
        params['event_name'] = event_name
    if source_name:
        params['source_name'] = source_name

    if start_time:
        params['timestamp_occured_gte'] = start_time
    if end_time:
        params['timestamp_occured_lte'] = end_time

    res = http_request('GET', '/events', params=params)
    if res['page']['totalElements'] == 0:
        return []

    return res.get('_embedded', {}).get('eventResources', [])


def get_events_by_alarm_command():
    args = demisto.args()
    alarm_id = args['alarm_id']

    alarm = get_alarm(alarm_id)

    events = parse_events(alarm['events'])

    return_outputs(tableToMarkdown('Events of Alarm {}:'.format(alarm_id), events),
                   {'AlienVault.Event(val.ID && val.ID == obj.ID)': events},
                   alarm)


def fetch_incidents():
    last_run = demisto.getLastRun()
    # Get the last fetch time, if exists
    last_fetch = last_run.get('timestamp')

    # Handle first time fetch, fetch incidents retroactively
    # OR
    # Handle first time after release
    if last_fetch is None:
        time_field = last_run.get('time')
        if time_field:
            last_fetch = date_to_timestamp(time_field, parse_time(time_field))
        else:
            last_fetch, _ = parse_date_range(FETCH_TIME, to_timestamp=True)

    incidents = []
    limit = dict_value_to_int(demisto.params(), 'fetch_limit')
    items = search_alarms(start_time=last_fetch, direction='asc', limit=limit)
    for item in items:
        incident = item_to_incident(item)
        incidents.append(incident)

    if incidents:
        #  updating according to latest incident
        time_str = str(incidents[-1].get('occurred'))

        # add one second to last incident occurred time to avoid duplications
        occurred = datetime.strptime(time_str, '%Y-%m-%dT%H:%M:%S.%fZ')
        occurred = occurred + timedelta(seconds=1)
        time_str = occurred.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        last_fetch = str(date_to_timestamp(time_str, date_format=parse_time(time_str)))

    demisto.setLastRun({'timestamp': last_fetch})
    demisto.incidents(incidents)


''' COMMANDS MANAGER / SWITCH PANEL '''
COMMANDS = {
    'test-module': test_module,
    'fetch-incidents': fetch_incidents,
    'alienvault-search-alarms': search_alarms_command,
    'alienvault-get-alarm': get_alarm_command,
    'alienvault-search-events': search_events_command,
    'alienvault-get-events-by-alarm': get_events_by_alarm_command,
}


def main():
    global AUTH_TOKEN
    cmd = demisto.command()
    LOG('Command being called is {}'.format(cmd))

    try:
        handle_proxy()
        AUTH_TOKEN = get_token()

        if cmd in COMMANDS:
            COMMANDS[cmd]()

    # Log exceptions
    except Exception as e:
        import traceback
        LOG(traceback.format_exc())

        if demisto.command() == 'fetch-incidents':
            LOG(str(e))
            LOG.print_log()
            raise
        else:
            return_error('An error occurred: {}'.format(str(e)))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
