import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import requests

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''
BASE_URL = '{}/openapi/v3'.format(demisto.params()['domain'])
API_KEY = demisto.params()['api_key']
USE_SSL = not demisto.params().get('insecure', False)

''' HELPER FUNCTIONS '''


def get_time_obj(t, time_format=None):
    '''
    convert a time string to datetime object

    :type t: ``string`` or ``int``
    :param t: time object as string or int for timestamp (required)

    :type time_format: ``string``
    :param time_format: time format string  (optional)

    :return: datetime object
    :rtype: ``datetime``
    '''
    if time_format is not None:
        return datetime.strptime(t, time_format)
    if isinstance(t, int):
        return datetime.fromtimestamp(t)
    elif isinstance(t, tuple(STRING_TYPES)):
        if '.' in t:
            # in case of "2018-09-14T13:27:18.123456Z"
            return datetime.strptime(t, '%Y-%m-%dT%H:%M:%S.%fZ')
        else:
            # in case of "2018-09-14T13:27:18.123456Z"
            return datetime.strptime(t, '%Y-%m-%dT%H:%M:%SZ')


def get_time_str(time_obj, time_format=None):
    '''
    convert a datetime object to time format string

    :type t: ``datetime``
    :param t: time object (required)

    :type time_format: ``string``
    :param time_format: time format string (optional)

    :return: time format string
    :rtype: ``string``
    '''
    if time_format is None:
        return time_obj.isoformat().split('.')[0] + 'Z'
    else:
        return datetime.strftime(t, time_format)  # type:ignore  # pylint: disable=E0602


def http_request(requests_func, url_suffix, **kwargs):
    params = kwargs.get('params')
    headers = kwargs.get('headers', {})
    data = kwargs.get('data', {})

    res = requests_func(BASE_URL + url_suffix,
                        verify=USE_SSL,
                        params=params,
                        headers=headers,
                        data=data
                        )

    if res.status_code == 403:
        raise Exception('API Key is incorrect')

    if res.status_code not in [200, 201, ]:
        LOG('result is: %s' % (res.json(),))
        error = res.json()
        raise Exception('Your request failed with the following error: {}.\n'.format(error, ))

    return res.json()


@logger
def http_get(url_suffix, params=None, data=None):
    headers = {'X-Api-Key': API_KEY}
    return http_request(requests.get, url_suffix, headers=headers, params=params, data=data)


@logger
def http_patch(url_suffix, params=None, data=None):
    headers = {'X-Api-Key': API_KEY}
    return http_request(requests.patch, url_suffix, headers=headers, params=params, data=data)


@logger
def http_post(url_suffix, params=None, data=None):
    headers = {'X-Api-Key': API_KEY}
    return http_request(requests.post, url_suffix, headers=headers, params=params, data=data)


def playbook_name_to_id(name):
    playbooks = http_get('/exec/playbooks')['data']
    ids = [p['id'] for p in playbooks if p['name'] == name]
    if len(ids) != 1:
        raise ValueError('Could not find specific id for name "{}"'.format(name))

    return ids[0]


def get_endpoint_context(res=None, endpoint_id=None):
    if res is None:
        res = http_get('/endpoints/{}'.format(endpoint_id))['data']

    # Endpoint(val.Hostname == obj.Hostname)
    return [{
        'Hostname': endpoint['attributes']['hostname'],
        'ID': endpoint['id'],
        'IPAddress': [addr['attributes']['ip_address']['attributes']['ip_address']
                      for addr in endpoint['attributes']['endpoint_network_addresses']],
        'MACAddress': [addr['attributes']['mac_address']['attributes']['address']
                       for addr in endpoint['attributes']['endpoint_network_addresses']],
        'OS': endpoint['attributes']['platform'],
        'OSVersion': endpoint['attributes']['operating_system'],
        'IsIsolated': endpoint['attributes']['is_isolated'],
        'IsDecommissioned': endpoint['attributes']['is_decommissioned'],
    } for endpoint in res]


def get_endpoint_user_context(res=None, endpoint_user_id=None):
    if res is None:
        res = http_get('/endpoint_users/{}'.format(endpoint_user_id))['data']

    endpoint_users = []
    for endpoint_user in res:
        username = endpoint_user.get('attributes', {}).get('username', '')
        if '\\' in username:
            hostname, parsed_username = username.split('\\')
            user = {
                'Username': parsed_username,
                'Hostname': hostname
            }
        else:
            user = {
                'Username': username
            }
        endpoint_users.append(user)

    return endpoint_users


def get_full_timeline(detection_id, per_page=100):
    ''' iterate over all timeline  detections later then time t '''
    page = 1
    done = False
    activities = []  # type:ignore
    while not done:
        res = http_get('/detections/{}/timeline'.format(detection_id),
                       params={
                           'page': page,
                           'per_page': per_page,
        })

        if len(res['data']) == 0 or True:
            done = True

        activities.extend(res['data'])
        page += 1

    return activities


def process_timeline(detection_id):
    res = get_full_timeline(detection_id)

    activities = []
    domains = []
    files = []
    ips = []
    processes = []
    for activity in res:
        if activity['type'] != 'activity_timelines.ActivityOccurred':
            continue

        activity_time = get_time_str(get_time_obj(activity['attributes']['occurred_at']))
        notes = activity['attributes']['analyst_notes']
        additional_data = {}  # type:ignore

        if activity['attributes']['type'] == 'process_activity_occurred':
            process = activity['attributes']['process_execution']['attributes']['operating_system_process'][
                'attributes']
            image = process['image']['attributes']
            additional_data = {
                'MD5': image['md5'],
                'SHA256': image['sha256'],
                'Path': image['path'],
                'Type': image['file_type'],
                'CommandLine': process['command_line']['attributes']['command_line'],
            }
            files.append({
                'Name': os.path.basename(image['path']),
                'MD5': image['md5'],
                'SHA256': image['sha256'],
                'Path': image['path'],
                'Extension': os.path.splitext(image['path'])[-1],
            })
            processes.append({
                'Name': os.path.basename(image['path']),
                'Path': image['path'],
                'MD5': image['md5'],
                'SHA256': image['sha256'],
                'StartTime': get_time_str(get_time_obj(process['started_at'])),
                'CommandLine': process['command_line']['attributes']['command_line'],
            })

        elif activity['attributes']['type'] == 'network_connection_activity_occurred':
            network = activity['attributes']['network_connection']['attributes']
            additional_data = {
                'IP': network['ip_address']['attributes']['ip_address'],
                'Port': network['port'],
                'Domain': network['domain']['attributes']['name'],
            }
            domains.append({'Name': network['domain']['attributes']['name'],
                            # 'DNS' :
                            })
            ips.append({
                'Address': network['ip_address']['attributes']['ip_address'],
                'Port': network['port'],
            })

        activities.append({
            'Time': activity_time,
            'Type': activity['attributes']['type'].replace('_', ' '),
            'Notes': notes,
            'Activity Details': createContext(additional_data, removeNull=True),
        })

    return activities, domains, files, ips, processes


def detection_to_context(raw_detection):
    return {
        'Type': 'RedCanaryDetection',
        'ID': raw_detection['id'],
        'Headline': raw_detection['attributes']['headline'],
        'Severity': raw_detection['attributes']['severity'],
        'Summary': raw_detection['attributes']['summary'],
        'Classification': raw_detection['attributes']['classification']['superclassification'],
        'Subclassification': raw_detection['attributes']['classification']['subclassification'],
        'Time': get_time_str(get_time_obj(raw_detection['attributes']['time_of_occurrence'])),
        'Acknowledged': raw_detection['attributes']['last_acknowledged_at'] is None and raw_detection['attributes'][
            'last_acknowledged_by'] is None,
        'RemediationStatus': raw_detection['attributes'].get('last_remediated_status', {}).get('remediation_status',
                                                                                               ''),
        'Reason': raw_detection['attributes'].get('last_remediated_status', {}).get('reason', ''),
        'EndpointID': raw_detection.get('relationships', {}).get('affected_endpoint', {}).get('data', {}).get('id',
                                                                                                              ''),
        'EndpointUserID': raw_detection.get('relationships', {}).get('related_endpoint_user',
                                                                     {}).get('data', {}).get('id', '')
    }


def detections_to_entry(detections, show_timeline=False):
    fixed_detections = [detection_to_context(d) for d in detections]
    endpoints = [get_endpoint_context(endpoint_id=d['relationships']['affected_endpoint']['data']['id'])
                 for d in detections]
    endpoints = sum(endpoints, [])  # type: list
    endpoint_users = [
        get_endpoint_user_context(endpoint_user_id=d['relationships']['related_endpoint_user']['data']['id'])
        for d in detections]
    endpoint_users = sum(endpoint_users, [])  # type: list

    domains, files, ips, processes = [], [], [], []  # type:ignore
    activities = ''
    title = 'Detections'
    if show_timeline and len(detections) == 1:
        title = 'Detection {}'.format(fixed_detections[0]['Headline'])
        activities, domains, files, ips, processes = process_timeline(fixed_detections[0]['ID'])
        activities = tableToMarkdown('Detection Timeline', activities,
                                     headers=['Time', 'Type', 'Activity Details', 'Notes'])

    headers = ['ID', 'Headline', 'Severity', 'Time', 'Classification', 'Summary', ]
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': fixed_detections,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': '\n\n'.join([
            tableToMarkdown(title, fixed_detections, headers=headers, removeNull=True),
            activities,
        ]),
        'EntryContext': {
            'RedCanary.Detection(val.ID && val.ID == obj.ID)': createContext(fixed_detections, removeNull=True),
            'Account(val.Username == obj.Username)': createContext(endpoint_users, removeNull=True),
            'Domain(val.Username == obj.Username)': createContext(domains, removeNull=True),
            'Endpoint(val.Hostname == obj.Hostname)': createContext(endpoints, removeNull=True),
            'File(val.Name == obj.Name)': createContext(files, removeNull=True),
            'IP(val.Address == obj.Address)': createContext(ips, removeNull=True),
            'Process(val.Username == obj.Username)': createContext(processes, removeNull=True),
        }
    }


def get_unacknowledge_detections(t, per_page=50):
    ''' iterate over all unacknowledged detections later then time t'''
    page = 1
    passed = False
    while not passed:
        res = list_detections(page=page, per_page=per_page)

        if len(res) == 0:
            passed = True

        for detection in res:
            if get_time_obj(detection['attributes']['time_of_occurrence']) < t:
                passed = True
                break
            if detection['attributes']['last_acknowledged_at'] is not None or detection['attributes'][
                    'last_acknowledged_by'] is not None:
                continue

            yield detection

        page += 1


@logger
def detection_to_incident(raw_detection):
    detection = detection_to_context(raw_detection)
    detection['Timeline'] = get_full_timeline(detection['ID'])

    return {
        'type': 'RedCanaryDetection',
        'name': detection['Headline'],
        'details': detection['Summary'],
        'occurred': detection['Time'],
        'rawJSON': json.dumps(detection),
    }


''' FUNCTIONS '''


def list_detections_command():
    args = demisto.args()
    page = int(args.get('page', '1'))
    per_page = int(args.get('per-page', '50'))

    data = list_detections(page, per_page)
    return detections_to_entry(data)


@logger
def list_detections(page, per_page):
    res = http_get('/detections',
                   data={
                       'page': page,
                       'per_page': per_page
                   },
                   )
    return res['data']


def get_detection_command():
    args = demisto.args()
    _id = args['id']

    data = get_detection(_id)
    return detections_to_entry(data, show_timeline=True)


@logger
def get_detection(_id):
    res = http_get('/detections/{}'.format(_id))
    return res['data']


def acknowledge_detection_command():
    args = demisto.args()
    _id = args['id']

    acknowledge_detection(_id)
    return 'detection acknowledged successfully.'


@logger
def acknowledge_detection(_id):
    res = http_patch('/detections/{}/mark_acknowledged'.format(_id))
    return res['data']


def remediate_detection_command():
    args = demisto.args()
    _id = args['id']
    remediation_state = args['remediation-state']
    comment = args.get('comment')

    remediate_detection(_id, remediation_state, comment)
    return 'Detection was updated to "{}" successfully.'.format(remediation_state.replace('_', ' '))


@logger
def remediate_detection(_id, remediation_state, comment):
    res = http_patch('/detections/{}/update_remediation_state'.format(_id),
                     data={
                         'remediation_state': remediation_state,
                         'comment': comment,
                     })
    return res


def list_endpoints_command():
    args = demisto.args()
    page = int(args.get('page', '1'))
    per_page = int(args.get('per-page', '50'))

    data = list_endpoints(page, per_page)
    endpoints = get_endpoint_context(res=data)
    headers = ['ID', 'IPAddress', 'Hostname', 'MACAddress', 'IsIsolated', 'IsDecommissioned', 'OSVersion', ]
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': endpoints,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('EndPoints', endpoints, headers=headers, removeNull=True),
        'EntryContext': {
            'EndPoint(val.Hostname == obj.Hostname)': createContext(endpoints, removeNull=True),
        }
    }


@logger
def list_endpoints(page, per_page):
    res = http_get('/endpoints',
                   data={
                       'page': page,
                       'per_page': per_page
                   },
                   )

    return res['data']


def get_endpoint_command():
    args = demisto.args()
    _id = args['id']

    data = get_endpoint(_id)
    endpoints = get_endpoint_context(res=data)
    headers = ['ID', 'IPAddress', 'Hostname', 'MACAddress', 'IsIsolated', 'IsDecommissioned', 'OSVersion', ]
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': endpoints,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('EndPoint {}'.format(endpoints[0]['Hostname']), endpoints, headers=headers,
                                         removeNull=True),
        'EntryContext': {
            'EndPoint(val.Hostname == obj.Hostname)': createContext(endpoints, removeNull=True),
        }
    }


@logger
def get_endpoint(_id):
    res = http_get('/endpoints/{}'.format(_id))

    return res['data']


def get_endpoint_detections_command():
    args = demisto.args()
    _id = args['id']

    detections = get_endpoint_detections(_id)
    return detections_to_entry(detections)


@logger
def get_endpoint_detections(_id):
    endpoint = get_endpoint(_id)

    detection_ids = [d['href'].split('detections/')[1] for d in endpoint[0]['links']['detections']]
    detections = []  # type:ignore
    for detection_id in detection_ids:
        detections.extend(get_detection(detection_id))

    return detections


def execute_playbook_command():
    args = demisto.args()
    detection_id = args['detection-id']
    playbook_id = args.get('playbook-id')
    playbook_name = args.get('playbook-name')
    if playbook_id is None:
        if playbook_name is None:
            raise ValueError('You must specify either playbook-id or playbook-name.')
        playbook_id = playbook_name_to_id(args.get('playbook-name'))

    execute_playbook(playbook_id, detection_id)

    return 'playbook #{} execution started successfully.'.format(playbook_id)


def execute_playbook(playbook_id, detection_id):
    res = http_post('/exec/playbooks/{}/execute'.format(playbook_id),
                    params={
                        'resource_type': 'Detection',
                        'resource_id': detection_id,
                    })

    return res


def fetch_incidents():
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('time')

    # handle first time fetch
    if last_fetch is None:
        last_fetch = datetime.now() - timedelta(days=5)
    else:
        last_fetch = datetime.strptime(last_fetch, '%Y-%m-%dT%H:%M:%SZ')

    LOG('iterating on detections, looking for more recent than {}'.format(last_fetch))
    incidents = []
    for raw_detection in get_unacknowledge_detections(last_fetch, per_page=2):
        LOG('found detection #{}'.format(raw_detection['id']))
        incident = detection_to_incident(raw_detection)

        incidents.append(incident)

    if len(incidents) != 0:
        last_fetch = max([get_time_obj(incident['occurred']) for incident in incidents])  # noqa:F812
        demisto.setLastRun({'time': get_time_str(last_fetch + timedelta(seconds=1))})
    demisto.incidents(incidents)


@logger
def test_integration():
    list_detections(1, 1)
    return 'ok'


''' EXECUTION CODE '''
COMMANDS = {
    'test-module': test_integration,
    'fetch-incidents': fetch_incidents,
    'redcanary-list-detections': list_detections_command,
    'redcanary-list-endpoints': list_endpoints_command,
    'redcanary-get-endpoint': get_endpoint_command,
    'redcanary-get-endpoint-detections': get_endpoint_detections_command,
    'redcanary-get-detection': get_detection_command,
    'redcanary-acknowledge-detection': acknowledge_detection_command,
    'redcanary-update-remediation-state': remediate_detection_command,
    'redcanary-execute-playbook': execute_playbook_command,
}

try:
    handle_proxy()
    LOG('command is %s' % (demisto.command(),))
    command_func = COMMANDS.get(demisto.command())
    if command_func is not None:
        if demisto.command() == 'fetch-incidents':
            demisto.incidents(command_func())
        else:
            demisto.results(command_func())

except Exception as e:
    LOG(e.message)
    if demisto.command() != 'test-module':
        LOG.print_log()
    return_error('error has occurred: {}'.format(e.message, ))
