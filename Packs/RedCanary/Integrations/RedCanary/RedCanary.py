import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from collections.abc import Generator

from CommonServerUserPython import *

''' IMPORTS '''
import requests
import urllib3

# disable insecure warnings
urllib3.disable_warnings()

''' GLOBAL VARS '''
BASE_URL = ''
API_KEY = ''
USE_SSL = False

TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
''' HELPER FUNCTIONS '''


def get_time_obj(t, time_format=None):
    """
    convert a time string to datetime object

    :type t: ``string`` or ``int``
    :param t: time object as string or int for timestamp (required)

    :type time_format: ``string``
    :param time_format: time format string  (optional)

    :return: datetime object
    :rtype: ``datetime``
    """
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
            return datetime.strptime(t, TIME_FORMAT)
    return None


def get_time_str(time_obj, time_format=None):
    """
    convert a datetime object to time format string

    :type time_obj: ``datetime``
    :param time_obj: time object (required)

    :type time_format: ``string``
    :param time_format: time format string (optional)

    :return: time format string
    :rtype: ``string``
    """
    if time_format is None:
        return time_obj.isoformat().split('.')[0] + 'Z'
    else:
        return datetime.strftime(time_obj, time_format)  # type:ignore  # pylint: disable=E0602


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
    if res.status_code == 404:
        return {}

    if res.status_code not in [200, 201, ]:
        LOG(f'result is: {res.json()}')
        error = res.json()
        raise Exception(f'Your request failed with the following error: {error}.\n')

    return res.json()


def http_get(url_suffix, params=None, data=None):
    headers = {'X-Api-Key': API_KEY}
    return http_request(requests.get, url_suffix, headers=headers, params=params, data=data)


def http_patch(url_suffix, params=None, data=None):
    headers = {'X-Api-Key': API_KEY}
    return http_request(requests.patch, url_suffix, headers=headers, params=params, data=data)


def http_post(url_suffix, params=None, data=None):
    headers = {'X-Api-Key': API_KEY}
    return http_request(requests.post, url_suffix, headers=headers, params=params, data=data)


def playbook_name_to_id(name):
    playbooks = http_get('/automate/playbooks')['data']
    ids = [p['id'] for p in playbooks if p['name'] == name]
    if len(ids) != 1:
        raise ValueError(f'Could not find specific id for name "{name}"')

    return ids[0]


def get_endpoint_context(res=None, endpoint_id=None):
    if res is None:
        res = http_get(f'/endpoints/{endpoint_id}').get('data', [])

    endpoint_context = []
    for endpoint in res:
        endpoint_attributes = endpoint.get('attributes', {})
        current_endpoint_context = {
            'Hostname': endpoint_attributes.get('hostname'),
            'ID': endpoint.get('id'),
            'OS': endpoint_attributes.get('platform'),
            'OSVersion': endpoint_attributes.get('operating_system'),
            'IsIsolated': endpoint_attributes.get('is_isolated'),
            'IsDecommissioned': endpoint_attributes.get('is_decommissioned'),
        }
        ip_addresses = []
        mac_addresses = []
        for address in endpoint_attributes.get('endpoint_network_addresses', []):
            address_attributes = address.get('attributes', {})
            if address_attributes:
                ip_address_object = address_attributes.get('ip_address', {})
                if ip_address_object:
                    ip_address_attributes = ip_address_object.get('attributes', {})
                    if ip_address_attributes:
                        ip_addresses.append(ip_address_attributes.get('ip_address'))
                mac_address_object = address_attributes.get('mac_address', {})
                if mac_address_object:
                    mac_address_attributes = mac_address_object.get('attributes', {})
                    if mac_address_attributes:
                        mac_addresses.append(mac_address_attributes.get('address'))
        if ip_addresses:
            current_endpoint_context['IPAddress'] = ip_addresses
        if mac_addresses:
            current_endpoint_context['MACAddress'] = mac_addresses
        endpoint_context.append(current_endpoint_context)
    return endpoint_context


def get_endpoint_user_context(res=None, endpoint_user_id=None):
    if res is None:
        res = http_get(f'/endpoint_users/{endpoint_user_id}')['data']

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
    last_data = {}  # type:ignore

    while not done:
        res = http_get(f'/detections/{detection_id}/timeline', params={
            'page': page,
            'per_page': per_page,
        })
        current_data = res.get('data')

        # if there is no more data to get from this http request
        # or if the request provides the same information over and over again stop the loop
        if len(current_data) == 0 or current_data == last_data:
            current_data = {}
            done = True

        activities.extend(current_data)
        last_data = current_data
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
            process = activity['attributes']['process_execution']['attributes'].get(
                'operating_system_process', {})
            if not process:
                demisto.debug('##### process attributes corrupted, skipping additional data. process response:'
                              f'{activity.get("attributes", {}).get("process_execution")} #######')
            else:
                process = process.get('attributes', {}) or {}
                image = process.get('image', {}).get('attributes')
                additional_data = {
                    'MD5': image.get('md5'),
                    'SHA256': image.get('sha256'),
                    'Path': image.get('path'),
                    'Type': image.get('file_type'),
                    'CommandLine': process.get('command_line', {}).get(
                        'attributes', {}).get('command_line'),
                }
                files.append({
                    'Name': os.path.basename(image.get('path', '')),
                    'MD5': image.get('md5'),
                    'SHA256': image.get('sha256'),
                    'Path': image.get('path'),
                    'Extension': os.path.splitext(image.get('path', ''))[-1],
                })
                processes.append({
                    'Name': os.path.basename(image.get('path', '')),
                    'Path': image.get('path'),
                    'MD5': image.get('md5'),
                    'SHA256': image.get('sha256'),
                    'StartTime': get_time_str(get_time_obj(process.get('started_at'))),
                    'CommandLine': process.get('command_line', {}).get(
                        'attributes', {}).get('command_line'),
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
    endpoints = []
    for d in detections:
        if endpoint_id := demisto.get(d, 'relationships.affected_endpoint.data.id'):
            endpoints.append(get_endpoint_context(endpoint_id=endpoint_id))

    endpoints = sum(endpoints, [])  # type: list
    endpoint_users = []
    for d in detections:
        if endpoint_user_id := demisto.get(d, 'relationships.related_endpoint_user.data.id'):
            endpoint_users.append(get_endpoint_user_context(endpoint_user_id=endpoint_user_id))
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


def get_unacknowledged_detections(t: datetime, per_page: int = 50) -> Generator[dict, None, None]:
    """ iterate over all unacknowledged detections later then time t

    Args:
        t : last fetched time
        per_page: how many detections per page

    Yields:
        dict: A detection from api
    """
    page = 1
    res = list_detections(page=page, per_page=per_page, since=t)
    while res:
        for detection in res:
            attributes = detection.get('attributes', {})
            # If 'last_acknowledged_at' or 'last_acknowledged_by' are in attributes,
            # the detection is acknowledged and should not create a new incident.
            if attributes.get('last_acknowledged_at') is None and attributes.get('last_acknowledged_by') is None:
                yield detection

        page += 1
        res = list_detections(page=page, per_page=per_page, since=t)


@logger
def detection_to_incident(raw_detection):
    detection = detection_to_context(raw_detection)

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
def list_detections(page, per_page, since=None):
    if isinstance(since, datetime):
        since = datetime.strftime(since, TIME_FORMAT)
    res = http_get('/detections',
                   params=assign_params(
                       page=page,
                       per_page=per_page,
                       since=since
                   ),
                   )
    return res.get('data', [])


def get_detection_command():
    args = demisto.args()
    _id = args['id']

    data = get_detection(_id)
    return detections_to_entry(data, show_timeline=True)


@logger
def get_detection(_id):
    res = http_get(f'/detections/{_id}')
    return res['data']


def acknowledge_detection_command():
    args = demisto.args()
    _id = args['id']

    acknowledge_detection(_id)
    return 'detection acknowledged successfully.'


@logger
def acknowledge_detection(_id):
    res = http_patch(f'/detections/{_id}/mark_acknowledged')
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
    res = http_patch(f'/detections/{_id}/update_remediation_state', data={
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
                   params={
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
    res = http_get(f'/endpoints/{_id}')

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

    return f'playbook #{playbook_id} execution started successfully.'


def execute_playbook(playbook_id, detection_id):
    res = http_post(f'/automate/playbooks/{playbook_id}/execute', params={
        'resource_type': 'Detection',
        'resource_id': detection_id,
    })

    return res


def fetch_incidents(last_run, per_page):
    last_incidents_ids = []

    if last_run:
        last_fetch = last_run.get('time')
        last_fetch = datetime.strptime(last_fetch, TIME_FORMAT)
        last_incidents_ids = last_run.get('last_event_ids')
    else:
        # first time fetching
        last_fetch = parse_date_range(demisto.params().get('fetch_time', '3 days'), TIME_FORMAT)[0]

    demisto.debug(f'iterating on detections, looking for more recent than {last_fetch}')
    incidents = []
    new_incidents_ids = []
    for raw_detection in get_unacknowledged_detections(last_fetch, per_page=per_page):
        demisto.debug('found a new detection in RedCanary #{}'.format(raw_detection['id']))
        incident = detection_to_incident(raw_detection)
        # the rawJson is a string of dictionary e.g. - ('{"ID":2,"Type":5}')
        incident_id = json.loads(incident.get('rawJSON')).get("ID")
        if incident_id not in last_incidents_ids:
            # makes sure that the incident wasn't fetched before
            incidents.append(incident)
        new_incidents_ids.append(incident_id)

    if incidents:
        last_fetch = max([get_time_obj(incident['occurred']) for incident in incidents])  # noqa:F812
        last_run = {'time': get_time_str(last_fetch), 'last_event_ids': new_incidents_ids}

    return last_run, incidents


@logger
def test_integration():
    list_detections(1, 1)
    return 'ok'


def main():
    global BASE_URL, API_KEY, USE_SSL
    params = demisto.params()
    BASE_URL = urljoin(params.get('domain', ''), '/openapi/v3')
    API_KEY = params.get('api_key_creds', {}).get('password') or params.get('api_key')
    USE_SSL = not params.get('insecure', False)
    per_page = params.get('fetch_limit', 2)

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
        LOG(f'command is {demisto.command()}')
        command_func = COMMANDS.get(demisto.command())
        if command_func is not None:
            if demisto.command() == 'fetch-incidents':
                initial_last_run = demisto.getLastRun()
                last_run, incidents = fetch_incidents(initial_last_run, per_page)
                demisto.incidents(incidents)
                demisto.setLastRun(last_run)
            else:
                demisto.results(command_func())

    except Exception as e:
        LOG(str(e))
        if demisto.command() != 'test-module':
            LOG.print_log()
        return_error(f'error has occurred: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
