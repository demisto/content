import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
import base64
from dateutil.parser import parse

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

CLIENT_ID = demisto.params().get('client_id')
SECRET = demisto.params().get('secret')
# Remove trailing slash to prevent wrong URL path to service
SERVER = demisto.params()['url'][:-1] if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else \
    demisto.params()['url']
# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)
# How many time before the first fetch to retrieve incidents
FETCH_TIME = demisto.params().get('fetch_time', '3 days')
BYTE_CREDS = '{name}:{password}'.format(name=CLIENT_ID, password=SECRET).encode('utf-8')
# Headers to be sent in requests
HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': 'Basic {}'.format(base64.b64encode(BYTE_CREDS).decode())
}
# Note: True life time is actually 30 mins
TOKEN_LIFE_TIME = 28
INCIDENTS_PER_FETCH = int(demisto.params().get('incidents_per_fetch', 15))
# Remove proxy if not set to true in params
if not demisto.params().get('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

''' KEY DICTIONARY '''

DETECTIONS_BASE_KEY_MAP = {
    'device.hostname': 'System',
    'device.cid': 'CustomerID',
    'hostinfo.domain': 'MachineDomain',
    'detection_id': 'ID',
    'created_timestamp': 'ProcessStartTime',
    'max_severity': 'MaxSeverity',
    'show_in_ui': 'ShowInUi',
    'status': 'Status'
}

DETECTIONS_BEHAVIORS_KEY_MAP = {
    'filename': 'FileName',
    'scenario': 'Scenario',
    'md5': 'MD5',
    'sha256': 'SHA256',
    'ioc_type': 'IOCType',
    'ioc_value': 'IOCValue',
    'cmdline': 'CommandLine',
    'user_name': 'UserName',
    'behavior_id': 'ID',
}

SEARCH_IOC_KEY_MAP = {
    'type': 'Type',
    'value': 'Value',
    'policy': 'Policy',
    'source': 'Source',
    'share_level': 'ShareLevel',
    'expiration_timestamp': 'Expiration',
    'description': 'Description',
    'created_timestamp': 'CreatedTime',
    'created_by': 'CreatedBy',
    'modified_timestamp': 'ModifiedTime',
    'modified_by': 'ModifiedBy'
}

SEARCH_DEVICE_KEY_MAP = {
    'device_id': 'ID',
    'external_ip': 'ExternalIP',
    'local_ip': 'LocalIP',
    'hostname': 'Hostname',
    'os_version': 'OS',
    'mac_address': 'MacAddress',
    'first_seen': 'FirstSeen',
    'last_seen': 'LastSeen'
}

''' SPLIT KEY DICTIONARY '''

"""
    Pattern:
    {
        'Path': 'Path to item',
        'NewKey': 'Value of output key',
        'Delim': 'Delimiter char',
        'Index': Split Array Index
    }
"""
DETECTIONS_BEHAVIORS_SPLIT_KEY_MAP = [
    {
        'Path': 'parent_details.parent_process_graph_id',
        'NewKey': 'SensorID',
        'Delim': ':',
        'Index': 1
    },
    {
        'Path': 'parent_details.parent_process_graph_id',
        'NewKey': 'ParentProcessID',
        'Delim': ':',
        'Index': 2
    },
    {
        'Path': 'triggering_process_graph_id',
        'NewKey': 'ProcessID',
        'Delim': ':',
        'Index': 2
    },
]

''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, data=None, headers=HEADERS, safe=False, get_token_flag=True):
    """
        A wrapper for requests lib to send our requests and handle requests and responses better.

        :type method: ``str``
        :param method: HTTP method for the request.

        :type url_suffix: ``str``
        :param url_suffix: The suffix of the URL (endpoint)

        :type params: ``dict``
        :param params: The URL params to be passed.

        :type data: ``str``
        :param data: The body data of the request.

        :type headers: ``dict``
        :param headers: Request headers

        :type safe: ``bool``
        :param safe: If set to true will return None in case of http error

        :type get_token_flag: ``bool``
        :param get_token_flag: If set to True will call get_token()

        :return: Returns the http request response json
        :rtype: ``dict``
    """
    if get_token_flag:
        token = get_token()
        headers['Authorization'] = 'Bearer {}'.format(token)
    url = SERVER + url_suffix
    try:
        res = requests.request(
            method,
            url,
            verify=USE_SSL,
            params=params,
            data=data,
            headers=headers,
        )
    except requests.exceptions.RequestException:
        return_error('Error in connection to the server. Please make sure you entered the URL correctly.')
    # Handle error responses gracefully
    if res.status_code not in {200, 201, 202}:
        err_msg = 'Error in API call. code:{code}; reason: {reason}'.format(code=res.status_code, reason=res.reason)
        # try to create a new token
        if res.status_code == 403 and get_token_flag:
            LOG(err_msg)
            token = get_token(new_token=True)
            headers['Authorization'] = 'Bearer {}'.format(token)
            return http_request(method, url_suffix, params, data, headers, safe, get_token_flag=False)
        elif safe:
            return None
        return_error(err_msg)
    return res.json()


def create_entry_object(contents='', ec=None, hr=''):
    """
        Creates an entry object

        :type contents: ``dict``
        :param contents: Raw response to output

        :type ec: ``dict``
        :param ec: Entry context of the entry object

        :type hr: ``str``
        :param hr: Human readable

        :return: Entry object
        :rtype: ``dict``
    """
    return {
        'Type': entryTypes['note'],
        'Contents': contents,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr,
        'EntryContext': ec
    }


def detection_to_incident(detection):
    """
        Creates an incident of a detection.

        :type detection: ``dict``
        :param detection: Single detection object

        :return: Incident representation of a detection
        :rtype ``dict``
    """
    incident = {
        'name': 'Detection ID: ' + str(detection.get('detection_id')),
        'occurred': str(detection.get('created_timestamp')),
        'rawJSON': json.dumps(detection),
        'severity': severity_string_to_int(detection.get('max_severity_displayname'))
    }
    return incident


def severity_string_to_int(severity):
    """
        Converts a severity string to DBot score representation

        :type severity: ``str``
        :param severity: String representation of a severity

        :return: DBot score representation of the severity
        :rtype ``int``
    """
    if severity in ('Critical', 'High'):
        return 3
    elif severity in ('Medium', 'Low'):
        return 2
    return 0


def get_trasnformed_dict(old_dict, transformation_dict):
    """
        Returns a dictionary with the same values as old_dict, with the correlating key:value in transformation_dict

        :type old_dict: ``dict``
        :param old_dict: Old dictionary to pull values from

        :type transformation_dict: ``dict``
        :param transformation_dict: Transformation dictionary that contains oldkeys:newkeys

        :return Transformed dictionart (according to transformation_dict values)
        :rtype ``dict``
    """
    new_dict = {}
    for k in list(old_dict.keys()):
        if k in transformation_dict:
            new_dict[transformation_dict[k]] = old_dict[k]
    return new_dict


def extract_transformed_dict_with_split(old_dict, transformation_dict_arr):
    """
        Extracts new values out of old_dict using a json structure of:
        {'Path': 'Path to item', 'NewKey': 'Value of output key', 'Delim': 'Delimiter char', 'Index': Split Array Index}
    """
    new_dict = {}
    for trans_dict in transformation_dict_arr:
        try:
            val = demisto.get(old_dict, trans_dict['Path'])
            if 'split' in dir(val):
                i = trans_dict['Index']
                new_dict[trans_dict['NewKey']] = val.split(trans_dict['Delim'])[i]
        except Exception as ex:
            LOG('Error {exception} with: {tdict}'.format(exception=ex, tdict=trans_dict))
    return new_dict


def get_passed_mins(start_time, end_time_str):
    """
        Returns the time passed in mins
        :param start_time: Start time in datetime
        :param end_time_str: End time in str
        :return: The passed mins in int
    """
    time_delta = start_time - datetime.fromtimestamp(end_time_str)
    return time_delta.seconds / 60


''' COMMAND SPECIFIC FUNCTIONS '''


def get_token(new_token=False):
    """
        Retrieves the token from the server if it's expired and updates the global HEADERS to include it

        :param new_token: If set to True will generate a new token regardless of time passed

        :rtype: ``str``
        :return: Token
    """
    now = datetime.now()
    ctx = demisto.getIntegrationContext()
    if ctx and not new_token:
        passed_mins = get_passed_mins(now, ctx.get('time'))
        if passed_mins >= TOKEN_LIFE_TIME:
            # token expired
            auth_token = get_token_request()
            demisto.setIntegrationContext({'auth_token': auth_token, 'time': date_to_timestamp(now) / 1000})
        else:
            # token hasn't expired
            auth_token = ctx.get('auth_token')
    else:
        # there is no token
        auth_token = get_token_request()
        demisto.setIntegrationContext({'auth_token': auth_token, 'time': date_to_timestamp(now) / 1000})
    return auth_token


def get_token_request():
    """
        Sends token request

        :rtype ``str``
        :return: Access token
    """
    body = {
        'client_id': CLIENT_ID,
        'client_secret': SECRET
    }
    headers = {
        'Authorization': HEADERS['Authorization']
    }
    token_res = http_request('POST', '/oauth2/token', data=body, headers=headers, safe=True,
                             get_token_flag=False)
    if not token_res:
        err_msg = 'Authorization Error: User has no authorization to create a token. Please make sure you entered the' \
                  ' credentials correctly.'
        raise Exception(err_msg)
    return token_res.get('access_token')


def get_detections(last_behavior_time=None, behavior_id=None, filter_arg=None):
    """
        Sends detections request. The function will ignore the arguments passed according to priority:
        filter_arg > behavior_id > last_behavior_time

        :param last_behavior_time: 3rd priority. The last behavior time of results will be greater than this value
        :param behavior_id: 2nd priority. The result will only contain the detections with matching behavior id
        :param filter_arg: 1st priority. The result will be filtered using this argument.
        :return: Response json of the get detection endpoint (IDs of the detections)
    """
    endpoint_url = '/detects/queries/detects/v1'
    params = {
        'sort': 'first_behavior.asc'
    }
    if filter_arg:
        params['filter'] = filter_arg
    elif behavior_id:
        params['filter'] = "behaviors.behavior_id:'{0}'".format(behavior_id)
    elif last_behavior_time:
        params['filter'] = "first_behavior:>'{0}'".format(last_behavior_time)

    response = http_request('GET', endpoint_url, params)
    return response


def get_fetch_detections(last_created_timestamp=None, behavior_id=None, filter_arg=None):
    """ Sends detection request, based om created_timestamp field. Used for fetch-incidents

    Args:
        last_created_timestamp: last created timestamp of the results will be greater than this value.
        behavior_id: The result will only contain the detections with matching behavior id.
        filter_arg: The result will be filtered using this argument.

    Returns:
        Response json of the get detection endpoint (IDs of the detections)
    """
    endpoint_url = '/detects/queries/detects/v1'
    params = {
        'sort': 'first_behavior.asc'
    }
    if filter_arg:
        params['filter'] = filter_arg
    elif behavior_id:
        params['filter'] = "behaviors.behavior_id:'{0}'".format(behavior_id)
    elif last_created_timestamp:
        params['filter'] = "created_timestamp:>'{0}'".format(last_created_timestamp)

    response = http_request('GET', endpoint_url, params)
    return response


def get_detections_entities(detections_ids):
    """
        Sends detection entities request
        :param detections_ids: IDs of the requested detections.
        :return: Response json of the get detection entities endpoint (detection objects)
    """
    ids_json = {'ids': detections_ids}
    if detections_ids:
        response = http_request(
            'POST',
            '/detects/entities/summaries/GET/v1',
            data=json.dumps(ids_json)
        )
        return response
    return detections_ids


def create_ioc():
    """
        UNTESTED - Creates an IoC
        :return: Response json of create IoC request
    """
    args = demisto.args()
    input_args = {}
    # req args:
    input_args['type'] = args['ioc_type']
    input_args['value'] = args['ioc_value']
    input_args['policy'] = args['policy']
    # opt args:
    input_args['expiration_days'] = args.get('expiration_days')
    input_args['source'] = args.get('source')
    input_args['description'] = args.get('description')

    payload = {k: str(v) for k, v in input_args.items() if v}
    headers = {'Authorization': HEADERS['Authorization']}
    return http_request('POST', '/indicators/entities/iocs/v1', params=payload, headers=headers)


def search_iocs():
    """
        UNTESTED IN OAUTH 2- Searches an IoC
        :return: IoCs that were found in the search
    """
    args = demisto.args()
    ids = args.get('ids')
    if not ids:
        search_args = {
            'types': str(args.get('ioc_types', '')).split(','),
            'values': str(args.get('ioc_values', '')).split(','),
            'policies': str(args.get('policy', '')),
            'sources': str(args.get('sources', '')).split(','),
            'from.expiration_timestamp': str(args.get('expiration_from', '')),
            'to.expiration_timestamp': str(args.get('expiration_to', '')),
            'limit': str(args.get('limit', 50))
        }
        payload = {}
        for k, arg in search_args.items():
            if type(arg) is list:
                if arg[0]:
                    payload[k] = arg
            elif arg:
                payload[k] = arg
        ids = http_request('GET', '/indicators/queries/iocs/v1', payload).get('resources')
        if not ids:
            return None
    else:
        ids = str(ids)
    payload = {
        'ids': ids
    }
    return http_request('GET', '/indicators/entities/iocs/v1', params=payload)


def enrich_ioc_dict_with_ids(ioc_dict):
    """
        Enriches the provided ioc_dict with IoC ID
        :param ioc_dict: IoC dict transformed using the SEARCH_IOC_KEY_MAP
        :return: ioc_dict with its ID key:value updated
    """
    for ioc in ioc_dict:
        ioc['ID'] = '{type}:{val}'.format(type=ioc.get('Type'), val=ioc.get('Value'))
    return ioc_dict


def delete_ioc():
    """
        UNTESTED - Sends a delete IoC request
        :return: Response json of delete IoC
    """
    ids = str(demisto.args().get('ids'))
    payload = {
        'ids': ids
    }
    return http_request('DELETE', '/indicators/entities/iocs/v1', payload)


def update_iocs():
    """
        UNTESTED - Updates the values one or more IoC
        :return: Response json of update IoC request
    """
    args = demisto.args()
    input_args = {
        'ids': args.get('ids'),
        'policy': args.get('policy', ''),
        'expiration_days': args.get('expiration_days', ''),
        'source': args.get('source'),
        'description': args.get('description')
    }
    payload = {k: str(v) for k, v in input_args.items() if v}
    headers = {'Authorization': HEADERS['Authorization']}
    return http_request('PATCH', '/indicators/entities/iocs/v1', params=payload, headers=headers)


def search_device():
    """
        Searches for devices using the argument provided by the command execution. Returns empty
        result of no device was found
        :return: Search device response json
    """
    args = demisto.args()
    input_arg_dict = {
        'device_id': str(args.get('ids', '')).split(','),
        'status': str(args.get('status', '')).split(','),
        'hostname': str(args.get('hostname', '')).split(','),
        'platform_name': str(args.get('platform_name', '')).split(','),
        'site_name': str(args.get('site_name', '')).split(',')
    }
    url_filter = '{}'.format(str(args.get('filter', '')))
    for k, arg in input_arg_dict.items():
        if arg:
            if type(arg) is list:
                arg_filter = ''
                for arg_elem in arg:
                    if arg_elem:
                        first_arg = '{filter},{inp_arg}'.format(filter=arg_filter, inp_arg=k) if arg_filter else k
                        arg_filter = "{first}:'{second}'".format(first=first_arg, second=arg_elem)
                if arg_filter:
                    url_filter = "{url_filter}{arg_filter}".format(url_filter=url_filter + '+' if url_filter else '',
                                                                   arg_filter=arg_filter)
            else:
                # All args should be a list. this is a fallback
                url_filter = "{url_filter}+{inp_arg}:'{arg_val}'".format(url_filter=url_filter, inp_arg=k, arg_val=arg)
    raw_res = http_request('GET', '/devices/queries/devices/v1', params={'filter': url_filter})
    device_ids = raw_res.get('resources')
    if not device_ids:
        return None
    return http_request('GET', '/devices/entities/devices/v1', params={'ids': device_ids})


def behavior_to_entry_context(behavior):
    """
        Transforms a behavior to entry context representation
        :param behavior: Behavior dict in the format of crowdstrike's API response
        :return: Behavior in entry context representation
    """
    raw_entry = get_trasnformed_dict(behavior, DETECTIONS_BEHAVIORS_KEY_MAP)
    raw_entry.update(extract_transformed_dict_with_split(behavior, DETECTIONS_BEHAVIORS_SPLIT_KEY_MAP))
    return raw_entry


def resolve_detection(ids, status, assigned_to_uuid, show_in_ui):
    """
        Sends a resolve detection request
        :param ids: Single or multiple ids in an array string format
        :param status: New status of the detection
        :param assigned_to_uuid: uuid to assign the detection to
        :param show_in_ui: Boolean flag in string format (true/false)
        :return: Resolve detection response json
    """
    payload = {
        'ids': ids
    }
    if status:
        payload['status'] = status
    if assigned_to_uuid:
        payload['assigned_to_uuid'] = assigned_to_uuid
    if show_in_ui:
        payload['show_in_ui'] = show_in_ui
    # We do this so show_in_ui value won't contain ""
    data = json.dumps(payload).replace('"show_in_ui": "false"', '"show_in_ui": false').replace('"show_in_ui": "true"',
                                                                                               '"show_in_ui": true')
    return http_request('PATCH', '/detects/entities/detects/v2', data=data)


def contain_host(ids):
    """
        Contains host(s) with matching ids
        :param ids: IDs of host to contain
        :return: Contain host response json
    """
    payload = {
        'ids': ids
    }
    data = json.dumps(payload)
    params = {
        'action_name': 'contain'
    }
    return http_request('POST', '/devices/entities/devices-actions/v2', data=data, params=params)


def lift_host_containment(ids):
    """
        Lifts off containment from host(s) with matchind ids
        :param ids: IDs of host to lift off containment from
        :return: Lift off containment response json
    """
    payload = {
        'ids': ids
    }
    data = json.dumps(payload)
    params = {
        'action_name': 'lift_containment'
    }
    return http_request('POST', '/devices/entities/devices-actions/v2', data=data, params=params)


def timestamp_length_equalization(timestamp1, timestamp2):
    """
        Makes sure the timestamps are of the same length.
    Args:
        timestamp1: a timestamp
        timestamp2: a timestamp

    Returns:
        the two timestamps in the same length (the shorter one)
    """
    if len(str(timestamp1)) > len(str(timestamp2)):
        timestamp1 = str(timestamp1)[:len(str(timestamp2))]

    else:
        timestamp2 = str(timestamp2)[:len(str(timestamp1))]

    return int(timestamp1), int(timestamp2)


''' COMMANDS FUNCTIONS '''


def fetch_incidents():
    """
        Fetches incident using the detections API
        :return: Fetched detections in incident format
    """
    last_run = demisto.getLastRun()
    # Get the last fetch time, if exists
    last_fetch = last_run.get('first_behavior_time')

    # Handle first time fetch, fetch incidents retroactively
    if last_fetch is None:
        last_fetch, _ = parse_date_range(FETCH_TIME, date_format='%Y-%m-%dT%H:%M:%SZ')

    # timestamp creation excepts only '%Y-%m-%dT%H:%M:%SZ' date format
    if '.' in last_fetch:
        last_fetch_for_timestamp = last_fetch.split('.')[0] + 'Z'

    else:
        last_fetch_for_timestamp = last_fetch

    last_fetch_timestamp = date_to_timestamp(last_fetch_for_timestamp, date_format='%Y-%m-%dT%H:%M:%SZ')

    fetch_query = demisto.params().get('fetch_query')

    if fetch_query:
        fetch_query = "created_timestamp:>'{time}'+{query}".format(time=last_fetch, query=fetch_query)
        detections_ids = demisto.get(get_fetch_detections(filter_arg=fetch_query), 'resources')

    else:
        detections_ids = demisto.get(get_fetch_detections(last_created_timestamp=last_fetch), 'resources')
    incidents = []

    if detections_ids:
        # Limit the results to INCIDENTS_PER_FETCH`z
        detections_ids = detections_ids[0:INCIDENTS_PER_FETCH]
        raw_res = get_detections_entities(detections_ids)

        if "resources" in raw_res:
            for detection in demisto.get(raw_res, "resources"):
                incident = detection_to_incident(detection)
                incident_date = incident['occurred']
                incident_date_timestamp = int(parse(incident_date).timestamp())

                # make sure that the two timestamps are in the same length
                if len(str(incident_date_timestamp)) != len(str(last_fetch_timestamp)):
                    incident_date_timestamp, last_fetch_timestamp = timestamp_length_equalization(
                        incident_date_timestamp, last_fetch_timestamp)

                # Update last run and add incident if the incident is newer than last fetch
                if incident_date_timestamp > last_fetch_timestamp:
                    last_fetch = incident_date
                    last_fetch_timestamp = incident_date_timestamp

                incidents.append(incident)

        demisto.setLastRun({'first_behavior_time': last_fetch})

    return incidents


def create_ioc_command():
    """
        UNTESTED - Creates an IoC
        :return: EntryObject of create IoC command
    """
    raw_res = create_ioc()
    return create_entry_object(contents=raw_res, hr="Custom IoC was created successfully.")


def search_iocs_command():
    """
        UNTESTED IN OAUTH 2 - Searches for an ioc
        :return: EntryObject of search IoC command
    """
    raw_res = search_iocs()
    if not raw_res:
        return create_entry_object(hr='Could not find any Indicators of Compromise.')
    iocs = raw_res.get('resources')
    ec = [get_trasnformed_dict(ioc, SEARCH_IOC_KEY_MAP) for ioc in iocs]
    enrich_ioc_dict_with_ids(ec)
    return create_entry_object(contents=raw_res, ec={'CrowdStrike.IoC(val.ID === obj.ID)': ec},
                               hr=tableToMarkdown('Indicators of Compromise', ec))


def delete_iocs_command():
    """
        UNTESTED - Deletes an IoC
        :return: EntryObject of delete IoC command
    """
    raw_res = delete_ioc()
    ids = demisto.args().get('ids')
    return create_entry_object(contents=raw_res, hr="Custom IoC {0} successfully deleted.".format(ids))


def update_iocs_command():
    """
        UNTESTED - Updates an IoC
        :return: EntryObject of update IoC command
    """
    raw_res = update_iocs()
    ids = demisto.args().get('ids')
    return create_entry_object(contents=raw_res, hr="Custom IoC {0} successfully updated.".format(ids))


def search_device_command():
    """
        Searches for a device
        :return: EntryObject of search device command
    """
    raw_res = search_device()
    if not raw_res:
        return create_entry_object(hr='Could not find any devices.')
    devices = raw_res.get('resources')
    entries = [get_trasnformed_dict(device, SEARCH_DEVICE_KEY_MAP) for device in devices]
    headers = ['ID', 'Hostname', 'OS', 'MacAddress', 'LocalIP', 'ExternalIP', 'FirstSeen', 'LastSeen']
    hr = tableToMarkdown('Devices', entries, headers=headers, headerTransform=pascalToSpace)
    ec = {'CrowdStrike.Device(val.ID === obj.ID)': entries}
    return create_entry_object(contents=raw_res, ec=ec, hr=hr)


def get_behavior_command():
    """
        Gets a behavior by ID
        :return: EntryObject of get behavior command
    """
    behavior_id = demisto.args().get('behavior_id')
    detections_ids = demisto.get(get_detections(behavior_id=behavior_id), 'resources')
    raw_res = get_detections_entities(detections_ids)
    entries = []
    if "resources" in raw_res:
        for resource in demisto.get(raw_res, "resources"):
            for behavior in demisto.get(resource, 'behaviors'):
                entries.append(behavior_to_entry_context(behavior))
    hr = tableToMarkdown('Behavior ID: {}'.format(behavior_id), entries, headerTransform=pascalToSpace)
    # no dt since behavior vary by more than their ID
    ec = {'CrowdStrike.Behavior': entries}
    return create_entry_object(contents=raw_res, ec=ec, hr=hr)


def search_detections_command():
    """
        Searches for a detection
        :return: EntryObject of search detections command
    """
    d_args = demisto.args()
    detections_ids = argToList(d_args.get('ids'))
    if not detections_ids:
        filter_arg = d_args.get('filter')
        if not filter_arg:
            return_error('Command Error: Please provide at least one argument.')
        detections_ids = get_detections(filter_arg=filter_arg).get('resources')
    raw_res = get_detections_entities(detections_ids)
    entries = []
    headers = ['ID', 'Status', 'System', 'ProcessStartTime', 'CustomerID', 'MaxSeverity']
    if "resources" in raw_res:
        for detection in demisto.get(raw_res, "resources"):
            detection_entry = {}
            for path, new_key in DETECTIONS_BASE_KEY_MAP.items():
                detection_entry[new_key] = demisto.get(detection, path)
            behaviors = []
            for behavior in demisto.get(detection, 'behaviors'):
                behaviors.append(behavior_to_entry_context(behavior))
            detection_entry['Behavior'] = behaviors
            entries.append(detection_entry)
    hr = tableToMarkdown('Detections Found:', entries, headers=headers, removeNull=True, headerTransform=pascalToSpace)
    ec = {'CrowdStrike.Detection(val.ID === obj.ID)': entries}
    return create_entry_object(contents=raw_res, ec=ec, hr=hr)


def resolve_detection_command():
    """
        Resolves single or multiple detections
        :return: EntryObject of resolve detection command
    """
    args = demisto.args()
    ids = argToList(args.get('ids'))
    status = args.get('status')
    assigned_to_uuid = args.get('assigned_to_uuid')
    show_in_ui = args.get('show_in_ui')
    raw_res = resolve_detection(ids, status, assigned_to_uuid, show_in_ui)
    args.pop('ids')
    hr = "Detection {0} updated\n".format(str(ids)[1:-1])
    hr += 'With the following values:\n'
    for k, arg in args.items():
        hr += '\t{name}:{val}\n'.format(name=k, val=arg)
    return create_entry_object(contents=raw_res, hr=hr)


def contain_host_command():
    """
        Contains hosts with user arg ids
        :return: EntryObject of contain host command
    """
    ids = argToList(demisto.args().get('ids'))
    raw_res = contain_host(ids)
    hr = "Host {} contained".format(str(ids)[1:-1])
    return create_entry_object(contents=raw_res, hr=hr)


def lift_host_containment_command():
    """
        Lifts containment off a host
        :return: EntryObject of lift host containment
    """
    ids = argToList(demisto.args().get('ids'))
    raw_res = lift_host_containment(ids)
    hr = "Containment has been lift off host {}".format(str(ids)[1:-1])
    return create_entry_object(contents=raw_res, hr=hr)


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is {}'.format(demisto.command()))

# should raise error in case of issue
if demisto.command() == 'fetch-incidents':
    demisto.incidents(fetch_incidents())

try:
    if demisto.command() == 'test-module':
        get_token(new_token=True)
        demisto.results('ok')
    elif demisto.command() == 'cs-falcon-search-device':
        demisto.results(search_device_command())
    elif demisto.command() == 'cs-falcon-get-behavior':
        demisto.results(get_behavior_command())
    elif demisto.command() == 'cs-falcon-search-detection':
        demisto.results(search_detections_command())
    elif demisto.command() == 'cs-falcon-resolve-detection':
        demisto.results(resolve_detection_command())
    elif demisto.command() == 'cs-falcon-contain-host':
        demisto.results(contain_host_command())
    elif demisto.command() == 'cs-falcon-lift-host-containment':
        demisto.results(lift_host_containment_command())
    # Log exceptions
except Exception as e:
    return_error(str(e))
