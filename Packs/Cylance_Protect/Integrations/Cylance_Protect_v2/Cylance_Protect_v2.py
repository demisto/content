import demistomock as demisto
from CommonServerPython import *

import jwt
import uuid
import requests
import urllib3
import json
import re
import zipfile
from io import BytesIO
from datetime import datetime, timedelta

# disable insecure warnings
urllib3.disable_warnings()

# CONSTANTS
TOKEN_TIMEOUT = 300  # 5 minutes

URI_AUTH = 'auth/v2/token'
URI_DEVICES = 'devices/v2'
URI_POLICIES = 'policies/v2'
URI_ZONES = 'zones/v2'
URI_THREATS = 'threats/v2'
URI_LISTS = 'globallists/v2'
URI_HOSTNAME = 'devices/v2/hostname'
URI_OPTICS = 'instaqueries/v2'  # Optics InstaQuery API Endpoint

SCOPE_DEVICE_LIST = 'device:list'
SCOPE_DEVICE_READ = 'device:read'
SCOPE_DEVICE_UPDATE = 'device:update'
SCOPE_DEVICE_THREAT_LIST = 'device:threatlist'
SCOPE_POLICY_LIST = 'policy:list'
SCOPE_POLICY_READ = 'policy:read'
SCOPE_ZONE_CREATE = 'zone:create'
SCOPE_ZONE_LIST = 'zone:list'
SCOPE_ZONE_READ = 'zone:read'
SCOPE_ZONE_UPDATE = 'zone:update'
SCOPE_THREAT_READ = 'threat:read'
SCOPE_THREAT_DEVICE_LIST = 'threat:devicelist'
SCOPE_THREAT_UPDATE = 'threat:update'
SCOPE_GLOBAL_LIST = 'globallist:list'
SCOPE_THREAT_LIST = 'threat:list'
SCOPE_GLOBAL_LIST_CREATE = 'globallist:create'
SCOPE_GLOBAL_LIST_DELETE = 'globallist:delete'
SCOPE_OPTICS_LIST = 'opticssurvey:list'  # Get InstaQueries
SCOPE_OPTICS_CREATE = 'opticssurvey:create'  # Create InstaQuery
SCOPE_OPTICS_GET = 'opticssurvey:read'  # Read a InstaQuery


# PREREQUISITES
def load_server_url():   # pragma: no cover
    """ Cleans and loads the server url from the configuration """
    url = demisto.params()['server']
    url = re.sub(r'/[\/]+$/', '', url)
    url = re.sub(r'\/$', '', url)
    return url


# GLOBALS
APP_ID = ''
APP_SECRET = ''
TID = ''
SERVER_URL = ''
FILE_THRESHOLD = ''
USE_SSL = False


# HELPERS
def generate_jwt_times():   # pragma: no cover
    """
    Generates the epoch time window in which the token will be valid
    Returns the current timestamp and the timeout timestamp (in that order)
    """
    now = datetime.utcnow()
    timeout_datetime = now + timedelta(seconds=TOKEN_TIMEOUT)
    epoch_time = int((now - datetime(1970, 1, 1)).total_seconds())
    epoch_timeout = int((timeout_datetime - datetime(1970, 1, 1)).total_seconds())
    return epoch_time, epoch_timeout


def api_call(uri, method='post', headers={}, body={}, params={}, accept_404=False, access_token=''):   # pragma: no cover
    """
    Makes an API call to the server URL with the supplied uri, method, headers, body and params
    """
    if not headers:
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + access_token
        }

    url = f'{SERVER_URL}/{uri}'
    res = requests.request(method, url, headers=headers, data=json.dumps(body), params=params, verify=USE_SSL)
    if res.status_code < 200 or res.status_code >= 300:
        if res.status_code == 409 and str(res.content).find('already an entry for this threat') != -1:
            raise Warning(res.content)
        if res.status_code != 404 and not accept_404:
            return_error(
                'Got status code ' + str(res.status_code) + ' with body ' + str(res.content) + ' with headers ' + str(
                    res.headers))
    return json.loads(res.text) if res.text else res.ok


def get_authentication_token(scope=None):
    """
    Generates a JWT authorization token with an optional scope and queries the API for an access token
    Returns the received API access token
    """
    # Generate token ID
    token_id = str(uuid.uuid4())

    # Generate current time & token timeout
    epoch_time, epoch_timeout = generate_jwt_times()
    # Token claims
    claims = {
        'exp': epoch_timeout,
        'iat': epoch_time,
        'iss': 'http://cylance.com',
        'sub': APP_ID,
        'tid': TID,
        'jti': token_id
    }

    if scope:
        claims['scp'] = scope

    # Encode the token
    encoded = jwt.encode(claims, APP_SECRET, algorithm='HS256')
    payload = {'auth_token': encoded}
    headers = {'Content-Type': 'application/json; charset=utf-8'}
    res = api_call(method='post', uri=URI_AUTH, body=payload, headers=headers)
    return res['access_token']


def threat_to_incident(threat):
    incident = {
        'name': 'Cylance Protect v2 threat ' + threat['name'],
        'occurred': threat['last_found'] + 'Z',
        'rawJSON': json.dumps(threat)
    }

    host_name = None
    devices = get_threat_devices_request(threat['sha256'], None, None)['page_items']
    for device in devices:
        if device['date_found'] == threat['last_found']:
            host_name = device['name']

    labels = [{'type': 'Classification', 'value': threat['classification']}, {'type': 'MD5', 'value': threat['md5']},
              {'type': 'SHA256', 'value': threat['sha256']}, {'type': 'ThreatLastFound', 'value': threat['last_found']},
              {'type': 'HostName', 'value': host_name}]
    incident['labels'] = labels
    return incident


def normalize_score(score):   # pragma: no cover
    """
    Translates API raw float (-1 to 1) score to UI score (-100 to 100)
    """
    return score * 100


def translate_score(score, threshold):   # pragma: no cover
    if score > 0:
        dbot_score = 1
    elif threshold <= score:
        dbot_score = 2
    else:
        dbot_score = 3
    return dbot_score


# FUNCTIONS
def test():   # pragma: no cover
    access_token = get_authentication_token()
    if not access_token:
        raise Exception('Unable to get access token')
    demisto.results('ok')


def get_devices():
    page = demisto.args()['pageNumber'] if 'pageNumber' in demisto.args() else None
    page_size = demisto.args()['pageSize'] if 'pageSize' in demisto.args() else None
    result = get_devices_request(page, page_size)
    devices = result['page_items']
    hr = []
    devices_context = []
    endpoint_context = []
    for device in devices:
        current_device_context = {
            'AgentVersion': device['agent_version'],
            'DateFirstRegistered': device['date_first_registered'],
            'ID': device['id'],
            'IPAddress': device['ip_addresses'],
            'MACAdress': device['mac_addresses'],
            'Hostname': device['name'],
            'State': device['state']
        }
        if device['policy']:
            policy = {}
            if device['policy']['id']:
                policy['ID'] = device['policy']['id']
            if device['policy']['name']:
                policy['Name'] = device['policy']['name']
            if policy:
                current_device_context['Policy'] = policy
        devices_context.append(current_device_context)
        endpoint_context.append({
            'IPAddress': device['ip_addresses'],
            'MACAdress': device['mac_addresses'],
            'Hostname': device['name']
        })
        current_device = dict(device)
        current_device['ip_addresses'] = ', '.join(current_device['ip_addresses'])
        current_device['mac_addresses'] = ', '.join(current_device['mac_addresses'])
        current_device['policy'] = current_device['policy']['name']
        hr.append(current_device)

    ec = {
        'CylanceProtect.Device(val.ID && val.ID === obj.ID)': devices_context,
        'Endpoint(val.Hostname && val.Hostname === obj.Hostname)': endpoint_context
    }

    entry = {
        'Type': entryTypes['note'],
        'Contents': devices,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Cylance Protect Devices', hr, headerTransform=underscoreToCamelCase,
                                         removeNull=True),
        'EntryContext': ec
    }

    demisto.results(entry)


def get_devices_request(page=None, page_size=None):  # pragma: no cover
    access_token = get_authentication_token(scope=SCOPE_DEVICE_LIST)

    params = {}
    if page:
        params['page'] = page
    if page_size:
        params['page_size'] = page_size
    res = api_call(uri=URI_DEVICES, method='get', params=params, access_token=access_token)
    return res


def get_device():
    device_id = demisto.args()['id']
    device = get_device_request(device_id)
    hr = []
    if device:
        device_context = {
            'IPAddress': device['ip_addresses'],
            'MACAdress': device['mac_addresses'],
            'Hostname': device['host_name'],
            'OSVersion': device['os_version'],
            'UpdateAvailable': device['update_available'],
            'BackgroundDetection': device['background_detection'],
            'DateFirstRegistered': device['date_first_registered'],
            'DateLastModified': device['date_last_modified'],
            'DateOffline': device['date_offline'],
            'IsSafe': device['is_safe'],
            'LastLoggedInUser': device['last_logged_in_user'],
            'State': device['state'],
            'ID': device['id'],
            'Name': device['name']
        }
        if device['update_type']:
            device_context['UpdateType'] = device['update_type']
        if device['policy']:
            policy = {}
            if device['policy']['id']:
                policy['ID'] = device['policy']['id']
            if device['policy']['name']:
                policy['Name'] = device['policy']['name']
            if policy:
                device_context['Policy'] = policy
        endpoint_context = {
            'IPAddress': device['ip_addresses'],
            'MACAdress': device['mac_addresses'],
            'Hostname': device['host_name'],
            'OSVersion': device['os_version']
        }
        ec = {
            'Endpoint(val.Hostname && val.Hostname === obj.Hostname)': endpoint_context,
            'CylanceProtect.Device(val.ID && val.ID === obj.ID)': device_context
        }

        current_device = dict(device)
        current_device['ip_addresses'] = ', '.join(current_device['ip_addresses'])
        current_device['mac_addresses'] = ', '.join(current_device['mac_addresses'])
        current_device['policy'] = current_device['policy']['name']
        hr.append(current_device)

    else:
        ec = {}

    title = 'Cylance Protect Device ' + device_id

    entry = {
        'Type': entryTypes['note'],
        'Contents': device,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, hr, headerTransform=underscoreToCamelCase, removeNull=True),
        'EntryContext': ec
    }

    demisto.results(entry)


def get_device_request(device_id):  # pragma: no cover
    access_token = get_authentication_token(scope=SCOPE_DEVICE_READ)

    uri = f'{URI_DEVICES}/{device_id}'
    res = api_call(uri=uri, method='get', access_token=access_token)
    return res


def get_device_by_hostname():
    hostname_id = demisto.args()['hostname']
    device = get_hostname_request(hostname_id)
    title = 'Cylance Protect Device ' + hostname_id
    if device:
        device_context = {
            'AgentVersion': device['agent_version'],
            'IPAddress': device['ip_addresses'],
            'MACAdress': device['mac_addresses'],
            'Hostname': device['host_name'],
            'OSVersion': device['os_version'],
            'UpdateAvailable': device['update_available'],
            'BackgroundDetection': device['background_detection'],
            'DateFirstRegistered': device['date_first_registered'],
            'DateLastModified': device['date_last_modified'],
            'DateOffline': device['date_offline'],
            'IsSafe': device['is_safe'],
            'LastLoggedInUser': device['last_logged_in_user'],
            'State': device['state'],
            'ID': device['id'],
            'Name': device['name']
        }
        if device['update_type']:
            device_context['UpdateType'] = device['update_type']
        if device['policy']:
            policy = {}
            if device['policy']['id']:
                policy['ID'] = device['policy']['id']
            if device['policy']['name']:
                policy['Name'] = device['policy']['name']
            if policy:
                device_context['Policy'] = policy
        endpoint_context = {
            'IPAddress': device['ip_addresses'],
            'MACAdress': device['mac_addresses'],
            'Hostname': device['host_name'],
            'OSVersion': device['os_version']
        }
        ec = {
            'Endpoint(val.Hostname && val.Hostname === obj.Hostname)': endpoint_context,
            'CylanceProtect.Device(val.ID && val.ID === obj.ID)': device_context
        }

        current_device = dict(device)
        current_device['ip_addresses'] = ', '.join(current_device['ip_addresses'])
        current_device['mac_addresses'] = ', '.join(current_device['mac_addresses'])
        current_device['policy'] = current_device['policy']['name']
        hr = tableToMarkdown(title, [current_device], headerTransform=underscoreToCamelCase, removeNull=True)

    else:
        ec = {}
        hr = '### Device For Hostname ' + hostname_id + ' Was Not Found'

    entry = {
        'Type': entryTypes['note'],
        'Contents': device,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr,
        'EntryContext': ec
    }

    demisto.results(entry)


def get_hostname_request(hostname):  # pragma: no cover

    access_token = get_authentication_token(scope=SCOPE_DEVICE_READ)

    uri = f'{URI_HOSTNAME}/{hostname}'
    res = api_call(uri=uri, method='get', access_token=access_token)
    if not res:
        return None
    return res[0]


def update_device():
    device_id = demisto.args()['id']

    name = demisto.args()['name'] if 'name' in demisto.args() else None
    policy_id = demisto.args()['policyId'] if 'policyId' in demisto.args() else None
    add_zones = demisto.args()['addZones'] if 'addZones' in demisto.args() else None
    remove_zones = demisto.args()['removeZones'] if 'removeZones' in demisto.args() else None

    update_device_request(device_id, name, policy_id, add_zones, remove_zones)

    hr = {}

    if name:
        hr['Name'] = name
    if policy_id:
        hr['PolicyID'] = policy_id
    if add_zones:
        hr['AddedZones'] = add_zones
    if remove_zones:
        hr['RemovedZones'] = remove_zones

    device = hr.copy()
    device['id'] = device_id

    title = 'Device ' + device_id + ' was updated successfully.'
    entry = {
        'Type': entryTypes['note'],
        'Contents': device,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, [hr])
    }

    demisto.results(entry)


def update_device_request(device_id, name=None, policy_id=None, add_zones=None, remove_zones=None):  # pragma: no cover
    access_token = get_authentication_token(scope=SCOPE_DEVICE_UPDATE)

    body = {}
    if name:
        body['name'] = name
    if policy_id:
        body['policy_id'] = policy_id
    if add_zones:
        body['add_zone_ids'] = [add_zones]
    if remove_zones:
        body['remove_zone_ids'] = [remove_zones]

    # Do we have anything to update?
    if not body:
        raise Exception('No changes detected')

    uri = f'{URI_DEVICES}/{device_id}'
    res = api_call(uri=uri, method='put', access_token=access_token, body=body)
    return res


def get_device_threats():
    device_id = demisto.args()['id']
    page = demisto.args()['pageNumber'] if 'pageNumber' in demisto.args() else None
    page_size = demisto.args()['pageSize'] if 'pageSize' in demisto.args() else None

    device_threats = get_device_threats_request(device_id, page, page_size)['page_items']
    dbot_score_array = []

    for threat in device_threats:
        dbot_score = 0
        score = threat.get('cylance_score', None)
        if score:
            threat['cylance_score'] = normalize_score(threat['cylance_score'])
            threshold = demisto.args().get('threshold', FILE_THRESHOLD)
            dbot_score = translate_score(threat['cylance_score'], int(threshold))
        dbot_score_array.append(create_dbot_score_entry(threat, dbot_score).to_context())
    if device_threats:
        dbot_score_dict = {Common.DBotScore.get_context_path(): []}  # type: Dict[str, List[Dict[str, str]]]
        for dbot_score_entry in dbot_score_array:
            for _key, value in list(dbot_score_entry.items()):
                dbot_score_dict[Common.DBotScore.get_context_path()].append(value)

        threats_context = createContext(data=device_threats, keyTransform=underscoreToCamelCase)
        threats_context = add_capitalized_hash_to_context(threats_context)
        ec = {'File': threats_context}
        ec.update(dbot_score_dict)

        title = 'Cylance Protect Device Threat ' + device_id
        demisto.results({
            'Type': entryTypes['note'],
            'Contents': device_threats,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, device_threats, headerTransform=underscoreToCamelCase),
            'EntryContext': ec
        })
    else:
        demisto.results('No threats found.')


def get_device_threats_request(device_id, page=None, page_size=None):  # pragma: no cover
    access_token = get_authentication_token(scope=SCOPE_DEVICE_THREAT_LIST)

    params = {}
    if page:
        params['page'] = page
    if page_size:
        params['page_size'] = page_size
    uri = f'{URI_DEVICES}/{device_id}/threats'
    res = api_call(uri=uri, method='get', access_token=access_token, params=params)
    return res


def get_policies():
    page = demisto.args()['pageNumber'] if 'pageNumber' in demisto.args() else None
    page_size = demisto.args()['pageSize'] if 'pageSize' in demisto.args() else None

    policies = get_policies_request(page, page_size)['page_items']

    context_policies = createContext(data=policies, keyTransform=underscoreToCamelCase)
    ec = {
        'CylanceProtect.Policies(val.id && val.id === obj.id)': context_policies
    }

    title = 'Cylance Protect Policies'
    entry = {
        'Type': entryTypes['note'],
        'Contents': policies,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, policies, headerTransform=underscoreToCamelCase),
        'EntryContext': ec
    }

    demisto.results(entry)


def get_policies_request(page=None, page_size=None):  # pragma: no cover
    access_token = get_authentication_token(scope=SCOPE_POLICY_LIST)

    params = {}
    if page:
        params['page'] = page
    if page_size:
        params['page_size'] = page_size

    res = api_call(uri=URI_POLICIES, method='get', access_token=access_token, params=params)
    return res


def create_zone():
    name = demisto.args()['name']
    policy_id = demisto.args()['policy_id']
    criticality = demisto.args()['criticality']

    zone = create_zone_request(name, policy_id, criticality)

    title = 'Zone ' + name + ' was created successfully.'
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': zone,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, [zone], headerTransform=underscoreToCamelCase)
    })


def create_zone_request(name, policy_id, criticality):  # pragma: no cover
    access_token = get_authentication_token(scope=SCOPE_ZONE_CREATE)

    body = {
        'name': name,
        'policy_id': policy_id,
        'criticality': criticality
    }
    res = api_call(uri=URI_ZONES, method='post', access_token=access_token, body=body)
    return res


def get_zones():
    page = demisto.args()['pageNumber'] if 'pageNumber' in demisto.args() else None
    page_size = demisto.args()['pageSize'] if 'pageSize' in demisto.args() else None

    zones = get_zones_request(page, page_size)['page_items']

    context_zones = createContext(data=zones, keyTransform=underscoreToCamelCase, removeNull=True)
    ec = {
        'CylanceProtect.Zones(val.Id && val.Id === obj.Id)': context_zones
    }
    title = 'Cylance Protect Zones'

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': zones,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, zones, headerTransform=underscoreToCamelCase, removeNull=True),
        'EntryContext': ec
    })


def get_zones_request(page=None, page_size=None):  # pragma: no cover
    access_token = get_authentication_token(scope=SCOPE_ZONE_LIST)

    params = {}
    if page:
        params['page'] = page
    if page_size:
        params['page_size'] = page_size

    res = api_call(uri=URI_ZONES, method='get', access_token=access_token, params=params)
    return res


def get_zone():
    zone_id = demisto.args()['id']
    zone = get_zone_request(zone_id)

    context_zone = createContext(data=zone, keyTransform=underscoreToCamelCase, removeNull=True)
    ec = {
        'CylanceProtect.Zones(val.Id && val.Id === obj.Id)': context_zone
    }
    title = 'Cylance Protect Zone ' + zone_id

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': zone,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, zone, headerTransform=underscoreToCamelCase, removeNull=True),
        'EntryContext': ec
    })


def get_zone_request(zone_id):  # pragma: no cover
    access_token = get_authentication_token(scope=SCOPE_ZONE_READ)

    uri = f'{URI_ZONES}/{zone_id}'
    res = api_call(uri=uri, method='get', access_token=access_token)
    return res


def update_zone():
    zone_id = demisto.args()['id']

    # Get current zone and fill in requires missing arguments
    current_zone = get_zone_request(zone_id)

    # Details to update
    name = demisto.args()['name'] if 'name' in demisto.args() else current_zone['name']
    policy_id = demisto.args()['policy_id'] if 'policy_id' in demisto.args() else current_zone['policy_id']
    criticality = demisto.args()['criticality'] if 'criticality' in demisto.args() else current_zone['criticality']
    zone = update_zone_request(zone_id, name, policy_id, criticality)
    hr = {}
    if name:
        hr['Name'] = name
    if policy_id:
        hr['PolicyID'] = policy_id
    if criticality:
        hr['Criticality'] = criticality
    title = 'Zone was updated successfully.'

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': zone,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, [hr])
    })


def update_zone_request(zone_id, name, policy_id, criticality):  # pragma: no cover
    access_token = get_authentication_token(scope=SCOPE_ZONE_UPDATE)

    body = {}
    if name:
        body['name'] = name
    if policy_id:
        body['policy_id'] = policy_id
    if criticality:
        body['criticality'] = criticality

    # Do we have anything to update?
    if not body:
        raise Exception('No changes detected')

    uri = f'{URI_ZONES}/{zone_id}'
    res = api_call(uri=uri, method='put', access_token=access_token, body=body)
    return res


def get_threat():
    sha256 = demisto.args().get('sha256')
    threat = get_threat_request(sha256)
    if threat:
        dbot_score = 0
        score = threat.get('cylance_score', None)
        if score:
            threat['cylance_score'] = normalize_score(threat['cylance_score'])
            threshold = demisto.args().get('threshold', FILE_THRESHOLD)
            dbot_score = translate_score(threat['cylance_score'], int(threshold))
        context_threat = createContext(data=threat, keyTransform=underscoreToCamelCase, removeNull=True)
        context_threat = add_capitalized_hash_to_context(context_threat)
        ec = {'File': context_threat}
        ec.update(create_dbot_score_entry(threat, dbot_score).to_context())

        title = 'Cylance Protect Threat ' + sha256

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': threat,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, threat, headerTransform=underscoreToCamelCase, removeNull=True),
            'EntryContext': ec
        })
    else:
        demisto.results('Threat was not found.')


def get_threat_request(sha256):  # pragma: no cover
    access_token = get_authentication_token(scope=SCOPE_THREAT_READ)

    uri = f'{URI_THREATS}/{sha256}'
    res = api_call(uri=uri, method='get', access_token=access_token, body={}, params={}, accept_404=False)
    return res


def create_dbot_score_entry(threat, dbot_score):
    dbot_score_entry = Common.DBotScore(
        threat.get('sha256'),
        DBotScoreType.FILE,
        integration_name='Cylance Protect',
        score=dbot_score)
    return dbot_score_entry


def get_threats():
    page = demisto.args().get('pageNumber')
    page_size = demisto.args().get('pageSize')

    threats = get_threats_request(page, page_size)['page_items']
    dbot_score_array = []
    for threat in threats:
        dbot_score = 0
        score = threat.get('cylance_score', None)
        if score:
            threat['cylance_score'] = normalize_score(threat['cylance_score'])
            threshold = demisto.args().get('threshold', FILE_THRESHOLD)
            dbot_score = translate_score(threat['cylance_score'], int(threshold))
        dbot_score_array.append(create_dbot_score_entry(threat, dbot_score).to_context())

    dbot_score_dict = {Common.DBotScore.get_context_path(): []}  # type: Dict[str, List[Dict[str, str]]]
    for dbot_score_entry in dbot_score_array:
        for _key, value in list(dbot_score_entry.items()):
            dbot_score_dict[Common.DBotScore.get_context_path()].append(value)

    context_threat = createContext(data=threats, keyTransform=underscoreToCamelCase, removeNull=True)
    context_threat = add_capitalized_hash_to_context(context_threat)
    ec = {'File': context_threat}
    ec.update(dbot_score_dict)
    title = 'Cylance Protect Threats'
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': threats,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, threats, headerTransform=underscoreToCamelCase, removeNull=True),
        'EntryContext': ec
    })


def get_threats_request(page=None, page_size=None):  # pragma: no cover
    access_token = get_authentication_token(scope=SCOPE_THREAT_LIST)

    params = {}
    if page in demisto.args():
        params['page'] = demisto.args()['page']
    if page_size in demisto.args():
        params['page_size'] = demisto.args()['pageSize']

    res = api_call(uri=URI_THREATS, method='get', access_token=access_token, params=params)
    return res


def get_threat_devices():
    threat_hash = demisto.args()['sha256']
    page = demisto.args()['pageNumber'] if 'pageNumber' in demisto.args() else None
    page_size = demisto.args()['pageSize'] if 'pageSize' in demisto.args() else None

    threats = get_threat_devices_request(threat_hash, page, page_size)['page_items']

    if threats:
        threats_context = threats[:]

        for threat in threats:
            threat['ip_addresses'] = ', '.join(threat['ip_addresses'])
            threat['mac_addresses'] = ', '.join(threat['mac_addresses'])

        file_paths = []
        endpoint_context = []
        devices_context = []
        for threat in threats_context:
            endpoint_context.append({
                'Hostname': threat['name'],
                'IPAddress': threat['ip_addresses'],
                'MACAddress': threat['mac_addresses']
            })
            current_device = {
                'Hostname': threat['name'],
                'IPAddress': threat['ip_addresses'],
                'MACAddress': threat['mac_addresses'],
                'AgentVersion': threat['agent_version'],
                'DateFound': threat['date_found'],
                'FilePath': threat['file_path'],
                'ID': threat['id'],
                'State': threat['state'],
                'FileStatus': threat['file_status']
            }
            if threat['policy_id']:
                current_device['PolicyID'] = threat['policy_id']
            devices_context.append(current_device)
            file_path = threat.pop('file_path')
            file_paths.append({
                'FilePath': file_path
            })

        file_context = {
            'SHA256': threat_hash,
            'Path': file_paths
        }

        ec = {
            'File': file_context,
            'Endpoint(val.Hostname && val.Hostname === obj.Hostname)': endpoint_context,
            'CylanceProtect.Threat(val.SHA256 && val.SHA256 === obj.SHA256)': {
                'SHA256': threat_hash,
                'Devices': devices_context
            }
        }

        title = 'Cylance Protect Threat ' + threat_hash + ' Devices'
        demisto.results({
            'Type': entryTypes['note'],
            'Contents': threats,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, threats, headerTransform=underscoreToCamelCase, removeNull=True),
            'EntryContext': ec
        })
    else:
        demisto.results('No devices found on given threat.')


def get_threat_devices_request(threat_hash, page=None, page_size=None):  # pragma: no cover
    access_token = get_authentication_token(scope=SCOPE_THREAT_DEVICE_LIST)

    params = {}
    if page:
        params['page'] = page
    if page_size:
        params['page_size'] = page_size

    uri = f'{URI_THREATS}/{threat_hash}/devices'
    res = api_call(uri=uri, method='get', access_token=access_token, params=params)
    return res


def get_list():
    page = demisto.args()['pageNumber'] if 'pageNumber' in demisto.args() else None
    page_size = demisto.args()['pageSize'] if 'pageSize' in demisto.args() else None

    lst = get_list_request(demisto.args()['listTypeId'], page, page_size)['page_items']
    dbot_score_array = []
    for threat in lst:
        dbot_score = 0
        score = threat.get('cylance_score', None)
        if score:
            threat['cylance_score'] = normalize_score(threat['cylance_score'])
            threshold = demisto.args().get('threshold', FILE_THRESHOLD)
            dbot_score = translate_score(threat['cylance_score'], int(threshold))
        dbot_score_array.append(create_dbot_score_entry(threat, dbot_score).to_context())
    if lst:
        dbot_score_dict = {Common.DBotScore.get_context_path(): []}  # type: Dict[str, List[Dict[str, str]]]
        for dbot_score_entry in dbot_score_array:
            for _key, value in list(dbot_score_entry.items()):
                dbot_score_dict[Common.DBotScore.get_context_path()].append(value)

        context_list = createContext(data=lst, keyTransform=underscoreToCamelCase, removeNull=True)
        context_list = add_capitalized_hash_to_context(context_list)
        ec = {'File': context_list}
        ec.update(dbot_score_dict)

        title = 'Cylance Protect Global List'
        demisto.results({
            'Type': entryTypes['note'],
            'Contents': lst,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, lst, headerTransform=underscoreToCamelCase, removeNull=True),
            'EntryContext': ec
        })
    else:
        demisto.results('No list of this type was found.')


def get_list_request(list_type_id, page=None, page_size=None):  # pragma: no cover
    access_token = get_authentication_token(scope=SCOPE_GLOBAL_LIST)

    params = {}
    if list_type_id == 'GlobalQuarantine':
        params['listTypeId'] = 0
    else:  # List Type ID is GlobalSafe
        params['listTypeId'] = 1
    if page:
        params['page'] = page
    if page_size:
        params['page_size'] = page_size
    res = api_call(uri=URI_LISTS, method='get', access_token=access_token, params=params)
    return res


def get_list_entry_by_hash(sha256=None, list_type_id=None):
    if not sha256:
        sha256 = demisto.args()['sha256']
    if not list_type_id:
        list_type_id = demisto.args()['listTypeId']
    total_pages = 0
    current_page = 0
    found_hash = None
    while not found_hash and total_pages >= current_page:
        if not current_page:
            current_page = 1
        lst = get_list_request(list_type_id, current_page, 200)
        if not total_pages:
            total_pages = lst['total_pages']
        for i in lst['page_items']:
            if i['sha256'] == sha256:
                found_hash = i
                break
        current_page += 1
    if demisto.command() == 'cylance-protect-get-list-entry':
        if found_hash:
            context_list = createContext(data=found_hash, keyTransform=underscoreToCamelCase, removeNull=True)
            ec = {
                'CylanceListSearch': context_list
            }
            title = 'Cylance Protect Global List Entry'

            demisto.results({
                'Type': entryTypes['note'],
                'Contents': found_hash,
                'ContentsFormat': formats['json'],
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': tableToMarkdown(title, found_hash, headerTransform=underscoreToCamelCase,
                                                 removeNull=True),
                'EntryContext': ec
            })
            return None
        else:
            demisto.results("Hash not found")
            return None
    else:
        return found_hash


def get_indicators_report():  # pragma: no cover

    url = 'https://protect.cylance.com/Reports/ThreatDataReportV1/indicators/' + demisto.args()['token']
    res = requests.request('GET', url, verify=USE_SSL)
    filename = 'Indicators_Report.csv'
    demisto.results(fileResult(filename, res.content))


def update_device_threats():  # pragma: no cover
    device_id = demisto.args()['device_id']
    threat_id = demisto.args()['threat_id']
    event = demisto.args()['event']
    update_device_threats_request(device_id, threat_id, event)
    demisto.results('Device threat was updated successfully.')


def update_device_threats_request(device_id, threat_id, event):  # pragma: no cover
    access_token = get_authentication_token(scope=SCOPE_THREAT_UPDATE)

    body = {
        'threat_id': threat_id,
        'event': event
    }

    uri = f'{URI_DEVICES}/{device_id}/threats'
    res = api_call(uri=uri, method='post', access_token=access_token, body=body)

    return res


def download_threat():
    contents = {}
    context = {}
    dbot_score = 0

    sha256 = demisto.args()['sha256']
    threat_url = download_threat_request(sha256)

    threat_file = requests.get(threat_url, allow_redirects=True, verify=USE_SSL)
    if threat_file.status_code == 200:
        if demisto.args()['unzip'] == "yes":
            file_archive = BytesIO(threat_file.content)
            zip_file = zipfile.ZipFile(file_archive)
            file_data = zip_file.read(sha256.upper(), pwd=b'infected')
            demisto.results(fileResult(sha256, file_data))
        else:
            demisto.results(fileResult(sha256, threat_file.content + b'.zip'))
    else:
        return_error('Could not fetch the file')

    threat = get_threat_request(sha256)
    if threat:
        # add data about the threat if found
        if threat.get('cylance_score'):
            score = normalize_score(threat.get('cylance_score'))
            threshold = demisto.args().get('threshold', FILE_THRESHOLD)
            dbot_score = translate_score(score, int(threshold))

        contents = {
            'Download URL': threat_url,
            'File Name': threat.get('name'),
            'File Size': threat.get('file_size'),
            'Detected By': threat.get('detected_by'),
            'GlobalQuarantine': threat.get('global_quarantined'),
            'Safelisted': threat.get('safelisted'),
            'Timestamp': threat.get('cert_timestamp'),
        }

        context[outputPaths['file']] = {
            'DownloadURL': threat_url,
            'SHA256': threat.get('sha256'),
            'Name': threat.get('name'),
            'Size': threat.get('file_size'),
            'Safelisted': threat.get('safelisted'),
            'Timestamp': threat.get('cert_timestamp'),
            'MD5': threat.get('md5')
        }

        if dbot_score == 3:
            context[outputPaths['file']]['Malicious'] = {
                'Vendor': 'Cylance Protect',
                'Description': 'Score determined by get threat command'
            }

        context[outputPaths['dbotscore']] = {
            'Indicator': threat.get('sha256'),
            'Type': 'file',
            'Vendor': 'Cylance Protect',
            'Score': dbot_score
        }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Cylance Protect - Downloading threat attached to the following hash: '
                                         + sha256, contents),
        'EntryContext': context
    })


def download_threat_request(hash):  # pragma: no cover
    access_token = get_authentication_token(scope=SCOPE_THREAT_READ)

    uri = '{}/{}/{}'.format(URI_THREATS, "download", hash)
    res = api_call(uri=uri, method='get', access_token=access_token)
    if not isinstance(res, dict) or not res.get('url'):
        error_msg = f'No url was found - {res}' if isinstance(res, str) else 'No url was found'
        return_error(error_msg)
    return res['url']


def add_hash_to_list():
    context = {}

    sha256 = demisto.args().get('sha256')
    list_type = demisto.args().get('listType')
    reason = demisto.args().get('reason')
    category = demisto.args().get('category')

    if list_type == "GlobalSafe" and not category:
        return_error('Category argument is required for list type of Global Safe')

    add_hash = add_hash_to_list_request(sha256, list_type, reason, category)
    if not add_hash:
        return_error('Could not add hash to list')

    contents = {
        'Threat File SHA256': sha256,
        'List Type': list_type,
        'Category': category,
        'Reason': reason
    }

    context[outputPaths['file']] = {
        'SHA256': sha256,
        'Cylance': {
            'ListType': list_type,
            'Category': category
        }
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(
            f'The requested threat has been successfully added to {list_type} hashlist.', contents),
        'EntryContext': context
    })


def add_hash_to_list_request(sha256, list_type, reason, category=None):  # pragma: no cover
    access_token = get_authentication_token(scope=SCOPE_GLOBAL_LIST_CREATE)

    body = {
        'sha256': sha256,
        'list_type': list_type,
        'reason': reason
    }
    if category:
        body['category'] = category.replace(" ", "")
    res = api_call(uri=URI_LISTS, method='post', access_token=access_token, body=body)
    return res


def delete_hash_from_lists():
    sha256 = demisto.args().get('sha256')
    list_type = demisto.args().get('listType')
    context = {}

    delete_hash_from_lists_request(sha256, list_type)

    contents = {
        'Threat File SHA256': sha256,
        'Threat List Type': list_type
    }

    context[outputPaths['file']] = {
        'SHA256': sha256,
        'Cylance': {
            'ListType': list_type
        }
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(
            f'The requested threat has been successfully removed from {list_type} hashlist.', contents),
        'EntryContext': context
    })


def delete_hash_from_lists_request(sha256, list_type):  # pragma: no cover
    access_token = get_authentication_token(scope=SCOPE_GLOBAL_LIST_DELETE)

    body = {
        'sha256': sha256,
        'list_type': list_type
    }
    res = api_call(uri=URI_LISTS, method='delete', access_token=access_token, body=body)
    return res


def delete_devices():
    device_ids = demisto.args().get('deviceIds')
    device_ids_list = argToList(device_ids)
    contents = []
    context_list = []

    for device_id in device_ids_list:
        device = get_device_request(device_id)
        if not device:
            continue
        device_name = device.get('name')
        context_list.append({
            'Id': device_id,
            'Name': device_name,
            'Deleted': True
        })
        contents.append({
            'Device Removed': device_id,
            'Device Name': device_name,
            'Deletion status': True
        })
    batch_size = demisto.args().get("batch_size", 20)
    try:
        batch_size = int(batch_size)
    except ValueError:
        return_error("Error: Batch Size specified must represent an int.")
    for i in range(0, len(device_ids_list), batch_size):
        current_deleted_devices_batch = device_ids_list[i:i + batch_size]
        delete_devices_request(current_deleted_devices_batch)

    context = {
        'Cylance.Device(val.Id && val.Id == obj.Id)': context_list
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(
            'The requested devices have been successfully removed from your organization list.', contents),
        'EntryContext': context
    })


def delete_devices_request(device_ids):  # pragma: no cover
    access_token = get_authentication_token()

    body = {
        'device_ids': device_ids
    }

    res = api_call(uri=URI_DEVICES, method='delete', access_token=access_token, body=body)
    if not res or not res.get('request_id'):
        return_error('Delete response does not contain request id')

    return res


def get_policy_details():
    policy_id = demisto.args()['policyID']
    contents = {}  # type: Dict
    context = {}  # type: Dict
    title = 'Could not find policy details for that ID'
    filetype_actions_threat_contents = []  # type: list
    filetype_actions_suspicious_contents = []  # type: list
    safelist_contents = []  # type: list
    title_filetype_actions_threat = 'Cylance Policy Details - FileType Actions Threat Files'
    title_filetype_actions_suspicious = 'Cylance Policy Details - FileType Actions Suspicious Files'
    title_safelist = 'Cylance Policy Details - File Exclusions - SafeList'
    title_memory_exclusion = 'Cylance Policy Details - Memory Violation Actions \n' + \
                             'This table provides detailed information about the memory violation settings. \n' + \
                             'Memory protections Exclusion List :'
    title_memory_violation = 'Memory Violation Settings: '
    title_additional_settings = 'Cylance Policy Details - Policy Settings. \n' + \
                                'Various policy settings are contained within this section.'

    policy_details = get_policy_details_request(policy_id)
    memory_violations_content = []

    if policy_details:
        title = 'Cylance Policy Details for: ' + policy_id
        date_time = ''
        # timestamp in response comes back as bugged string, convert to actual timestamp.
        timestamp = policy_details.get('policy_utctimestamp')
        if timestamp:
            reg = re.search(r"\d{13}", timestamp)
            if reg:
                ts = float(reg.group())
                date_time = datetime.fromtimestamp(ts / 1000).strftime('%Y-%m-%dT%H:%M:%S.%f+00:00')

        context = {
            'ID': policy_details.get('policy_id'),
            'Name': policy_details.get('policy_name'),
            'Timestamp': date_time
        }

        contents = {
            'Policy Name': policy_details.get('policy_name'),
            'Policy Created At': date_time
        }

        suspicious_files = policy_details.get('filetype_actions').get('suspicious_files')
        if suspicious_files:
            suspicious_files_list = []
            for file in suspicious_files:
                suspicious_files_list.append({
                    'Actions': file.get('actions'),
                    'File Type': file.get('file_type')
                })

        threat_files = policy_details.get('filetype_actions').get('threat_files')
        if threat_files:
            threat_files_list = []
            for file in threat_files:
                threat_files_list.append({
                    'Actions': file.get('actions'),
                    'File Type': file.get('file_type')
                })

        filetype_actions_suspicious_contents = suspicious_files_list
        filetype_actions_threat_contents = threat_files_list
        safelist = policy_details.get('file_exclusions')
        if safelist:
            file_exclusions_list = []
            for file_exclusion in safelist:
                file_exclusions_list.append({
                    'Research Class ID': file_exclusion.get('research_class_id'),
                    'Infinity': file_exclusion.get('infinity'),
                    'File Type': file_exclusion.get('file_type'),
                    'AV Industry': file_exclusion.get('av_industry'),
                    'Cloud Score': file_exclusion.get('cloud_score'),
                    'File Hash': file_exclusion.get('file_hash'),
                    'Research Subclass ID': file_exclusion.get('research_subclass_id'),
                    'Reason': file_exclusion.get('reason'),
                    'File Name': file_exclusion.get('file_name'),
                    'Category Id': file_exclusion.get('category_id'),
                    'MD5': file_exclusion.get('md5')
                })

            safelist_contents = file_exclusions_list

        memory_violations = policy_details.get('memoryviolation_actions').get('memory_violations')
        for memory_violation in memory_violations:
            memory_violations_content.append({
                'Action': memory_violation.get('action'),
                'Violation Type': memory_violation.get('violation_type')
            })

        additional_settings = policy_details.get('policy')
        additional_settings_content = []
        for additional_setting in additional_settings:
            additional_settings_content.append({
                'Name': additional_setting.get('name'),
                'Value': additional_setting.get('value')
            })

    context.update(policy_details)
    results = CommandResults(
        outputs=context,
        outputs_prefix='Cylance.Policy',
        outputs_key_field='policy_id',
        readable_output=tableToMarkdown(title, contents)
        + tableToMarkdown(title_filetype_actions_suspicious, filetype_actions_suspicious_contents)
        + tableToMarkdown(title_filetype_actions_threat, filetype_actions_threat_contents)
        + tableToMarkdown(title_safelist, safelist_contents)
        + tableToMarkdown(title_memory_exclusion, policy_details.get('memory_exclusion_list'))
        + tableToMarkdown(title_memory_violation, memory_violations_content)
        + tableToMarkdown(title_additional_settings, memory_violations_content),
        raw_response=policy_details
    )
    return_results(results)


def get_policy_details_request(policy_id):   # pragma: no cover
    access_token = get_authentication_token(scope=SCOPE_POLICY_READ)

    uri = f'{URI_POLICIES}/{policy_id}'
    res = api_call(uri=uri, method='get', access_token=access_token)
    return res


def create_instaquery_request(name, description, artifact, value_type, match_values, match_type, zone_list):
    # Create request
    data = {
        "name": name,
        "description": description,
        "artifact": artifact,
        "match_value_type": value_type,
        "match_values": match_values,
        "case_sensitive": False,
        "match_type": match_type,
        "zones": zone_list
    }

    access_token = get_authentication_token([SCOPE_OPTICS_CREATE, SCOPE_OPTICS_GET])
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + access_token
    }
    uri = URI_OPTICS
    res = api_call(uri=uri, method='post', body=data, headers=headers)
    return res


def create_instaquery():
    query_args = demisto.args()
    name = query_args.get('name')
    description = query_args.get('description')
    artifact = query_args.get('artifact')
    match_value_type = query_args.get('match_value_type')
    match_values = query_args.get('match_values').split(",")
    match_type = query_args.get('match_type')
    zones = "".join(query_args.get('zone').split("-")).upper()  # Remove '-' and upper case
    zone_list = zones.split(",")

    # Process the match value
    if artifact in match_value_type:
        value_type = re.findall(r'(?<=\.).*', match_value_type)[0]  # Remove the artifact prefix
    else:
        value_type = []
        demisto.error('The value type is not suitable with the selected artifact')

    # Create request
    res = create_instaquery_request(name, description, artifact, value_type, match_values, match_type, zone_list)

    if res:
        # Return results to context and war room
        results = CommandResults(
            outputs=res,
            outputs_prefix='InstaQuery.New',
            outputs_key_field='id'
        )
        return_results(results)


def get_instaquery_result_request(query_id):
    # Create request
    access_token = get_authentication_token([SCOPE_OPTICS_GET, SCOPE_OPTICS_CREATE])
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + access_token
    }
    # Endpoint format /instaqueries/v2/{queryID}/results
    uri = URI_OPTICS + "/" + query_id + "/results"
    res = api_call(uri=uri, method='get', headers=headers)
    return res


def get_instaquery_result():
    query_id = demisto.args().get('query_id')
    res = get_instaquery_result_request(query_id)

    if res['result']:
        results_count = len(res.get('result'))
        result_title = str(results_count) + " results found, find more details in context. Here is the 1st result:" \
            if results_count > 1 else "1 result found:"
        readable_results = tableToMarkdown(
            result_title,
            json.loads(res['result'][0]['Result']).get('Properties')
        )
    else:
        readable_results = "### No result found"

    # Return results to context and war room
    results = CommandResults(
        outputs=res,
        outputs_prefix='InstaQuery.Results',
        outputs_key_field='id',
        readable_output=readable_results
    )
    return_results(results)


def list_instaquery_request(page, page_size):
    # Create request
    access_token = get_authentication_token([SCOPE_OPTICS_LIST, SCOPE_OPTICS_GET])
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + access_token
    }
    # Endpoint format /instaqueries/v2/{queryID}/results
    uri = URI_OPTICS + "?page=" + page + "&page_size=" + page_size
    res = api_call(uri=uri, method='get', headers=headers)
    return res


def list_instaquery():
    page = demisto.args().get('page_number')
    page_size = demisto.args().get('page_size')
    res = list_instaquery_request(page, page_size)
    if res:
        # Return results to context and war room
        results = CommandResults(
            outputs=res,
            outputs_prefix='InstaQuery.List',
        )
        return_results(results)


def fetch_incidents():
    now = datetime.utcnow()
    last_run = demisto.getLastRun().get('time')
    if last_run is None:
        now = now - timedelta(days=3)
        last_run = now
    else:
        last_run = datetime.strptime(last_run, '%Y-%m-%dT%H:%M:%S')  # Converts string to datetime object
    current_run = last_run
    threats = get_threats_request().get('page_items', [])

    incidents = []
    for threat in threats:
        last_found = datetime.strptime(threat['last_found'], '%Y-%m-%dT%H:%M:%S')
        if last_found > last_run:
            incident = threat_to_incident(threat)
            incidents.append(incident)
        if last_found > current_run:
            current_run = last_found

    demisto.incidents(incidents)
    demisto.setLastRun({'time': current_run.isoformat().split('.')[0]})


def add_capitalized_hash_to_context(threats_context):  # pragma: no cover
    """Add capitalized hash keys to the context such as SHA256 and MD5,
    the keys are redundant since they are used for avoiding BC issues.

    Args:
        threats_context(list): list of dicts of context outputs for the threats of interest, each containing
        the key 'Sha256' (and possibly (Md5)).

    Returns:
        threats_context(list): list of dicts of context outputs for the threats of interest, each containing
        the key and value 'Sha256' (and possibly Md5) as well as the key and value 'SHA256' (and possible MD5).
    """
    if not isinstance(threats_context, list):
        threats_context = [threats_context]

    for context_item in threats_context:
        if context_item.get('Sha256'):
            context_item['SHA256'] = context_item.get('Sha256')
        if context_item.get('Md5'):
            context_item['MD5'] = context_item.get('Md5')

    return threats_context


# EXECUTION
def main():    # pragma: no cover
    params = demisto.params()

    global APP_ID
    APP_ID = params.get('app_creds', {}).get('identifier') or params.get('app_id')
    global APP_SECRET
    APP_SECRET = params.get('app_creds', {}).get('password') or params.get('app_secret')
    global TID
    TID = params.get('api_key', {}).get('password') or params.get('tid')
    global SERVER_URL
    SERVER_URL = load_server_url()
    global FILE_THRESHOLD
    FILE_THRESHOLD = params['file_threshold']
    global USE_SSL
    USE_SSL = not params.get('unsecure', False)
    command = demisto.command()

    if not all((APP_ID, APP_SECRET, TID)):
        raise DemistoException('Please fill out the Application ID, Application Secret and Tenant API Key')

    LOG(f'Command being called is {command}')
    try:
        handle_proxy()
        if demisto.command() == 'test-module':
            test()

        if demisto.command() == 'fetch-incidents':
            fetch_incidents()

        elif demisto.command() == 'cylance-protect-get-devices':
            get_devices()

        elif demisto.command() == 'cylance-protect-get-device':
            get_device()

        elif demisto.command() == 'cylance-protect-get-device-by-hostname':
            get_device_by_hostname()

        elif demisto.command() == 'cylance-protect-update-device':
            update_device()

        elif demisto.command() == 'cylance-protect-get-device-threats':
            get_device_threats()

        elif demisto.command() == 'cylance-protect-get-policies':
            get_policies()

        elif demisto.command() == 'cylance-protect-create-zone':
            create_zone()

        elif demisto.command() == 'cylance-protect-get-zones':
            get_zones()

        elif demisto.command() == 'cylance-protect-get-zone':
            get_zone()

        elif demisto.command() == 'cylance-protect-update-zone':
            update_zone()

        elif demisto.command() == 'cylance-protect-get-threat':
            get_threat()

        elif demisto.command() == 'cylance-protect-get-threats':
            get_threats()

        elif demisto.command() == 'cylance-protect-get-threat-devices':
            get_threat_devices()

        elif demisto.command() == 'cylance-protect-get-indicators-report':
            get_indicators_report()

        elif demisto.command() == 'cylance-protect-update-device-threats':
            update_device_threats()

        elif demisto.command() == 'cylance-protect-get-list':
            get_list()

        elif demisto.command() == 'cylance-protect-get-list-entry':
            get_list_entry_by_hash()

        # new commands
        elif demisto.command() == 'cylance-protect-download-threat':
            download_threat()

        elif demisto.command() == 'cylance-protect-add-hash-to-list':
            add_hash_to_list()

        elif demisto.command() == 'cylance-protect-delete-hash-from-lists':
            delete_hash_from_lists()

        elif demisto.command() == 'cylance-protect-delete-devices':
            delete_devices()

        elif demisto.command() == 'cylance-protect-get-policy-details':
            get_policy_details()

        # Optics InstaQuery command
        elif demisto.command() == 'cylance-optics-create-instaquery':
            create_instaquery()

        elif demisto.command() == 'cylance-optics-get-instaquery-result':
            get_instaquery_result()

        elif demisto.command() == 'cylance-optics-list-instaquery':
            list_instaquery()

    except Warning as w:
        demisto.results({
            'Type': 11,
            'Contents': str(w),
            'ContentsFormat': formats['text']
        })

    except Exception as e:
        demisto.error('#### error in Cylance Protect v2: ' + str(e))
        if demisto.command() == 'fetch-incidents':
            LOG.print_log()
            raise
        else:
            return_error(str(e))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
