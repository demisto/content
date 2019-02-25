import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import requests


# disable insecure warnings
requests.packages.urllib3.disable_warnings()

# remove proxy if not set to true in params
if not demisto.params().get('proxy', False):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

''' GLOBALS'''

SERVER = demisto.params().get('server').rstrip('/') + '/api/v1/'
AUTH_TOKEN = demisto.params().get('auth_token')
VERIFY_CERTIFICATE = not demisto.params().get('insecure', True)
FETCH_DELTA = int(demisto.params().get('fetchDelta', 24))
RELEVANT_DEVICE_ENTRIES = {
    'description': 'Description',
    'id': 'ID',
    'ip_address': 'Address',
    'last_seen': 'LastSeen',
    'live': 'Status',
    'location': 'Location',
    'name': 'Name',
    'updated_std': 'LastUpdated',
    'version': 'Version'
}
RELEVANT_TOKEN_ENTRIES = {
    'canarytoken': 'CanaryToken',
    'created_printable': 'CreatedTime',
    'enabled': 'Status',
    'kind': 'Kind',
    'triggered_count': 'Triggered',
    'doc_name': 'DocName',
    'url': 'TokenURL'
}
DEF_PARAMS = {
    'auth_token': AUTH_TOKEN,
}
'''HELPER FUNCTIONS'''


def http_request(method, url, params=None):
    """
    HTTP request helper function
    """
    if params is None:
        params = DEF_PARAMS
    res = requests.request(
        method=method,
        url=url,
        params=params,
        verify=VERIFY_CERTIFICATE
    )

    if not res.ok:
        demisto.debug(res.text)
        return_error('Could not execute the request')

    try:
        res_json = res.json()
        return res_json
    except Exception as ex:
        demisto.debug(str(ex))
        return_error(str(ex))


def get_alerts(last_fetch=None):
    """
    Retrieve all unacknowledged alerts from Canary Tools
    :param last_fetch: Last fetch incidents time
    """

    if last_fetch:
        params = {
            'auth_token': AUTH_TOKEN,
            'newer_than': last_fetch
        }
        res = http_request('GET', SERVER + 'incidents/unacknowledged', params)
    else:
        res = http_request('GET', SERVER + 'incidents/unacknowledged')
    alerts = res.get('incidents')
    return alerts


def create_incident(alert):
    """
    Turns an alert from Canary Tools to the incident structure in Demisto
    :return: Demisto incident, e.g., CanaryToken triggered
    """
    incident = {
        'name': alert.get('description').get('description'),
        'occurred': timestamp_to_datestring(1000 * (int(alert.get('description').get('created')))),
        'rawJSON': json.dumps(alert)
    }
    return incident


'''COMMANDS'''


def test_module():
    try:
        res = requests.request('GET', SERVER + 'ping', params=DEF_PARAMS, verify=VERIFY_CERTIFICATE)
        if not res.ok:
            try:
                res_json = res.json()
                return_error('Could not connect, reason: {}'.format(res_json.get('message')))

            except Exception as ex:
                demisto.debug(str(ex))
                return_error('Could not parse server response, please verify instance parameters')
        demisto.results('ok')
    except Exception as ex:
        demisto.debug(str(ex))
        return_error('Failed to establish new connection, please verify instance parameters')


def list_canaries():
    """
    Retrieve all Canaries available in Canary Tools
    :return: json response, a list of all devices
    """
    res = http_request('GET', SERVER + 'devices/all')
    new_devices = [
        {new_key: device[old_key] if old_key in device else None for old_key, new_key in
         RELEVANT_DEVICE_ENTRIES.items()} for
        device in res['devices']]
    return res, new_devices


def list_canaries_command():
    """
    Retrieve all Canaries available in Canary Tools
    """
    res_json, new_devices = list_canaries()
    context = createContext(new_devices, removeNull=True)
    headers = [
        'ID',
        'Name',
        'Description',
        'Address',
        'Status',
        'Location',
        'Version',
        'LastSeen',
        'LastUpdated'
    ]
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': res_json,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Canary Devices', new_devices, headers=headers),
        'EntryContext': {'CanaryTools.Device(val.ID && val.ID === obj.ID)': context}
    })


def list_tokens():
    """
    Retrieve all Canary Tokens available in Canary Tools
    :return: json response, a list of all tokens
    """
    res = http_request('GET', SERVER + 'canarytokens/fetch')
    new_tokens = []
    for token in res['tokens'][:-1]:
        new_tokens.append({new_key: token[old_key] if old_key in token else None for old_key, new_key in
                           RELEVANT_TOKEN_ENTRIES.items()})
    return res, new_tokens


def list_tokens_command():
    """
    Retrieve all Canary Tokens available in Canary Tools
    """
    res_json, new_tokens = list_tokens()
    headers = sorted(new_tokens[0].keys())
    context = createContext(new_tokens, removeNull=True)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': res_json,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Canary Tools Tokens', new_tokens, headers=headers),
        'EntryContext': {'CanaryTools.Token(val.CanaryToken && val.CanaryToken === obj.CanaryToken)': context}
    })


def get_token_command():
    """
    Fetch a Canary Token from the Canary Tools server
    :return: Canary Token information or file
    """
    token = demisto.args().get('token')
    params = {
        'auth_token': AUTH_TOKEN,
        'canarytoken': token
    }

    res = http_request('GET', SERVER + 'canarytoken/fetch', params=params)
    context = createContext(res.get('token').get('canarytoken'), removeNull=True)
    results = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': res,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': 'File Fetched Successfully',
        'EntryContext': {
            'CanaryTools.Token(val.CanaryToken && val.CanaryToken === obj.CanaryToken)': context}
    }

    if res.get('token').get('doc'):
        name = res.get('token').get('doc_name')
        content = res.get('token').get('doc')
        token_file = fileResult(name, content)
        demisto.results(token_file)
    elif res.get('token').get('web_image'):
        name = res.get('token').get('web_image_name')
        content = res.get('token').get('web_image')
        token_file = fileResult(name, content)
        demisto.results(token_file)
    else:
        results['HumanReadable'] = tableToMarkdown('Canary Tools Tokens', res.get('token'))
    demisto.results(results)


def check_whitelist(ip, port):
    """
    Check if a given IP address is whitelisted in Canary Tools
    :return: json response
    """
    params = {
        'auth_token': AUTH_TOKEN,
        'src_ip': ip,
        'dst_port': port
    }

    res = http_request('GET', SERVER + 'settings/is_ip_whitelisted', params=params)
    return res


def check_whitelist_command():
    """
    Check if a given IP address is whitelisted in Canary Tools
    """
    ip = demisto.args().get('ip')
    port = demisto.args().get('port')
    res = check_whitelist(ip, port)

    if not port:
        port = 'Any'
    context = {
        'Address': str(ip),
        'Port': str(port),
        'Whitelisted': str(res.get('is_ip_whitelisted'))
    }
    if res.get('is_ip_whitelisted'):
        context = createContext(context, removeNull=True)
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': res,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': 'The IP address {}:{} is Whitelisted'.format(ip, port),
            'EntryContext': {
                'CanaryTools.IP(val.Address && val.Address===obj.Address && val.Port && val.Port===obj.Port)': context}
        })
    else:
        context = createContext(context, removeNull=True)
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': res,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': 'The IP address {}:{} is not Whitelisted'.format(ip, port),
            'EntryContext': {
                'CanaryTools.IP(val.Address && val.Address===obj.Address && val.Port && val.Port===obj.Port)': context}
        })


def whitelist_ip(ip, port):
    """
    Whitelist an IP address in Canary Tools
    :return: json response
    """
    params = {
        'auth_token': AUTH_TOKEN,
        'src_ip': ip,
        'dst_port': port
    }

    res = http_request('POST', SERVER + 'settings/whitelist_ip_port', params=params)
    return res


def whitelist_ip_command():
    """
    Whitelist an IP address in Canary Tools
    """
    ip = demisto.args().get('ip')
    port = demisto.args().get('port')
    res = whitelist_ip(ip, port)

    if not port:
        port = 'Any'

    result_status = res.get('result')
    if result_status == 'success':
        context = {
            'Address': str(ip),
            'Port': str(port),
            'Whitelisted': 'True'
        }
        context = createContext(context, removeNull=True)
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': res,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': 'The IP address ' + str(ip) + ':' + str(
                port) + ' was added to the Whitelist',
            'EntryContext': {
                'CanaryTools.IP(val.Address && val.Address===obj.Address && val.Port && val.Port===obj.Port)': context}
        })
    elif result_status == 'failure':
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': res,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': res.get('message')
        })
    elif result_status == 'error':
        return_error(res.get('message'))


def alert_status_command():
    """
    Acknowledge or Uncknowledge an Alert in Canary Tools
    """
    args = demisto.args()
    alert = args.get('alert_id')
    status = args.get('status')
    context = {
        'ID': str(alert),
        'Status': str(status),
    }
    context = createContext(context, removeNull=True)
    params = {
        'auth_token': AUTH_TOKEN,
        'incident': alert
    }
    if status == 'Acknowledge':
        res = http_request('POST', SERVER + 'incident/acknowledge', params=params)
        if res.get('action') == 'acknowledged':
            demisto.results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': res,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': 'The Alert {} was '.format(alert) + res.get('action'),
                'EntryContext': {'CanaryTools.Alert(val.ID && val.ID === obj.ID)': context}
            })
    elif status == 'Unacknowledge':
        res = http_request('POST', SERVER + 'incident/unacknowledge', params=params)
        if res.get('action') == 'unacknowledged':
            demisto.results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': res,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': 'The Alert {} was '.format(alert) + res.get('action'),
                'EntryContext': {'CanaryTools.Alert(val.ID && val.ID === obj.ID)': context}
            })
        else:
            return_error('Unsupported command')


def fetch_incidents_command():
    """
    Fetch alerts from Canary Tools as incidents in Demisto
    last_fetch: The latest fetched alert creation time
    """
    last_fetch = demisto.getLastRun().get('time')

    if last_fetch is None:
        last_fetch = parse_date_range('{} hours'.format(str(FETCH_DELTA)), '%Y-%m-%d-%H:%M:%S')[0]

    # All alerts retrieved from get_alerts are newer than last_fetch and are in a chronological order
    alerts = get_alerts(last_fetch)

    incidents = []
    current_fetch = last_fetch
    for alert in alerts:
        current_fetch = 1000 * (int(alert.get('description').get('created')))
        current_fetch = timestamp_to_datestring(current_fetch, '%Y-%m-%d-%H:%M:%S')
        incident = create_incident(alert)
        incidents.append(incident)

    demisto.incidents(incidents)
    demisto.setLastRun({'time': current_fetch})


# Execution Code
try:
    if demisto.command() == 'test-module':
        test_module()
    elif demisto.command() == 'canarytools-list-tokens':
        list_tokens_command()
    elif demisto.command() == 'canarytools-get-token':
        get_token_command()
    elif demisto.command() == 'canarytools-list-canaries':
        list_canaries_command()
    elif demisto.command() == 'canarytools-check-whitelist':
        check_whitelist_command()
    elif demisto.command() == 'canarytools-whitelist-ip':
        whitelist_ip_command()
    elif demisto.command() == 'canarytools-edit-alert-status':
        alert_status_command()
    elif demisto.command() == 'fetch-incidents':
        fetch_incidents_command()
except Exception, e:
    return_error('Unable to perform command : {}, Reason: {}'.format(demisto.command, e))
