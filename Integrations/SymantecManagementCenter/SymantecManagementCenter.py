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

USERNAME = demisto.params().get('credentials').get('identifier')
PASSWORD = demisto.params().get('credentials').get('password')
SERVER = (demisto.params()['url'][:-1]
          if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url'])
BASE_URL = SERVER + '/api/'
USE_SSL = not demisto.params().get('insecure', False)
HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

''' HELPER FUNCTIONS '''


def http_request(method, path, params=None, data=None):
    params = params if params is not None else {}
    data = data if data is not None else {}
    res = requests.request(
        method,
        BASE_URL + path,
        auth=(USERNAME, PASSWORD),
        verify=USE_SSL,
        params=params,
        data=data,
        headers=HEADERS
    )

    if res.status_code < 200 or res.status_code > 300:
        status = res.status_code
        message = res.reason
        details = ''
        try:
            error_json = res.json()
            message = error_json.get('statusMessage')
            details = error_json.get('message')
        except Exception:
            pass
        return_error('Error in API call, status code: {}, reason: {}, details: {}'.format(status, message, details))

    return res.json()


''' FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get system info
    """
    sys_info = http_request('GET', 'system/info')


def list_devices_command():
    """
    List devices in Symantec MC using provided query filters
    """

    contents = []
    context = {}
    build = demisto.args().get('build')
    description = demisto.args().get('description')
    model = demisto.args().get('model')
    name = demisto.args().get('name')
    os_version = demisto.args().get('os_version')
    platform = demisto.args().get('platform')
    device_type = demisto.args().get('type')
    limit = int(demisto.args().get('limit', 10))

    devices = list_devices_request(build, description, model, name, os_version, platform, device_type)

    if devices:
        if limit:
            devices = devices[:limit]

        for device in devices:
            contents.append({
                'UUID': device.get('uuid'),
                'Name': device.get('name'),
                'LastChanged': device.get('lastChanged'),
                'Host': device.get('host'),
                'Type': device.get('type')
            })

        context['SymantecMC.Device(val.UUID && val.UUID === obj.UUID)'] = createContext(contents)

    headers = ['UUID', 'Name', 'LastChanged', 'Host', 'Type']
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': devices,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Symantec Management Center Devices', contents,
                                         removeNull=True, headers=headers, headerTransform=pascalToSpace),
        'EntryContext': context
    })


def list_devices_request(build, description, model, name, os_version, platform, device_type):
    """
    Get devices from Symantec MC
    :param build: Device build number query
    :param description: Device description query
    :param model: Device model query
    :param name: Device name query
    :param os_version: Device OS version query
    :param platform: Device platform query
    :param device_type: Device type
    :return: List of MC devices
    """

    path = 'devices'
    params = {}

    if build:
        params['build'] = build
    if description:
        params['description'] = description
    if model:
        params['model'] = model
    if name:
        params['name'] = name
    if os_version:
        params['osVersion'] = os_version
    if platform:
        params['platform'] = platform
    if device_type:
        params['type'] = device_type

    response = http_request('GET', path, params)
    return response


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is ' + demisto.command())
handle_proxy()

try:
    if demisto.command() == 'test-module':
        test_module()
        demisto.results('ok')
    elif demisto.command() == 'symantec-mc-list-devices':
        list_devices_command()

except Exception as e:
    LOG(str(e))
    LOG.print_log()
    raise
