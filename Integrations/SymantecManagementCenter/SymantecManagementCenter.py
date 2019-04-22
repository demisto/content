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
    return_outputs(tableToMarkdown('Symantec Management Center Devices', contents,
                                   removeNull=True, headers=headers, headerTransform=pascalToSpace), context, devices)


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


def get_device_command():
    """
    Command to get information for a specified device
    :return: An entry with the device data
    """
    uuid = demisto.args()['uuid']
    content = {}
    context = {}

    device = get_device_request(uuid)
    if device:
        content = {
            'UUID': device.get('uuid'),
            'Name': device.get('name'),
            'LastChanged': device.get('lastChanged'),
            'LastChangedBy': device.get('lastChangedBy'),
            'Description': device.get('description'),
            'Model': device.get('model'),
            'Platform': device.get('platform'),
            'Type': device.get('type'),
            'OSVersion': device.get('osVersion'),
            'Build': device.get('build'),
            'SerialNumber': device.get('serialNumber'),
            'Host': device.get('host'),
            'ManagementStatus': device.get('managementStatus'),
            'DeploymentStatus': device.get('deploymentStatus')
        }

        context['SymantecMC.Device(val.UUID && val.UUID === obj.UUID)'] = createContext(content)

    headers = ['UUID', 'Name', 'LastChanged', 'LastChangedBy', 'Description',
               'Model', 'Platform', 'Host', 'Type', 'OSVersion', 'Build', 'SerialNumber',
               'ManagementStatus', 'DeploymentStatus']

    return_outputs(tableToMarkdown('Symantec Management Center Device', content,
                                   removeNull=True, headers=headers, headerTransform=pascalToSpace), context, device)


def get_device_request(uuid):
    """
    Return data for a specified device
    :param uuid: The device UUID
    :return: The device data
    """
    path = 'devices/' + uuid

    response = http_request('GET', path)

    return response


def get_device_health_command():
    """
        Command to get health information for a specified device
        :return: An entry with the device data and health
        """
    uuid = demisto.args()['uuid']
    health_content = []
    human_readable = ''
    context = {}

    device_health = get_device_health_request(uuid)
    if device_health and device_health.get('health'):

        if not isinstance(device_health['health'], list):
            device_health['health'] = [device_health['health']]

        device_content = {
            'UUID': device_health.get('uuid'),
            'Name': device_health.get('name')
        }

        for health in device_health['health']:
            health_content.append({
                'Category': health.get('category'),
                'Name': health.get('name'),
                'State': health.get('state'),
                'Message': health.get('message'),
                'Status': health.get('status')
            })

        device_headers = ['UUID', 'Name']
        content = device_content
        human_readable = tableToMarkdown('Symantec Management Center Device', device_content,
                                         removeNull=True, headers=device_headers, headerTransform=pascalToSpace)
        if health_content:
            health_headers = ['Category', 'Name', 'State', 'Message', 'Status']
            human_readable += tableToMarkdown('Device Health', health_content,
                                              removeNull=True, headers=health_headers, headerTransform=pascalToSpace)
            content['Health'] = health_content

        context['SymantecMC.Device(val.UUID && val.UUID === obj.UUID)'] = createContext(content)

    return_outputs(human_readable, context, device_health)


def get_device_health_request(uuid):
    """
    Return health for a specified device
    :param uuid: The device UUID
    :return: The device health data
    """
    path = 'devices/' + uuid + '/health'

    response = http_request('GET', path)

    return response


def get_device_license_command():
    """
    Command to get license information for a specified device
    :return: An entry with the device data and license information
    """
    uuid = demisto.args()['uuid']
    license_content = []
    human_readable = ''
    context = {}

    device_license = get_device_license_request(uuid)
    if device_license:

        if not isinstance(device_license['components'], list):
            device_license['components'] = [device_license['components']]

        device_content = {
            'UUID': device_license.get('uuid'),
            'Name': device_license.get('name'),
            'Type': device_license.get('deviceType'),
            'LicenseStatus': device_license.get('licenseStatus')
        }

        for component in device_license['components']:
            license_content.append({
                'Name': component.get('componentName'),
                'ActivationDate': component.get('activationDate'),
                'ExpirationDate': component.get('expirationDate'),
                'Validity': component.get('validity')
            })

        device_headers = ['UUID', 'Name']
        content = device_content
        human_readable = tableToMarkdown('Symantec Management Center Device', device_content,
                                         removeNull=True, headers=device_headers, headerTransform=pascalToSpace)
        if license_content:
            license_headers = ['Name', 'ActivationDate', 'ExpirationDate', 'Validity']
            human_readable += tableToMarkdown('License Components', license_content,
                                              removeNull=True, headers=license_headers, headerTransform=pascalToSpace)
            content['LicenseComponent'] = license_content

        context['SymantecMC.Device(val.UUID && val.UUID === obj.UUID)'] = createContext(content)

    return_outputs(human_readable, context, device_license)


def get_device_license_request(uuid):
    """
    Return the license for a specified device
    :param uuid: The device UUID
    :return: The device license data
    """
    path = 'devices/' + uuid + '/license'

    response = http_request('GET', path)

    return response


def get_device_status_command():
    """
    Command to get the status for a specified device
    :return: An entry with the device status data
    """
    uuid = demisto.args()['uuid']
    content = {}
    context = {}

    device = get_device_status_request(uuid)
    if device:
        content = {
            'UUID': device.get('uuid'),
            'Name': device.get('name'),
            'CheckDate': device.get('checkDate'),
            'StartDate': device.get('startDate'),
            'MonitorState': device.get('monitorState'),
            'Warnings': len(device.get('warnings', [])),
            'Errors': len(device.get('errors', []))
        }

        context['SymantecMC.Device(val.UUID && val.UUID === obj.UUID)'] = createContext(content)

    headers = ['UUID', 'Name', 'CheckDate', 'StartDate', 'MonitorState', 'Warnings', 'Errors']

    return_outputs(tableToMarkdown('Symantec Management Center Device Status', content,
                                   removeNull=True, headers=headers, headerTransform=pascalToSpace), context, device)


def get_device_status_request(uuid):
    """
    Return data for a specified device status
    :param uuid: The device UUID
    :return: The device status data
    """
    path = 'devices/' + uuid + '/status'

    response = http_request('GET', path)

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
    elif demisto.command() == 'symantec-mc-get-device':
        get_device_command()
    elif demisto.command() == 'symantec-mc-get-device-health':
        get_device_health_command()
    elif demisto.command() == 'symantec-mc-get-device-license':
        get_device_license_command()
    elif demisto.command() == 'symantec-mc-get-device-status':
        get_device_status_command()

except Exception as e:
    LOG(str(e))
    LOG.print_log()
    raise
