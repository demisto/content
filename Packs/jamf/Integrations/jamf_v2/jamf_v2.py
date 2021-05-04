"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any, Union, Tuple, List
import xml.etree.ElementTree as ElementTree

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''
POST_HEADERS = {
    'Content-Type': 'application/xml',
    'Accept': 'application/xml'
}

GET_HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}
MAX_PAGE_SIZE = 1000
''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def get_computers_request(self, id=None, basic_subset=False, match=None):
        """Retrieve the computers results.
        Args:
            id: computer id.
            basic_subset: basic subset for all of the computers.
            match: match computers by specific characteristics.
        Returns:
            Computers response from API.
        """
        uri = '/computers'
        if id:
            res = self._http_request(method='GET', url_suffix=f'{uri}/id/{id}/subset/General', headers=GET_HEADERS)
        elif basic_subset:
            res = self._http_request(method='GET', url_suffix=f'{uri}/subset/basic', headers=GET_HEADERS)
        elif match:
            res = self._http_request(method='GET', url_suffix=f'{uri}/match/{match}', headers=GET_HEADERS)
        else:
            res = self._http_request(method='GET', url_suffix=uri, headers=GET_HEADERS)

        return res

    def get_computer_subset_request(self, identifier=None, identifier_value=None, subset=None):
        """Retrieve the computer subset results.
        Args:
            identifier: The identifier to search computer.
            identifier_value: The value of the identifier.
            subset: Subset to search for.
        Returns:
            Computer subset response from API.
        """

        uri = '/computers'

        if identifier and identifier_value:
            if subset:
                res = self._http_request(method='GET', url_suffix=f'{uri}/{identifier}/{identifier_value}/subset/'
                                                                  f'{subset}', headers=GET_HEADERS,
                                         error_handler=self._computer_subset_error_handler)
            else:
                err_msg = 'You must specify subset argument.'
                raise DemistoException(err_msg)
        else:
            err_msg = 'You must specify identifier and identifier_value arguments.'
            raise DemistoException(err_msg)

        return res

    @staticmethod
    def _computer_subset_error_handler(res):
        if res.status_code == 404:
            raise DemistoException("The server has not found anything matching the request URI")

    def computer_lock_request(self, id=None, passcode=None, lock_message=None):
        """Lock computer.
        Args:
            id: The computer id.
            passcode: The passcode to lock the computer.
            lock_message: The lock message.
        Returns:
            Computer lock response from API.
        """

        uri = '/computercommands/command/DeviceLock'
        request_body = '<?xml version="1.0" encoding="UTF-8"?>' + \
                       '<computer_command>' + \
                       '<general>' + \
                       f'<passcode>{passcode}</passcode>' + \
                       f'<lock_message>{lock_message}</lock_message>' + \
                       '</general>' + \
                       '<computers>' + \
                       '<computer>' + \
                       f'<id>{id}</id>' + \
                       '</computer>' + \
                       '</computers>' + \
                       '</computer_command>'

        res = self._http_request(method='POST', data=request_body, url_suffix=uri, headers=POST_HEADERS,
                                 resp_type='response', error_handler=self._computer_lock_error_handler)

        json_res = json.loads(xml2json(res.content))
        return json_res

    @staticmethod
    def _computer_lock_error_handler(res):
        if res.status_code == 400 and 'Unable to match computer' in res.text:
            raise DemistoException("ID doesn't exist.")
        if res.status_code == 400 and 'is not managed' in res.text:
            raise DemistoException("Device is unmanaged.")

    def computer_erase_request(self, id=None, passcode=None):
        """Erase computer.
        Args:
            id: The computer id.
            passcode: The passcode to lock the computer.
        Returns:
            Computer erase response from API.
        """

        uri = '/computercommands/command/EraseDevice'
        request_body = '<?xml version="1.0" encoding="UTF-8"?>' + \
                       '<computer_command>' + \
                       '<general>' + \
                       '<command> EraseDevice </command>' + \
                       f'<passcode>{passcode}</passcode>' + \
                       '</general>' + \
                       '<computers>' + \
                       '<computer>' + \
                       f'<id>{id}</id>' + \
                       '</computer>' + \
                       '</computers>' + \
                       '</computer_command>'

        res = self._http_request(method='POST', data=request_body, url_suffix=uri, headers=POST_HEADERS,
                                 resp_type='response')
        if res.status_code < 200 or res.status_code >= 300:
            return_error('Failed to erase the computer')

        raw_action = json.loads(xml2json(res.content))
        return raw_action

    def get_users_request(self, id=None, name=None, email=None):
        """ users. """

        uri = '/users'
        if id:
            res = self._http_request(method='GET', url_suffix=f'{uri}/id/{id}', headers=GET_HEADERS)
        elif name:
            res = self._http_request(method='GET', url_suffix=f'{uri}/name/{name}', headers=GET_HEADERS)
        elif email:
            res = self._http_request(method='GET', url_suffix=f'{uri}/email/{email}', headers=GET_HEADERS)
        else:
            res = self._http_request(method='GET', url_suffix=f'{uri}', headers=GET_HEADERS)

        return res

    def get_mobile_devices_request(self, id=None, match=None):
        """ mobile devices. """

        uri = '/mobiledevices'
        if id:
            res = self._http_request(method='GET', url_suffix=f'{uri}/id/{id}', headers=GET_HEADERS)
        elif match:
            res = self._http_request(method='GET', url_suffix=f'{uri}/match/{match}', headers=GET_HEADERS)
        else:
            res = self._http_request(method='GET', url_suffix=f'{uri}', headers=GET_HEADERS)

        return res

    def get_mobile_devices_subset_request(self, identifier=None, identifier_value=None, subset=None):

        """Retrieve the mobile device subset results.
        Args:
            identifier: The identifier to search mobile device.
            identifier_value: The value of the identifier.
            subset: Subset to search for.
        Returns:
            Mobile device subset response from API.
        """

        uri = '/mobiledevices'
        if identifier and identifier_value:
            if subset:
                res = self._http_request(method='GET', url_suffix=f'{uri}/{identifier}/{identifier_value}/subset/'
                                                                  f'{subset}', headers=GET_HEADERS)
            else:
                err_msg = 'You must specify subset argument'
                raise Exception(err_msg)
        else:
            err_msg = 'You must specify identifier and identifier_value arguments'
            raise Exception(err_msg)

        return res

    def get_computers_by_app_request(self, app=None, version=None):
        """ mobile devices. """

        uri = '/computerapplications'
        if app:
            if version:
                res = self._http_request(method='GET', url_suffix=f'{uri}/application/{app}/version/{version}',
                                         headers=GET_HEADERS)
            else:
                res = self._http_request(method='GET', url_suffix=f'{uri}/application/{app}', headers=GET_HEADERS)
        else:
            err_msg = 'You must specify application argument'
            raise Exception(err_msg)

        return res

    def mobile_device_lost_request(self, id=None, lost_message=None):
        """Lock computer.
        Args:
            id: The computer id.
            lost_message: The lost message.
        Returns:
            Mobile device lost response from API.
        """

        uri = '/mobiledevicecommands/command/DeviceLock'
        request_body = '<?xml version="1.0" encoding="UTF-8"?>' + \
                       '<mobile_device_command>' + \
                       '<general>' + \
                       '<command>EnableLostMode</command>' + \
                       f'<lost_mode_message>{lost_message}</lost_mode_message>' + \
                       '</general>' + \
                       '<mobile_devices>' + \
                       '<mobile_device>' + \
                       f'<id>{id}</id>' + \
                       '</mobile_device>' + \
                       '</mobile_devices>' + \
                       '</mobile_device_command>'

        res = self._http_request(method='POST', data=request_body, url_suffix=uri, headers=POST_HEADERS,
                                 resp_type='response')
        if res.status_code < 200 or res.status_code >= 300:
            return_error('Enable Lost Mode failed')

        raw_action = json.loads(xml2json(res.content))
        return raw_action

    def mobile_device_erase_request(self, id=None, preserve_data_plan=False, clear_activation_code=False):
        """Erase.
        Args:
            id: The computer id.
            preserve_data_plan: Retain cellular data plans.
            clear_activation_code: Clear Activation Lock on the device.
        Returns:
            Computer lock response from API.
        """

        uri = '/mobiledevicecommands/command/EraseDevice'
        request_body = '<?xml version="1.0" encoding="UTF-8"?>' + \
                       '<mobile_device_command>' + \
                       '<general>' + \
                       '<command>EraseDevice</command>' + \
                       f'<preserve_data_plan>{preserve_data_plan}</preserve_data_plan>' + \
                       f'<clear_activation_code>{clear_activation_code}</clear_activation_code>' + \
                       '</general>' + \
                       '<mobile_devices>' + \
                       '<mobile_device>' + \
                       f'<id>{id}</id>' + \
                       '</mobile_device>' + \
                       '</mobile_devices>' + \
                       '</mobile_device_command>'

        res = self._http_request(method='POST', data=request_body, url_suffix=uri, headers=POST_HEADERS,
                                 resp_type='response')
        if res.status_code < 200 or res.status_code >= 300:
            return_error('Failed to erase mobile device')

        raw_action = json.loads(xml2json(res.content))
        return raw_action


''' HELPER FUNCTIONS '''


def pagination(response, limit, page):
    if limit > MAX_PAGE_SIZE:
        limit = MAX_PAGE_SIZE
    return response[page * limit:(page + 1) * limit]


def get_computers_readable_output(response, id):
    readable_output = []
    if id:
        computers_response = response.get('computer').get('general')
        readable_output.append({
            'ID': computers_response.get('id'),
            'Name': computers_response.get('name'),
            'MAC address': computers_response.get('mac_address'),
            'IP address': computers_response.get('ip_address')
        })
    else:
        computers_response = response
        for computer in computers_response:
            readable_output.append({
                'ID': computer.get('id'),
                'Name': computer.get('name'),

            })
    return computers_response, readable_output


def get_computer_subset_readable_output(response, subset):
    readable_output = {}
    computers_response = response.get('computer').get(subset)
    if subset == 'general':
        readable_output = {
            'ID': computers_response.get('id'),
            'Name': computers_response.get('name'),
            'MAC address': computers_response.get('mac_address'),
            'Alternate MAC address': computers_response.get('alt_mac_address'),
            'IP address': computers_response.get('ip_address'),
            'Serial Number': computers_response.get('serial_number'),
            'UDID': computers_response.get('udid'),
            'Platform': computers_response.get('platform'),
            'Managed': computers_response.get('remote_management').get('managed'),
            'Management Username': computers_response.get('remote_management').get('management_username')
        }

    elif subset == 'location':
        readable_output = {
            'Username': computers_response.get('username'),
            'Real Name': computers_response.get('realname'),
            'Email Address': computers_response.get('email_address'),
            'Position': computers_response.get('position'),
            'Department': computers_response.get('department'),
            'Building': computers_response.get('building'),
            'Room': computers_response.get('room'),
            'Phone': computers_response.get('phone'),

        }
    elif subset == 'purchasing':
        readable_output = {
            'Is Purchased': computers_response.get('is_purchased'),
            'Is Leased': computers_response.get('is_leased'),
            'Vendor': computers_response.get('vendor'),
            'Purchase Price': computers_response.get('purchase_price'),
            'Warranty Expires': computers_response.get('warranty_expires'),
            'Lease Expires': computers_response.get('lease_expires'),
            'Purchasing Contact': computers_response.get('purchasing_contact')
        }

    elif subset == 'peripherals':
        readable_output = computers_response

    elif subset == 'hardware':
        devices_sizes = []
        for device in computers_response.get('storage'):
            devices_sizes.append({device.get('disk'): device.get('size')})
        readable_output = {
            'Model': computers_response.get('id'),
            'os name': computers_response.get('name'),
            'os version': computers_response.get('mac_address'),
            'os build': computers_response.get('ip_address'),
            'processor type': computers_response.get('id'),
            'number of processors': computers_response.get('name'),
            'number of cores': computers_response.get('mac_address'),
            'total ram': computers_response.get('ip_address'),
            'sip status': computers_response.get('name'),
            'storage': devices_sizes
        }

    elif subset == 'certificates':
        certificate_details = []
        for certificate in computers_response:
            certificate_details.append({
                'Common Name': certificate.get('common_name'),
                'Identity': certificate.get('identity'),
                'Expires UTC': certificate.get('expires_utc'),
                'Expires Epoch': certificate.get('expires_epoch')
            })
    elif subset == 'software':
        readable_output = {
            'Number of running services ': len(computers_response.get('running_services')),
            'Number of installed applications': computers_response.get('applications').get('size'),
        }
    elif subset == 'extensionAttributes':
        extension_attributes = []
        for extension_attribute in computers_response:
            extension_attributes.append({
                'ID': extension_attribute.get('id'),
                'Name': extension_attribute.get('name'),
                'Type': extension_attribute.get('type'),
                'Value': extension_attribute.get('multi_value')
            })
    elif subset == 'GroupsAccounts':
        readable_output = {
            'Number of groups': len(computers_response.get('computer_group_memberships')),
            'Number of installed applications': len(computers_response.get('local_accounts'))
        }
    elif subset == 'iphones':
        readable_output = computers_response

    elif subset == 'ConfigurationProfiles':
        configuration_profiles = []
        for profile in computers_response:
            configuration_profiles.append({
                'ID': profile.get('id'),
                'Is Removable': profile.get('is_removable')
            })

    return computers_response, readable_output


def computer_commands_readable_output(response):
    computer_lock_response = response.get('computer_command').get('command')
    readable_output = {
        'ID': computer_lock_response.get('computer_id'),
        'Command UUID': computer_lock_response.get('command_uuid'),

    }
    return computer_lock_response, readable_output


def get_users_readable_output(response, id, name, email):
    readable_output = []
    if id or name or email:
        users_response = response.get('user')
        readable_output.append({
            'ID': users_response.get('id'),
            'Name': users_response.get('name'),
            'Email': users_response.get('email'),
            'Phone': users_response.get('phone_number')

        })
    else:
        users_response = response
        for user in users_response:
            readable_output.append({
                'ID': user.get('id'),
                'Name': user.get('name'),

            })
    return users_response, readable_output


def get_mobile_devices_readable_output(response, id, all_details):
    readable_output = []
    if id:
        mobile_dev_response = response.get('mobile_devices')
        readable_output.append({
            'ID': mobile_dev_response.get('id'),
            'Name': mobile_dev_response.get('name'),
            'Capacity': mobile_dev_response.get('capacity'),
            'UDID': mobile_dev_response.get('udid')

        })
    elif all_details:
        pass

    else:
        mobile_dev_response = response.get('mobile_devices')
        for user in mobile_dev_response:
            readable_output.append({
                'ID': user.get('id'),
                'Name': user.get('name'),
                'UDID': user.get('udid')
            })
    return mobile_dev_response, readable_output


def get_mobile_device_subset_readable_output(response, subset):
    readable_output = {}
    mobile_response = response
    if subset == 'general':
        mobile_response = response.get('general')

        readable_output = {
            'ID': mobile_response.get('id'),
            'Name': mobile_response.get('name'),
            'WIFI MAC address': mobile_response.get('wifi_mac_address'),
            'Bluetooth MAC address': mobile_response.get('bluetooth_mac_address'),
            'IP address': mobile_response.get('ip_address'),
            'Serial Number': mobile_response.get('serial_number'),
            'UDID': mobile_response.get('udid'),
            'Model': mobile_response.get('model'),
            'Model Number': mobile_response.get('model_number'),
            'Managed': mobile_response.get('managed'),
            'Supervised': mobile_response.get('supervised')
        }
    elif subset == 'location':
        mobile_response = response.get('location')

        readable_output = {
            'Username': mobile_response.get('username'),
            'Real Name': mobile_response.get('realname'),
            'Email Address': mobile_response.get('email_address'),
            'Position': mobile_response.get('position'),
            'Department': mobile_response.get('department'),
            'Building': mobile_response.get('building'),
            'Room': mobile_response.get('room'),
            'Phone': mobile_response.get('phone'),

        }
    elif subset == 'purchasing':
        mobile_response = response.get('purchasing')

        readable_output = {
            'Is Purchased': mobile_response.get('is_purchased'),
            'Is Leased': mobile_response.get('is_leased'),
            'Vendor': mobile_response.get('vendor'),
            'Purchase Price': mobile_response.get('purchase_price'),
            'Warranty Expires': mobile_response.get('warranty_expires'),
            'Lease Expires': mobile_response.get('lease_expires'),
            'Purchasing Contact': mobile_response.get('purchasing_contact')
        }
    elif subset == 'certificates':
        mobile_response = response.get('certificates')

        certificate_details = []
        for certificate in mobile_response:
            certificate_details.append({
                'Common Name': certificate.get('common_name'),
                'Identity': certificate.get('identity'),
                'Expires UTC': certificate.get('expires_utc'),
                'Expires Epoch': certificate.get('expires_epoch')
            })
    elif subset == 'applications':
        mobile_response = response.get('applications')

        readable_output = {
            'Number of applications': mobile_response.get('size'),
        }
    elif subset == 'extensionAttributes':
        mobile_response = response.get('extension_attributes')
        extension_attributes = []
        for extension_attribute in mobile_response:
            extension_attributes.append({
                'ID': extension_attribute.get('id'),
                'Name': extension_attribute.get('name'),
                'Type': extension_attribute.get('type'),
                'Value': extension_attribute.get('multi_value')
            })
    elif subset == 'ConfigurationProfiles':
        mobile_response = response.get('configuration_profiles')
        configuration_profiles = []
        for profile in mobile_response:
            configuration_profiles.append({
                'Display Name': profile.get('display_name'),
                'version': profile.get('version'),
                'identifier': profile.get('identifier'),
                'uuid': profile.get('uuid')
            })
    elif subset == 'security':
        mobile_response = response.get('security_object')

        readable_output = {
            'Data Protection': mobile_response.get('data_protection'),
            'Block Level Encryption Capable': mobile_response.get('block_level_encryption_capable'),
            'File Level Encryption Capable': mobile_response.get('file_level_encryption_capable'),
            'Passcode Present': mobile_response.get('passcode_present'),
            'Passcode Compliant': mobile_response.get('passcode_compliant'),
            'Passcode Lock Grace Period Enforced': mobile_response.get('passcode_lock_grace_period_enforced'),
            'Hardware Encryption': mobile_response.get('hardware_encryption'),
            'Activation Lock Enabled': mobile_response.get('activation_lock_enabled'),
            'Jailbreak Detected': mobile_response.get('jailbreak_detected'),
            'Lost Mode Enabled': mobile_response.get('lost_mode_enabled'),
            'Lost Mode Enforced': mobile_response.get('lost_mode_enforced'),
            'Lost Mode Enable Issued UTC': mobile_response.get('lost_mode_enable_issued_utc'),
            'Lost Mode Message': mobile_response.get('lost_mode_message'),
            'Lost Mode Phone': mobile_response.get('lost_mode_phone'),
            'Lost Mode Footnote': mobile_response.get('lost_mode_footnote'),
            'Phone': mobile_response.get('activation_lock_enabled'),

        }
    elif subset == 'network':
        mobile_response = response.get('network')

        readable_output = {
            'Home Carrier Network': mobile_response.get('home_carrier_network'),
            'Cellular Technology': mobile_response.get('cellular_technology'),
            'Voice_roaming_enabled': mobile_response.get('voice_roaming_enabled'),
            'Imei': mobile_response.get('imei'),
            'Iccid': mobile_response.get('iccid'),
            'Current Carrier Network': mobile_response.get('current_carrier_network'),
            'Carrier Settings Version': mobile_response.get('carrier_settings_version'),
            'Current Mobile Country Code': mobile_response.get('current_mobile_country_code'),
            'Current Mobile Network Code': mobile_response.get('current_mobile_network_code'),
            'Home Mobile Country Code': mobile_response.get('home_mobile_country_code'),
            'Home Mobile Network Code': mobile_response.get('home_mobile_network_code'),
            'Data Roaming Enabled': mobile_response.get('data_roaming_enabled'),
            'Phone Number': mobile_response.get('phone_number')
        }
    elif subset == 'provisioningProfiles':
        mobile_response = response.get('provisioning_profiles')

        readable_output = mobile_response
    elif subset == 'MobileDeviceGroups':
        mobile_response = response.get('mobile_device_groups')

        readable_output = {
            'Number of groups': mobile_response.get('size'),
        }
    return mobile_response, readable_output


def get_computers_by_app_readable_output(response):
    readable_output = []
    computers_response = response.get('computer_applications')
    readable_output.append({
        'ID': computers_response.get('id'),
        'Name': computers_response.get('name'),
        'Capacity': computers_response.get('capacity'),
        'UDID': computers_response.get('udid')
    })

    return computers_response, readable_output


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        if client.get_computers_request():
            message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def get_computers_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id = args.get('id')
    basic_subset = argToBoolean(args.get('basic_subset', False))
    match = args.get('match')
    limit = arg_to_number(args.get('limit', 50))
    page = arg_to_number(args.get('page', 0))

    response = client.get_computers_request(id, basic_subset, match)
    if not id:
        response = pagination(response.get('computers'), limit, page)

    computers_response, readable_output = get_computers_readable_output(response, id)

    return CommandResults(
        readable_output=tableToMarkdown(
            'Jamf get computers result',
            readable_output
        ),
        outputs_prefix='Jamf.Computers',
        outputs_key_field='id',
        outputs=computers_response,
        raw_response=response
    )


def get_computer_subset_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    identifier = args.get('identifier')
    identifier_value = args.get('identifier_value')
    subset = args.get('subset')

    response = client.get_computer_subset_request(identifier, identifier_value, subset)

    computers_response, readable_output = get_computer_subset_readable_output(response, subset.lower())
    return CommandResults(
        readable_output=tableToMarkdown(
            'Jamf computer subset result',
            readable_output
        ),
        outputs_prefix='Jamf.Computer.Subset',
        outputs_key_field='id',
        outputs=computers_response,
        raw_response=response
    )


def computer_lock_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id = args.get('id')
    passcode = args.get('passcode')
    lock_msg = args.get('lock_message')

    response = client.computer_lock_request(id, passcode, lock_msg)
    computer_lock_response, readable_output = computer_commands_readable_output(response)
    return CommandResults(
        readable_output=tableToMarkdown(
            f'Computer {id} locked successfully',
            readable_output
        ),
        outputs_prefix='Jamf.ComputeCommands.DeviceLock',
        outputs_key_field='id',
        outputs=computer_lock_response,
        raw_response=response
    )


def computer_erase_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id = args.get('id')
    passcode = args.get('passcode')

    response = client.computer_erase_request(id, passcode)
    computer_lock_response, readable_output = computer_commands_readable_output(response)
    return CommandResults(
        readable_output=tableToMarkdown(
            f'Computer {id} erase successfully',
            readable_output
        ),
        outputs_prefix='Jamf.ComputerCommands.EraseDevice',
        outputs_key_field='id',
        outputs=computer_lock_response,
        raw_response=response
    )


def get_users_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id = args.get('id')
    name = args.get('name')
    email = args.get('email')
    limit = arg_to_number(args.get('limit', 50))
    page = arg_to_number(args.get('page', 0))
    response = client.get_users_request(id, name, email)
    if not id or not name or not email:
        response = pagination(response.get('users'), limit, page)

    computers_response, readable_output = get_users_readable_output(response, id, name, email)

    return CommandResults(
        readable_output=tableToMarkdown(
            'Jamf get users result',
            readable_output
        ),
        outputs_prefix='Jamf.Users',
        outputs_key_field='id',
        outputs=computers_response,
        raw_response=response
    )


def get_mobile_devices_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id = args.get('id')
    match = args.get('match', False)

    response = client.get_mobile_devices_request(id, match)

    computers_response, readable_output = get_mobile_devices_readable_output(response, id, match)

    return CommandResults(
        readable_output=tableToMarkdown(
            'Jamf get mobile devices result',
            readable_output
        ),
        outputs_prefix='Jamf.MobileDevices',
        outputs_key_field='id',
        outputs=computers_response,
        raw_response=response
    )


def get_mobile_device_subset_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    identifier = args.get('identifier')
    identifier_value = args.get('identifier_value')
    subset = args.get('subset', 'General')

    response = client.get_mobile_devices_subset_request(identifier, identifier_value, subset)

    computers_response, readable_output = get_computer_subset_readable_output(response, subset.lower())
    return CommandResults(
        readable_output=tableToMarkdown(
            'Jamf computer subset result',
            readable_output
        ),
        outputs_prefix='Jamf.MobileDevice.Subset',
        outputs_key_field='id',
        outputs=computers_response,
        raw_response=response
    )


def get_computers_by_app_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    app = args.get('application')
    version = args.get('version')

    response = client.get_computers_by_app_request(app, version)

    computers_response, readable_output = get_computers_by_app_readable_output(response, app, version)

    return CommandResults(
        readable_output=tableToMarkdown(
            'Jamf computers by application result',
            readable_output
        ),
        outputs_prefix='Jamf.ComputersByApp',
        outputs_key_field='id',
        outputs=computers_response,
        raw_response=response
    )


def mobile_device_lost_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id = args.get('id')
    lost_mode_msg = args.get('lost_mode_message')

    response = client.mobile_device_lost_request(id, lost_mode_msg)
    computer_lock_response, readable_output = computer_commands_readable_output(response)
    return CommandResults(
        readable_output=tableToMarkdown(
            f'Computer {id} locked successfully',
            readable_output
        ),
        outputs_prefix='Jamf.ComputeCommands.DeviceLock',
        outputs_key_field='id',
        outputs=computer_lock_response,
        raw_response=response
    )


def mobile_device_erase_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id = args.get('id')
    preserve_data_plan = args.get('preserve_data_plan')
    clear_activation_code = args.get('clear_activation_code')
    response = client.mobile_device_erase_request(id, preserve_data_plan, clear_activation_code)
    computer_lock_response, readable_output = computer_commands_readable_output(response)
    return CommandResults(
        readable_output=tableToMarkdown(
            f'Mobile device {id} erased successfully',
            readable_output
        ),
        outputs_prefix='Jamf.ComputeCommands.EraseDevice',
        outputs_key_field='id',
        outputs=computer_lock_response,
        raw_response=response
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    try:
        params = demisto.params()
        base_url = urljoin(params.get('url', '').rstrip('/'), '/JSSResource')
        username = params.get('credentials', {}).get('identifier')
        password = params.get('credentials', {}).get('password')

        verify_certificate = not params.get('insecure', False)
        proxy = params.get('proxy', False)

        client = Client(base_url=base_url, verify=verify_certificate, proxy=proxy, auth=(username, password))

        if demisto.command() == 'test-module':
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'jamf-computers-get':
            return_results(get_computers_command(client, demisto.args()))

        elif demisto.command() == 'jamf-get-computer-subset':
            return_results(get_computer_subset_command(client, demisto.args()))

        elif demisto.command() == 'jamf-computer-lock':
            return_results(computer_lock_command(client, demisto.args()))

        elif demisto.command() == 'jamf-computer-erase':
            return_results(computer_erase_command(client, demisto.args()))

        elif demisto.command() == 'jamf-get-users':
            return_results(get_users_command(client, demisto.args()))

        elif demisto.command() == 'jamf-get-mobile-devices':
            return_results(get_mobile_devices_command(client, demisto.args()))

        elif demisto.command() == 'jamf-get-mobile-device-subset':
            return_results(get_mobile_device_subset_command(client, demisto.args()))

        elif demisto.command() == 'jamf-get-computers-by-application':
            return_results(get_computers_by_app_command(client, demisto.args()))

        elif demisto.command() == 'jamf-mobile-device-lost-mode':
            return_results(mobile_device_lost_command(client, demisto.args()))

        elif demisto.command() == 'jamf-mobile-device-erase':
            return_results(mobile_device_erase_command(client, demisto.args()))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
