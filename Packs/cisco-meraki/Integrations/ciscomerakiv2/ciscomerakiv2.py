
from requests import Response
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa


import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''


base_url = 'https://api.meraki.com/api/v1/'


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def fetch_organizations(self):
        res = self._http_request('GET', url_suffix='organizations')
        return res

    def fetch_org_dev_inv(self, organization_id: str = None, params: dict = None):
        url_suffix = f'organizations/{organization_id}/devices'
        res = self._http_request('GET', url_suffix=url_suffix)
        return res

    def fetch_organization_licenses(self, organization_id: str = None, params: dict = None):
        url_suffix = f'organizations/{organization_id}/licenses'
        res = self._http_request('GET', url_suffix=url_suffix, params=params)
        return res

    def fetch_organization_networks(self, organization_id: str = None):
        url_suffix = f'organizations/{organization_id}/networks'
        res = self._http_request('GET', url_suffix=url_suffix)
        return res

    def fetch_device(self, serial: str = None):
        url_suffix = f'devices/{serial}'
        res = self._http_request('GET', url_suffix=url_suffix)
        return res

    def fetch_device_clients(self, serial: str = None, timespan: str = None):
        url_suffix = f'devices/{serial}/clients'
        params = None
        if timespan:
            params = {
                'timespan': timespan
            }
        res = self._http_request('GET', url_suffix=url_suffix, params=params)
        return res

    def fetch_network_clients(self, network_id: str = None, timespan: int = 86400):
        url_suffix = f'networks/{network_id}/clients'
        params = {
            'timespan': timespan
        }
        res = self._http_request('GET', url_suffix=url_suffix, params=params)
        return res

    def fetch_network_devices(self, network_id: str = None):
        url_suffix = f'networks/{network_id}/devices'
        res = self._http_request('GET', url_suffix=url_suffix)
        return res

    def get_network_ssids(self, network_id: str = None):
        url_suffix = f'networks/{network_id}/wireless/ssids'
        res = self._http_request('GET', url_suffix=url_suffix)
        return res

    def search_clients(self, organization_id: str = None, mac: str = None):
        url_suffix = f'organizations/{organization_id}/clients/search'
        params = {
            'mac': mac
        }
        res = self._http_request('GET', url_suffix=url_suffix, params=params)
        return res

    def update_device(self, serial: str = None, updates: dict = {}):
        body = dict()
        for k, v in updates.items():
            if v or isinstance(v, bool):
                body[k] = v
        url_suffix = f'devices/{serial}'
        res = self._http_request('PUT', url_suffix=url_suffix, json_data=body)
        return res

    def fetch_org_uplinks(self, organization_id: str = None, serials: list = [], network_ids: list = []):
        params = {
            'networkIds': network_ids,
            'serials': serials
        }
        url_suffix = f'organizations/{organization_id}/uplinks/statuses'
        res = self._http_request('GET', url_suffix=url_suffix, params=params)
        return res

    def fetch_wireless_firewall_rules(self, network_id: str = None, number: str = None):
        url_suffix = f'networks/{network_id}/wireless/ssids/{number}/firewall/l3FirewallRules'
        res = self._http_request('GET', url_suffix=url_suffix)
        return res.get('rules', [])

    def fetch_appliance_firewall_rules(self, network_id: str = None):
        url_suffix = f'networks/{network_id}/appliance/firewall/l3FirewallRules'
        res = self._http_request('GET', url_suffix=url_suffix)
        return res.get('rules', [])

    def update_wireless_firewall_rules(self, network_id: str = None, number: str = None, rules: list = [], allow_lan: bool = False):
        url_suffix = f'networks/{network_id}/wireless/ssids/{number}/firewall/l3FirewallRules'
        body = {
            'rules': rules,
            'allowLanAccess': allow_lan
        }
        res = self._http_request('PUT', url_suffix=url_suffix, json_data=body)
        return res.get('rules', [])

    def update_appliance_firewall_rules(self, network_id: str = None, rules: list = [], syslog: bool = False):
        url_suffix = f'networks/{network_id}/appliance/firewall/l3FirewallRules'
        body = {
            'rules': rules,
            'syslogDefaultRule': syslog
        }
        res = self._http_request('PUT', url_suffix=url_suffix, json_data=body)
        return res.get('rules', [])

    def remove_device(self, network_id: str = None, serial: str = None):
        params = {
            'serial': serial
        }
        url_suffix = f'networks/{network_id}/devices/remove'
        res = self._http_request('POST', url_suffix=url_suffix, params=params, ok_codes=[204, 404], resp_type='response')
        return res

    def claim_device(self, network_id: str = None, serials: list = None):
        body = {
            'serials': serials
        }
        url_suffix = f'networks/{network_id}/devices/claim'
        res = self._http_request('POST', url_suffix=url_suffix, json_data=body, resp_type='response')
        return res


''' HELPER FUNCTIONS '''


def test_module_command(client: Client):
    client.fetch_organizations()
    return_results('ok')


def extract_errors(res: Response) -> list:
    errors = None
    try:
        errors = res.json().get('errors')
    except Exception:
        errors = None
    return errors


def meraki_fetch_org_command(client: Client, args: dict):
    res = client.fetch_organizations()
    command_results = CommandResults(
        outputs_prefix='Meraki.Organizations',
        outputs=res,
        outputs_key_field='id',
        readable_output=tableToMarkdown('Organizations:', res)
    )
    return_results(command_results)


def meraki_fetch_org_devices_command(client: Client, args: dict):
    organization_id = args.get('organizationId')
    res = client.fetch_org_dev_inv(organization_id=organization_id)
    command_results = CommandResults(
        outputs_prefix='Meraki.Devices',
        outputs=res,
        outputs_key_field='serial',
        readable_output=tableToMarkdown(f'Organization ({organization_id}) Devices:', res)
    )
    return_results(command_results)


def meraki_fetch_device_clients_command(client: Client, args: dict):
    serial = args.get('serial')
    timespan = args.get('timespan')
    res = client.fetch_device_clients(serial=serial, timespan=timespan)
    command_results = CommandResults(
        outputs_prefix='Meraki.Clients',
        outputs=res,
        outputs_key_field='id',
        readable_output=tableToMarkdown(f'Device (Serial: {serial}) Clients:', res)
    )
    return_results(command_results)


def meraki_fetch_network_clients_command(client: Client, args: dict):
    network_id = args.get('networkId')
    timespan = arg_to_number(args.get('timespan', "86400"))
    res = client.fetch_network_clients(network_id=network_id, timespan=timespan)
    command_results = CommandResults(
        outputs_prefix='Meraki.Clients',
        outputs=res,
        outputs_key_field='id',
        readable_output=tableToMarkdown(f'Network (ID: {network_id}) Clients:', res)
    )
    return_results(command_results)


def meraki_search_clients_command(client: Client, args: dict):
    organization_id = args.get('organizationId')
    mac = args.get('mac')
    res = client.search_clients(organization_id=organization_id, mac=mac)
    command_results = CommandResults(
        outputs_prefix='Meraki.Search.Clients',
        outputs=res,
        outputs_key_field='id',
        readable_output=tableToMarkdown(f'Client search (MAC: {mac}):', res)
    )
    return_results(command_results)


def meraki_get_org_lic_state_command(client: Client, args: dict):
    organization_id = args.get('organizationId')
    network_id = args.get('networkId')
    device_serials = args.get('deviceSerial')
    state = args.get('state').split(",") if args.get('state') else args.get('state')
    input_params = {
        'network_id': network_id,
        'deviceSerial': device_serials,
        'state': state
    }
    send_params = {k: v for k, v in input_params.items() if v}
    res = client.fetch_organization_licenses(organization_id=organization_id, params=send_params)
    command_results = CommandResults(
        outputs_prefix='Meraki.Licenses',
        outputs=res,
        outputs_key_field='id',
        readable_output=tableToMarkdown(f'Organization ({organization_id}) Licenses:', res)
    )
    return_results(command_results)


def meraki_fetch_networks_command(client: Client, args: dict):
    organization_id = args.get('organizationId')
    res = client.fetch_organization_networks(organization_id=organization_id)
    command_results = CommandResults(
        outputs_prefix='Meraki.Networks',
        outputs=res,
        outputs_key_field='id',
        readable_output=tableToMarkdown(f'Organization ({organization_id}) Networks:', res)
    )
    return_results(command_results)


def meraki_fetch_network_devices_command(client: Client, args: dict):
    network_id = args.get('networkId')
    res = client.fetch_network_devices(network_id=network_id)
    command_results = CommandResults(
        outputs_prefix='Meraki.Devices',
        outputs=res,
        outputs_key_field='id',
        readable_output=tableToMarkdown(f'Network ({network_id}) Devices:', res)
    )
    return_results(command_results)


def meraki_fetch_device_command(client: Client, args: dict):
    serial = args.get('serial')
    res = client.fetch_device(serial=serial)
    command_results = CommandResults(
        outputs_prefix='Meraki.Devices',
        outputs=res,
        outputs_key_field='id',
        readable_output=tableToMarkdown(f'Device (Serial: {serial}):', res)
    )
    return_results(command_results)


def meraki_update_device_command(client: Client, args: dict):
    serial = args.get('serial')
    updates = {
        'name': args.get('name'),
        'tags': argToList(args.get('tags')),
        'lat': args.get('lat'),
        'lng': args.get('lng'),
        'address': args.get('address'),
        'notes': args.get('notes'),
        'moveMapMarker': argToBoolean(args.get('moveMapMarker')),
        'switchProfileId': args.get('switchProfileId'),
        'floorPlanId': args.get('floorPlanId')
    }
    res = client.update_device(serial=serial, updates=updates)
    command_results = CommandResults(
        outputs_prefix='Meraki.Devices',
        outputs=res,
        outputs_key_field='serial',
        readable_output=tableToMarkdown(f'Updated device (Serial: {serial}):', res)
    )
    return_results(command_results)


def meraki_claim_device_command(client: Client, args: dict):
    network_id = args.get('networkId')
    serials = args.get('serials')
    serial_list = argToList(serials)
    res = client.claim_device(network_id=network_id, serials=serial_list)
    outputs = {
        "networkId": network_id,
        "serials": serials,
        'success': False,
        'errors': None
    }
    readable_output = f'Claim of Serial numbers {serials} from network ID {network_id} failed'
    if res.status_code == 204:
        outputs['success'] = True
        readable_output = f'Claim of Serial numbers {serials} from network ID {network_id} succeeded'
    elif res.status_code == 404:
        errors = extract_errors(res)
        outputs['errors'] = errors
        readable_output = f'Claim of Serial number {serials} from network ID {network_id} failed:\n{",".join(errors)}'
    command_results = CommandResults(
        outputs_prefix='Meraki.ClaimDevices',
        outputs=outputs,
        outputs_key_field=['networkId', 'serials'],
        readable_output=readable_output
    )
    return_results(command_results)


def meraki_fetch_organization_uplinks_command(client: Client, args: dict):
    organization_id = args.get('organizationId')
    network_ids = argToList(args.get('networkIds'))
    serials = argToList(args.get('serials'))
    res = client.fetch_org_uplinks(organization_id=organization_id, network_ids=network_ids, serials=serials)
    command_results = CommandResults(
        outputs_prefix='Meraki.Uplinks',
        outputs=res,
        outputs_key_field='serial',
        readable_output=tableToMarkdown(f'Uplinks (Organization ID: {organization_id}):', res)
    )
    return_results(command_results)


def meraki_fetch_wireless_firewall_rules_command(client: Client, args: dict):
    network_id = args.get('networkId')
    number = args.get('number')
    res = client.fetch_wireless_firewall_rules(network_id=network_id, number=number)
    command_results = CommandResults(
        outputs_prefix='Meraki.Firewall.Rules',
        outputs=res,
        outputs_key_field=['policy', 'protocol', 'destPort', 'destCidr'],
        readable_output=tableToMarkdown(f'Firewall Rules for SSID {number} on Network ID {network_id}:', res)
    )
    return_results(command_results)


def meraki_fetch_appliance_firewall_rules_command(client: Client, args: dict):
    network_id = args.get('networkId')
    res = client.fetch_appliance_firewall_rules(network_id=network_id)
    command_results = CommandResults(
        outputs_prefix='Meraki.Firewall.Rules',
        outputs=res,
        outputs_key_field=['policy', 'protocol', 'destPort', 'destCidr'],
        readable_output=tableToMarkdown(f'Firewall Rules for appliance (Network ID: {network_id}):', res)
    )
    return_results(command_results)


def meraki_update_wireless_firewall_rules_command(client: Client, args: dict):
    network_id = args.get('networkId')
    number = args.get('number')
    rules = argToList(args.get('rules'))
    allow_lan = argToBoolean(args.get('allowLanAccess'))
    res = client.update_wireless_firewall_rules(network_id=network_id, number=number, rules=rules, allow_lan=allow_lan)
    command_results = CommandResults(
        outputs_prefix='Meraki.Firewall.Rules',
        outputs=res,
        outputs_key_field=['policy', 'protocol', 'destPort', 'destCidr'],
        readable_output=tableToMarkdown(f'Firewall Rules for SSID {number} on Network ID {network_id}:', res)
    )
    return_results(command_results)


def meraki_update_appliance_firewall_rules_command(client: Client, args: dict):
    network_id = args.get('networkId')
    rules = argToList(args.get('rules'))
    syslog = argToBoolean(args.get('syslogDefaultRule', "false"))
    res = client.update_appliance_firewall_rules(network_id=network_id, rules=rules, syslog=syslog)
    command_results = CommandResults(
        outputs_prefix='Meraki.Firewall.Rules',
        outputs=res,
        outputs_key_field=['policy', 'protocol', 'destPort', 'destCidr'],
        readable_output=tableToMarkdown(f'Firewall Rules for appliance (Network ID: {network_id}):', res)
    )
    return_results(command_results)


def meraki_remove_device_command(client: Client, args: dict):
    network_id = args.get('networkId')
    serial = args.get('serial')
    res = client.remove_device(network_id=network_id, serial=serial)
    outputs = {
        "networkId": network_id,
        "serial": serial,
        'success': False,
        'errors': None
    }
    readable_output = f'Removal of Serial number {serial} from network ID {network_id} failed'
    if res.status_code == 204:
        outputs['success'] = True
        readable_output = f'Removal of Serial number {serial} from network ID {network_id} succeeded'
    elif res.status_code == 404:
        errors = extract_errors(res)
        outputs['errors'] = errors
        readable_output = f'Removal of Serial number {serial} from network ID {network_id} failed:\n{",".join(errors)}'
    command_results = CommandResults(
        outputs_prefix='Meraki.DeviceRemoval',
        outputs=outputs,
        outputs_key_field=['networkId', 'serial'],
        readable_output=readable_output
    )
    return_results(command_results)


def meraki_fetch_ssids_command(client: Client, args: dict):
    network_id = args.get('networkId')
    res = client.get_network_ssids(network_id=network_id)
    command_results = CommandResults(
        outputs_prefix='Meraki.SSID',
        outputs=res,
        outputs_key_field=['number', 'name'],
        readable_output=tableToMarkdown(f'Network ({network_id}) SSIDs:', res)
    )
    return_results(command_results)


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    args = demisto.args()
    api_key = params.get('apiKey')

    verify = not params.get('insecure')
    proxy = params.get('proxy')
    headers = {
        'X-Cisco-Meraki-API-Key': api_key,
        'Content-Type': 'application/json',
    }

    commands = {
        'meraki-fetch-organizations': meraki_fetch_org_command,
        'meraki-fetch-organization-devices': meraki_fetch_org_devices_command,
        'meraki-get-organization-license-state': meraki_get_org_lic_state_command,
        'meraki-fetch-networks': meraki_fetch_networks_command,
        'meraki-fetch-network-devices': meraki_fetch_network_devices_command,
        'meraki-update-device': meraki_update_device_command,
        'meraki-claim-device': meraki_claim_device_command,
        'meraki-fetch-device': meraki_fetch_device_command,
        'meraki-fetch-organization-uplinks': meraki_fetch_organization_uplinks_command,
        'meraki-fetch-device-clients': meraki_fetch_device_clients_command,
        'meraki-fetch-network-clients': meraki_fetch_network_clients_command,
        'meraki-search-clients': meraki_search_clients_command,
        'meraki-fetch-wireless-firewall-rules': meraki_fetch_wireless_firewall_rules_command,
        'meraki-fetch-appliance-firewall-rules': meraki_fetch_appliance_firewall_rules_command,
        'meraki-update-wireless-firewall-rules': meraki_update_wireless_firewall_rules_command,
        'meraki-update-appliance-firewall-rules': meraki_update_appliance_firewall_rules_command,
        'meraki-remove-device': meraki_remove_device_command,
        'meraki-fetch-ssids': meraki_fetch_ssids_command
    }

    # try:
    client = Client(
        base_url,
        verify=verify,
        proxy=proxy,
        headers=headers
    )

    command = demisto.command()

    if command == 'test-module':
        test_module_command(client)

    elif command in commands:
        commands[command](client, args)

    # except Exception as err:
    #    demisto.error(traceback.format_exc())  # print the traceback
    #    return_error(f'Failed to execute {command} command.\nError:\n{str(err)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
