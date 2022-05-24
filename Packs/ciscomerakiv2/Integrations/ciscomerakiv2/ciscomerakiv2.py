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

    def fetch_org_dev_inv(self, organization_id: str = None, params:dict = None):
        url_suffix = f'organizations/{organization_id}/devices/statuses'
        res = self._http_request('GET', url_suffix=url_suffix, params=params)
        return res



''' HELPER FUNCTIONS '''


def test_module_command(client, args):
    res = client.fetch_organizations()
    return_results('ok')


def meraki_fetch_org_command(client, args):
    res = client.fetch_organizations()
    return_error(res)
    command_results = CommandResults(
        outputs_prefix='Meraki.Organization',
        outputs=res,
        outputs_key_field='id',
        readable_output=tableToMarkdown('Organizations:', res)
    )
    return_results(command_results)


def meraki_fetch_org_dev_inv_command(client, args):
    organization_id = args.get('organizationId')
    input_params = {
        'network_ids': args.get('networkIds'),
        'serials': args.get('serials'),
        'statuses': args.get('statuses').split(","),
        'product_types': args.get('productTypes').split(","),
        'models': args.get('productTypes').split(",")
    }
    send_params = {k: v for k, v in input_params.items() if v}
    res = client.fetch_org_dev_inv(organization_id=organization_id, params=send_params)
    command_results = CommandResults(
        outputs_prefix='Meraki.Organization.Devices',
        outputs=res,
        outputs_key_field='serial',
        readable_output=tableToMarkdown(f'Organization ({organization_id}) Devices:', res)
    )
    return_results(command_results)



def meraki_get_org_lic_state_command(client, args):
    pass


def meraki_fetch_networks_command(client, args):
    pass


def meraki_fetch_devices_command(client, args):
    pass


def meraki_get_device_command(client, args):
    pass


def meraki_update_device_command(client, args):
    pass


def meraki_claim_device_command(client, args):
    pass


def meraki_fetch_device_uplink_command(client, args):
    pass


def meraki_fetch_clients(client, args):
    pass


def meraki_fetch_firewall_rules_command(client, args):
    pass


def meraki_updated_firewall_rules_command(client, args):
    pass


def meraki_remove_device_command(client, args):
    pass


def meraki_fetch_ssids_command(client, args):
    pass


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
        'meraki-fetch-organization-device-inventory': meraki_fetch_org_dev_inv_command,
        'meraki-get-organization-license-state': meraki_get_org_lic_state_command,
        'meraki-fetch-networks': meraki_fetch_networks_command,
        'meraki-fetch-devices': meraki_fetch_devices_command,
        'meraki-get-device': meraki_get_device_command,
        'meraki-update-device': meraki_update_device_command,
        'meraki-claim-device': meraki_claim_device_command,
        'meraki-fetch-device-uplink': meraki_fetch_device_uplink_command,
        'meraki-fetch-clients': meraki_fetch_clients,
        'meraki-fetch-firewall-rules': meraki_fetch_firewall_rules_command,
        'meraki-update-firewall-rules': meraki_updated_firewall_rules_command,
        'meraki-remove-device': meraki_remove_device_command,
        'meraki-fetch-ssids': meraki_fetch_ssids_command
    }

    #try:
    client = Client(
        base_url,
        verify=verify,
        proxy=proxy,
        headers=headers
    )

    command = demisto.command()

    if command == 'test-module':
        test_module_command(client, args)

    elif command in commands:
        commands[command](client, args)

    #except Exception as err:
    #    demisto.error(traceback.format_exc())  # print the traceback
    #    return_error(f'Failed to execute {command} command.\nError:\n{str(err)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
