import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3
import traceback

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50
GLOBAL_VAR = 'global'

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, url, credentials, verify, proxy, adom):
        super().__init__(base_url=url.rstrip('/'), verify=verify, proxy=proxy, ok_codes=(200, 204))
        self.username = credentials["identifier"]
        self.password = credentials["password"]
        self.session_token = self.get_session_token()
        self.adom = adom

    def get_session_token(self):
        body = {
            "id": 1,
            "method": "exec",
            "params": [{
                "url": "/sys/login/user",
                "data": {
                    "user": self.username,
                    "passwd": self.password
                }
            }]
        }

        response = self._http_request(
            method='POST',
            url_suffix='jsonrpc',
            json_data=body
        )
        return response.get('session')

    def fortimanager_http_request(self, method, url, data=None):
        body = {
            "id": 1,
            "method": method,
            "params": [{
                "url": url
            }],
            "session": self.session_token
        }

        if data:
            body['params'][0]['data'] = [data]

        response = self._http_request(
            method='POST',
            url_suffix='jsonrpc',
            json_data=body
        )

        return response.get('result')[0].get('data')


def get_global_or_adom(client, args):
    adom = args.get('adom') if args.get('adom') else client.adom
    if adom == GLOBAL_VAR:
        return GLOBAL_VAR
    else:
        return f"adom/{adom}"


def setup_request_data(args, excluded_args):
    return {key.replace('_', '-'): args.get(key) for key in args if key not in excluded_args}


def list_adom_devices_command(client):
    devices_data = client.fortimanager_http_request("get", f"/dvmdb/adom/{client.adom}/device")

    return CommandResults(
        outputs_prefix='FortiManager.Device',
        outputs_key_field='name',
        outputs=devices_data,
        readable_output=tableToMarkdown(f"ADOM {client.adom} Devices", devices_data, removeNull=True,
                                        headerTransform=string_to_table_header),
        raw_response=devices_data,
    )


def list_adom_devices_groups_command(client):
    device_groups_data = client.fortimanager_http_request("get", f"/dvmdb/adom/{client.adom}/group")

    return CommandResults(
        outputs_prefix='FortiManager.DeviceGroup',
        outputs_key_field='name',
        outputs=device_groups_data,
        readable_output=tableToMarkdown(f"ADOM {client.adom} Device Groups", device_groups_data, removeNull=True,
                                        headerTransform=string_to_table_header),
        raw_response=device_groups_data,
    )


def list_firewall_addresses_command(client, args):
    firewall_addresses = client.fortimanager_http_request("get", f"/pm/config/{get_global_or_adom(client, args)}"
                                                                 f"/obj/firewall/address")

    return CommandResults(
        outputs_prefix='FortiManager.Address',
        outputs_key_field='name',
        outputs=firewall_addresses,
        readable_output=tableToMarkdown("Firewall IPv4 Addresses", firewall_addresses,
                                        removeNull=True, headerTransform=string_to_table_header),
        raw_response=firewall_addresses,
    )


def list_firewall_address_groups_command(client, args):
    firewall_address_groups = client.fortimanager_http_request("get", f"/pm/config/"
                                                                      f"{get_global_or_adom(client, args)}"
                                                                      f"/obj/firewall/addrgrp")

    return CommandResults(
        outputs_prefix='FortiManager.AddressGroup',
        outputs_key_field='name',
        outputs=firewall_address_groups,
        readable_output=tableToMarkdown("Firewall IPv4 Address Groups", firewall_address_groups,
                                        removeNull=True, headerTransform=string_to_table_header),
        raw_response=firewall_address_groups,
    )


def list_service_categories_command(client, args):
    service_categories = client.fortimanager_http_request("get", f"/pm/config/"
                                                                 f"{get_global_or_adom(client, args)}/"
                                                                 f"obj/firewall/service/category")

    return CommandResults(
        outputs_prefix='FortiManager.ServiceCategory',
        outputs_key_field='name',
        outputs=service_categories,
        readable_output=tableToMarkdown("Service Categories", service_categories, removeNull=True,
                                        headerTransform=string_to_table_header),
        raw_response=service_categories,
    )


def list_service_groups_command(client, args):
    service_groups = client.fortimanager_http_request("get", f"/pm/config/"
                                                             f"{get_global_or_adom(client, args)}"
                                                             f"/obj/firewall/service/group")

    return CommandResults(
        outputs_prefix='FortiManager.ServiceGroup',
        outputs_key_field='name',
        outputs=service_groups,
        readable_output=tableToMarkdown("Service Groups", service_groups, removeNull=True,
                                        headerTransform=string_to_table_header),
        raw_response=service_groups,
    )


def list_policy_packages_command(client, args):
    policy_packages = client.fortimanager_http_request("get", f"pm/pkg/{get_global_or_adom(client, args)}")

    return CommandResults(
        outputs_prefix='FortiManager.PolicyPackage',
        outputs_key_field='name',
        outputs=policy_packages,
        readable_output=tableToMarkdown("Policy Packages", policy_packages, removeNull=True,
                                        headerTransform=string_to_table_header),
        raw_response=policy_packages,
    )


def list_policies_command(client, args):
    policies = client.fortimanager_http_request("get", f"/pm/config/"
                                                       f"{get_global_or_adom(client, args)}"
                                                       f"pkg/{args.get('package')}/firewall/policy")

    return CommandResults(
        outputs_prefix='FortiManager.PolicyPackage.Policy',
        outputs_key_field='name',
        outputs=policies,
        readable_output=tableToMarkdown(f"ADOM {client.adom} Policy Package {args.get('package')} Policies",
                                        policies, removeNull=True, headerTransform=string_to_table_header),
        raw_response=policies,
    )


def create_address_command(client, args):
    firewall_addresses = client.fortimanager_http_request("add", f"/pm/config/{get_global_or_adom(client, args)}"
                                                                 f"/obj/firewall/address",
                                                          data=setup_request_data(args, ['adom']))

    return f"Created new Address {firewall_addresses[0].get('name')}"


def create_firewall_address_groups_command(client, args):
    firewall_address_groups = client.fortimanager_http_request("add", f"/pm/config/"
                                                                      f"{get_global_or_adom(client, args)}"
                                                                      f"/obj/firewall/addrgrp",
                                                               data=setup_request_data(args, ['adom']))

    return f"Created new Address Group {firewall_address_groups[0].get('name')}"


def create_service_groups_command(client, args):
    service_groups = client.fortimanager_http_request("add", f"/pm/config/"
                                                             f"{get_global_or_adom(client, args)}"
                                                             f"/obj/firewall/service/group",
                                                      data=setup_request_data(args, ['adom']))

    return f"Created new Service Group {service_groups[0].get('name')}"


def create_policy_packages_command(client, args):
    package_settings = {
        'central-nat': args.get('central_nat'),
        'consolidated-firewall': args.get('consolidated_firewall'),
        'fwpolicy-implicit-log': args.get('fwpolicy_implicit_log'),
        'fwpolicy6-implicit-log': args.get('fwpolicy6_implicit_log'),
        'inspection-mode': args.get('inspection_mode'),
        'ngfw-mode': args.get('ngfw_mode'),
        'ssl-ssh-profile': args.get('ssl_ssh_profile')
    }

    args['package settings'] = package_settings
    client.fortimanager_http_request("add", f"pm/pkg/{get_global_or_adom(client, args)}",
                                     data=setup_request_data(args, ['adom', 'central_nat', 'consolidated_firewall',
                                                                    'fwpolicy_implicit_log',
                                                                    'fwpolicy6_implicit_log', 'inspection_mode',
                                                                    'ngfw_mode', 'ssl_ssh_profile']))

    return f"Created new Policy Package {args.get('name')}"


def create_policy_command(client, args):
    for additional_param in args.get('additional_params').split(','):
        field_and_value = additional_param.split('=')
        args[field_and_value[0]] = field_and_value[1]

    policies = client.fortimanager_http_request("add", f"/pm/config/"
                                                       f"{get_global_or_adom(client, args)}"
                                                       f"pkg/{args.get('package')}/firewall/policy",
                                                data=setup_request_data(args, ['adom', 'package', 'additional_params']))

    return f"Created policy with ID {policies[0].get('id')}"


def delete_address_command(client, args):
    client.fortimanager_http_request("delete", f"/pm/config/{get_global_or_adom(client, args)}"
                                               f"/obj/firewall/address/{args.get('address')}")
    return f"Deleted Address {args.get('address')}"


def delete_address_group_command(client, args):
    client.fortimanager_http_request("delete", f"/pm/config/{get_global_or_adom(client, args)}"
                                               f"/obj/firewall/addrgrp/{args.get('address_group')}")
    return f"Deleted Address Group {args.get('address_group')}"


def delete_service_group_command(client, args):
    client.fortimanager_http_request("delete", f"/pm/config/{get_global_or_adom(client, args)}"
                                               f"/obj/firewall/service/group/{args.get('service_group')}")
    return f"Deleted Address Group {args.get('service_group')}"


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    creds = demisto.params().get('creds')

    # get the service API url
    base_url = demisto.params().get('url')

    adom = demisto.params().get('adom')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            url=base_url,
            credentials=creds,
            verify=verify_certificate,
            proxy=proxy,
            adom=adom
        )

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results("ok")

        elif demisto.command() == 'fortimanager-devices-list':
            return_results(list_adom_devices_command(client))

        elif demisto.command() == 'fortimanager-device-groups-list':
            return_results(list_adom_devices_groups_command(client))

        elif demisto.command() == 'fortimanager-addresses-list':
            return_results(list_firewall_addresses_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-address-groups-list':
            return_results(list_firewall_address_groups_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-service-categories-list':
            return_results(list_service_categories_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-service-group-list':
            return_results(list_service_groups_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-firewall-policy-package-list':
            return_results(list_policy_packages_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-firewall-policy-list':
            return_results(list_policies_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-address-create':
            return_results(create_address_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-address-group-create':
            return_results(create_firewall_address_groups_command(client, demisto.args))

        elif demisto.command() == 'fortimanager-firewall-policy-package-create':
            return_results(create_policy_packages_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-firewall-policy-create':
            return_results(create_policy_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-address-delete':
            return_results(delete_address_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-address-group-delete':
            return_results(delete_address_group_command(client, demisto.args()))

        elif demisto.command() == '':
            return_results(delete_service_group_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
