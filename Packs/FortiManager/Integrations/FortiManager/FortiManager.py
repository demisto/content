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

        if response.get('result')[0].get('status').get('code') != 0:
            raise DemistoException(response.get('result')[0].get('status').get('message'))

        return response.get('result')[0].get('data')


def get_global_or_adom(client, args):
    adom = args.get('adom') if args.get('adom') else client.adom
    if adom == GLOBAL_VAR:
        return GLOBAL_VAR
    else:
        return f"adom/{adom}"


def setup_request_data(args, excluded_args):
    return {key.replace('_', '-'): args.get(key) for key in args if key not in excluded_args}


def get_specific_entity(entity_name):
    if entity_name:
        return f"/{entity_name}"
    else:
        return ""


def get_range_for_list_command(args):
    first_index = args.get('from')
    last_index = args.get('to')
    list_range = []

    if first_index:
        list_range.append(first_index)

    if last_index:
        list_range.append(list_range)

    if list_range:
        return {"range": [list_range]}
    else:
        return None


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
                                                                 f"/obj/firewall/address"
                                                                 f"{get_specific_entity(args.get('address'))}",
                                                          data=get_range_for_list_command(args))

    return CommandResults(
        outputs_prefix='FortiManager.Address',
        outputs_key_field='name',
        outputs=firewall_addresses,
        readable_output=tableToMarkdown("Firewall IPv4 Addresses", firewall_addresses,
                                        removeNull=True, headerTransform=string_to_table_header),
        raw_response=firewall_addresses,
    )


def list_firewall_address_groups_command(client, args):
    address_group = get_specific_entity(args.get('address_group'))
    firewall_address_groups = client.fortimanager_http_request("get", f"/pm/config/"
                                                                      f"{get_global_or_adom(client, args)}"
                                                                      f"/obj/firewall/addrgrp{address_group}",
                                                               data=get_range_for_list_command(args))

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
                                                                 f"obj/firewall/service/category"
                                                                 f"{get_specific_entity(args.get('service_category'))}",
                                                          data=get_range_for_list_command(args))

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
                                                             f"/obj/firewall/service/group"
                                                             f"{get_specific_entity(args.get('service_group'))}",
                                                      data=get_range_for_list_command(args))

    return CommandResults(
        outputs_prefix='FortiManager.ServiceGroup',
        outputs_key_field='name',
        outputs=service_groups,
        readable_output=tableToMarkdown("Service Groups", service_groups, removeNull=True,
                                        headerTransform=string_to_table_header),
        raw_response=service_groups,
    )


def list_custom_service_command(client, args):
    custom_services = client.fortimanager_http_request("get", f"/pm/config/"
                                                              f"{get_global_or_adom(client, args)}"
                                                              f"/obj/firewall/service/custom"
                                                              f"{get_specific_entity(args.get('custom_service'))}",
                                                       data=get_range_for_list_command(args))

    return CommandResults(
        outputs_prefix='FortiManager.CustomServices',
        outputs_key_field='name',
        outputs=custom_services,
        readable_output=tableToMarkdown("Custom Services", custom_services, removeNull=True,
                                        headerTransform=string_to_table_header),
        raw_response=custom_services,
    )


def list_policy_packages_command(client, args):
    policy_packages = client.fortimanager_http_request("get", f"pm/pkg/{get_global_or_adom(client, args)}"
                                                              f"{get_specific_entity(args.get('policy_package'))}",
                                                       data=get_range_for_list_command(args))

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
                                                       f"/pkg/{args.get('package')}/firewall/policy",
                                                data=get_range_for_list_command(args))

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

    return f"Created new Address {firewall_addresses.get('name')}"


def update_address_command(client, args):
    firewall_addresses = client.fortimanager_http_request("update", f"/pm/config/{get_global_or_adom(client, args)}"
                                                                    f"/obj/firewall/address/{args.get('name')}",
                                                          data=setup_request_data(args, ['adom']))

    return f"Updated Address {firewall_addresses.get('name')}"


def create_firewall_address_groups_command(client, args):
    firewall_address_groups = client.fortimanager_http_request("add", f"/pm/config/"
                                                                      f"{get_global_or_adom(client, args)}"
                                                                      f"/obj/firewall/addrgrp",
                                                               data=setup_request_data(args, ['adom']))

    return f"Created new Address Group {firewall_address_groups.get('name')}"


def update_firewall_address_groups_command(client, args):
    firewall_address_groups = client.fortimanager_http_request("update", f"/pm/config/"
                                                                         f"{get_global_or_adom(client, args)}"
                                                                         f"/obj/firewall/addrgrp/{args.get('name')}",
                                                               data=setup_request_data(args, ['adom']))

    return f"Updated Address Group {firewall_address_groups.get('name')}"


def create_service_groups_command(client, args):
    service_groups = client.fortimanager_http_request("add", f"/pm/config/"
                                                             f"{get_global_or_adom(client, args)}"
                                                             f"/obj/firewall/service/group",
                                                      data=setup_request_data(args, ['adom']))

    return f"Created new Service Group {service_groups.get('name')}"


def update_service_groups_command(client, args):
    service_groups = client.fortimanager_http_request("update", f"/pm/config/"
                                                                f"{get_global_or_adom(client, args)}"
                                                                f"/obj/firewall/service/group/{args.get('name')}",
                                                      data=setup_request_data(args, ['adom']))

    return f"Updated Service Group {service_groups.get('name')}"


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


def update_policy_packages_command(client, args):
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
    client.fortimanager_http_request("update", f"pm/pkg/{get_global_or_adom(client, args)}/{args.get('name')}",
                                     data=setup_request_data(args, ['adom', 'central_nat', 'consolidated_firewall',
                                                                    'fwpolicy_implicit_log',
                                                                    'fwpolicy6_implicit_log', 'inspection_mode',
                                                                    'ngfw_mode', 'ssl_ssh_profile']))

    return f"Update Policy Package {args.get('name')}"


def create_policy_command(client, args):
    for additional_param in args.get('additional_params').split(','):
        field_and_value = additional_param.split('=')
        args[field_and_value[0]] = field_and_value[1]

    policies = client.fortimanager_http_request("add", f"/pm/config/"
                                                       f"{get_global_or_adom(client, args)}"
                                                       f"/pkg/{args.get('package')}/firewall/policy/{args.get('name')}",
                                                data=setup_request_data(args, ['adom', 'package', 'additional_params']))

    return f"Created policy with ID {policies.get('id')}"


def create_custom_service_command(client, args):
    custom_services = client.fortimanager_http_request("add", f"/pm/config/"
                                                              f"{get_global_or_adom(client, args)}"
                                                              f"/obj/firewall/service/custom",
                                                       data=setup_request_data(args, ['adom']))
    return f"Created new Custom Service {custom_services.get('name')}"


def update_custom_service_command(client, args):
    custom_services = client.fortimanager_http_request("update", f"/pm/config/{get_global_or_adom(client, args)}"
                                                                 f"/obj/firewall/service/custom/{args.get('name')}",
                                                       data=setup_request_data(args, ['adom']))
    return f"Updated Custom Service {custom_services.get('name')}"


def update_policy_command(client, args):
    for additional_param in args.get('additional_params').split(','):
        field_and_value = additional_param.split('=')
        args[field_and_value[0]] = field_and_value[1]

    policies = client.fortimanager_http_request("update", f"/pm/config/"
                                                          f"{get_global_or_adom(client, args)}"
                                                          f"/pkg/{args.get('package')}/firewall/policy/"
                                                          f"{args.get('name')}",
                                                data=setup_request_data(args, ['adom', 'package', 'additional_params']))

    return f"Created policy with ID {policies.get('id')}"


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


def delete_policy_package_command(client, args):
    client.fortimanager_http_request("delete", f"pm/pkg/{get_global_or_adom(client, args)}/{args.get('pkg_path')}")
    return f"Deleted Policy Package {args.get('pkg_path')}"


def delete_policy_command(client, args):
    client.fortimanager_http_request("delete", f"/pm/config/{get_global_or_adom(client, args)}/pkg/"
                                               f"{args.get('package')}/firewall/policy{args.get('policy')}")
    return f"Deleted Policy {args.get('policy')}"


def delete_custom_service_command(client, args):
    client.fortimanager_http_request("delete", f"/pm/config/{get_global_or_adom(client, args)}"
                                               f"/obj/firewall/service/custom/{args.get('custom')}")
    return f"Deleted Custom Service {args.get('custom')}"


def move_policy_command(client, args):
    client.fortimanager_http_request("move", f"/pm/config/{get_global_or_adom(client, args)}"
                                             f"/pkg/{args.get('package')}/firewall/policy/{args.get('policy')}",
                                     data=setup_request_data(args, ['adom', 'package', 'policy']))

    return f"Created policy with ID {args.get('policy')}"


def list_dynamic_interface_command(client, args):
    dynamic_interfaces = client.fortimanager_http_request("get", f"/pm/config/"
                                                                 f"{get_global_or_adom(client, args)}"
                                                                 f"/obj/dynamic/interface",
                                                          data=get_range_for_list_command(args))

    return CommandResults(
        outputs_prefix='FortiManager.DynamicInterface',
        outputs_key_field='name',
        outputs=dynamic_interfaces,
        readable_output=tableToMarkdown(f"ADOM {client.adom} Dynamic Interfaces",
                                        dynamic_interfaces, removeNull=True, headerTransform=string_to_table_header),
        raw_response=dynamic_interfaces,
    )


def list_dynamic_address_mapping_command(client, args):
    dynamic_mapping = client.fortimanager_http_request("get", f"/pm/config/{get_global_or_adom(client, args)}"
                                                              f"/obj/firewall/address"
                                                              f"/{args.get('address')}/dynamic_mapping"
                                                              f"{get_specific_entity(args.get('dynamic_mapping'))}",
                                                       data=get_range_for_list_command(args))

    return CommandResults(
        outputs_prefix='FortiManager.Address.DynamicMapping',
        outputs_key_field='name',
        outputs=dynamic_mapping,
        readable_output=tableToMarkdown(f"Address {args.get('dynamic_mapping')} Dynamic Mapping",
                                        dynamic_mapping, removeNull=True, headerTransform=string_to_table_header),
        raw_response=dynamic_mapping,
    )


def create_dynamic_address_mapping_command(client, args):
    client.fortimanager_http_request("add", f"/pm/config/{get_global_or_adom(client, args)}"
                                            f"/obj/firewall/address/{args.get('address')}/dynamic_mapping",
                                     data=setup_request_data(args, ['adom', 'address']))

    return f"Created new dynamic mapping in address {args.get('address')}"


def update_dynamic_address_mapping_command(client, args):
    client.fortimanager_http_request("update", f"/pm/config/{get_global_or_adom(client, args)}"
                                               f"/obj/firewall/address/{args.get('address')}/dynamic_mapping",
                                     data=setup_request_data(args, ['adom', 'address']))

    return f"Updated dynamic mapping in address {args.get('address')}"


def delete_dynamic_address_mapping_command(client, args):
    client.fortimanager_http_request("update", f"/pm/config/{get_global_or_adom(client, args)}"
                                               f"/obj/firewall/address/{args.get('address')}/dynamic_mapping/"
                                               f"{args.get('dynamic_mapping')}",
                                     data=setup_request_data(args, ['adom', 'address']))

    return f"Deleted dynamic mapping {args.get('dynamic_mapping')} in address {args.get('address')}"


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    creds = demisto.params().get('creds')
    base_url = demisto.params().get('url')
    adom = demisto.params().get('adom')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

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
            list_adom_devices_command(client)
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

        elif demisto.command() == 'fortimanager-address-update':
            return_results(update_address_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-address-group-create':
            return_results(create_firewall_address_groups_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-address-group-update':
            return_results(update_firewall_address_groups_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-service-group-create':
            return_results(create_service_groups_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-service-group-update':
            return_results(update_service_groups_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-firewall-policy-package-create':
            return_results(create_policy_packages_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-firewall-policy-package-update':
            return_results(update_policy_packages_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-firewall-policy-create':
            return_results(create_policy_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-firewall-policy-update':
            return_results(update_policy_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-address-delete':
            return_results(delete_address_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-address-group-delete':
            return_results(delete_address_group_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-service-group-delete':
            return_results(delete_service_group_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-firewall-policy-package-delete':
            return_results(delete_policy_package_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-firewall-policy-delete':
            return_results(delete_policy_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-custom-service-list':
            return_results(list_custom_service_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-custom-service-create':
            return_results(create_custom_service_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-custom-service-update':
            return_results(update_custom_service_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-custom-service-delete':
            return_results(delete_custom_service_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-firewall-policy-move':
            return_results(move_policy_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-dynamic-interface-list':
            return_results(list_dynamic_interface_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-dynamic-address-mappings-list':
            return_results(list_dynamic_address_mapping_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-dynamic-address-mappings-create':
            return_results(create_dynamic_address_mapping_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-dynamic-address-mappings-update':
            return_results(update_dynamic_address_mapping_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-dynamic-address-mapping-delete':
            return_results(delete_dynamic_address_mapping_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{traceback.format_exc()}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
