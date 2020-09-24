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

    def get_session_token(self, get_new_token=False):
        if get_new_token:
            response = self.fortimanager_http_request('exec', "/sys/login/user",
                                                      json_data={'user': self.username, 'passwd': self.password},
                                                      add_session_token=False)

            demisto.setIntegrationContext({'session': response.get('session')})
            return response.get('session')

        else:
            current_token = demisto.getIntegrationContext().get('session')
            return current_token if current_token else self.get_session_token(get_new_token=True)

    def fortimanager_http_request(self, method, url, data_in_list=None, json_data=None, range_info=None,
                                  other_params=None, add_session_token=True):
        body = {
            "id": 1,
            "method": method,
            "params": [{
                "url": url
            }],
        }

        if add_session_token:
            body['session'] = self.session_token

        if data_in_list:
            body['params'][0]['data'] = [data_in_list]

        if json_data:
            body['params'][0]['data'] = json_data

        if range_info:
            body['params'][0]['range'] = range_info

        if other_params:
            for param in other_params:
                body['params'][0][param] = other_params.get(param)

        response = self._http_request(
            method='POST',
            url_suffix='jsonrpc',
            json_data=body
        )
        return response

    def fortimanager_api_call(self, method, url, data=None, range_info=None, other_params=None):
        response = self.fortimanager_http_request(method, url, data_in_list=data, range_info=range_info,
                                                  other_params=other_params)

        # catch session token expiration - fetch new token and retry
        if response.get('result')[0].get('status').get('code') != -11:
            self.session_token = self.get_session_token(get_new_token=True)
            response = self.fortimanager_http_request(method, url, data_in_list=data, range_info=range_info,
                                                      other_params=other_params)

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

    if first_index is not None:
        list_range.append(int(first_index))

    if last_index is not None:
        list_range.append(int(last_index) + 1)

    if list_range:
        return list_range

    else:
        return None


def list_adom_devices_command(client, args):
    devices_data = client.fortimanager_api_call("get", f"/dvmdb/{get_global_or_adom(client, args)}/device"
                                                       f"{get_specific_entity(args.get('device'))}")

    headers = ['name', 'ip', 'hostname', 'os_type', 'adm_usr', 'app_ver', 'vdom']

    return CommandResults(
        outputs_prefix='FortiManager.Device',
        outputs_key_field='name',
        outputs=devices_data,
        readable_output=tableToMarkdown(f"ADOM {get_global_or_adom(client, args)} Devices", devices_data,
                                        removeNull=True, headerTransform=string_to_table_header, headers=headers),
        raw_response=devices_data,
    )


def list_adom_devices_groups_command(client, args):
    device_groups_data = client.fortimanager_api_call("get", f"/dvmdb/{get_global_or_adom(client, args)}/group"
                                                             f"{get_specific_entity(args.get('group'))}")

    return CommandResults(
        outputs_prefix='FortiManager.DeviceGroup',
        outputs_key_field='name',
        outputs=device_groups_data,
        readable_output=tableToMarkdown(f"ADOM {get_global_or_adom(client, args)} Device Groups", device_groups_data,
                                        removeNull=True, headerTransform=string_to_table_header),
        raw_response=device_groups_data,
    )


def list_firewall_addresses_command(client, args):
    firewall_addresses = client.fortimanager_api_call("get", f"/pm/config/{get_global_or_adom(client, args)}"
                                                             f"/obj/firewall/address"
                                                             f"{get_specific_entity(args.get('address'))}",
                                                      range_info=get_range_for_list_command(args))

    headers = ['name', 'type', 'subnet', 'start-ip', 'end-ip', 'fqdn', 'wildcard', 'country', 'wildcard-fqdn']

    return CommandResults(
        outputs_prefix='FortiManager.Address',
        outputs_key_field='name',
        outputs=firewall_addresses,
        readable_output=tableToMarkdown("Firewall IPv4 Addresses", firewall_addresses,
                                        removeNull=True, headerTransform=string_to_table_header, headers=headers),
        raw_response=firewall_addresses,
    )


def list_firewall_address_groups_command(client, args):
    address_group = get_specific_entity(args.get('address_group'))
    firewall_address_groups = client.fortimanager_api_call("get", f"/pm/config/"
                                                                  f"{get_global_or_adom(client, args)}"
                                                                  f"/obj/firewall/addrgrp{address_group}",
                                                           range_info=get_range_for_list_command(args))

    return CommandResults(
        outputs_prefix='FortiManager.AddressGroup',
        outputs_key_field='name',
        outputs=firewall_address_groups,
        readable_output=tableToMarkdown("Firewall IPv4 Address Groups", firewall_address_groups,
                                        removeNull=True, headerTransform=string_to_table_header),
        raw_response=firewall_address_groups,
    )


def list_service_categories_command(client, args):
    service_categories = client.fortimanager_api_call("get", f"/pm/config/"
                                                             f"{get_global_or_adom(client, args)}/"
                                                             f"obj/firewall/service/category"
                                                             f"{get_specific_entity(args.get('service_category'))}",
                                                      range_info=get_range_for_list_command(args))

    return CommandResults(
        outputs_prefix='FortiManager.ServiceCategory',
        outputs_key_field='name',
        outputs=service_categories,
        readable_output=tableToMarkdown("Service Categories", service_categories, removeNull=True,
                                        headerTransform=string_to_table_header),
        raw_response=service_categories,
    )


def list_service_groups_command(client, args):
    service_groups = client.fortimanager_api_call("get", f"/pm/config/"
                                                         f"{get_global_or_adom(client, args)}"
                                                         f"/obj/firewall/service/group"
                                                         f"{get_specific_entity(args.get('service_group'))}",
                                                  range_info=get_range_for_list_command(args))

    return CommandResults(
        outputs_prefix='FortiManager.ServiceGroup',
        outputs_key_field='name',
        outputs=service_groups,
        readable_output=tableToMarkdown("Service Groups", service_groups, removeNull=True,
                                        headerTransform=string_to_table_header),
        raw_response=service_groups,
    )


def list_custom_service_command(client, args):
    custom_services = client.fortimanager_api_call("get", f"/pm/config/"
                                                          f"{get_global_or_adom(client, args)}"
                                                          f"/obj/firewall/service/custom"
                                                          f"{get_specific_entity(args.get('custom_service'))}",
                                                   range_info=get_range_for_list_command(args))

    return CommandResults(
        outputs_prefix='FortiManager.CustomServices',
        outputs_key_field='name',
        outputs=custom_services,
        readable_output=tableToMarkdown("Custom Services", custom_services, removeNull=True,
                                        headerTransform=string_to_table_header),
        raw_response=custom_services,
    )


def list_policy_packages_command(client, args):
    policy_packages = client.fortimanager_api_call("get", f"pm/pkg/{get_global_or_adom(client, args)}"
                                                          f"{get_specific_entity(args.get('policy_package'))}",
                                                   range_info=get_range_for_list_command(args))

    return CommandResults(
        outputs_prefix='FortiManager.PolicyPackage',
        outputs_key_field='name',
        outputs=policy_packages,
        readable_output=tableToMarkdown("Policy Packages", policy_packages, removeNull=True,
                                        headerTransform=string_to_table_header),
        raw_response=policy_packages,
    )


def list_policies_command(client, args):
    policies = client.fortimanager_api_call("get", f"/pm/config/"
                                                   f"{get_global_or_adom(client, args)}"
                                                   f"/pkg/{args.get('package')}/firewall/policy",
                                            range_info=get_range_for_list_command(args))

    return CommandResults(
        outputs_prefix='FortiManager.PolicyPackage.Policy',
        outputs_key_field='name',
        outputs=policies,
        readable_output=tableToMarkdown(f"ADOM {client.adom} Policy Package {args.get('package')} Policies",
                                        policies, removeNull=True, headerTransform=string_to_table_header),
        raw_response=policies,
    )


def create_address_command(client, args):
    firewall_addresses = client.fortimanager_api_call("add", f"/pm/config/{get_global_or_adom(client, args)}"
                                                             f"/obj/firewall/address",
                                                      data=setup_request_data(args, ['adom']))

    return f"Created new Address {firewall_addresses.get('name')}"


def update_address_command(client, args):
    firewall_addresses = client.fortimanager_api_call("update", f"/pm/config/{get_global_or_adom(client, args)}"
                                                                f"/obj/firewall/address",
                                                      data=setup_request_data(args, ['adom']))

    return f"Updated Address {firewall_addresses.get('name')}"


def create_firewall_address_groups_command(client, args):
    firewall_address_groups = client.fortimanager_api_call("add", f"/pm/config/"
                                                                  f"{get_global_or_adom(client, args)}"
                                                                  f"/obj/firewall/addrgrp",
                                                           data=setup_request_data(args, ['adom']))

    return f"Created new Address Group {firewall_address_groups.get('name')}"


def update_firewall_address_groups_command(client, args):
    firewall_address_groups = client.fortimanager_api_call("update", f"/pm/config/"
                                                                     f"{get_global_or_adom(client, args)}"
                                                                     f"/obj/firewall/addrgrp",
                                                           data=setup_request_data(args, ['adom']))

    return f"Updated Address Group {firewall_address_groups.get('name')}"


def create_service_groups_command(client, args):
    service_groups = client.fortimanager_api_call("add", f"/pm/config/"
                                                         f"{get_global_or_adom(client, args)}"
                                                         f"/obj/firewall/service/group",
                                                  data=setup_request_data(args, ['adom']))

    return f"Created new Service Group {service_groups.get('name')}"


def update_service_groups_command(client, args):
    service_groups = client.fortimanager_api_call("update", f"/pm/config/"
                                                            f"{get_global_or_adom(client, args)}"
                                                            f"/obj/firewall/service/group",
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
    client.fortimanager_api_call("add", f"pm/pkg/{get_global_or_adom(client, args)}",
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
    client.fortimanager_api_call("update", f"pm/pkg/{get_global_or_adom(client, args)}",
                                 data=setup_request_data(args, ['adom', 'central_nat', 'consolidated_firewall',
                                                                'fwpolicy_implicit_log',
                                                                'fwpolicy6_implicit_log', 'inspection_mode',
                                                                'ngfw_mode', 'ssl_ssh_profile']))

    return f"Update Policy Package {args.get('name')}"


def create_policy_command(client, args):
    for additional_param in args.get('additional_params').split(','):
        field_and_value = additional_param.split('=')
        args[field_and_value[0]] = field_and_value[1]

    policies = client.fortimanager_api_call("add", f"/pm/config/"
                                                   f"{get_global_or_adom(client, args)}"
                                                   f"/pkg/{args.get('package')}/firewall/policy",
                                            data=setup_request_data(args, ['adom', 'package', 'additional_params']))

    return f"Created policy with ID {policies.get('id')}"


def create_custom_service_command(client, args):
    custom_services = client.fortimanager_api_call("add", f"/pm/config/"
                                                          f"{get_global_or_adom(client, args)}"
                                                          f"/obj/firewall/service/custom",
                                                   data=setup_request_data(args, ['adom']))
    return f"Created new Custom Service {custom_services.get('name')}"


def update_custom_service_command(client, args):
    custom_services = client.fortimanager_api_call("update", f"/pm/config/{get_global_or_adom(client, args)}"
                                                             f"/obj/firewall/service/custom",
                                                   data=setup_request_data(args, ['adom']))
    return f"Updated Custom Service {custom_services.get('name')}"


def update_policy_command(client, args):
    for additional_param in args.get('additional_params').split(','):
        field_and_value = additional_param.split('=')
        args[field_and_value[0]] = field_and_value[1]

    policies = client.fortimanager_api_call("update", f"/pm/config/"
                                                      f"{get_global_or_adom(client, args)}"
                                                      f"/pkg/{args.get('package')}/firewall/policy",
                                            data=setup_request_data(args, ['adom', 'package', 'additional_params']))

    return f"Created policy with ID {policies.get('id')}"


def delete_address_command(client, args):
    client.fortimanager_api_call("delete", f"/pm/config/{get_global_or_adom(client, args)}"
                                           f"/obj/firewall/address/{args.get('address')}")
    return f"Deleted Address {args.get('address')}"


def delete_address_group_command(client, args):
    client.fortimanager_api_call("delete", f"/pm/config/{get_global_or_adom(client, args)}"
                                           f"/obj/firewall/addrgrp/{args.get('address_group')}")
    return f"Deleted Address Group {args.get('address_group')}"


def delete_service_group_command(client, args):
    client.fortimanager_api_call("delete", f"/pm/config/{get_global_or_adom(client, args)}"
                                           f"/obj/firewall/service/group/{args.get('service_group')}")
    return f"Deleted Address Group {args.get('service_group')}"


def delete_policy_package_command(client, args):
    client.fortimanager_api_call("delete", f"pm/pkg/{get_global_or_adom(client, args)}/{args.get('pkg_path')}")
    return f"Deleted Policy Package {args.get('pkg_path')}"


def delete_policy_command(client, args):
    client.fortimanager_api_call("delete", f"/pm/config/{get_global_or_adom(client, args)}/pkg/"
                                           f"{args.get('package')}/firewall/policy{args.get('policy')}")
    return f"Deleted Policy {args.get('policy')}"


def delete_custom_service_command(client, args):
    client.fortimanager_api_call("delete", f"/pm/config/{get_global_or_adom(client, args)}"
                                           f"/obj/firewall/service/custom/{args.get('custom')}")
    return f"Deleted Custom Service {args.get('custom')}"


def move_policy_command(client, args):
    client.fortimanager_api_call("move", f"/pm/config/{get_global_or_adom(client, args)}"
                                         f"/pkg/{args.get('package')}/firewall/policy/{args.get('policy')}",
                                 other_params=setup_request_data(args, ['adom', 'package', 'policy']))

    return f"Created policy with ID {args.get('policy')}"


def list_dynamic_interface_command(client, args):
    dynamic_interfaces = client.fortimanager_api_call("get", f"/pm/config/"
                                                             f"{get_global_or_adom(client, args)}"
                                                             f"/obj/dynamic/interface",
                                                      range_info=get_range_for_list_command(args))

    return CommandResults(
        outputs_prefix='FortiManager.DynamicInterface',
        outputs_key_field='name',
        outputs=dynamic_interfaces,
        readable_output=tableToMarkdown(f"ADOM {client.adom} Dynamic Interfaces",
                                        dynamic_interfaces, removeNull=True, headerTransform=string_to_table_header),
        raw_response=dynamic_interfaces,
    )


def list_dynamic_address_mapping_command(client, args):
    dynamic_mapping = client.fortimanager_api_call("get", f"/pm/config/{get_global_or_adom(client, args)}"
                                                          f"/obj/firewall/address"
                                                          f"/{args.get('address')}/dynamic_mapping"
                                                          f"{get_specific_entity(args.get('dynamic_mapping'))}",
                                                   range_info=get_range_for_list_command(args))

    return CommandResults(
        outputs_prefix='FortiManager.Address.DynamicMapping',
        outputs_key_field='name',
        outputs=dynamic_mapping,
        readable_output=tableToMarkdown(f"Address {args.get('dynamic_mapping')} Dynamic Mapping",
                                        dynamic_mapping, removeNull=True, headerTransform=string_to_table_header),
        raw_response=dynamic_mapping,
    )


def create_dynamic_address_mapping_command(client, args):
    client.fortimanager_api_call("add", f"/pm/config/{get_global_or_adom(client, args)}"
                                        f"/obj/firewall/address/{args.get('address')}/dynamic_mapping",
                                 data=setup_request_data(args, ['adom', 'address']))

    return f"Created new dynamic mapping in address {args.get('address')}"


def update_dynamic_address_mapping_command(client, args):
    client.fortimanager_api_call("update", f"/pm/config/{get_global_or_adom(client, args)}"
                                           f"/obj/firewall/address/{args.get('address')}/dynamic_mapping",
                                 data=setup_request_data(args, ['adom', 'address']))

    return f"Updated dynamic mapping in address {args.get('address')}"


def delete_dynamic_address_mapping_command(client, args):
    client.fortimanager_api_call("update", f"/pm/config/{get_global_or_adom(client, args)}"
                                           f"/obj/firewall/address/{args.get('address')}/dynamic_mapping/"
                                           f"{args.get('dynamic_mapping')}",
                                 data=setup_request_data(args, ['adom', 'address']))

    return f"Deleted dynamic mapping {args.get('dynamic_mapping')} in address {args.get('address')}"


def commit_adom_command(client, args):
    client.fortimanager_api_call('exec', f"/dvmdb/{get_global_or_adom(client, args)}/workspace/commit")

    return f"Committed ADOM {get_global_or_adom(client, args)}"


def commit_device_command(client, args):
    client.fortimanager_api_call('exec', f"/dvmdb/{get_global_or_adom(client, args)}/workspace/"
                                         f"commit/dev/{args.get('device')}")

    return f"Committed ADOM {get_global_or_adom(client, args)} to device {args.get('device')}"


def install_policy_package_command(client, args):
    client.fortimanager_api_call('add', f"/pm​/pkg​/{get_global_or_adom(client, args)}"
                                        f"/{args.get('package')}​/schedule",
                                 data={
                                     'adom_rev_comment': args.get('adom_rev_comment'),
                                     'adom_rev_name': args.get('adom_rev_name'),
                                     'dev_rev_comment': args.get('dev_rev_comment'),
                                     'scope': args.get('scope'),
                                     'datetime': args.get('datetime')
                                 })
    return f"Installed a policy package {args.get('get')} in ADOM: {get_global_or_adom(client, args)}"


def lock_adom_command(client, args):
    client.fortimanager_api_call('exec', f"/dvmdb/{get_global_or_adom(client, args)}/workspace/lock")
    return f"Locked {get_global_or_adom(client, args)}"


def unlock_adom_command(client, args):
    client.fortimanager_api_call('exec', f"/dvmdb/{get_global_or_adom(client, args)}/workspace/unlock")
    return f"Unlocked {get_global_or_adom(client, args)}"


def lock_device_command(client, args):
    client.fortimanager_api_call('exec', f"/dvmdb/{get_global_or_adom(client, args)}/workspace/lock/"
                                         f"dev/{args.get('device')}")
    return f"Locked Device {args.get('device')} in ADOM {get_global_or_adom(client, args)}"


def unlock_device_command(client, args):
    client.fortimanager_api_call('exec', f"/dvmdb/{get_global_or_adom(client, args)}/workspace/unlock/"
                                         f"dev/{args.get('device')}")
    return f"Unlocked Device {args.get('device')} in ADOM {get_global_or_adom(client, args)}"


def lock_package_command(client, args):
    client.fortimanager_api_call('exec', f"/dvmdb/{get_global_or_adom(client, args)}/workspace/lock/"
                                         f"pkg/{args.get('package')}")
    return f"Locked Package {args.get('package')} in ADOM {get_global_or_adom(client, args)}"


def unlock_package_command(client, args):
    client.fortimanager_api_call('exec', f"/dvmdb/{get_global_or_adom(client, args)}/workspace/unlock/"
                                         f"pkg/{args.get('package')}")
    return f"Unlocked Package {args.get('package')} in ADOM {get_global_or_adom(client, args)}"


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
            list_adom_devices_command(client, {})
            return_results("ok")

        elif demisto.command() == 'fortimanager-devices-list':
            return_results(list_adom_devices_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-device-groups-list':
            return_results(list_adom_devices_groups_command(client, demisto.args()))

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

        elif demisto.command() == 'fortimanager-commit-adom':
            return_results(commit_adom_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-commit-device':
            return_results(commit_adom_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-policy-package-install':
            return_results(install_policy_package_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-adom-lock':
            return_results(lock_adom_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-adom-unlock':
            return_results(unlock_adom_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-device-lock':
            return_results(lock_device_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-device-unlock':
            return_results(unlock_device_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-package-lock':
            return_results(lock_package_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-package-unlock':
            return_results(unlock_package_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{traceback.format_exc()}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
