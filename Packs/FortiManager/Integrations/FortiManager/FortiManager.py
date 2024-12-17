import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3
from typing import Dict

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

GLOBAL_VAR = 'global'

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, url: str, credentials: Dict, verify: bool, proxy: bool, adom: str):
        super().__init__(base_url=url.rstrip('/'), verify=verify, proxy=proxy, ok_codes=(200, 204))
        handle_proxy()
        self.username = credentials["identifier"]
        self.password = credentials["password"]
        self.session_token = self.get_session_token()
        self.adom = adom

    def get_session_token(self, get_new_token: bool = False):
        if get_new_token:
            response = self.fortimanager_http_request('exec', "/sys/login/user",
                                                      json_data={'user': self.username, 'passwd': self.password},
                                                      add_session_token=False)

            if response.get('result')[0].get('status', {}).get('code') != 0:
                raise DemistoException(f"Unable to get new session token. Reason - "
                                       f"{response.get('result')[0].get('status').get('message')}")

            demisto.setIntegrationContext({'session': response.get('session')})
            return response.get('session')

        else:
            current_token = demisto.getIntegrationContext().get('session')
            return current_token if current_token else self.get_session_token(get_new_token=True)

    def fortimanager_http_request(self, method: str, url: str, data_in_list: Dict = None, json_data: Dict = None,
                                  range_info: List = None, other_params: Dict = None, add_session_token: bool = True):
        body: Dict = {
            "id": 1,
            "method": method,
            "verbose": 1,
            "params": [{
                "option": "object member",
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

    def fortimanager_api_call(self, method: str, url: str, data_in_list: Dict = None, json_data: Dict = None,
                              range_info: List = None, other_params: Dict = None):
        response = self.fortimanager_http_request(method, url, data_in_list=data_in_list, range_info=range_info,
                                                  other_params=other_params, json_data=json_data)

        # catch session token expiration - fetch new token and retry
        if response.get('result')[0].get('status', {}).get('code') == -11:
            self.session_token = self.get_session_token(get_new_token=True)
            response = self.fortimanager_http_request(method, url, data_in_list=data_in_list, range_info=range_info,
                                                      other_params=other_params, json_data=json_data)

        if response.get('result')[0].get('status', {}).get('code') != 0:
            raise DemistoException(response.get('result')[0].get('status').get('message'))

        return response.get('result')[0].get('data')


def get_global_or_adom(client: Client, args: Dict):
    """Get the ADOM scope on which the command should run.
    If 'adom' command argument is entered use it, otherwise use the default client ADOM parameter.

    """
    adom = args.get('adom') if args.get('adom') else client.adom
    # if the command is reffereing to a specified ADOM then the command should return "adom/{adom_name}"
    # if it refferes to the general system then we should return "global"
    if adom == GLOBAL_VAR:
        return GLOBAL_VAR
    else:
        return f"adom/{adom}"


def setup_request_data(args: Dict, excluded_args: List):
    return {key.replace('_', '-'): args.get(key) for key in args if key not in excluded_args}


def get_specific_entity(entity_name: str):
    if entity_name:
        return f"/{entity_name}"
    else:
        return ""


def get_range_for_list_command(args: Dict):
    first_index = args.get('offset', 0)
    last_index = int(args.get('limit', 50)) - 1
    list_range = []

    # A bug on Forti API when the first index is 0, need to add 1 to the last index for consistency
    if int(first_index) == 0:
        list_range.append(0)
        list_range.append(int(last_index) + 1)

    else:
        list_range.append(int(first_index))
        list_range.append(int(last_index))

    return list_range


def split_param(args, name, default_val='', skip_if_none=False):
    if not skip_if_none or (skip_if_none and args.get(name)):
        args[name] = args.get(name, default_val).split(',')


def resolve_enum(entity_object, field_name, enum_dict):
    """
    Method resolves enum values to
    """
    if type(entity_object) is list:
        for entity in entity_object:
            if field_name in entity:
                entity[field_name] = enum_dict.get(entity[field_name], entity[field_name])

    else:
        if field_name in entity_object:
            entity_object[field_name] = enum_dict.get(entity_object[field_name], entity_object[field_name])


def list_adom_devices_command(client, args):
    devices_data = client.fortimanager_api_call("get", f"/dvmdb/{get_global_or_adom(client, args)}/device"
                                                       f"{get_specific_entity(args.get('device'))}",
                                                range_info=get_range_for_list_command(args))

    headers = ['name', 'ip', 'hostname', 'os_type', 'adm_usr', 'app_ver', 'vdom', 'ha_mode']

    # Only show vdom names in human readable
    hr_devices_data = devices_data
    if type(devices_data) is list:
        for device in devices_data:
            vdom_names = []
            for vdom in device.get('vdom', []):
                if vdom.get('name'):
                    vdom_names.append(vdom.get('name'))
            hr_devices_data[devices_data.index(device)]['vdom'] = vdom_names

    else:
        vdom_names = []
        for vdom in devices_data.get('vdom', []):
            if vdom.get('name'):
                vdom_names.append(vdom.get('name'))

        hr_devices_data['vdom'] = vdom_names

    return CommandResults(
        outputs_prefix='FortiManager.Device',
        outputs_key_field='name',
        outputs=devices_data,
        readable_output=tableToMarkdown(f"ADOM {get_global_or_adom(client, args)} Devices", hr_devices_data,
                                        removeNull=True, headerTransform=string_to_table_header, headers=headers),
        raw_response=devices_data,
    )


def list_adom_devices_groups_command(client, args):
    device_groups_data = client.fortimanager_api_call("get", f"/dvmdb/{get_global_or_adom(client, args)}/group"
                                                             f"{get_specific_entity(args.get('group'))}",
                                                      range_info=get_range_for_list_command(args))

    headers = ['name', 'type', 'os_type']

    return CommandResults(
        outputs_prefix='FortiManager.DeviceGroup',
        outputs_key_field='name',
        outputs=device_groups_data,
        readable_output=tableToMarkdown(f"ADOM {get_global_or_adom(client, args)} Device Groups", device_groups_data,
                                        removeNull=True, headerTransform=string_to_table_header, headers=headers),
        raw_response=device_groups_data,
    )


def list_firewall_addresses_command(client, args):
    firewall_addresses = client.fortimanager_api_call("get", f"/pm/config/{get_global_or_adom(client, args)}"
                                                             f"/obj/firewall/address"
                                                             f"{get_specific_entity(args.get('address'))}",
                                                      range_info=get_range_for_list_command(args))

    headers = ['name', 'type', 'subnet', 'start-ip', 'end-ip', 'fqdkn', 'wildcard', 'country', 'wildcard-fqdn', 'sdn',
               'comment'] if not args.get('address') else None

    return CommandResults(
        outputs_prefix='FortiManager.Address',
        outputs_key_field='name',
        outputs=firewall_addresses,
        readable_output=tableToMarkdown("Firewall IPv4 Addresses", firewall_addresses,
                                        removeNull=True, headerTransform=string_to_table_header, headers=headers),
        raw_response=firewall_addresses,
    )


def create_address_command(client, args):
    client.fortimanager_api_call("add", f"/pm/config/{get_global_or_adom(client, args)}/obj/firewall/address",
                                 data_in_list=setup_request_data(args, ['adom']))

    return f"Created new Address {args.get('name')}"


def update_address_command(client, args):
    client.fortimanager_api_call("update", f"/pm/config/{get_global_or_adom(client, args)}/obj/firewall/address",
                                 data_in_list=setup_request_data(args, ['adom']))

    return f"Updated Address {args.get('name')}"


def delete_address_command(client, args):
    client.fortimanager_api_call("delete", f"/pm/config/{get_global_or_adom(client, args)}"
                                           f"/obj/firewall/address/{args.get('address')}")
    return f"Deleted Address {args.get('address')}"


def list_address_groups_command(client, args):
    address_group = get_specific_entity(args.get('address_group'))
    firewall_address_groups = client.fortimanager_api_call("get", f"/pm/config/"
                                                                  f"{get_global_or_adom(client, args)}"
                                                                  f"/obj/firewall/addrgrp{address_group}",
                                                           range_info=get_range_for_list_command(args))

    headers = ['name', 'member', 'tagging', 'allow-routing', 'comment'] if not args.get('address_group') else None

    return CommandResults(
        outputs_prefix='FortiManager.AddressGroup',
        outputs_key_field='name',
        outputs=firewall_address_groups,
        readable_output=tableToMarkdown("Firewall IPv4 Address Groups", firewall_address_groups,
                                        removeNull=True, headerTransform=string_to_table_header, headers=headers),
        raw_response=firewall_address_groups,
    )


def create_address_group_command(client, args):
    data = setup_request_data(args, ['adom'])
    data['member'] = data.get('member').split(',')
    client.fortimanager_api_call("add", f"/pm/config/{get_global_or_adom(client, args)}/obj/firewall/addrgrp",
                                 data_in_list=data)

    return f"Created new Address Group {args.get('name')}"


def update_address_group_command(client, args):
    data = setup_request_data(args, ['adom'])
    data['member'] = data.get('member').split(',')
    client.fortimanager_api_call("update", f"/pm/config/{get_global_or_adom(client, args)}/obj/firewall/addrgrp",
                                 data_in_list=data)

    return f"Updated Address Group {args.get('name')}"


def delete_address_group_command(client, args):
    client.fortimanager_api_call("delete", f"/pm/config/{get_global_or_adom(client, args)}"
                                           f"/obj/firewall/addrgrp/{args.get('address_group')}")
    return f"Deleted Address Group {args.get('address_group')}"


def list_service_categories_command(client, args):
    service_categories = client.fortimanager_api_call("get", f"/pm/config/"
                                                             f"{get_global_or_adom(client, args)}/"
                                                             f"obj/firewall/service/category"
                                                             f"{get_specific_entity(args.get('service_category'))}",
                                                      range_info=get_range_for_list_command(args))
    headers = ['name', 'comment']

    return CommandResults(
        outputs_prefix='FortiManager.ServiceCategory',
        outputs_key_field='name',
        outputs=service_categories,
        readable_output=tableToMarkdown("Service Categories", service_categories, removeNull=True,
                                        headerTransform=string_to_table_header, headers=headers),
        raw_response=service_categories,
    )


def list_service_groups_command(client, args):
    service_groups = client.fortimanager_api_call("get", f"/pm/config/"
                                                         f"{get_global_or_adom(client, args)}"
                                                         f"/obj/firewall/service/group"
                                                         f"{get_specific_entity(args.get('service_group'))}",
                                                  range_info=get_range_for_list_command(args))

    headers = ['name', 'member', 'proxy', 'comment'] if not args.get('service_group') else None

    return CommandResults(
        outputs_prefix='FortiManager.ServiceGroup',
        outputs_key_field='name',
        outputs=service_groups,
        readable_output=tableToMarkdown("Service Groups", service_groups, removeNull=True,
                                        headerTransform=string_to_table_header, headers=headers),
        raw_response=service_groups,
    )


def create_service_group_command(client, args):
    data = setup_request_data(args, ['adom'])
    data['member'] = data.get('member').split(',')
    client.fortimanager_api_call("add", f"/pm/config/{get_global_or_adom(client, args)}/obj/firewall/service/group",
                                 data_in_list=data)

    return f"Created new Service Group {args.get('name')}"


def update_service_group_command(client, args):
    data = setup_request_data(args, ['adom'])
    data['member'] = data.get('member').split(',') if data.get('member') else None
    client.fortimanager_api_call("update", f"/pm/config/{get_global_or_adom(client, args)}/obj/firewall/service/group",
                                 data_in_list=data)

    return f"Updated Service Group {args.get('name')}"


def delete_service_group_command(client, args):
    client.fortimanager_api_call("delete", f"/pm/config/{get_global_or_adom(client, args)}"
                                           f"/obj/firewall/service/group/{args.get('service_group')}")
    return f"Deleted Service Group {args.get('service_group')}"


def list_custom_service_command(client, args):
    custom_services = client.fortimanager_api_call("get", f"/pm/config/"
                                                          f"{get_global_or_adom(client, args)}"
                                                          f"/obj/firewall/service/custom"
                                                          f"{get_specific_entity(args.get('custom_service'))}",
                                                   range_info=get_range_for_list_command(args))

    headers = ['name', 'category', 'protocol', 'iprange', 'fqdn', 'comment'] if not args.get('custom_service') else None

    return CommandResults(
        outputs_prefix='FortiManager.CustomService',
        outputs_key_field='name',
        outputs=custom_services,
        readable_output=tableToMarkdown("Custom Services", custom_services, removeNull=True,
                                        headerTransform=string_to_table_header, headers=headers),
        raw_response=custom_services,
    )


def create_custom_service_command(client, args):
    client.fortimanager_api_call("add", f"/pm/config/{get_global_or_adom(client, args)}/obj/firewall/service/custom",
                                 data_in_list=setup_request_data(args, ['adom']))
    return f"Created new Custom Service {args.get('name')}"


def update_custom_service_command(client, args):
    client.fortimanager_api_call("update", f"/pm/config/{get_global_or_adom(client, args)}/obj/firewall/service/custom",
                                 data_in_list=setup_request_data(args, ['adom']))
    return f"Updated Custom Service {args.get('name')}"


def delete_custom_service_command(client, args):
    client.fortimanager_api_call("delete", f"/pm/config/{get_global_or_adom(client, args)}"
                                           f"/obj/firewall/service/custom/{args.get('custom')}")
    return f"Deleted Custom Service {args.get('custom')}"


def list_policy_packages_command(client, args):
    policy_packages = client.fortimanager_api_call("get", f"pm/pkg/{get_global_or_adom(client, args)}"
                                                          f"{get_specific_entity(args.get('policy_package'))}")

    # No native range filter in API call, implementing manually
    from_val = int(args.get('offset', 0))
    to_val = args.get('limit')
    if not args.get('limit'):
        policy_packages = policy_packages[from_val:]

    else:
        policy_packages = policy_packages[from_val:int(to_val)]

    headers = ['name', 'obj_ver', 'type', 'scope_member'] if not args.get('policy_package') else None

    return CommandResults(
        outputs_prefix='FortiManager.PolicyPackage',
        outputs_key_field='name',
        outputs=policy_packages,
        readable_output=tableToMarkdown("Policy Packages", policy_packages, removeNull=True,
                                        headerTransform=string_to_table_header, headers=headers),
        raw_response=policy_packages,
    )


def create_policy_package_command(client, args):
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
                                 data_in_list=setup_request_data(args, ['adom', 'central_nat', 'consolidated_firewall',
                                                                        'fwpolicy_implicit_log',
                                                                        'fwpolicy6_implicit_log', 'inspection_mode',
                                                                        'ngfw_mode', 'ssl_ssh_profile']))

    return f"Created new Policy Package {args.get('name')}"


def update_policy_package_command(client, args):
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
                                 data_in_list=setup_request_data(args, ['adom', 'central_nat', 'consolidated_firewall',
                                                                        'fwpolicy_implicit_log',
                                                                        'fwpolicy6_implicit_log', 'inspection_mode',
                                                                        'ngfw_mode', 'ssl_ssh_profile']))

    return f"Update Policy Package {args.get('name')}"


def delete_policy_package_command(client, args):
    client.fortimanager_api_call("delete", f"pm/pkg/{get_global_or_adom(client, args)}/{args.get('pkg_path')}")
    return f"Deleted Policy Package {args.get('pkg_path')}"


def list_policies_command(client, args):
    policies = client.fortimanager_api_call("get", f"/pm/config/"
                                                   f"{get_global_or_adom(client, args)}"
                                                   f"/pkg/{args.get('package')}/firewall/policy"
                                                   f"{get_specific_entity(args.get('policy_id'))}",
                                            range_info=get_range_for_list_command(args))

    headers = ['policyid', 'name', 'srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'schedule', 'service', 'users', 'action']

    return CommandResults(
        outputs_prefix='FortiManager.PolicyPackage.Policy',
        outputs_key_field='name',
        outputs=policies,
        readable_output=tableToMarkdown(f"ADOM {client.adom} Policy Package {args.get('package')} Policies",
                                        policies, removeNull=True, headerTransform=string_to_table_header,
                                        headers=headers),
        raw_response=policies,
    )


def create_policy_command(client, args):
    if args.get('additional_params'):
        for additional_param in args.get('additional_params').split(','):
            field_and_value = additional_param.split('=')
            args[field_and_value[0]] = field_and_value[1]

    json_data = setup_request_data(args, ['adom', 'package', 'additional_params'])
    split_param(json_data, 'dstaddr', 'all', skip_if_none=True)
    split_param(json_data, 'dstaddr6', 'all', skip_if_none=True)
    split_param(json_data, 'dstintf', 'any')
    split_param(json_data, 'schedule', 'always')
    split_param(json_data, 'service', 'ALL')
    split_param(json_data, 'srcaddr', 'all', skip_if_none=True)
    split_param(json_data, 'srcaddr6', 'all', skip_if_none=True)
    split_param(json_data, 'srcintf', 'any')

    if not (json_data.get('dstaddr') or json_data.get('dstaddr6')):
        raise DemistoException("Please enter 'dstaddr' or 'dstaddr6' command arguments")

    if not (json_data.get('srcaddr') or json_data.get('srcaddr6')):
        raise DemistoException("Please enter 'srcaddr' or 'srcaddr6' command arguments")

    policies = client.fortimanager_api_call("add", f"/pm/config/"
                                                   f"{get_global_or_adom(client, args)}"
                                                   f"/pkg/{args.get('package')}/firewall/policy",
                                            json_data=json_data)

    return f"Created policy with ID {policies.get('policyid')}"


def update_policy_command(client, args):
    if args.get('additional_params'):
        for additional_param in args.get('additional_params').split(','):
            field_and_value = additional_param.split('=')
            args[field_and_value[0]] = field_and_value[1]

    data = setup_request_data(args, ['adom', 'package', 'additional_params'])
    split_param(data, 'dstaddr', 'all', skip_if_none=True)
    split_param(data, 'dstaddr6', 'all', skip_if_none=True)
    split_param(data, 'dstintf', 'any', skip_if_none=True)
    split_param(data, 'schedule', 'always', skip_if_none=True)
    split_param(data, 'service', 'ALL', skip_if_none=True)
    split_param(data, 'srcaddr', 'all', skip_if_none=True)
    split_param(data, 'srcaddr6', 'all', skip_if_none=True)
    split_param(data, 'srcintf', 'any', skip_if_none=True)

    policies = client.fortimanager_api_call("update", f"/pm/config/"
                                                      f"{get_global_or_adom(client, args)}"
                                                      f"/pkg/{args.get('package')}/firewall/policy",
                                            data_in_list=data)

    return f"Updated policy with ID {policies.get('policyid')}"


def delete_policy_command(client, args):
    client.fortimanager_api_call("delete", f"/pm/config/{get_global_or_adom(client, args)}/pkg/"
                                           f"{args.get('package')}/firewall/policy/{args.get('policy')}")
    return f"Deleted Policy {args.get('policy')}"


def move_policy_command(client, args):
    client.fortimanager_api_call("move", f"/pm/config/{get_global_or_adom(client, args)}"
                                         f"/pkg/{args.get('package')}/firewall/policy/{args.get('policy')}",
                                 other_params=setup_request_data(args, ['adom', 'package', 'policy']))

    return f"Moved policy with ID {args.get('policy')} {args.get('option')} {args.get('target')} " \
           f"in Policy Package: {args.get('package')}"


def list_dynamic_interface_command(client, args):
    dynamic_interfaces = client.fortimanager_api_call("get", f"/pm/config/"
                                                             f"{get_global_or_adom(client, args)}"
                                                             f"/obj/dynamic/interface",
                                                      range_info=get_range_for_list_command(args))

    headers = ['name']

    return CommandResults(
        outputs_prefix='FortiManager.DynamicInterface',
        outputs_key_field='name',
        outputs=dynamic_interfaces,
        readable_output=tableToMarkdown(f"ADOM {client.adom} Dynamic Interfaces",
                                        dynamic_interfaces, removeNull=True, headerTransform=string_to_table_header,
                                        headers=headers),
        raw_response=dynamic_interfaces,
    )


def install_policy_package_command(client, args):
    response = client.fortimanager_api_call('exec', "/securityconsole/install/package",
                                            json_data={
                                                'adom_rev_comment': args.get('adom_rev_comment'),
                                                'adom_rev_name': args.get('adom_rev_name'),
                                                'dev_rev_comment': args.get('dev_rev_comment'),
                                                'adom': get_global_or_adom(client, args).replace('adom/', ''),
                                                'pkg': args.get('package'),
                                                'scope': [{
                                                    "name": args.get('name'),
                                                    "vdom": args.get('vdom')
                                                }]
                                            })
    formatted_response = {'id': response.get('task')}
    return CommandResults(
        outputs_prefix='FortiManager.Installation',
        outputs_key_field='id',
        outputs=formatted_response,
        readable_output=f"Initiated installation of the policy package: {args.get('package')} "
                        f"in ADOM: {get_global_or_adom(client, args)}\n"
                        f"On Device {args.get('name')} and VDOM {args.get('vdom')}.\nTask ID: {response.get('task')}."
                        f"\n\nYou can check the installation status by running:\n"
                        f"!fortimanager-firewall-policy-package-install-status task_id={response.get('task')}",
        raw_response=response
    )


def install_policy_package_status_command(client, args):
    task_data = client.fortimanager_api_call('get', f"/task/task/{args.get('task_id')}")

    headers = ['id', 'title', 'adom', 'percent', 'state', 'line']

    return CommandResults(
        outputs_prefix='FortiManager.Installation',
        outputs_key_field='id',
        outputs=task_data,
        readable_output=tableToMarkdown(f"Installation Task {args.get('task_id')} Status",
                                        task_data, removeNull=True, headerTransform=string_to_table_header,
                                        headers=headers),
        raw_response=task_data
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    creds = demisto.params().get('credentials')
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
            try:
                list_adom_devices_command(client, {})
            except DemistoException as e:
                if 'No permission for the resource' in str(e):
                    raise DemistoException("Unable to connect to the FortiManager Server - please check the "
                                           "entered credentials and ADOM.")

                if 'Invalid url' in str(e):
                    raise DemistoException("Unable to connect to the default ADOM - please check the "
                                           "entered credentials and ADOM.")

                else:
                    raise

            return_results("ok")

        elif demisto.command() == 'fortimanager-devices-list':
            return_results(list_adom_devices_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-device-groups-list':
            return_results(list_adom_devices_groups_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-address-list':
            return_results(list_firewall_addresses_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-address-create':
            return_results(create_address_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-address-update':
            return_results(update_address_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-address-delete':
            return_results(delete_address_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-address-group-list':
            return_results(list_address_groups_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-address-group-create':
            return_results(create_address_group_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-address-group-update':
            return_results(update_address_group_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-address-group-delete':
            return_results(delete_address_group_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-service-categories-list':
            return_results(list_service_categories_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-service-group-list':
            return_results(list_service_groups_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-service-group-create':
            return_results(create_service_group_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-service-group-update':
            return_results(update_service_group_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-service-group-delete':
            return_results(delete_service_group_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-custom-service-list':
            return_results(list_custom_service_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-custom-service-create':
            return_results(create_custom_service_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-custom-service-update':
            return_results(update_custom_service_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-custom-service-delete':
            return_results(delete_custom_service_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-firewall-policy-package-list':
            return_results(list_policy_packages_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-firewall-policy-package-create':
            return_results(create_policy_package_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-firewall-policy-package-update':
            return_results(update_policy_package_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-firewall-policy-package-delete':
            return_results(delete_policy_package_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-firewall-policy-list':
            return_results(list_policies_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-firewall-policy-create':
            return_results(create_policy_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-firewall-policy-update':
            return_results(update_policy_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-firewall-policy-delete':
            return_results(delete_policy_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-firewall-policy-move':
            return_results(move_policy_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-dynamic-interface-list':
            return_results(list_dynamic_interface_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-firewall-policy-package-install':
            return_results(install_policy_package_command(client, demisto.args()))

        elif demisto.command() == 'fortimanager-firewall-policy-package-install-status':
            return_results(install_policy_package_status_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception:
        return_error(f'Failed to execute {demisto.command()} command.')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
