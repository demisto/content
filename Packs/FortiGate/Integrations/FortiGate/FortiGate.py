import requests
import json
register_module_line('FortiGate', 'start', __line__())


''' IMPORTS '''


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

USER_NAME = demisto.params().get('credentials').get('identifier')
PASS_token = demisto.params().get('credentials').get('password')
SERVER = demisto.params()['server'][:-1] if (demisto.params()['server'] and demisto.params()
                                             ['server'].endswith('/')) else demisto.params()['server']
USE_SSL = not demisto.params().get('unsecure', False)
BASE_URL = SERVER + '/api/v2/'


# remove proxy if not set to true in params
if not demisto.params().get('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


''' HELPER FUNCTIONS '''

@logger
def http_request(method, url_suffix, params={}, headers={}, data=None):

    res = requests.request(method, BASE_URL + url_suffix, verify=USE_SSL, params=params, headers=headers ,data=data)
    if res.status_code not in {200}:
        return_error(
            f'Error in API call to FortiGate [{res.status_code}] - {res.reason}')
    if method.upper() != 'GET':
        return res.status_code

    return res.json()


@logger
def create_addr_string(list_of_addr_data_dicts):
    addr_string = ""
    for addr_index in range(0, len(list_of_addr_data_dicts)):
        cur_addr_data = list_of_addr_data_dicts[addr_index]
        cur_addr_name = cur_addr_data.get("name")
        if addr_index == len(list_of_addr_data_dicts) - 1:
            addr_string += f"{cur_addr_name}"
        else:
            addr_string += f"{cur_addr_name}\n"
    return addr_string


@logger
def convert_arg_to_int(arg_str, arg_name_str):
    try:
        arg_int = int(arg_str)
    except ValueError:
        return_error(f"Error: {arg_name_str} must have an integer value.")
    return arg_int


@logger
def prettify_date(date_string):
    """
    This function receives a string representing a date, for example 2018-07-28T10:47:55.000Z.
    It returns the same date in a readable format - for example, 2018-07-28 10:47:55.
    """
    date_string = date_string[:-5]  # remove the .000z at the end
    date_prettified = date_string.replace("T", " ")
    return date_prettified


@logger
def create_banned_ips_entry_context(ips_data_array):
    ips_contexts_array = []
    for ip_data in ips_data_array:
        current_ip_context = {
            "IP": ip_data.get("ip_address"),
            "Source": ip_data.get("source")
        }
        if ip_data.get("expires"):
            expiration_in_ms = 1000 * int(ip_data.get("expires", 0))
            current_ip_context["Expires"] = prettify_date(
                timestamp_to_datestring(expiration_in_ms))
        if ip_data.get("created"):
            creation_in_ms = 1000 * int(ip_data.get("created", 0))
            current_ip_context["Created"] = prettify_date(
                timestamp_to_datestring(creation_in_ms))
        ips_contexts_array.append(current_ip_context)
    return ips_contexts_array


@logger
def create_banned_ips_human_readable(entry_context):
    banned_ip_headers = ["IP", "Created", "Expires", "Source"]
    human_readable = tableToMarkdown(
        "Banned IP Addresses", entry_context, banned_ip_headers)
    return human_readable


@logger
def str_to_bool(str_representing_bool):
    return str_representing_bool and str_representing_bool.lower() == 'true'


@logger
def generate_src_or_dst_request_data(policy_id, policy_field, policy_field_value, keep_original_data, add_or_remove):
    address_list_for_request = policy_field_value.split(",")
    if str_to_bool(keep_original_data):
        # the return value is an array with one element
        policy_data = get_policy_request(policy_id)[0]
        existing_adresses_list = policy_data.get(policy_field)
        existing_adresses_list = [address_data["name"]
                                  for address_data in existing_adresses_list]
        if add_or_remove.lower() == "add":
            for address in existing_adresses_list:
                if address not in address_list_for_request:
                    address_list_for_request.append(address)
        else:
            address_list_for_request = [
                address for address in existing_adresses_list if address not in address_list_for_request]

    address_data_dicts_for_request = policy_addr_array_from_arg(
        address_list_for_request, False)
    return address_data_dicts_for_request


@logger
def policy_addr_array_from_arg(policy_addr_data, is_data_string=True):
    # if the data isn't in string format, it's already an array and requires no formatting
    policy_adr_str_array = policy_addr_data.split(
        ",") if is_data_string else policy_addr_data
    policy_addr_dict_array = []
    for src_addr_name in policy_adr_str_array:
        cur_addr_dict = {
            "name": src_addr_name
        }
        policy_addr_dict_array.append(cur_addr_dict)
    return policy_addr_dict_array


''' COMMANDS + REQUESTS FUNCTIONS '''


@logger
def test_module():
    """
    Perform basic login and logout operation, validate connection.
    """
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer '+str(PASS_token)
        }
    http_request('GET', 'cmdb/system/vdom', None, headers)
    return True


@logger
def get_addresses_command():
    contents = []
    context = {}
    addresses_context = []
    address = demisto.args().get('address')
    name = demisto.args().get('name', '')

    addresses = get_addresses_request(address, name)
    for address in addresses:
        subnet = address.get('subnet')
        if subnet:
            subnet = subnet.replace(" ", "-")
        contents.append({
            'Name': address.get('name'),
            'Subnet': subnet,
            'StartIP': address.get('start-ip'),
            'EndIP': address.get('end-ip')
        })
        addresses_context.append({
            'Name': address.get('name'),
            'Subnet': subnet,
            'StartIP': address.get('start-ip'),
            'EndIP': address.get('end-ip')
        })

    context['Fortigate.Address(val.Name && val.Name === obj.Name)'] = addresses_context
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate addresses', contents),
        'EntryContext': context
    })


@logger
def get_addresses_request(address, name):
    uri_suffix = 'cmdb/firewall/address/' + name
    params = {
        #'action': 'select',
        'vdom': address
    }
    headers = {
        'Authorization': 'Bearer '+str(PASS_token)
    }
    response = http_request('GET', uri_suffix, params, headers)
    # Different structure if we choose all domains
    if address == '*':
        return response[0].get('results')
    return response.get('results')


@logger
def ban_ip(ip_addresses_array, time_to_expire=0):
    uri_suffix = 'monitor/user/banned/add_users/'
    headers = {
        'Authorization': 'Bearer '+str(PASS_token)
    }
    payload = {
        'ip_addresses': ip_addresses_array,
        'expiry': time_to_expire
    }

    response = http_request('POST', uri_suffix, None, headers, data=json.dumps(payload))
    return response


@logger
def ban_ip_command():
    ip_addresses_string = demisto.args()['ip_address']
    ip_addresses_array = argToList(ip_addresses_string)
    for ip_address in ip_addresses_array:
        if not is_ip_valid(ip_address, accept_v6_ips=True):
            return_error('Error: invalid IP address sent as argument.')

    time_to_expire = demisto.args().get('expiry')
    if time_to_expire:
        time_to_expire = convert_arg_to_int(time_to_expire, 'expiry')
    else:
        # The default time to expiration is 0, which means infinite time (It will remain banned).
        time_to_expire = 0

    response = ban_ip(ip_addresses_array, time_to_expire)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': f'IPs {ip_addresses_string} banned successfully'
    })


@logger
def unban_ip(ip_addresses_array):
    uri_suffix = 'monitor/user/banned/clear_users/'
    headers = {
        'Authorization': 'Bearer '+str(PASS_token)
    }
    payload = {
        'ip_addresses': ip_addresses_array
    }
    response = http_request('POST', uri_suffix, None, headers, data=json.dumps(payload))
    return response


@logger
def unban_ip_command():
    ip_addresses_string = demisto.args()['ip_address']
    ip_addresses_array = argToList(ip_addresses_string)
    for ip_address in ip_addresses_array:
        if not is_ip_valid(ip_address, accept_v6_ips=True):
            return_error('Error: invalid IP address sent as argument.')

    response = unban_ip(ip_addresses_array)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': f'IPs {ip_addresses_string} un-banned successfully'
    })


@logger
def get_banned_ips():
    uri_suffix = 'monitor/user/banned/select/'
    headers = {
        'Authorization': 'Bearer '+str(PASS_token)
    }
    response = http_request('GET', uri_suffix, None, headers)
    return response


@logger
def get_banned_ips_command():
    response = get_banned_ips()
    ips_data_array = response.get('results')
    entry_context = create_banned_ips_entry_context(ips_data_array)
    human_readable = create_banned_ips_human_readable(entry_context)
    return_outputs(
        raw_response=response,
        readable_output=human_readable,
        outputs={
            'Fortigate.BannedIP(val.IP===obj.IP)': entry_context
        }
    )


@logger
def get_policy_command():
    contents = []
    context = {}
    policy_context = []
    policy_name = demisto.args().get('policyName')
    policy_id = demisto.args().get('policyID')
    policy_title = 'all policies'

    policies = get_policy_request(policy_id)

    for policy in policies:
        if policy_name == policy.get('name') or not policy_name:
            if policy_name or policy_id:
                policy_title = policy.get('name')
            security_profiles = []
            all_security_profiles = [policy.get('webfilter-profile'), policy.get('ssl-ssh-profile'),
                                     policy.get(
                                         'dnsfilter-profile'), policy.get('profile-protocol-options'),
                                     policy.get('profile-type'), policy.get('av-profile')]
            for security_profile in all_security_profiles:
                if security_profile:
                    security_profiles.append(security_profile)

            src_address = policy.get('srcaddr')
            if src_address and isinstance(src_address, list) and isinstance(src_address[0], dict):
                src_address = create_addr_string(src_address)
            dest_address = policy.get('dstaddr')
            if dest_address and isinstance(dest_address, list) and isinstance(dest_address[0], dict):
                dest_address = create_addr_string(dest_address)
            service = policy.get('service')
            if service and isinstance(service, list) and isinstance(service[0], dict):
                service = service[0].get('name')

            contents.append({
                'Name': policy.get('name'),
                'ID': int(policy.get('policyid')),
                'Description': policy.get('comments'),
                'Status': policy.get('status'),
                'Source': src_address,
                'Destination': dest_address,
                'Service': service,
                'Action': policy.get('action'),
                'Log': policy.get('logtraffic'),
                'Security': security_profiles,
                'NAT': policy.get('nat')
            })
            policy_context.append({
                'Name': policy.get('name'),
                'ID': int(policy.get('policyid')),
                'Description': policy.get('comments'),
                'Status': policy.get('status'),
                'Source': src_address,
                'Destination': dest_address,
                'Service': service,
                'Action': policy.get('action'),
                'Log': policy.get('logtraffic'),
                'Security': security_profiles,
                'NAT': policy.get('nat')
            })

    context['Fortigate.Policy(val.ID && val.ID === obj.ID)'] = policy_context

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate policy details for ' + policy_title, contents),
        'EntryContext': context
    })


@logger
def get_policy_request(policy_id):
    uri_suffix = 'cmdb/firewall/policy/'
    if policy_id:
        uri_suffix = uri_suffix + policy_id + '/'
    # We have the option to filter only the data we need from each policy,
    # reducing by over 80% the amount of data we need to read.
    params = {
        'format': 'policyid|action|name|comments|status|service|logtraffic|srcaddr|'
                  'dstaddr|webfilter-profile|ssl-ssh-profile|dnsfilter-profile|'
                  'profile-protocol-options|profile-type|av-profile|nat'
    }
    headers = {
        'Authorization': 'Bearer '+str(PASS_token)
    }
    response = http_request('GET', uri_suffix, params, headers)
    return response.get('results')


@logger
def update_policy_command():
    contents = []
    context = {}
    policy_context = []
    security_profiles = []

    policy_id = demisto.args().get('policyID')
    policy_field = demisto.args().get('field')
    policy_field_value = demisto.args().get('value')
    keep_original_data = demisto.args().get('keep_original_data')
    add_or_remove = demisto.args().get('add_or_remove')

    if keep_original_data and keep_original_data.lower() == 'true' and not add_or_remove:
        return_error(
            'Error: add_or_remove must be specified if keep_original_data is true.')

    update_policy_request(policy_id, policy_field,
                          policy_field_value, keep_original_data, add_or_remove)
    policy = get_policy_request(policy_id)[0]
    all_security_profiles = [policy.get('webfilter-profile'), policy.get('ssl-ssh-profile'), policy.get(
        'dnsfilter-profile'), policy.get('profile-protocol-options'), policy.get('profile-type'), policy.get('av-profile')]

    for security_profile in all_security_profiles:
        if security_profile:
            security_profiles.append(security_profile)

    src_address = policy.get('srcaddr')
    if src_address and isinstance(src_address, list) and isinstance(src_address[0], dict):
        src_address = src_address[0].get('name')
    dest_address = policy.get('dstaddr')
    if dest_address and isinstance(dest_address, list) and isinstance(dest_address[0], dict):
        dest_address = dest_address[0].get('name')
    service = policy.get('service')
    if service and isinstance(service, list) and isinstance(service[0], dict):
        service = service[0].get('name')

    contents.append({
        'Name': policy.get('name'),
        'ID': policy.get('policyid'),
        'Description': policy.get('comments'),
        'Status': policy.get('status'),
        'Source': src_address,
        'Destination': dest_address,
        'Service': service,
        'Action': policy.get('action'),
        'Log': policy.get('logtraffic'),
        'Security': security_profiles,
        'NAT': policy.get('nat')
    })
    policy_context.append({
        'Name': policy.get('name'),
        'ID': policy.get('policyid'),
        'Description': policy.get('comments'),
        'Status': policy.get('status'),
        'Source': src_address,
        'Destination': dest_address,
        'Service': service,
        'Action': policy.get('action'),
        'Log': policy.get('logtraffic'),
        'Security': security_profiles,
        'NAT': policy.get('nat')
    })

    context['Fortigate.Policy(val.ID && val.ID === obj.ID)'] = policy_context

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate policy ID ' + policy_id + ' has been updated successfully.', contents),
        'EntryContext': context
    })


@logger
def update_policy_request(policy_id, policy_field, policy_field_value, keep_original_data, add_or_remove):
    uri_suffix = 'cmdb/firewall/policy/' + policy_id
    # if not does_path_exist(uri_suffix):
    #     return_error('Requested policy ID ' + policy_id +
    #                  ' does not exist in Firewall config.')

    field_to_api_key = {
        'description': 'comments',
        'source': 'srcaddr',
        'destination': 'dstaddr',
        'log': 'logtraffic'
    }

    if policy_field in field_to_api_key:
        policy_field = field_to_api_key[policy_field]

    if policy_field in {'srcaddr', 'dstaddr'}:
        policy_field_value = generate_src_or_dst_request_data(
            policy_id, policy_field, policy_field_value, keep_original_data, add_or_remove)
    headers = {
        'Authorization': 'Bearer '+str(PASS_token)
    }
    payload = {
        'policyid': int(policy_id),
        'q_origin_key': int(policy_id),
        policy_field: policy_field_value
    }

    response = http_request('PUT', uri_suffix, None,
                            headers, json.dumps(payload))
    return response


@logger
def create_policy_command():
    contents = []
    context = {}
    policy_context = []

    policy_name = demisto.args().get('policyName')
    policy_description = demisto.args().get('description', '')
    policy_srcintf = demisto.args().get('sourceIntf')
    policy_dstintf = demisto.args().get('dstIntf')
    policy_source_address = policy_addr_array_from_arg(
        demisto.args().get('source'))
    policy_destination_address = policy_addr_array_from_arg(
        demisto.args().get('destination'))
    policy_service = demisto.args().get('service')
    policy_action = demisto.args().get('action')
    policy_status = demisto.args().get('status')
    policy_log = demisto.args().get('log')
    policy_nat = demisto.args().get('nat')

    create_policy_request(policy_name, policy_description, policy_srcintf, policy_dstintf,
                          policy_source_address, policy_destination_address, policy_service,
                          policy_action, policy_status, policy_log, policy_nat)
    contents.append({
        'Name': policy_name,
        'Description': policy_description,
        'Status': policy_status,
        'Service': policy_service,
        'Action': policy_action,
        'Log': policy_log,
        'Source': {
            'Interface': policy_srcintf,
            'Address': policy_source_address
        },
        'Destination': {
            'Interface': policy_dstintf,
            'Address': policy_destination_address
        },
        'NAT': policy_nat
    })

    policy_context.append({
        'Name': policy_name,
        'Description': policy_description,
        'Status': policy_status,
        'Service': policy_service,
        'Action': policy_action,
        'Log': policy_log,
        'Source': {
            'Interface': policy_srcintf,
            'Address': policy_source_address
        },
        'Destination': {
            'Interface': policy_dstintf,
            'Address': policy_destination_address
        },
        'NAT': policy_nat
    })

    context['Fortigate.Policy(val.Name && val.Name === obj.Name)'] = policy_context

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate policy ' + policy_name + ' created successfully', contents),
        'EntryContext': context
    })


@logger
def create_policy_request(policy_name, policy_description, policy_srcintf, policy_dstintf,
                          policy_source_address, policy_destination_address, policy_service,
                          policy_action, policy_status, policy_log, policy_nat):

    uri_suffix = 'cmdb/firewall/policy/'
    headers = {
        'Authorization': 'Bearer '+str(PASS_token)
    }
    payload = {
        'json': {
            'name': policy_name,
            'srcintf': [{'name': policy_srcintf}],
            'dstintf': [{'name': policy_dstintf}],
            'srcaddr': policy_source_address,
            'dstaddr': policy_destination_address,
            'action': policy_action,
            'status': policy_status,
            'schedule': 'always',
            'service': [{'name': policy_service}],
            'comments': policy_description,
            'logtraffic': policy_log,
            'nat': policy_nat
        }
    }

    response = http_request('POST', uri_suffix, None,
                            headers, json.dumps(payload))
    return response


@logger
def move_policy_command():
    contents = []
    context = {}
    policy_id = demisto.args().get('policyID')
    position = demisto.args().get('position')
    neighbour = demisto.args().get('neighbor')

    move_policy_request(policy_id, position, neighbour)

    policy_context = {
        'ID': int(policy_id),
        'Moved': True
    }
    contents.append({
        'ID': policy_id,
        'Moved': True
    })

    context['Fortigate.Policy(val.ID && val.ID === obj.ID)'] = policy_context

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate policy with ID ' + policy_id + ' moved successfully', contents),
        'EntryContext': context
    })


@logger
def move_policy_request(policy_id, position, neighbour):
    uri_suffix = 'cmdb/firewall/policy/' + policy_id
    params = {
        'action': 'move',
        position: neighbour
    }
    headers = {
        'Authorization': 'Bearer '+str(PASS_token)
    }
    response = http_request('PUT', uri_suffix, params, headers)
    return response


@logger
def delete_policy_command():
    contents = []
    context = {}
    policy_id = demisto.args().get('policyID')

    delete_policy_request(policy_id)

    policy_context = {
        'ID': policy_id,
        'Deleted': True
    }
    contents.append({
        'ID': policy_id,
        'Deleted': True
    })

    context['Fortigate.Policy(val.ID && val.ID === obj.ID)'] = policy_context

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate policy with ID ' + policy_id + ' deleted successfully', contents),
        'EntryContext': context
    })


@logger
def delete_policy_request(policy_id):
    uri_suffix = 'cmdb/firewall/policy/' + policy_id
    headers = {
        'Authorization': 'Bearer '+str(PASS_token)
    }
    response = http_request('DELETE', uri_suffix, None, headers)
    return response


@logger
def get_address_groups_command():
    contents = []
    context = {}
    address_groups_context = []
    address_group_name = demisto.args().get('groupName', '')
    title = address_group_name if address_group_name else 'all'

    address_groups = get_address_groups_request(address_group_name)
    for address_group in address_groups:
        members = address_group.get('member')
        members_list = []
        for member in members:
            members_list.append(member.get('name'))
        contents.append({
            'Name': address_group.get('name'),
            'Members': members_list,
            'UUID': address_group.get('uuid')
        })
        address_groups_context.append({
            'Name': address_group.get('name'),
            'Member': {
                'Name': members_list
            },
            'UUID': address_group.get('uuid')
        })

    context['Fortigate.AddressGroup(val.Name && val.Name === obj.Name)'] = address_groups_context

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate address groups ' + title, contents),
        'EntryContext': context
    })


@logger
def get_address_groups_request(address_group_name):
    uri_suffix = 'cmdb/firewall/addrgrp/' + address_group_name
    headers = {
        'Authorization': 'Bearer '+str(PASS_token)
    }
    response = http_request('GET', uri_suffix, None, headers)
    return response.get('results')


@logger
def update_address_group_command():
    contents = []
    context = {}
    address_group_context = []
    group_name = demisto.args().get('groupName', '')
    address = demisto.args().get('address', '')
    action = demisto.args().get('action')
    if action not in ['add', 'remove']:
        return_error('Action must be add or remove')

    old_address_groups = get_address_groups_request(group_name)
    address_group_members = []  # type: list
    new_address_group_members = []  # type: list

    if isinstance(old_address_groups, list):
        old_address_group = old_address_groups[0]
        address_group_members = old_address_group.get('member')
    if action == 'add':
        address_group_members.append({'name': address})
        new_address_group_members = address_group_members
    if action == 'remove':
        for address_group_member in address_group_members:
            if address_group_member.get('name') != address:
                new_address_group_members.append(address_group_member)
    update_address_group_request(group_name, new_address_group_members)
    address_group = get_address_groups_request(group_name)[0]
    members = address_group.get('member')
    members_list = []
    for member in members:
        members_list.append(member.get('name'))
    contents.append({
        'Name': address_group.get('name'),
        'Members': members_list,
        'UUID': address_group.get('uuid')
    })
    address_group_context.append({
        'Name': address_group.get('name'),
        'Address': {
            'Name': members_list
        },
        'UUID': address_group.get('uuid')
    })

    context['Fortigate.AddressGroup(val.Name && val.Name === obj.Name)'] = address_group_context

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate address group ' + group_name + ' updated successfully', contents),
        'EntryContext': context
    })


@logger
def update_address_group_request(group_name, new_address_group_members):
    uri_suffix = 'cmdb/firewall/addrgrp/' + group_name
    # Check whether target object already exists
    # if not does_path_exist(uri_suffix):
    #     return_error('Requested address group' + group_name +
    #                  'does not exist in Firewall config.')
    headers = {
        'Authorization': 'Bearer '+str(PASS_token)
    }
    payload = {
        'member': new_address_group_members
    }
    result = http_request('PUT', uri_suffix, None, headers, json.dumps(payload))
    return result


@logger
def create_address_group_command():
    contents = []
    context = {}
    address_group_context = []
    group_name = demisto.args().get('groupName', '')
    address = demisto.args().get('address', '')

    create_address_group_request(group_name, address)

    contents.append({
        'Name': group_name,
        'Address': address,
    })
    address_group_context.append({
        'Name': group_name,
        'Address': address
    })

    context['Fortigate.AddressGroup(val.Name && val.Name === obj.Name)'] = address_group_context

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate address group ' + group_name + ' created successfully', contents),
        'EntryContext': context
    })


@logger
def create_address_group_request(group_name, address):
    uri_suffix = 'cmdb/firewall/addrgrp/'
    # if does_path_exist(uri_suffix + group_name):
    #     return_error('Address group already exists.')
    headers = {
        'Authorization': 'Bearer '+str(PASS_token)
    }
    payload = {
        'name': group_name, 'member': [{'name': address}]
    }
    result = http_request('POST', uri_suffix, None, headers, json.dumps(payload))
    return result


@logger
def delete_address_group_command():
    contents = []
    context = {}
    address_group_context = []
    name = demisto.args().get('name', '')

    delete_address_group_request(name)

    contents.append({
        'Name': name,
        'Deleted': True
    })
    address_group_context.append({
        'Name': name,
        'Deleted': True
    })

    context['Fortigate.AddressGroup(val.Name && val.Name === obj.Name)'] = address_group_context

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate address group ' + name + ' deleted successfully', contents),
        'EntryContext': context
    })


@logger
def delete_address_group_request(name):
    uri_suffix = 'cmdb/firewall/addrgrp/' + name
    headers = {
        'Authorization': 'Bearer '+str(PASS_token)
    }
    response = http_request('DELETE', uri_suffix, None, headers)
    return response


@logger
def create_address_command():
    contents = []
    context = {}
    address_context = []
    args = demisto.args()
    address_name = args.get('name', '')
    address = args.get('address', '')
    mask = args.get('mask', '')
    fqdn = args.get('fqdn', '')

    if fqdn and address:
        return_error(
            "Please provide only one of the two arguments: fqdn or address")

    create_address_request(address_name, address, mask, fqdn)

    if address:
        address_dict = {
            'Name': address_name,
            'IPAddress': address
        }
        contents.append(address_dict)
        address_context.append(address_dict)
    elif fqdn:
        fqdn_dict = {
            'Name': address_name,
            'FQDN': fqdn
        }
        contents.append(fqdn_dict)
        address_context.append(fqdn_dict)

    context['Fortigate.Address(val.Name && val.Name === obj.Name)'] = address_context

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate address ' + address_name + ' created successfully', contents),
        'EntryContext': context
    })


@logger
def create_address_request(address_name, address, mask, fqdn):
    uri_suffix = 'cmdb/firewall/address/'
    headers = {
        'Authorization': 'Bearer '+str(PASS_token)
    }
    # if does_path_exist(uri_suffix + address_name):
    #     return_error('Address already exists.')
    if address:
        subnet = address + " " + mask
        payload = {
            'name': address_name,
            'subnet': subnet
        }
    elif fqdn:
        payload = {
            'name': address_name,
            "type": "fqdn",
            "fqdn": fqdn
        }
    result = http_request('POST', uri_suffix, None, headers,json.dumps(payload))
    return result


@logger
def delete_address_command():
    contents = []
    context = {}
    address_context = []
    name = demisto.args().get('name', '')

    delete_address_request(name)

    address_dict = {
        'Name': name,
        'Deleted': True
    }
    contents.append(address_dict)
    address_context.append(address_dict)

    context['Fortigate.Address(val.Name && val.Name === obj.Name)'] = address_context

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate address ' + name + ' deleted successfully', contents),
        'EntryContext': context
    })


@logger
def delete_address_request(name):
    uri_suffix = 'cmdb/firewall/address/' + name
    headers = {
        'Authorization': 'Bearer '+str(PASS_token)
    }
    response = http_request('DELETE', uri_suffix, None, headers)
    return response


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG(f'command is {demisto.command()}')

try:
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_module()
        demisto.results('ok')
    elif demisto.command() == 'fortigate-get-addresses':
        get_addresses_command()
    elif demisto.command() == 'fortigate-get-policy':
        get_policy_command()
    elif demisto.command() == 'fortigate-update-policy':
        update_policy_command()
    elif demisto.command() == 'fortigate-create-policy':
        create_policy_command()
    elif demisto.command() == 'fortigate-move-policy':
        move_policy_command()
    elif demisto.command() == 'fortigate-delete-policy':
        delete_policy_command()
    elif demisto.command() == 'fortigate-get-address-groups':
        get_address_groups_command()
    elif demisto.command() == 'fortigate-update-address-group':
        update_address_group_command()
    elif demisto.command() == 'fortigate-create-address-group':
        create_address_group_command()
    elif demisto.command() == 'fortigate-delete-address-group':
        delete_address_group_command()
    elif demisto.command() == 'fortigate-ban-ip':
        ban_ip_command()
    elif demisto.command() == 'fortigate-unban-ip':
        unban_ip_command()
    elif demisto.command() == 'fortigate-get-banned-ips':
        get_banned_ips_command()
    elif demisto.command() == 'fortigate-create-address':
        create_address_command()
    elif demisto.command() == 'fortigate-delete-address':
        delete_address_command()

except Exception as e:
    LOG(e)
    LOG.print_log()
    raise


register_module_line('FortiGate', 'end', __line__())
