import demistomock as demisto
from CommonServerPython import *
import requests
import json
import re
import urllib.request
import urllib.parse
import urllib.error
import urllib3

urllib3.disable_warnings()

handle_proxy()

ENDPOINTS_INFO_DEFAULT_COLUMNS = [
    'computerName',
    'ipAddresses',
    'operatingSystem',
    'osBitness',
    'cidsDefsetVersion',
    'lastScanTime',
    'description',
    'quarantineDesc',
    'domainOrWorkgroup',
    'macAddresses',
    'group',
    'dhcpServer',
    'biosVersion',
    'virtualizationPlatform',
    'computerTimeStamp',
    'creationTime',
    'agentTimestamp',
    'hardwareKey'
]
GROUPS_INFO_DEFAULT_COLUMNS = [
    'fullPathName',
    'numberOfPhysicalComputers',
    'numberOfRegisteredUsers',
    'policySerialNumber',
    'policyDate',
    'description',
    'created',
    'id'
]

'''LITERALS'''

EPOCH_MINUTE = 60 * 1000
EPOCH_HOUR = 60 * EPOCH_MINUTE

'''HELPER FUNCTIONS'''


def fix_url(base):
    return base if base.endswith('/') else (base + '/')


def endpoint_ip_extract(raw_json):
    ips_array = []
    for content in raw_json:
        ip = {'Address': content.get('ipAddresses', [''])[0],
              'Mac': content.get('computerName')
              }
        ip = createContext(ip, removeNull=True)
        if ip:
            ips_array.append(ip)
    return ips_array


def endpoint_endpoint_extract(raw_json):
    endpoints_arr = []
    for content in raw_json:
        endpoint = {'Hostname': content.get('computerName'),
                    'MACAddress': content.get('macAddresses', [''])[0],
                    'Domain': content.get('domainOrWorkgroup'),
                    'IPAddress': content.get('ipAddresses', [''])[0],
                    'DHCPServer': content.get('dhcpServer'),
                    'OS': content.get('operatingSystem'),
                    'OSVersion': content.get('osVersion'),
                    'BIOSVersion': content.get('biosVersion'),
                    'Memory': content.get('memory'),
                    'Processors': content.get('processorType')
                    }
        endpoint = createContext(endpoint, removeNull=True)
        if endpoint:
            endpoints_arr.append(endpoint)
    return endpoints_arr


def build_query_params(params):
    list_params = list(map(lambda key: key + '=' + str(params[key]), params.keys()))
    query_params = '&'.join(list_params)
    return '?' + query_params if query_params else ''


def do_auth(server, crads, insecure, domain):
    url = fix_url(str(server)) + 'sepm/api/v1/identity/authenticate'
    body = {
        'username': crads.get('identifier') if crads.get('identifier') else '',
        'password': urllib.parse.quote(crads.get('password')) if crads.get('password') else '',
        'domain': domain if domain else ''
    }
    res = requests.post(url, headers={"Content-Type": "application/json"}, data=json.dumps(body), verify=not insecure)
    res.raise_for_status()
    return parse_response(res)


def do_get(token, raw, suffix):
    insecure = demisto.getParam('insecure')
    server = demisto.getParam('server')
    url = fix_url(server) + suffix
    res = requests.get(url, headers={'Authorization': 'Bearer ' + token}, verify=not insecure)
    res.raise_for_status()
    if raw:
        return res
    else:
        return parse_response(res)


def do_post(token, is_xml, suffix, body):
    insecure = demisto.getParam('insecure')
    server = demisto.getParam('server')
    url = fix_url(server) + suffix
    res = requests.post(url, headers={'Authorization': 'Bearer ' + token}, data=body, verify=not insecure)
    res.raise_for_status()
    parsed_response = {}
    if is_xml:
        if res.content:
            parsed_response = xml2json(res.content)
        else:
            return_error('Unable to parse the following response: {}'.format(res))
    else:
        parsed_response = parse_response(res)
    return parsed_response


def do_put(token, suffix, body):
    insecure = demisto.getParam('insecure')
    server = demisto.getParam('server')
    url = fix_url(server) + suffix
    res = requests.put(url, headers={'Authorization': 'Bearer ' + token,
                                     'Content-Type': 'application/json'}, data=json.dumps(body), verify=not insecure)
    parsed_response = parse_response(res)
    return parsed_response


def do_patch(token, suffix, body):
    insecure = demisto.getParam('insecure')
    server = demisto.getParam('server')
    url = fix_url(server) + suffix
    res = requests.patch(
        url,
        headers={
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json'
        },
        data=json.dumps(body),
        verify=not insecure
    )
    res.raise_for_status()
    parsed_response = parse_response(res)
    return parsed_response


def parse_response(resp):
    if resp.status_code == 200 or resp.status_code == 207:
        if resp.text == '':
            return resp
        try:
            return resp.json()
        except Exception as ex:
            return_error('Unable to parse response: {}'.format(ex))
    else:
        try:
            message = resp.json().get('errorMessage')
            return_error('Error: {}'.format(message))
        except Exception:
            return_error('Error: {}'.format(resp))


def get_token_from_response(resp):
    if resp.get('token'):
        return resp.get('token')
    else:
        return_error('No token: {}'.format(resp))


def choose_columns(column_arg, default_list):
    if not column_arg:
        columns_list = default_list
        columns_list.sort()
    elif column_arg == 'all' or column_arg == '*':
        columns_list = []
    else:
        columns_list = argToList(column_arg)
    return columns_list


def build_command_xml(data):
    return '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"' \
           ' xmlns:com="http://command.client.webservice.sepm.symantec.com/"> \
            <soapenv:Header/><soapenv:Body>{0}</soapenv:Body></soapenv:Envelope>'.format(data)


def build_client_xml(data):
    return '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" ' \
           'xmlns:cli="http://client.webservice.sepm.symantec.com/"> \
            <soapenv:Header/><soapenv:Body>{0}</soapenv:Body></soapenv:Envelope>'.format(data)


def get_command_status_details(token, command_id):
    xml = build_command_xml(
        '<com:getCommandStatusDetails><commandID>{0}</commandID></com:getCommandStatusDetails>'.format(command_id))
    res_json = do_post(token, True, 'sepm/ws/v1/CommandService', xml)
    return res_json


def build_command_response_output(title, command_id, message, response):
    cmd_status_details = response.get('cmdStatusDetail')
    cmd_status_details.pop('hardwareKey', None)
    md = tableToMarkdown(title, cmd_status_details) + '\n'
    md += '### Command ID: {0}\n'.format(command_id)
    md += '### ' + message
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': {
            'cmdStatusDetail': cmd_status_details,
            'commandId': command_id
        },
        'HumanReadable': md,
        'EntryContext': {
            'SEPM.LastCommand': createContext({'CommandDetails': cmd_status_details, 'CommandId': command_id},
                                              removeNull=True)
        }
    })


def get_computer_id_by_ip(token, ip):
    xml = build_client_xml('<cli:getComputersByIP><ipAddresses>{0}</ipAddresses></cli:getComputersByIP>'.format(ip))
    res_json = do_post(token, True, 'sepm/ws/v1/ClientService', xml)
    return demisto.get(json.loads(res_json),
                       'Envelope.Body.getComputersByIPResponse.ComputerResult.computers.computerId')


def get_computer_id_by_hostname(token, hostname):
    xml = build_client_xml(
        '<cli:getComputersByHostName><computerHostNames>{0}</computerHostNames>'
        '</cli:getComputersByHostName>'.format(hostname))
    res_json = do_post(token, True, 'sepm/ws/v1/ClientService', xml)
    return demisto.get(json.loads(res_json),
                       'Envelope.Body.getComputersByHostNameResponse.ComputerResult.computers.computerId')


def get_computer_id(token, endpoint_ip, endpoint_host_name):
    computer_id = ""
    if endpoint_ip:
        try:
            computer_id = get_computer_id_by_ip(token, endpoint_ip)
        except Exception:
            return_error('Failed to locate the endpoint by its IP address.')
    elif endpoint_host_name:
        try:
            computer_id = get_computer_id_by_hostname(token, endpoint_host_name)
        except Exception:
            return_error('Failed to locat the endpoint by its hostname.')
    else:
        return_error('Please provide the IP address or the hostname of endpoint.')
    return computer_id


def update_content(token, computer_id):
    xml = build_command_xml(
        '<com:runClientCommandUpdateContent><computerGUIDList>{0}</computerGUIDList>'
        '</com:runClientCommandUpdateContent>'.format(computer_id))
    res_json = do_post(token, True, 'sepm/ws/v1/CommandService', xml)
    command_id = demisto.get(json.loads(
        res_json), 'Envelope.Body.runClientCommandUpdateContentResponse.CommandClientResult.commandId')
    if not command_id:
        error_code = demisto.get(
            res_json, 'Envelope.Body.runClientCommandUpdateContentResponse.CommandClientResult.inputErrors.errorCode')
        error_message = demisto.get(
            res_json,
            'Envelope.Body.runClientCommandUpdateContentResponse.CommandClientResult.inputErrors.errorMessage')
        if error_code or error_message:
            return_error('An error response has returned from server:'
                         ' {0} with code: {1}'.format(error_message, error_code))
        else:
            return_error('Could not retrieve command ID, no error was returned from server')
    return command_id


def scan(token, computer_id, scan_type):
    xml = build_command_xml(
        '<com:runClientCommandScan><computerGUIDList>{0}</computerGUIDList>'
        '<scanType>{1}</scanType></com:runClientCommandScan>'.format(computer_id, scan_type))
    res_json = do_post(token, True, 'sepm/ws/v1/CommandService', xml)
    command_id = demisto.get(json.loads(res_json), 'Envelope.Body.runClientCommandScanResponse.'
                                                   'CommandClientResult.commandId')
    if not command_id:
        error_code = demisto.get(json.loads(
            res_json), 'Envelope.Body.runClientCommandScanResponse.CommandClientResult.inputErrors.errorCode')
        error_message = demisto.get(json.loads(
            res_json), 'Envelope.Body.runClientCommandScanResponse.CommandClientResult.inputErrors.errorMessage')
        if error_code or error_message:
            return_error('An error response has returned from server: {0} with code: {1}'.format(error_message,
                                                                                                 error_code))
        else:
            return_error('Could not retrieve command ID, no error was returned from server')
    return command_id


def quarantine(token, computer_id, action_type):
    xml = build_command_xml(
        '<com:runClientCommandQuarantine><command><commandType>{0}</commandType><targetObjectIds>{1}'
        '</targetObjectIds><targetObjectType>COMPUTER</targetObjectType></command>'
        '</com:runClientCommandQuarantine>'.format(action_type, computer_id))
    res_json = do_post(token, True, 'sepm/ws/v1/CommandService', xml)
    command_id = demisto.get(json.loads(
        res_json), 'Envelope.Body.runClientCommandQuarantineResponse.CommandClientResult.commandId')
    if not command_id:
        error_code = demisto.get(json.loads(
            res_json), 'Envelope.Body.runClientCommandQuarantineResponse.CommandClientResult.inputErrors.errorCode')
        error_message = demisto.get(json.loads(
            res_json), 'Envelope.Body.runClientCommandQuarantineResponse.CommandClientResult.inputErrors.errorMessage')
        if error_code or error_message:
            return_error('An error response has returned from server: {0} with code: {1}'.format(error_message,
                                                                                                 error_code))
        else:
            return_error('Could not retrieve command ID, no error was returned from server')
    return command_id


def validate_time_zone(time_zone):
    pattern = re.compile("^[+-][0-9][0-9]:[0-9][0-9]")
    return bool(pattern.match(time_zone))


def parse_epoch_to_local(epoch, time_zone):
    if not validate_time_zone(time_zone):
        return_error('timeZone param should be in the format of [+/-][h][h]:[m][m]. For exmaple +04:30')
    operator = time_zone[0]
    hour = int(time_zone[1:3])
    minutes = int(time_zone[4:6])
    time_zone_epoch = hour * EPOCH_HOUR + minutes * EPOCH_MINUTE
    local = int(epoch) + time_zone_epoch if operator == '+' else int(epoch) - time_zone_epoch
    return local


def change_assigined(policy):
    new_format = {
        'Policy Name': policy.get('PolicyName'),
        'Type': policy.get('Type'),
        'ID': policy.get('ID'),
        'Assigned': True if (policy.get('AssignedLocations') or policy.get('AssignedCloudGroups')) else False,
        'Discription': policy.get('Discription'),
        'Enabled': policy.get('Enabled')
    }
    return new_format


def sanitize_policies_list_for_md(policies_list):
    return list(map(change_assigined, policies_list))


def sanitize_policies_list(policies_list):
    return list(map(lambda policy: {
        'PolicyName': policy['name'],
        'Type': policy['policytype'],
        'ID': policy['id'],
        'Description': policy['desc'],
        'Enabled': policy['enabled'],
        'AssignedLocations': list(map(lambda location: {
            'GroupID': location.get('groupId'),
            'Locations': location.get('locationIds')
        }, policy.get('assignedtolocations') if policy.get('assignedtolocations') else [])),
        'AssignedCloudGroups': list(map(lambda location: {
            'GroupID': location.get('groupId'),
            'Locations': location.get('locationIds')
        }, policy.get('assignedtocloudgroups') if policy.get('assignedtocloudgroups') else [])),
    }, policies_list))


def validate_ip(ip):
    pattern = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    return bool(pattern.match(ip))


def get_client_content(token, time_zone):
    client_content_json = do_get(token, False, 'sepm/api/v1/stats/client/content')
    epoch_time = client_content_json.get('lastUpdated')
    if time_zone:
        epoch_time = parse_epoch_to_local(epoch_time, time_zone)
    last_update_date = timestamp_to_datestring(epoch_time, '%a %b %d %y %H:%M:%S %z')
    client_version = client_content_json.get('clientDefStatusList')
    return client_content_json, client_version, last_update_date


def get_endpoints_info(token, computer_name, last_update, os, page_size, columns, group_name=None):
    params = {
        'computerName': computer_name,
        'lastUpdate': last_update,
        'os': os,
        'pageSize': page_size,
        'columns': columns
    }
    params = createContext(params, removeNull=True)
    json_response = do_get(token, False, 'sepm/api/v1/computers' + build_query_params(params))
    filtered_json_response = json_response.get('content')
    final_json = []
    entry_context = []
    for content in filtered_json_response:
        group = content.get('group', {'name': ''})
        bool_start = group.get('name').startswith(group_name[:-1]) if group_name and group_name[-1] == '*' else False
        if (not group_name) or group.get('name') == group_name or bool_start:  # No group name filter
            # used `set` on the mac address list as it sometimes contained duplicated values
            content['macAddresses'] = list(set(content.get('macAddresses')))
            entry_context.append({
                'Hostname': content.get('computerName'),
                'Domain': content.get('domainOrWorkgroup'),
                'IPAddresses': content.get('ipAddresses'),
                'OS': content.get('operatingSystem', '') + ' | ' + content.get('osBitness', ''),
                'Description': content.get('content.description'),
                'MACAddresses': content.get('macAddresses'),
                'BIOSVesrsion': content.get('biosVersion'),
                'DHCPServer': content.get('dhcpServer'),
                'HardwareKey': content.get('hardwareKey'),
                'LastScanTime': epochToTimestamp(content.get('lastScanTime')),
                'RunningVersion': content.get('deploymentRunningVersion'),
                'TargetVersion': content.get('deploymentTargetVersion'),
                'Group': group.get('name'),
                'PatternIdx': content.get('patternIdx'),
                'OnlineStatus': content.get('onlineStatus'),
                'UpdateTime': epochToTimestamp(content.get('lastUpdateTime')),
            })
            final_json.append(content)

    return final_json, entry_context


def create_endpints_filter_string(computer_name, last_update, os, page_size, group_name=None):
    md = '## Endpoints Information'
    if last_update != '0':
        md += ', filtered for last updated status: {}'.format(last_update) if last_update else ''
    md += ', filtered for hostname: {}'.format(computer_name) if computer_name else ''
    md += ', filtered for os: {}'.format(os) if os else ''
    md += ', filtered for group name: {}'.format(group_name) if group_name else ''
    md += ', page size: {}'.format(page_size) if page_size else ''
    md += '\n'
    return md


def get_groups_info(token, columns):
    json_res = do_get(token, False, 'sepm/api/v1/groups' + build_query_params({'columns': columns}))
    sepm_groups = []
    filtered_json_response = json_res.get('content')
    for entry in filtered_json_response:
        group = {}
        for header in GROUPS_INFO_DEFAULT_COLUMNS:
            group[header] = entry[header]
            sepm_groups.append(group)
    return filtered_json_response, json_res, sepm_groups


def get_command_status(token, command_id):
    command_status_json = get_command_status_details(token, command_id)
    cmd_status_detail = demisto.get(json.loads(command_status_json),
                                    'Envelope.Body.getCommandStatusDetailsResponse.'
                                    'CommandStatusDetailResult.cmdStatusDetail')
    cmd_status_detail.pop('hardwareKey', None)
    state_id = cmd_status_detail.get('stateId')
    is_done = False
    if state_id == '2' or state_id == '3':
        is_done = True
    message = 'Command is done.' if is_done else 'Command is in progress. Run !sep-command-status to check again.'
    return cmd_status_detail, message


def get_list_of_policies(token):
    policies_list = do_get(token, False, 'sepm/api/v1/policies/summary').get('content')
    fixed_policy_list = sanitize_policies_list(policies_list)
    md_list = sanitize_policies_list_for_md(fixed_policy_list)
    return md_list, policies_list, fixed_policy_list


def endpoint_quarantine(token, endpoint, action):
    action_type = 'Quarantine' if action == 'Add' else 'Undo'
    computer_id = get_id_by_endpoint(token, endpoint)
    command_id = quarantine(token, computer_id, action_type)
    return command_id


def get_location_list(token, group_id):
    url = 'sepm/api/v1/groups/{}/locations'.format(group_id)
    url_resp = do_get(token, False, url)
    location_ids = list(map(lambda location_string: {'ID': location_string.split('/')[-1]}, url_resp))
    return url_resp, location_ids


def get_id_by_endpoint(token, endpoint):
    computer_id = ""
    if not endpoint:
        return_error('Please provide the IP address or the hostname of endpoint.')
    elif validate_ip(endpoint):
        computer_id = get_computer_id(token, endpoint, None)
    else:
        computer_id = get_computer_id(token, None, endpoint)
    return computer_id


def scan_endpoint(token, endpoint, scan_type):
    computer_id = get_id_by_endpoint(token, endpoint)
    command_id = scan(token, computer_id, scan_type)
    return command_id


def update_endpoint_content(token, endpoint):
    computer_id = get_id_by_endpoint(token, endpoint)
    command_id = update_content(token, computer_id)
    return command_id


def filter_only_old_clients(filtered_json_response, desired_version):
    filtered = []
    for content in filtered_json_response:
        RunningVersion = content.get('deploymentRunningVersion')
        TargetVersion = content.get('deploymentTargetVersion')

        if (desired_version and RunningVersion != desired_version) or \
                (not desired_version and RunningVersion != TargetVersion):
            filtered.append(content)
    return filtered


'''COMMANDS'''


def system_info_command(token):
    version_json = do_get(token, False, 'sepm/api/v1/version')
    avdef_json = do_get(token, False, 'sepm/api/v1/content/avdef/latest')
    system_info_json = {
        'version': version_json,
        'avdef': avdef_json
    }
    md = '## System Information\n'
    md += tableToMarkdown('Version', version_json)
    md += tableToMarkdown('AV Definitions', avdef_json)
    context = avdef_json.get('publishedBySymantec')
    if type(context) is dict:
        context = createContext(context, removeNull=True)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': system_info_json,
        'HumanReadable': md,
        'EntryContext': {
            'SEPM.ServerAVDefVersion': context
        }
    })


def old_clients_command(token):
    computer_name = demisto.getArg('computerName')
    last_update = demisto.getArg('lastUpdate')
    os = demisto.getArg('os')
    page_size = demisto.getArg('pageSize')
    columns = demisto.getArg('columns')
    group_name = demisto.getArg('groupName')
    desired_version = demisto.getArg('desiredVersion')
    filtered_json_response, entry_context = get_endpoints_info(token, computer_name, last_update, os, page_size,
                                                               columns, group_name)
    columns_list = choose_columns(columns, ENDPOINTS_INFO_DEFAULT_COLUMNS)
    filtered_json_response = filter_only_old_clients(filtered_json_response, desired_version)
    md = create_endpints_filter_string(computer_name, last_update, os, page_size, group_name)
    md += tableToMarkdown('Old Endpoints', filtered_json_response, columns_list)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': filtered_json_response,
        'HumanReadable': md
    })


def client_content_command(token):
    time_zone = demisto.getParam('timeZone')
    client_content_json, client_version, last_update_date = get_client_content(token, time_zone)
    md = '## Client Content, last updated on {0}\n'.format(last_update_date)
    md += tableToMarkdown('Client Content Versions', client_version)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': client_content_json,
        'HumanReadable': md,
        'EntryContext': {
            'SEPM.ClientContentVersions': client_version,
            'SEPM.LastUpdated': last_update_date
        }
    })


def endpoints_info_command(token):
    computer_name = demisto.getArg('computerName')
    last_update = demisto.getArg('lastUpdate')
    os = demisto.getArg('os')
    page_size = demisto.getArg('pageSize')
    columns = demisto.getArg('columns')
    group_name = demisto.getArg('groupName')
    filtered_json_response, entry_context = get_endpoints_info(token, computer_name, last_update, os, page_size,
                                                               columns, group_name)
    columns_list = choose_columns(columns, ENDPOINTS_INFO_DEFAULT_COLUMNS)
    md = create_endpints_filter_string(computer_name, last_update, os, page_size, group_name)
    md += tableToMarkdown('Endpoints', filtered_json_response, columns_list)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': filtered_json_response,
        'HumanReadable': md,
        'IgnoreAutoExtract': True,
        'EntryContext': {
            'SEPM.Endpoint(val.Hostname == obj.Hostname)': createContext(entry_context, removeNull=True),
            'IP(val.Address === obj.Address)': endpoint_ip_extract(filtered_json_response),
            'Endpoint(val.Hostname == obj.Hostname)': endpoint_endpoint_extract(filtered_json_response)
        }
    })


def groups_info_command(token):
    columns = demisto.getArg('columns')
    filtered_json_response, json_res, sepm_groups = get_groups_info(token, columns)
    columns_list = choose_columns(columns, GROUPS_INFO_DEFAULT_COLUMNS)
    md = tableToMarkdown('Groups Information', filtered_json_response, columns_list)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': json_res,
        'HumanReadable': md,
        'IgnoreAutoExtract': True,
        'EntryContext': {'SEPM.Groups': sepm_groups}
    })


def command_status(token):
    command_id = demisto.getArg('commandId')
    cmd_status_detail, message = get_command_status(token, command_id)
    md = '### Command ID: {0}\n'.format(command_id)
    md += '### State ID: {0}\n'.format(cmd_status_detail.get('stateId'))
    md += '### ' + message
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': {
            'cmdStatusDetail': cmd_status_detail,
            'commandId': command_id
        },
        'HumanReadable': md,
        'IgnoreAutoExtract': True,
        'EntryContext': {
            'SEPM.LastCommand(val.CommandID && val.CommandID == obj.CommandID)': createContext(
                {'CommandDetails': cmd_status_detail, 'CommandID': command_id}, removeNull=True)
        }
    })


def list_policies_command(token):
    md_list, policies_list, fixed_policy_list = get_list_of_policies(token)
    md = tableToMarkdown('List of existing policies', md_list, [
        'Policy Name', 'Type', 'ID', 'Enabled', 'Assigned', 'Description'])
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': policies_list,
        'HumanReadable': md,
        'IgnoreAutoExtract': True,
        'EntryContext': {
            'SEPM.PoliciesList': createContext(fixed_policy_list, removeNull=True)
        }
    })


def assign_policie_command(token):
    group_id = demisto.getArg('groupID')
    locatoion_id = demisto.getArg('locationID')
    policy_type = demisto.getArg('policyType').lower()
    policy_id = demisto.getArg('policyID')
    do_put(token, 'sepm/api/v1/groups/{0}/locations/{1}/policies/{2}'.format(group_id,
                                                                             locatoion_id, policy_type),
           {'id': policy_id})
    md = '### Policy: {0}, of type: {1}, was assigned to location: {2}, in group: {3}'.format(
        policy_id, policy_type, locatoion_id, group_id)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': '',
        'HumanReadable': md,
        'EntryContext': {}
    })


def list_locations_command(token):
    group_id = demisto.getArg('groupID')
    url_resp, location_ids = get_location_list(token, group_id)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': url_resp,
        'HumanReadable': tableToMarkdown('Locations', list(map(lambda location: {'Location ID': location.get('ID')},
                                                               location_ids))),
        'IgnoreAutoExtract': True,
        'EntryContext': {
            'SEPM.Locations': location_ids
        }
    })


def endpoint_quarantine_command(token):
    endpoint = demisto.getArg('endpoint')
    action = demisto.getArg('actionType')
    command_id = endpoint_quarantine(token, endpoint, action)
    message = '### Initiated quarantine for endpoint {0}.' \
              ' Command ID: {1}.'.format(endpoint, command_id) \
        if action == 'Add' else '### Removing endpoint: {0} from quarantine. Command ID: {1}.'.format(endpoint,
                                                                                                      command_id)
    context = {
        'CommandID': command_id,
        'Action': action,
        'Endpoint': endpoint
    }
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': command_id,
        'HumanReadable': message,
        'IgnoreAutoExtract': True,
        'EntryContext': {
            'SEPM.Quarantine': context
        }
    })


def scan_endpoint_command(token):
    endpoint = demisto.getArg('endpoint')
    scan_type = demisto.getArg('scanType')
    command_id = scan_endpoint(token, endpoint, scan_type)
    message = '### Initiated scan on endpoint: {0} with type: {1}. Command ID: {2}.'.format(endpoint,
                                                                                            scan_type, command_id)
    context = {
        'CommandID': command_id,
        'Type': scan_type,
        'Endpoint': endpoint
    }
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': command_id,
        'HumanReadable': message,
        'IgnoreAutoExtract': True,
        'EntryContext': {
            'SEPM.Scan': context
        }
    })


def update_endpoint_content_command(token):
    endpoint = demisto.getArg('endpoint')
    command_id = update_endpoint_content(token, endpoint)
    message = '### Updating endpoint: {0}. Command ID: {1}.'.format(endpoint, command_id)
    context = {
        'CommandID': command_id,
        'Endpoint': endpoint
    }
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': command_id,
        'HumanReadable': message,
        'IgnoreAutoExtract': True,
        'EntryContext': {
            'SEPM.Update': context
        }
    })


def move_client_to_group(token, group_id, hardware_key):
    body = [{
        'group': {
            'id': group_id
        },
        'hardwareKey': hardware_key
    }]
    response = do_patch(token, 'sepm/api/v1/computers', body)
    message = '### Moved client to requested group successfully' \
        if response[0].get('responseCode') == '200' \
        else '### Error moving client'
    return response, message


def move_client_to_group_command(token):
    group_id = demisto.getArg('groupID')
    hardware_key = demisto.getArg('hardwareKey')
    response, message = move_client_to_group(token, group_id, hardware_key)
    demisto.results(
        {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': response,
            'HumanReadable': message,
            'IgnoreAutoExtract': True,
        })


def main():
    current_command = demisto.command()
    try:
        '''
        Before EVERY command the following tow lines are performed (do_auth and get_token_from_response)
        '''
        resp = do_auth(server=demisto.getParam('server'), crads=demisto.getParam(
            'authentication'), insecure=demisto.getParam('insecure'), domain=demisto.getParam('domain'))
        token = get_token_from_response(resp)
        if current_command == 'test-module':
            # This is the call made when pressing the integration test button.
            if token:
                demisto.results('ok')
        if current_command == 'sep-system-info':
            system_info_command(token)
        if current_command == 'sep-client-content':
            client_content_command(token)
        if current_command == 'sep-endpoints-info':
            endpoints_info_command(token)
        if current_command == 'sep-groups-info':
            groups_info_command(token)
        if current_command == 'sep-command-status':
            command_status(token)
        if current_command == 'sep-list-policies':
            list_policies_command(token)
        if current_command == 'sep-assign-policy':
            assign_policie_command(token)
        if current_command == 'sep-list-locations':
            list_locations_command(token)
        if current_command == 'sep-endpoint-quarantine':
            endpoint_quarantine_command(token)
        if current_command == 'sep-scan-endpoint':
            scan_endpoint_command(token)
        if current_command == 'sep-update-endpoint-content':
            update_endpoint_content_command(token)
        if current_command == 'sep-move-client-to-group':
            move_client_to_group_command(token)
        if current_command == 'sep-identify-old-clients':
            old_clients_command(token)
    except Exception as ex:
        return_error(f'Cannot perform the command: {current_command}. Error: {ex}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
