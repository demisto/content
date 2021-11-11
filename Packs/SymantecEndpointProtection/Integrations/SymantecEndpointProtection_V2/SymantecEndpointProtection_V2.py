import json
import re
from datetime import datetime, timedelta

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401

requests.packages.urllib3.disable_warnings()

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
FETCH_DELTA = int(demisto.params().get('fetchDelta', 24))
FETCH_ACKNOWLEDGED_EVENTS = False if demisto.params().get('fetchAcknowledged', 'No') == 'No' else True
SEP_EVENT_DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S.0'
OUTPUT_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

'''HELPER FUNCTIONS'''


def get_stats_args(report_type_required=True):
    args = demisto.args()

    # Get report type
    report_type = None
    if report_type_required is True:
        report_type = args.get("report_type")
        if report_type not in ["Hour", "Day", "Week", "Month"]:
            raise Exception("Invalid value provided for report type. Must be Hour, Day, Week or Month")

    start_time = get_arg_start_time_to_epoch(args)
    end_time = get_arg_end_time_to_epoch(args)

    return end_time, report_type, start_time


def epoch_to_date_string(epoch):
    return datetime.fromtimestamp(epoch).strftime(OUTPUT_DATETIME_FORMAT)


def get_utcfromtimestamp(time):
    return datetime.utcfromtimestamp(time)


def get_utcnow():
    return datetime.utcnow()


def epoch_seconds(d=None):
    if not d:
        d = get_utcnow()
    return int((d - get_utcfromtimestamp(0)).total_seconds())


def get_arg_end_time_to_epoch(args):
    # Default is now.
    end_time = args.get("end_time", None)
    if end_time is None:
        end_time = epoch_seconds()
    else:
        time_ago = get_utcnow() - timedelta(seconds=int(args.get("end_time")))
        end_time = epoch_seconds(time_ago)
    return end_time


def get_arg_start_time_to_epoch(args):
    # Default is seven days ago.
    time_ago = get_utcnow() - timedelta(seconds=int(args.get("start_time", 604800)))
    start_time = epoch_seconds(time_ago)
    return start_time


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
    list_params = map(lambda key: key + '=' + str(params[key]), params.keys())
    query_params = '&'.join(list_params)
    return '?' + query_params if query_params else ''


def do_auth(server, creds, insecure, domain):
    url = fix_url(str(server)) + 'sepm/api/v1/identity/authenticate'
    body = {
        'username': creds.get('identifier') if creds.get('identifier') else '',
        'password': creds.get('password') if creds.get('password') else '',
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


def get_token():
    integration_context = get_integration_context()
    refresh_token = integration_context.get('current_refresh_token', '')

    # Set keywords. Default without the scope prefix.
    access_token_keyword = 'access_token'
    valid_until_keyword = 'valid_until'

    access_token = integration_context.get(access_token_keyword)
    valid_until = integration_context.get(valid_until_keyword)
    if access_token and valid_until:
        if epoch_seconds() < valid_until:
            return access_token

    resp = do_auth(server=demisto.getParam('server'), creds=demisto.getParam(
        'authentication'), insecure=demisto.getParam('insecure'), domain=demisto.getParam('domain'))

    access_token = resp.get("token")
    expires_in = resp.get("tokenExpiration")
    refresh_token = resp.get("refreshToken")

    time_now = epoch_seconds()
    time_buffer = 5  # seconds by which to shorten the validity period
    if expires_in - time_buffer > 0:
        # err on the side of caution with a slightly shorter access token validity period
        expires_in = expires_in - time_buffer

    valid_until = time_now + expires_in
    integration_context.update({
        access_token_keyword: access_token,
        valid_until_keyword: valid_until,
        'current_refresh_token': refresh_token
    })

    set_integration_context(integration_context)
    return access_token


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
    return map(change_assigined, policies_list)


def sanitize_policies_list(policies_list):
    return map(lambda policy: {
        'PolicyName': policy['name'],
        'Type': policy['policytype'],
        'ID': policy['id'],
        'Description': policy['desc'],
        'Enabled': policy['enabled'],
        'AssignedLocations': map(lambda location: {
            'GroupID': location.get('groupId'),
            'Locations': location.get('locationIds')
        }, policy.get('assignedtolocations') if policy.get('assignedtolocations') else []),
        'AssignedCloudGroups': map(lambda location: {
            'GroupID': location.get('groupId'),
            'Locations': location.get('locationIds')
        }, policy.get('assignedtocloudgroups') if policy.get('assignedtocloudgroups') else []),
    }, policies_list)


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
    location_ids = map(lambda location_string: {'ID': location_string.split('/')[-1]}, url_resp)
    return url_resp, location_ids


def get_id_by_endpoint(token, endpoint):
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


def event_to_incident(event):
    occurred = datetime.strptime(event.get("eventDateTime"), SEP_EVENT_DATETIME_FORMAT)
    incident = {
        'name': event.get("subject"),
        'occurred': occurred.isoformat().split('.')[0] + 'Z',
        'rawJSON': json.dumps(event)
    }
    return incident


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
        'HumanReadable': tableToMarkdown('Locations', map(lambda location: {'Location ID': location.get('ID')},
                                                          location_ids)),
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


def fetch_incidents(token):
    json_response = do_get(token, False, 'sepm/api/v1/events/critical')
    if json_response is None:
        raise Exception("The response received is malformed. Null received.")

    return json_response


def fetch_incidents_command(token):
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('time')

    # handle first time fetch
    if last_fetch is None:
        last_fetch = datetime.now() - timedelta(hours=FETCH_DELTA)
    else:
        last_fetch = datetime.strptime(last_fetch, OUTPUT_DATETIME_FORMAT)

    current_fetch = last_fetch

    incidents = []
    response = fetch_incidents(token)
    events = response.get("criticalEventsInfoList", [])
    for event in events:

        event_acknowledged = False if event.get("acknowledged", 0) == 0 else True
        if event_acknowledged and not FETCH_ACKNOWLEDGED_EVENTS:
            demisto.info("Skipping event " + event.get('eventId') + " because it has already been acknowledged.")
            continue

        incident = event_to_incident(event)
        temp_date = datetime.strptime(incident['occurred'], OUTPUT_DATETIME_FORMAT)

        # update last run
        if temp_date > last_fetch:
            last_fetch = temp_date + timedelta(seconds=1)

        # avoid duplication due to weak time query
        if temp_date > current_fetch:
            incidents.append(incident)

    demisto.setLastRun({'time': last_fetch.isoformat().split('.')[0] + 'Z'})
    demisto.incidents(incidents)


def list_online_offline_clients(token):
    json_response = do_get(token, False, 'sepm/api/v1/stats/client/onlinestatus')
    if json_response is None:
        raise Exception("The response received is malformed. Null received.")

    return json_response


def list_online_offline_clients_command(token):
    response = list_online_offline_clients(token)
    client_count_stats_list = response.get("clientCountStatsList", [])
    online_count = offline_count = 0
    for item in client_count_stats_list:
        status = item.get("status").lower()
        if status == "online":
            online_count = item.get("clientsCount")

        if status == "offline":
            offline_count = item.get("clientsCount")

    context = {
        "online": online_count,
        "offline": offline_count,
        "total": online_count + offline_count
    }

    human_readable = tableToMarkdown("Online-offline clients", context, headerTransform=pascalToSpace)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'HumanReadable': human_readable,
        'IgnoreAutoExtract': True,
        'EntryContext': {
            'SEPM.Stats.Client.OnlineStatus': context
        }
    })


def get_threat_stats(token):
    json_response = do_get(token, False, 'sepm/api/v1/stats/threat')
    if json_response is None:
        raise Exception("The response received is malformed. Null received.")

    return json_response


def get_threat_stats_command(token):
    response = get_threat_stats(token)
    epoch_time = demisto.get(response, "Stats.lastUpdated")

    last_update_date = epoch_to_date_string(epoch_time)
    context = response.get("Stats")
    context["lastUpdated"] = last_update_date

    human_readable = tableToMarkdown("Threat Stats", context, headerTransform=pascalToSpace)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'HumanReadable': human_readable,
        'IgnoreAutoExtract': True,
        'EntryContext': {
            'SEPM.Stats.Threat': context
        }
    })


def get_autoresolved_attack_count(token):
    end_time, report_type, start_time = get_stats_args()

    url = 'sepm/api/v1/stats/autoresolved/{0}/{1}/to/{2}'.format(report_type, start_time, end_time)
    json_response = do_get(token, False, url)
    if json_response is None:
        raise Exception("The response received is malformed. Null received.")

    return json_response


def get_autoresolved_attack_count_command(token):
    response = get_autoresolved_attack_count(token)
    auto_resolved_attacks = response.get("autoResolvedAttacks")
    context = []
    for auto_resolved_attack in auto_resolved_attacks:
        epoch_time = auto_resolved_attack.get("epochTime")
        date_string = epoch_to_date_string(epoch_time)
        context.append({
            "clientsCount": auto_resolved_attack.get("autoResolvedAttacksCount"),
            "epochTime": epoch_time,
            "datetime": date_string
        })

    human_readable = tableToMarkdown("Auto-resolved attacks", context, headerTransform=pascalToSpace)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'HumanReadable': human_readable,
        'IgnoreAutoExtract': True,
        'EntryContext': {
            'SEPM.Stats.AutoResolvedAttacks': context
        }
    })


def get_infected_clients_count(token):
    end_time, report_type, start_time = get_stats_args()

    url = 'sepm/api/v1/stats/client/infection/{0}/{1}/to/{2}'.format(report_type, start_time, end_time)
    json_response = do_get(token, False, url)
    if json_response is None:
        raise Exception("The response received is malformed. Null received.")

    return json_response


def get_infected_clients_count_command(token):
    response = get_infected_clients_count(token)
    infected_clients = response.get("infectedClientStats")
    context = []
    for infected_client in infected_clients:
        epoch_time = infected_client.get("epochTime")
        date_string = epoch_to_date_string(epoch_time)
        context.append({
            "clientsCount": infected_client.get("clientsCount"),
            "epochTime": epoch_time,
            "datetime": date_string
        })

    human_readable = tableToMarkdown("Infected Clients", context, headerTransform=pascalToSpace)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'HumanReadable': human_readable,
        'IgnoreAutoExtract': True,
        'EntryContext': {
            'SEPM.Stats.Client.Infection': context
        }
    })


def get_malware_clients_count(token):
    end_time, report_type, start_time = get_stats_args()

    url = 'sepm/api/v1/stats/client/malware/{0}/{1}/to/{2}'.format(report_type, start_time, end_time)
    json_response = do_get(token, False, url)
    if json_response is None:
        raise Exception("The response received is malformed. Null received.")

    return json_response


def get_malware_clients_count_command(token):
    response = get_malware_clients_count(token)
    malware_clients = response.get("malwareClientStats")
    context = []
    for malware_client in malware_clients:
        epoch_time = malware_client.get("epochTime")
        date_string = epoch_to_date_string(epoch_time)
        context.append({
            "clientsCount": malware_client.get("clientsCount"),
            "epochTime": epoch_time,
            "datetime": date_string
        })

    human_readable = tableToMarkdown("Clients Reporting Malware Events", context, headerTransform=pascalToSpace)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'HumanReadable': human_readable,
        'IgnoreAutoExtract': True,
        'EntryContext': {
            'SEPM.Stats.Client.Malware': context
        }
    })


def get_risk_distribution(token):
    end_time, report_type, start_time = get_stats_args(report_type_required=False)

    url = 'sepm/api/v1/stats/client/risk/{0}/to/{1}'.format(start_time, end_time)
    json_response = do_get(token, False, url)
    if json_response is None:
        raise Exception("The response received is malformed. Null received.")

    return json_response


def get_risk_distribution_command(token):
    response = get_risk_distribution(token)
    context = response.get("riskDistributionStats")
    human_readable = tableToMarkdown("Risk Distribution", context, headerTransform=pascalToSpace)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'HumanReadable': human_readable,
        'IgnoreAutoExtract': True,
        'EntryContext': {
            'SEPM.Stats.Client.Risk': context
        }
    })


def get_client_version(token):
    url = 'sepm/api/v1/stats/client/version'
    json_response = do_get(token, False, url)
    if json_response is None:
        raise Exception("The response received is malformed. Null received.")

    return json_response


def get_client_version_command(token):
    response = get_client_version(token)
    context = response.get("clientVersionList")
    human_readable = tableToMarkdown("Client Version", context, headerTransform=pascalToSpace)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'HumanReadable': human_readable,
        'IgnoreAutoExtract': True,
        'EntryContext': {
            'SEPM.Stats.Client.Version': context
        }
    })


def get_replication_status(token):
    url = 'sepm/api/v1/replication/status'
    json_response = do_get(token, False, url)
    if json_response is None:
        raise Exception("The response received is malformed. Null received.")

    return json_response


def get_replication_status_command(token):
    response = get_replication_status(token)
    context = response.get("replicationStatus")
    human_readable = tableToMarkdown("Replication Status", context, headerTransform=pascalToSpace)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'HumanReadable': human_readable,
        'IgnoreAutoExtract': True,
        'EntryContext': {
            'SEPM.Replication.Status': context
        }
    })


def site_has_replication_partner(token):
    url = 'sepm/api/v1/replication/is_replicated'
    json_response = do_get(token, False, url)
    if json_response is None:
        raise Exception("The response received is malformed. Null received.")

    return json_response


def site_has_replication_partner_command(token):
    response = site_has_replication_partner(token)
    if isinstance(response, bool):
        demisto.results(response)
    else:
        raise Exception("An unexpected response was received. Expected boolean but got " + type(response))


def replicate_site(token):
    args = demisto.args()
    params = {
        "partnerSiteName": args.get("partner_site_name"),
        "logs": argToBoolean(args.get("logs")),
        "content": argToBoolean(args.get("content"))
    }

    params = createContext(params, removeNull=True)
    if len(params) < 3:
        raise Exception("partner_site_name, logs and content are required. Please provide values for these parameters.")

    url = 'sepm/api/v1/replication/replicatenow' + build_query_params(params)
    json_response = do_post(token=token, is_xml=False, suffix=url, body={})
    if json_response is None:
        raise Exception("The response received is malformed. Null received.")

    return json_response


def replicate_site_command(token):
    has_replication_partner = site_has_replication_partner(token)
    if not has_replication_partner:
        raise Exception("Cannot replicate a site that does not have a replication partner")

    response = replicate_site(token)
    human_readable = tableToMarkdown("Replication All Status", response, headerTransform=pascalToSpace)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'HumanReadable': human_readable,
        'IgnoreAutoExtract': True,
        'EntryContext': {
            'SEPM.Replication.Code': response.get("code")
        }
    })


def get_license_summary(token):
    url = 'sepm/api/v1/licenses/summary'
    json_response = do_get(token, False, url)
    if json_response is None:
        raise Exception("The response received is malformed. Null received.")

    return json_response


def get_license_summary_command(token):
    response = get_license_summary(token)
    human_readable = tableToMarkdown("Licenses Summary", response, headerTransform=pascalToSpace)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'HumanReadable': human_readable,
        'IgnoreAutoExtract': True,
        'EntryContext': {
            'SEPM.License.Summary': response
        }
    })


def main():
    current_command = demisto.command()
    try:
        token = get_token()
        if current_command == 'test-module':
            # This is the call made when pressing the integration test button.
            if token:
                demisto.results('ok')
        if current_command == 'fetch-incidents':
            fetch_incidents_command(token)
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
        if current_command == 'sep-stats-online-offline-clients':
            list_online_offline_clients_command(token)
        if current_command == 'sep-stats-get-threat-stats':
            get_threat_stats_command(token)
        if current_command == 'sep-stats-get-autoresolved-attacks-count':
            get_autoresolved_attack_count_command(token)
        if current_command == 'sep-stats-get-infected-clients-count':
            get_infected_clients_count_command(token)
        if current_command == 'sep-stats-get-malware-clients-count':
            get_malware_clients_count_command(token)
        if current_command == 'sep-stats-get-risk-distribution':
            get_risk_distribution_command(token)
        if current_command == 'sep-stats-get-client-version':
            get_client_version_command(token)
        if current_command == 'sep-replication-status':
            get_replication_status_command(token)
        if current_command == 'sep-replication-replicate':
            replicate_site_command(token)
        if current_command == 'sep-replication-site-has-replication-partner':
            site_has_replication_partner_command(token)
        if current_command == 'sep-license-summary':
            get_license_summary_command(token)
    except Exception as ex:
        return_error('Cannot perform the command: {}. Error: {}'.format(current_command, ex), ex)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
