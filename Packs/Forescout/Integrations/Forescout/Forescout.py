import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
import urllib3
from typing import Dict, List, Tuple, Any, Union, cast
import xml.etree.ElementTree as ET_PHONE_HOME
from copy import deepcopy
from datetime import datetime, timedelta, UTC
from dateutil.parser import parse as parsedate

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

PARAMS = demisto.params()
WEB_API_CREDENTIALS = PARAMS.get('web_api_credentials')
WEB_API_CREDENTIALS = {} if not WEB_API_CREDENTIALS else WEB_API_CREDENTIALS
WEB_API_USERNAME = WEB_API_CREDENTIALS.get('identifier', '')
WEB_API_PASSWORD = WEB_API_CREDENTIALS.get('password', '')

DEX_CREDENTIALS = PARAMS.get('dex_credentials')
DEX_CREDENTIALS = {} if not DEX_CREDENTIALS else DEX_CREDENTIALS
DEX_USERNAME = DEX_CREDENTIALS.get('identifier', '')
DEX_PASSWORD = DEX_CREDENTIALS.get('password', '')
DEX_ACCOUNT = PARAMS.get('dex_account', '')
DEX_ACCOUNT = '' if not DEX_ACCOUNT else DEX_ACCOUNT

# Remove trailing slash to prevent wrong URL path to service
BASE_URL = PARAMS.get('url', '').strip().rstrip('/')
# Should we use SSL
USE_SSL = not PARAMS.get('insecure', False)
try:
    HTTP_TIMEOUT = int(demisto.params().get('timeout', 60))
except ValueError as e:
    demisto.debug(f'Failed casting timeout parameter to int, falling back to 60 - {e}')
    HTTP_TIMEOUT = 60

WEB_AUTH = ''
LAST_JWT_FETCH = None
# Default JWT validity time set in Forescout Web API
JWT_VALIDITY_TIME = timedelta(minutes=5)

DEX_AUTH = (DEX_USERNAME + '@' + DEX_ACCOUNT, DEX_PASSWORD)
DEX_HEADERS = {
    'Content-Type': 'application/xml',
    'Accept': 'application/xml'
}

# Host fields to be included in output of get_host_command
HOSTFIELDS_TO_INCLUDE = {
    'os_classification': 'OSClassification',
    'classification_source_os': 'ClassificationSourceOS',
    'onsite': 'Onsite',
    'access_ip': 'AccessIP',
    'macs': 'MAC',
    'openports': 'OpenPort',
    'mac_vendor_string': 'MacVendorString',
    'cl_type': 'ClType',
    'cl_rule': 'ClRule',
    'vendor': 'Vendor',
    'fingerprint': 'Fingerprint',
    'gst_signed_in_stat': 'GstSignedInStat',
    'misc': 'Misc',
    'prim_classification': 'PrimClassification',
    'agent_install_mode': 'AgentInstallMode',
    'vendor_classification': 'VendorClassification',
    'user_def_fp': 'UserDefFp',
    'agent_visible_mode': 'AgentVisibleMode',
    'classification_source_func': 'ClassificationSourceFunc',
    'dhcp_class': 'DhcpClass',
    'samba_open_ports': 'SambaOpenPort',
    'mac_prefix32': 'MacPrefix32',
    'adm': 'ADM',
    'last_nbt_report_time': 'LastNbtReportTime',
    'agent_version': 'AgentVersion',
    'matched_fingerprints': 'MatchedFingerprint',
    'manage_agent': 'ManageAgent',
    'dhcp_req_fingerprint': 'DhcpReqFingerprint',
    'dhcp_opt_fingerprint': 'DhcpOptFingerprint',
    'online': 'Online',
    'nmap_def_fp7': 'NmapDefFp7',
    'ipv4_report_time': 'Ipv4ReportTime',
    'nmap_def_fp5': 'NmapDefFp5',
    'va_netfunc': 'VaNetfunc',
    'dhcp_os': 'DhcpOS',
    'engine_seen_packet': 'EngineSeenPacket',
    'nmap_netfunc7': 'NmapNetfunc7',
    'nmap_fp7': 'NmapFp7',
    'dhcp_hostname': 'DhcpHostname'
}


''' HELPER FUNCTIONS '''


def check_web_api_credentials():
    """
    Verify that credentials were entered for Data Exchange (DEX)
    """
    if not (WEB_API_USERNAME and WEB_API_PASSWORD):
        err_msg = 'Error in Forescout Integration - Web API credentials must' \
                  ' be entered in the Forescout integration configuration in order to execute this command.'
        return_error(err_msg)


def check_dex_credentials():
    """
    Verify that credentials were entered for Data Exchange (DEX)
    """
    if not (DEX_USERNAME and DEX_PASSWORD and DEX_ACCOUNT):
        err_msg = 'Error in Forescout Integration - Data Exchange (DEX) credentials must' \
                  ' be entered in the Forescout integration configuration in order to execute this command.'
        return_error(err_msg)


def create_update_lists_request_body(update_type: str, lists: str) -> ET_PHONE_HOME.Element:
    """
    Create XML request body formatted to DEX expectations

    Parameters
    ----------
    update_type : str
        The type of update to execute.
    lists : str
        The list names and associated values to update the list with.

    Returns
    -------
        XML Request Body Element
    """
    root = ET_PHONE_HOME.Element('FSAPI', attrib={'TYPE': 'request', 'API_VERSION': '2.0'})
    transaction = ET_PHONE_HOME.SubElement(root, 'TRANSACTION', attrib={'TYPE': update_type})
    lists_xml = ET_PHONE_HOME.SubElement(transaction, 'LISTS')
    if lists:
        list_val_pairs = lists.split('&')
        for list_val_pair in list_val_pairs:
            list_name, *values = list_val_pair.split('=')
            list_xml = ET_PHONE_HOME.SubElement(lists_xml, 'LIST', attrib={'NAME': list_name})
            if update_type != 'delete_all_list_values' and values:
                list_of_vals = '='.join(values).split(':')
                for val in list_of_vals:
                    val_xml = ET_PHONE_HOME.SubElement(list_xml, 'VALUE')
                    val_xml.text = val

    return root


def create_update_hostfields_request_body(host_ip: str, update_type: str,
                                          field: str, value: str, fields_json: str) -> ET_PHONE_HOME.Element:
    """
    Create XML request body formatted to DEX expectations

    Parameters
    ----------
    host_ip : str
        IP address of the target host.
    update_type : str
        The type of update to execute.
    field : str
        The host field to update.
    value : str
        The value to assign to the specified host field.
    fields_json: str
        Field-value pairs in valid JSON format. Useful for Forescout composite fields.

    Returns
    -------
        XML Request Body Element
    """
    root = ET_PHONE_HOME.Element('FSAPI', attrib={'TYPE': 'request', 'API_VERSION': '2.0'})
    transaction = ET_PHONE_HOME.SubElement(root, 'TRANSACTION', attrib={'TYPE': update_type})
    if update_type == 'update':
        ET_PHONE_HOME.SubElement(transaction, 'OPTIONS', attrib={'CREATE_NEW_HOST': 'false'})

    ET_PHONE_HOME.SubElement(transaction, 'HOST_KEY', attrib={'NAME': 'ip', 'VALUE': host_ip})
    props_xml = ET_PHONE_HOME.SubElement(transaction, 'PROPERTIES')

    # parse fields_json
    non_composite_fields = {}
    composite_fields: Dict[Any, Any] = {}
    if fields_json:
        fields_json_dict = json.loads(fields_json)
        for key, val in fields_json_dict.items():
            if isinstance(val, dict):
                composite_fields[key] = val
            elif isinstance(val, list):
                if len(val) >= 1 and isinstance(val[0], dict):
                    composite_fields[key] = val
                else:
                    non_composite_fields[key] = val
            else:
                non_composite_fields[key] = val

    # put non-composite fields all together
    if field:
        non_composite_fields[field] = argToList(value)

    for key, val in non_composite_fields.items():
        prop_xml = ET_PHONE_HOME.SubElement(props_xml, 'PROPERTY', attrib={'NAME': key})
        if update_type != 'delete':
            if isinstance(val, list):
                for sub_val in val:
                    val_xml = ET_PHONE_HOME.SubElement(prop_xml, 'VALUE')
                    val_xml.text = sub_val
            else:
                val_xml = ET_PHONE_HOME.SubElement(prop_xml, 'VALUE')
                val_xml.text = val

    if composite_fields:
        for table_prop_name, values in composite_fields.items():
            table_property_xml = ET_PHONE_HOME.SubElement(props_xml, 'TABLE_PROPERTY',
                                                          attrib={'NAME': table_prop_name})
            if update_type == 'update':
                if isinstance(values, list):

                    for row in values:
                        row_xml = ET_PHONE_HOME.SubElement(table_property_xml, 'ROW')

                        for key, val in row.items():
                            key_xml = ET_PHONE_HOME.SubElement(row_xml, 'CPROPERTY', attrib={'NAME': key})

                            if isinstance(val, list):
                                for sub_val in val:
                                    value_xml = ET_PHONE_HOME.SubElement(key_xml, 'CVALUE')
                                    value_xml.text = sub_val

                            else:
                                value_xml = ET_PHONE_HOME.SubElement(key_xml, 'CVALUE')
                                value_xml.text = val
                else:
                    row_xml = ET_PHONE_HOME.SubElement(table_property_xml, 'ROW')
                    for key, val in values.items():
                        key_xml = ET_PHONE_HOME.SubElement(row_xml, 'CPROPERTY', attrib={'NAME': key})
                        if isinstance(val, list):
                            for sub_val in val:
                                value_xml = ET_PHONE_HOME.SubElement(key_xml, 'CVALUE')
                                value_xml.text = sub_val
                        else:
                            value_xml = ET_PHONE_HOME.SubElement(key_xml, 'CVALUE')
                            value_xml.text = val

    return root


def filter_hostfields_data(args: Dict, data: Dict) -> List:
    """
    Filter host fields data by get_host_fields_command arguments.

    Parameters
    ----------
    args : dict
        The get_host_fields_command arguments.
    data : dict
        The data to filter.

    Returns
    -------
    list
        Filtered list of hostfields
    """
    search_term = args.get('search_term')
    host_fields = data.get('hostFields', [])
    host_field_type = args.get('host_field_type', 'all_types')
    if not search_term:
        # Still check to see if should filter host fields by their type
        if host_field_type == 'all_types':
            return host_fields
        else:
            host_field_types = argToList(host_field_type)
            filtered_hostfields = []
            for host_field in host_fields:
                if host_field.get('type') in host_field_types:
                    filtered_hostfields.append(host_field)
            return filtered_hostfields
    case_sensitive = args.get('case_sensitive', 'false')
    case_sensitive = False if case_sensitive.casefold() == 'false' else True
    if not case_sensitive:
        search_term = search_term.casefold()
    match_exactly = args.get('match_exactly', 'False')
    match_exactly = False if match_exactly.casefold() == 'false' else True
    if host_field_type != 'all_types':
        host_field_type = argToList(host_field_type)
    search_in = args.get('search_in', 'name')
    search_in = argToList(search_in)

    filtered_hostfields = []
    for host_field in host_fields:
        if isinstance(host_field_type, list):
            if host_field.get('type') not in host_field_type:
                continue
        vals_to_search = [host_field.get(part) for part in search_in]
        vals_to_search = ['' if val is None else val for val in vals_to_search]
        for val in vals_to_search:
            val_to_search = val
            if not case_sensitive:
                val_to_search = val.casefold()
            if match_exactly:
                if search_term == val_to_search:
                    filtered_hostfields.append(host_field)
                    break
                else:
                    continue
            else:
                if search_term in val_to_search:
                    filtered_hostfields.append(host_field)
                    break

    return filtered_hostfields


def dict_to_formatted_string(dictionary: Union[Dict, List]) -> str:
    """
    Return dictionary as clean string for war room output.

    Parameters
    ----------
    dictionary : dict | list
        The dictionary or list to format as a string.

    Returns
    -------
    str
        Clean string version of a dictionary

    Examples
    --------
    >>> example_dict = {'again': 'FsoD',
    ...                 'church': {'go': 'pArcB', 'month': '2009-08-11 16:42:51'},
    ...                 'production': 5507,
    ...                 'so': [9350, 'awzn', 7105, 'mMRxc']}
    >>> dict_to_formatted_string(example_dict)
    'again: FsoD, church: {go: pArcB, month: 2009-08-11 16:42:51}, production: 5507, so: [9350, awzn, 7105, mMRxc]'
    """
    return json.dumps(dictionary).lstrip('{').rstrip('}').replace('\'', '').replace('\"', '')


def format_policies_data(data: Dict) -> List:
    """
    Return policies formatted to Demisto standards.

    Parameters
    ----------
    data : dict
        The data returned from making API call to Forescout Web API policies endpoint.

    Returns
    -------
    list
        Formatted Policies
    """
    formatted_policies = []
    policies = data.get('policies', [])
    for policy in policies:
        formatted_policy = {
            'ID': str(policy.get('policyId')),
            'Name': policy.get('name'),
            'Description': policy.get('description')
        }
        formatted_rules = []
        rules = policy.get('rules', [])
        for rule in rules:
            formatted_rule = {
                'ID': str(rule.get('ruleId')),
                'Name': rule.get('name'),
                'Description': rule.get('description')
            }
            formatted_rules.append(formatted_rule)
        formatted_policy['Rule'] = formatted_rules
        formatted_policies.append(formatted_policy)
    return formatted_policies


def create_web_api_headers() -> Dict:
    """
    Update JWT if it has expired and return headers object that formats to Forescout Web API expectations

    Returns
    -------
    dict
        Headers object for the Forescout Web API calls
    """
    web_api_login()
    headers = {
        'Authorization': WEB_AUTH,
        'Accept': 'application/hal+json'
    }
    return headers


def web_api_login():
    """
    Get a JWT (Javascript Web Token) for authorization in calls to Web API
    """
    global LAST_JWT_FETCH
    global WEB_AUTH
    if not LAST_JWT_FETCH or datetime.now(UTC) >= LAST_JWT_FETCH + JWT_VALIDITY_TIME:
        url_suffix = '/api/login'
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        params = {'username': WEB_API_USERNAME, 'password': WEB_API_PASSWORD}
        response = http_request('POST', url_suffix, headers=headers, params=params, resp_type='response')
        fetch_time = parsedate(response.headers.get('Date', ''))
        WEB_AUTH = response.text
        LAST_JWT_FETCH = fetch_time


def http_request(method: str, url_suffix: str, full_url: str = None, headers: Dict = None,
                 auth: Tuple = None, params: Dict = None, data: Dict = None, files: Dict = None,
                 timeout: float = HTTP_TIMEOUT, resp_type: str = 'json') -> Any:
    """
    A wrapper for requests lib to send our requests and handle requests
    and responses better

    Parameters
    ----------
    method : str
        HTTP method, e.g. 'GET', 'POST' ... etc.
    url_suffix : str
        API endpoint.
    full_url : str
        Bypasses the use of BASE_URL + url_suffix. Useful if there is a need to
        make a request to an address outside of the scope of the integration
        API.
    headers : dict
        Headers to send in the request.
    auth : tuple
        Auth tuple to enable Basic/Digest/Custom HTTP Auth.
    params : dict
        URL parameters.
    data : dict
        Data to be sent in a 'POST' request.
    files : dict
        File data to be sent in a 'POST' request.
    timeout : int
        The amount of time in seconds a Request will wait for a client to
        establish a connection to a remote machine.
    resp_type : str
        Determines what to return from having made the HTTP request. The default
        is 'json'. Other options are 'text', 'content' or 'response' if the user
        would like the full response object returned.

    Returns
    -------
    dict | str | bytes | obj
        Response JSON from having made the request.
    """
    try:
        address = full_url if full_url else BASE_URL + url_suffix
        res = requests.request(
            method,
            address,
            verify=USE_SSL,
            params=params,
            data=data,
            files=files,
            headers=headers,
            auth=auth,  # type: ignore[arg-type]
            timeout=timeout
        )

        # Handle error responses gracefully
        if res.status_code not in {200, 304}:
            err_msg = 'Error in Forescout Integration API call [{}] - {}'.format(res.status_code, res.reason)
            try:
                # Try to parse json error response
                res_json = res.json()
                message = res_json.get('message')
                if message.endswith(' See log for more details.'):
                    message = message.replace(' See log for more details.', '')
                err_msg += '\n{}'.format(message)
                return_error(err_msg)
            except json.decoder.JSONDecodeError:
                if res.status_code in {400, 401, 501}:
                    # Try to parse xml error response
                    resp_xml = ET_PHONE_HOME.fromstring(res.content)
                    codes = [child.text for child in resp_xml.iter() if child.tag == 'CODE']
                    messages = [child.text for child in resp_xml.iter() if child.tag == 'MESSAGE']
                    err_msg += ''.join([f'\n{code}: {msg}' for code, msg in zip(codes, messages)])
                return_error(err_msg)

        resp_type = resp_type.casefold()
        try:
            if resp_type == 'json':
                return res.json()
            elif resp_type == 'text':
                return res.text
            elif resp_type == 'content':
                return res.content
            else:
                return res
        except json.decoder.JSONDecodeError:
            return_error(f'Failed to parse json object from response: {res.content!r}')

    except requests.exceptions.ConnectTimeout:
        err_msg = 'Connection Timeout Error - potential reasons may be that the Server URL parameter' \
                  ' is incorrect or that the Server is not accessible from your host.'
        return_error(err_msg)
    except requests.exceptions.SSLError:
        err_msg = 'SSL Certificate Verification Failed - try selecting \'Trust any certificate\' in' \
                  ' the integration configuration.'
        return_error(err_msg)
    except requests.exceptions.ProxyError:
        err_msg = 'Proxy Error - if \'Use system proxy\' in the integration configuration has been' \
                  ' selected, try deselecting it.'
        return_error(err_msg)
    except requests.exceptions.ConnectionError as e:
        # Get originating Exception in Exception chain
        while '__context__' in dir(e) and e.__context__:
            e = cast(Any, e.__context__)

        error_class = str(e.__class__)
        err_type = '<' + error_class[error_class.find('\'') + 1: error_class.rfind('\'')] + '>'
        err_msg = f'\nERRTYPE: {err_type}\nERRNO: [{e.errno}]\nMESSAGE: {e.strerror}\n' \
                  f'ADVICE: Check that the Server URL parameter is correct and that you' \
                  f' have access to the Server from your host.'
        return_error(err_msg)


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs API calls to Forescout Web API and DEX that require proper authentication
    """
    if WEB_API_USERNAME and WEB_API_PASSWORD:
        get_hosts({})
    if DEX_USERNAME and DEX_PASSWORD and DEX_ACCOUNT:
        update_lists({'update_type': 'add_list_values'})
    demisto.results('ok')


def get_host(args):
    fields = args.get('fields', '')
    ip = args.get('ip', '')
    mac = args.get('mac', '')
    id = args.get('id', '')
    url_suffix = '/api/hosts/'
    if not (ip or mac or id):
        err_msg = 'One of the command arguments, \'ip\', \'mac\' or \'id\' must be entered in order to identify the ' \
                  'endpoint to retrieve. '
        return_error(err_msg)

    if ip:
        # API endpoint format - https://{EM.IP}/api/hosts/ip/{ipv4}?fields={prop},..,{prop_n}
        url_suffix += 'ip/' + ip
    elif mac:
        # API endpoint format - https://{EM.IP}/api/hosts/mac/{mac}?fields={prop},..,{prop_n}
        url_suffix += 'mac/' + mac
    elif id:
        # API endpoint format - https://{EM.IP}/api/hosts/{obj_ID}?fields={prop},..,{prop_n}
        url_suffix += id

    params = {'fields': fields} if fields != '' else None
    headers = create_web_api_headers()
    response_data = http_request('GET', url_suffix, headers=headers, params=params, resp_type='json')
    return response_data


def get_host_command():
    check_web_api_credentials()
    args = demisto.args()
    ip = args.get('ip', '')
    mac = args.get('mac', '')
    id = args.get('id', '')
    identifier = 'IP=' + ip if ip else ('MAC=' + mac if mac else 'ID=' + id)
    requested_fields = argToList(args.get('fields', ''))
    data = get_host(args)
    host = data.get('host', {})
    fields = host.get('fields', {})

    included_fields = {HOSTFIELDS_TO_INCLUDE.get(key, key): val for key, val in fields.items()}
    for key, val in included_fields.items():
        if isinstance(val, list):
            new_val = [item.get('value') for item in val]
            included_fields[key] = new_val
        else:
            included_fields[key] = val.get('value')

    if not requested_fields:
        for key in list(included_fields.keys()):
            if key not in HOSTFIELDS_TO_INCLUDE.values():
                del included_fields[key]

    included_fields_readable = {}
    for key, val in included_fields.items():
        included_fields_readable[key] = dict_to_formatted_string(val) if isinstance(val, (dict, list)) else val

    content = {
        'ID': str(host.get('id')),
        'IPAddress': host.get('ip', ''),
        'MACAddress': host.get('mac', ''),
        **included_fields
    }

    # Construct endpoint object from API data according to Demisto conventions
    endpoint = {
        'IPAddress': host.get('ip', ''),
        'MACAddress': host.get('mac', '')
    }
    dhcp_server = fields.get('dhcp_server', {}).get('value')
    if dhcp_server:
        endpoint['DHCPServer'] = dhcp_server
    hostname = fields.get('hostname', {}).get('value')
    nbt_host = fields.get('nbthost', {}).get('value')
    hostname = hostname if hostname else nbt_host
    if hostname:
        endpoint['Hostname'] = hostname
    os = fields.get('os_classification', {}).get('value')
    if os:
        endpoint['OS'] = os
    vendor_and_model = fields.get('vendor_classification', {}).get('value')
    if vendor_and_model:
        endpoint['Model'] = vendor_and_model
    domain = fields.get('nbtdomain', {}).get('value')
    if domain:
        endpoint['Domain'] = domain

    human_readable_content = deepcopy(content)
    human_readable_content.update(included_fields_readable)

    context = {
        'Forescout.Host(val.ID && val.ID === obj.ID)': content,
        'Endpoint(val.ID && val.ID === obj.ID)': endpoint
    }

    title = 'Endpoint Details for {}'.format(identifier) if identifier else 'Endpoint Details'
    human_readable = tableToMarkdown(title, human_readable_content, removeNull=True)
    return_outputs(readable_output=human_readable, outputs=context, raw_response=data)


def get_hosts(args={}):
    url_suffix = '/api/hosts'
    headers = create_web_api_headers()
    rule_ids = args.get('rule_ids')
    fields = args.get('fields')
    if rule_ids and fields:
        url_suffix += '?matchRuleId=' + rule_ids + '&' + fields
    elif rule_ids:
        url_suffix += '?matchRuleId=' + rule_ids
    elif fields:
        url_suffix += '?' + fields
    response_data = http_request('GET', url_suffix, headers=headers, resp_type='json')
    return response_data


def get_hosts_command():
    check_web_api_credentials()
    args = demisto.args()
    response_data = get_hosts(args)
    content = [
        {
            'ID': str(x.get('hostId')),
            'IPAddress': x.get('ip', ''),
            'MACAddress': x.get('mac', '')
        } for x in response_data.get('hosts', [])
    ]
    endpoints = [
        {
            'IPAddress': x.get('ip', ''),
            'MACAddress': x.get('mac', '')
        } for x in response_data.get('hosts', [])
    ]
    context = {
        'Forescout.Host(val.ID && val.ID === obj.ID)': content,
        'Endpoint(val.ID && val.ID === obj.ID)': endpoints
    }
    title = 'Active Endpoints'
    human_readable = tableToMarkdown(title, content, removeNull=True)
    if not content:
        demisto.results('No hosts found for the specified filters.')
    else:
        return_outputs(readable_output=human_readable, outputs=context, raw_response=response_data)


def get_host_fields():
    url_suffix = '/api/hostfields'
    headers = create_web_api_headers()
    response_data = http_request('GET', url_suffix, headers=headers, resp_type='json')
    return response_data


def get_host_fields_command():
    check_web_api_credentials()
    args = demisto.args()
    data = get_host_fields()
    filtered_data = filter_hostfields_data(args, data)
    if not filtered_data:
        demisto.results('No host fields matched the specified filters.')
    else:
        content = [{key.title(): val for key, val in x.items()} for x in filtered_data]
        context = {'Forescout.HostField': content}
        title = 'Index of Host Fields'
        table_headers = ['Label', 'Name', 'Description', 'Type']
        human_readable = tableToMarkdown(title, content, headers=table_headers, removeNull=True)
        return_outputs(readable_output=human_readable, outputs=context, raw_response=data)


def get_policies():
    url_suffix = '/api/policies'
    headers = create_web_api_headers()
    response_data = http_request('GET', url_suffix, headers=headers, resp_type='json')
    return response_data


def get_policies_command():
    check_web_api_credentials()
    data = get_policies()
    content = format_policies_data(data)
    readable_content = deepcopy(content)
    for policy in readable_content:
        readable_rules = []
        for rule in policy.get('Rule', []):
            readable_rules.append(dict_to_formatted_string(rule))
        policy['Rule'] = readable_rules
    context = {'Forescout.Policy(val.ID && val.ID === obj.ID)': content}
    title = 'Forescout Policies'
    human_readable = tableToMarkdown(title, readable_content, removeNull=True)
    return_outputs(readable_output=human_readable, outputs=context, raw_response=data)


def update_lists(args={}):
    update_type = args.get('update_type', '')
    list_names = argToList(args.get('list_names', ''))
    values = ':'.join(argToList(args.get('values', '')))
    if values:
        lists = '&'.join([list_name + '=' + values for list_name in list_names])
    else:
        lists = '&'.join(list_names)
    req_body = create_update_lists_request_body(update_type, lists)
    data = ET_PHONE_HOME.tostring(req_body, encoding='UTF-8', method='xml')
    url_suffix = '/fsapi/niCore/Lists'
    resp_content = http_request('POST', url_suffix, headers=DEX_HEADERS, auth=DEX_AUTH, data=data, resp_type='content')
    return resp_content


def update_lists_command():
    check_dex_credentials()
    args = demisto.args()
    response_content = update_lists(args)
    resp_xml = ET_PHONE_HOME.fromstring(response_content)
    msg_list = [child.text for child in resp_xml.iter() if child.tag == 'MESSAGE']
    if len(msg_list) >= 1 and msg_list[0] is not None:
        msg = msg_list[0]
        msg = msg.replace('[', '').replace(']', '')
    else:
        err_msg = 'The response from Forescout could not be parsed correctly. It is uncertain if the list updates ' \
                  'were successfully executed.'
        return_error(err_msg)
    demisto.results(msg)


def update_host_fields(args={}):
    host_ip = args.get('host_ip', '')
    update_type = args.get('update_type', '')
    field = args.get('field', '')
    value = args.get('value', '')
    fields_json = args.get('fields_json', '')
    req_body = create_update_hostfields_request_body(host_ip, update_type, field, value, fields_json)
    data = ET_PHONE_HOME.tostring(req_body, encoding='UTF-8', method='xml')
    url_suffix = '/fsapi/niCore/Hosts'
    resp_content = http_request('POST', url_suffix, headers=DEX_HEADERS, auth=DEX_AUTH, data=data, resp_type='content')
    return resp_content


def update_host_fields_command():
    check_dex_credentials()
    args = demisto.args()
    update_type = args.get('update_type', '')
    field = args.get('field', '')
    host_ip = args.get('host_ip', '')
    fields_json = args.get('fields_json', '{}')
    try:
        fields_json_dict = json.loads(fields_json)
    except json.decoder.JSONDecodeError:
        return_error('Failed to parse \'fields_json\' command argument - invalid JSON format.')

    # Because the API has an error and says it deletes multiple things when it only deletes one
    # have to take care of it behind the curtains
    if update_type == 'delete':
        temp_args = {'update_type': update_type, 'host_ip': host_ip}
        for key, val in fields_json_dict.items():
            temp_args['fields_json'] = json.dumps({key: val})
            update_host_fields(temp_args)
        if field:
            temp_args['fields_json'] = json.dumps({field: ''})
            update_host_fields(temp_args)
        temp_args['field'] = ''
        update_host_fields(args)  # Takes care of composite_field

    response_content = update_host_fields(args)

    resp_xml = ET_PHONE_HOME.fromstring(response_content)
    msg_list = [child.text for child in resp_xml.iter() if child.tag == 'MESSAGE']
    if len(msg_list) >= 1 and msg_list[0] is not None:
        msg = msg_list[0]
        msg = msg.replace('[', '').replace(']', '')
    else:
        err_msg = 'The response from Forescout could not be parsed correctly. It is uncertain if the host fields ' \
                  'were successfully updated.'
        return_error(err_msg)
    demisto.results(msg)


''' COMMANDS MANAGER / SWITCH PANEL '''

COMMANDS = {
    'test-module': test_module,
    'forescout-get-host': get_host_command,
    'forescout-get-hosts': get_hosts_command,
    'forescout-get-host-fields': get_host_fields_command,
    'forescout-get-policies': get_policies_command,
    'forescout-update-lists': update_lists_command,
    'forescout-update-host-fields': update_host_fields_command
}

''' EXECUTION '''


def main():
    """Main execution block"""

    try:
        ''' SETUP '''

        if not ((WEB_API_USERNAME and WEB_API_PASSWORD) or (DEX_USERNAME and DEX_PASSWORD)):
            err_msg = 'The username and password for at least one of the \'Data Exchange (DEX)\' or the \'Web API\' ' \
                      'credentials are required though it is advisable to enter both in order for the integration to' \
                      ' be fully functional.'
            return_error(err_msg)

        if (DEX_USERNAME and DEX_PASSWORD) and not DEX_ACCOUNT:
            err_msg = 'When entering your \'Data Exchange (DEX)\' credentials, the \'Data Exchange (DEX) Account\' ' \
                      'configuration parameter is also required. For information on the correct value to enter here' \
                      ' - see Detailed Instructions (?).'
            return_error(err_msg)

        # Remove proxy if not set to true in params
        handle_proxy()

        cmd_name = demisto.command()
        LOG('Command being called is {}'.format(cmd_name))

        if cmd_name in COMMANDS.keys():
            COMMANDS[cmd_name]()

    except Exception as e:
        return_error(str(e))


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
