import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
from typing import Dict, List, Tuple, Any, Union
import xml.etree.ElementTree as ET_PHONE_HOME
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from dateutil.parser import parse as parsedate

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

PARAMS = demisto.params()

CREDENTIALS = PARAMS.get('credentials', {})
USERNAME = CREDENTIALS.get('identifier')
PASSWORD = CREDENTIALS.get('password')

DEX_CREDENTIALS = PARAMS.get('dex_credentials', {})
DEX_USERNAME = DEX_CREDENTIALS.get('identifier')
DEX_USERNAME = DEX_USERNAME if DEX_USERNAME != '' else USERNAME
DEX_PASSWORD = DEX_CREDENTIALS.get('password')
DEX_PASSWORD = DEX_PASSWORD if DEX_PASSWORD != '' else PASSWORD
DEX_ACCOUNT = PARAMS.get('dex_account')
# Remove trailing slash to prevent wrong URL path to service
BASE_URL = PARAMS.get('url', '').strip().rstrip('/')
# Should we use SSL
USE_SSL = not PARAMS.get('insecure', False)
DEX_HEADERS = {
    'Content-Type': 'application/xml',
    'Accept': 'application/xml'
}
DEX_AUTH = (DEX_USERNAME + '@' + DEX_ACCOUNT, DEX_PASSWORD)
AUTH = ''
LAST_JWT_FETCH = None
# Default JWT validity time set in Forescout Web API
JWT_VALIDITY_TIME = timedelta(minutes=5)
# Host fields to be included in output of get_host_command
HOSTFIELDS_TO_INCLUDE = {
    'os_classification': 'OSClassification',
    'classification_source_os': 'ClassificationSourceOS',
    'onsite': 'Onsite',
    'access_ip': 'AccessIP',
    'mac': 'MACAddress',
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
    '_times': 'Time',
    'macs': 'MAC',
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


def create_update_hostproperties_request_body(host_ip: str, update_type: str,
                                              properties: str, composite_property: str) -> ET_PHONE_HOME.Element:
    """
    Create XML request body formatted to DEX expectations

    Parameters
    ----------
    host_ip : str
        IP address of the target host.
    update_type : str
        The type of update to execute.
    properties : str
        The property names and associated values to update the property with.

    Returns
    -------
        XML Request Body Element
    """
    root = ET_PHONE_HOME.Element('FSAPI', attrib={'TYPE': 'request', 'API_VERSION': '2.0'})
    # tree = ET_PHONE_HOME.ElementTree(root)
    transaction = ET_PHONE_HOME.SubElement(root, 'TRANSACTION', attrib={'TYPE': update_type})
    if update_type == 'update':
        ET_PHONE_HOME.SubElement(transaction, 'OPTIONS', attrib={'CREATE_NEW_HOST': 'false'})

    # if update_type in {'update', 'delete'}:
    ET_PHONE_HOME.SubElement(transaction, 'HOST_KEY', attrib={'NAME': 'ip', 'VALUE': host_ip})
    props_xml = ET_PHONE_HOME.SubElement(transaction, 'PROPERTIES')
    prop_val_pairs = properties.split('&') if properties else []
    for pair in prop_val_pairs:
        prop, *value = pair.split('=')
        prop_xml = ET_PHONE_HOME.SubElement(props_xml, 'PROPERTY', attrib={'NAME': prop})
        if update_type != 'delete' and value:
            list_of_vals = '='.join(value).split(':')
            for val in list_of_vals:
                val_xml = ET_PHONE_HOME.SubElement(prop_xml, 'VALUE')
                val_xml.text = val
    if composite_property:
        composite_property_dict = json.loads(composite_property)
        table_property_name = list(composite_property_dict.keys())[0]
        table_property_xml = ET_PHONE_HOME.SubElement(props_xml, 'TABLE_PROPERTY',
                                                      attrib={'NAME': table_property_name})
        if update_type == 'update':
            values = composite_property_dict.get(table_property_name)
            if isinstance(values, list):

                for row in values:
                    row_xml = ET_PHONE_HOME.SubElement(table_property_xml, 'ROW')

                    for key, val in row.items():
                        key_xml = ET_PHONE_HOME.SubElement(row_xml, 'CPROPERTY', attrib={'NAME': key})

                        if isinstance(val, list):
                            for value in val:
                                value_xml = ET_PHONE_HOME.SubElement(key_xml, 'CVALUE')
                                value_xml.text = value

                        else:
                            value_xml = ET_PHONE_HOME.SubElement(key_xml, 'CVALUE')
                            value_xml.text = val
            else:
                row_xml = ET_PHONE_HOME.SubElement(table_property_xml, 'ROW')
                for key, val in values.items():
                    key_xml = ET_PHONE_HOME.SubElement(row_xml, 'CPROPERTY', attrib={'NAME': key})
                    if isinstance(val, list):
                        for value in val:
                            value_xml = ET_PHONE_HOME.SubElement(key_xml, 'CVALUE')
                            value_xml.text = value
                    else:
                        value_xml = ET_PHONE_HOME.SubElement(key_xml, 'CVALUE')
                        value_xml.text = val

    return root


def filter_hostfields_data(args: Dict, data: Dict) -> List:
    """
    Filter hostfields data by get_hostfields_command arguments.

    Parameters
    ----------
    args : dict
        The get_hostfields_command arguments.
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
        # Still check to see if should filter host properties by their type
        if host_field_type == 'all_types':
            return host_fields
        else:
            host_field_types = argToList(host_field_type)
            filtered_hostfields = []
            for host_field in host_fields:
                if host_field.get('type') in host_field_types:
                    filtered_hostfields.append(host_field)
            return filtered_hostfields
    case_sensitive = args.get('case_sensitive', 'False')
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
            'ID': policy.get('policyId'),
            'Name': policy.get('name'),
            'Description': policy.get('description')
        }
        formatted_rules = []
        rules = policy.get('rules', [])
        for rule in rules:
            formatted_rule = {
                'ID': rule.get('ruleId'),
                'Name': rule.get('name'),
                'Description': rule.get('description')
            }
            formatted_rules.append(formatted_rule)
        formatted_policy['Rule'] = formatted_rules
        formatted_policies.append(formatted_policy)
    return formatted_policies


def create_web_api_headers(entity_tag: str = '') -> Dict:
    """
    Return headers object that formats to Forescout Web API expectations and takes
    into account if an entity tag exists for a request to an endpoint.

    Parameters
    ----------
    entity_tag : str
        Entity tag to include in the headers if not None.

    Returns
    -------
    dict
        Headers object for the Forescout Web API calls
    """
    headers = {
        'Authorization': AUTH,
        'Accept': 'application/hal+json'
    }
    return headers


def login():
    global LAST_JWT_FETCH
    global AUTH
    if not LAST_JWT_FETCH or datetime.now(timezone.utc) >= LAST_JWT_FETCH + JWT_VALIDITY_TIME:
        url_suffix = '/api/login'
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        params = {'username': USERNAME, 'password': PASSWORD}
        response = http_request('POST', url_suffix, headers=headers, params=params, resp_type='response')
        fetch_time = parsedate(response.headers.get('Date', ''))
        AUTH = response.text
        LAST_JWT_FETCH = fetch_time


def http_request(method: str, url_suffix: str, full_url: str = None, headers: Dict = None, auth: Tuple = None,
                 params: Dict = None, data: Dict = None, files: Dict = None, resp_type: str = 'json') -> Any:
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
            auth=auth
        )

        # Handle error responses gracefully
        if res.status_code not in {200, 201, 304}:
            err_msg = 'Error in Forescout Integration API call [{}] - {}'.format(res.status_code, res.reason)
            try:
                # Try to parse json error response
                res_json = res.json()
                err_msg += '\n{}'.format(res_json.get('message'))
                return_error(err_msg)
            except json.decoder.JSONDecodeError:
                if res.status_code in {400, 401, 501}:
                    # Try to parse xml error response
                    resp_xml = ET_PHONE_HOME.fromstring(res.content)
                    demisto.info(str(res.content))
                    codes = [child.text for child in resp_xml.iter() if child.tag == 'CODE']
                    messages = [child.text for child in resp_xml.iter() if child.tag == 'MESSAGE']
                    err_msg += ''.join([f'\n{code}: {msg}' for code, msg in zip(codes, messages)])
                return_error(err_msg)

        resp_type = resp_type.casefold()
        if resp_type == 'json':
            return res.json()
        elif resp_type == 'text':
            return res.text
        elif resp_type == 'content':
            return res.content
        else:
            return res

    except requests.exceptions.ConnectionError:
        err_msg = 'Connection Error - Check that the Server URL parameter is correct.'
        return_error(err_msg)


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request that requires proper authentication
    """
    login()
    demisto.results('ok')


def get_host(args):
    identifier = args.get('identifier', '')
    fields = args.get('fields', '')
    login()
    url_suffix = '/api/hosts/'
    id_type, *ident = identifier.split('=')
    id_type = id_type.casefold()
    if len(ident) != 1 or id_type not in {'id', 'ip', 'mac'}:
        err_msg = 'The entered endpoint identifier should be prefaced by the identifier type,' \
            ' (\'ip\', \'mac\', or \'id\') followed by \'=\' and the actual ' \
            'identifier, e.g. \'ip=123.123.123.123\'.'  # disable-secrets-detection
        raise ValueError(err_msg)

    if id_type == 'ip':
        # API endpoint format - https://{EM.IP}/api/hosts/ip/{ipv4}?fields={prop},..,{prop_n}
        url_suffix += 'ip/'
    elif id_type == 'mac':
        # API endpoint format - https://{EM.IP}/api/hosts/mac/{mac}?fields={prop},..,{prop_n}
        url_suffix += 'mac/'
    # if id_type == 'id' don't change url_suffix -it's already in desired format as shown below
    # API endpoint format - https://{EM.IP}/api/hosts/{obj_ID}?fields={prop},..,{prop_n}

    url_suffix += '='.join(ident)
    params = {'fields': fields} if fields != '' else None
    headers = {
        'Authorization': AUTH,
        'Accept': 'application/hal+json'
    }
    entity_tag = ETAGS.get('get_host')
    if entity_tag:
        headers['If-None-Match'] = entity_tag
    response = http_request('GET', url_suffix, headers=headers, params=params, resp_type='response')
    return response


def get_host_command():
    args = demisto.args()
    identifier = args.get('identifier', '')
    requested_fields = argToList(args.get('fields', ''))
    response = get_host(args)
    data = response.json()
    host = data.get('host', {})
    fields = host.get('fields', {})

    if requested_fields and set(requested_fields).issubset(HOSTFIELDS_TO_INCLUDE.keys()):
        included_fields = {
            HOSTFIELDS_TO_INCLUDE.get(key): val for key, val in fields.items() if key in HOSTFIELDS_TO_INCLUDE.keys()
        }
        included_fields_readable = {
            HOSTFIELDS_TO_INCLUDE.get(key): dict_to_formatted_string(val)
            for key, val in fields.items() if key in HOSTFIELDS_TO_INCLUDE.keys()
        }
    else:
        included_fields = fields
        included_fields_readable = {key: dict_to_formatted_string(val) for key, val in fields.items()}

    content = {
        'ID': host.get('id'),
        'IP': host.get('ip'),
        'MAC': host.get('mac'),
        'EndpointURL': data.get('_links', {}).get('self', {}).get('href'),
        'Field': included_fields
    }

    human_readable_content = deepcopy(content)
    human_readable_content['Field'] = included_fields_readable

    context = {'Forescout.Host(val.ID && val.ID === obj.ID)': content}

    title = 'Endpoint Details for {}'.format(identifier) if identifier else 'Endpoint Details'
    human_readable = tableToMarkdown(title, human_readable_content, removeNull=True)
    return_outputs(readable_output=human_readable, outputs=context, raw_response=data)


def get_hosts(args={}):
    login()
    url_suffix = '/api/hosts'
    headers = {
        'Authorization': AUTH,
        'Accept': 'application/hal+json'
    }
    entity_tag = ETAGS.get('get_hosts')
    if entity_tag:
        headers['If-None-Match'] = entity_tag
    params: Dict = {}
    rule_ids = args.get('rule_ids')
    properties = args.get('properties')
    if rule_ids and properties:
        url_suffix += '?matchRuleId=' + rule_ids + '&' + properties
    elif rule_ids:
        url_suffix += '?matchRuleId=' + rule_ids
    elif properties:
        url_suffix += '?' + properties
    response = http_request('GET', url_suffix, headers=headers, params=params, resp_type='response', catch_500=True)
    return response


def get_hosts_command():
    args = demisto.args()
    response = get_hosts(args).json()
    content = [
        {
            'ID': x.get('hostId'),
            'IP': x.get('ip'),
            'MAC': x.get('mac'),
            'EndpointURL': x.get('_links', {}).get('self', {}).get('href')
        } for x in response.get('hosts', [])
    ]
    context = {'Forescout.Host(val.ID && val.ID === obj.ID)': content}
    title = 'Active Endpoints'
    human_readable = tableToMarkdown(title, content, removeNull=True)
    return_outputs(readable_output=human_readable, outputs=context, raw_response=response)


def get_hostfields():
    login()
    url_suffix = '/api/hostfields'
    headers = {
        'Authorization': AUTH,
        'Accept': 'application/hal+json'
    }
    entity_tag = ETAGS.get('get_hosts')
    if entity_tag:
        headers['If-None-Match'] = entity_tag
    params: Dict = {}
    response = http_request('GET', url_suffix, headers=headers, params=params, resp_type='response')
    return response


def get_hostfields_command():
    args = demisto.args()
    response = get_hostfields()
    data = response.json()
    filtered_data = filter_hostfields_data(args, data)
    if not filtered_data:
        demisto.results('No hostfields matched the specified filters.')
    else:
        content = [{key.title(): val for key, val in x.items()} for x in filtered_data]
        context = {'Forescout.HostField': content}
        title = 'Index of Host Properties'
        human_readable = tableToMarkdown(title, content, removeNull=True)
        return_outputs(readable_output=human_readable, outputs=context, raw_response=data)


def get_policies():
    login()
    url_suffix = '/api/policies'
    entity_tag = ETAGS.get('get_policies', '')
    headers = create_web_api_headers(entity_tag)
    response = http_request('GET', url_suffix, headers=headers, resp_type='response')
    return response


def get_policies_command():
    response = get_policies()
    data = response.json()
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
    lists = args.get('lists', '')
    req_body = create_update_lists_request_body(update_type, lists)
    data = ET_PHONE_HOME.tostring(req_body, encoding='UTF-8', method='xml')
    url_suffix = '/fsapi/niCore/Lists'
    response = http_request('POST', url_suffix, headers=DEX_HEADERS, auth=DEX_AUTH, data=data, resp_type='response')
    return response


def update_lists_command():
    args = demisto.args()
    response = update_lists(args)
    resp_xml = ET_PHONE_HOME.fromstring(response.content)
    code = [child.text for child in resp_xml.iter() if child.tag == 'CODE'][0]
    msg = [child.text for child in resp_xml.iter() if child.tag == 'MESSAGE'][0]
    result_msg = f'{code}: {msg}'
    demisto.results(result_msg)


def update_host_properties(args={}):
    host_ip = args.get('host_ip', '')
    update_type = args.get('update_type', '')
    properties = args.get('properties', '')
    composite_property = args.get('composite_property', '').replace('\'', '"')
    req_body = create_update_hostproperties_request_body(host_ip, update_type, properties, composite_property)
    data = ET_PHONE_HOME.tostring(req_body, encoding='UTF-8', method='xml')
    url_suffix = '/fsapi/niCore/Hosts'
    response = http_request('POST', url_suffix, headers=DEX_HEADERS, auth=DEX_AUTH, data=data, resp_type='response')
    return response


def update_host_properties_command():
    args = demisto.args()
    update_type = args.get('update_type', '')
    properties = args.get('properties', '')
    response = update_host_properties(args)

    # Because the API has an error and says it deletes multiple things when it only deletes one
    # have to take care of it behind the curtains
    if update_type == 'delete':
        args_copy = deepcopy(args)
        args_copy['properties'] = ''
        update_host_properties(args_copy)  # Takes care of composite_property
        args_copy['composite_property'] = ''
        for prop in properties.split('&'):
            args_copy['properties'] = prop
            update_host_properties(args_copy)

    resp_xml = ET_PHONE_HOME.fromstring(response.content)
    code = [child.text for child in resp_xml.iter() if child.tag == 'CODE'][0]
    msg = [child.text for child in resp_xml.iter() if child.tag == 'MESSAGE'][0]
    result_msg = f'{code}: {msg}'
    demisto.results(result_msg)


''' COMMANDS MANAGER / SWITCH PANEL '''

COMMANDS = {
    'test-module': test_module,
    'forescout-get-host': get_host_command,
    'forescout-get-hosts': get_hosts_command,
    'forescout-get-hostfields': get_hostfields_command,
    'forescout-get-policies': get_policies_command,
    'forescout-update-lists': update_lists_command,
    'forescout-update-host-properties': update_host_properties_command
}

''' EXECUTION '''


def main():
    """Main execution block"""

    try:
        # Remove proxy if not set to true in params
        handle_proxy()

        cmd_name = demisto.command()
        LOG('Command being called is {}'.format((cmd_name)))

        if cmd_name in COMMANDS.keys():
            COMMANDS[cmd_name]()

    # Log exceptions
    except Exception as e:
        LOG(str(e))
        LOG.print_log()
        raise


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
