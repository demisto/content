import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
from datetime import datetime
import requests
import json
import uuid
from typing import Dict, List, Any, Optional

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS '''
if not demisto.params().get('port'):
    return_error('Set a port for the instance')

URL = demisto.params()['server'].rstrip('/:') + ':' + demisto.params().get('port') + '/api/'
API_KEY = str(demisto.params().get('key'))
USE_SSL = not demisto.params().get('insecure')

# determine a vsys or a device-group
VSYS = demisto.params().get('vsys')
DEVICE_GROUP = demisto.params().get('device_group')
# configuration check
if DEVICE_GROUP and VSYS:
    return_error('Cannot configure both vsys and Device group. Set vsys for firewall, set Device group for Panorama')
if not DEVICE_GROUP and not VSYS:
    return_error('Set vsys for firewall or Device group for Panorama')

# setting security xpath relevant to FW or panorama management
if DEVICE_GROUP:
    XPATH_SECURITY_RULES = "/config/devices/entry/device-group/entry[@name=\'" + DEVICE_GROUP + "\']/"
else:
    XPATH_SECURITY_RULES = "/config/devices/entry/vsys/entry[@name=\'" + VSYS + "\']/rulebase/security/rules/entry"

# setting objects xpath relevant to FW or panorama management
if DEVICE_GROUP:
    XPATH_OBJECTS = "/config/devices/entry/device-group/entry[@name=\'" + DEVICE_GROUP + "\']/"
else:
    XPATH_OBJECTS = "/config/devices/entry/vsys/entry[@name=\'" + VSYS + "\']/"

# Security rule arguments for output handling
SECURITY_RULE_ARGS = {
    'rulename': 'Name',
    'source': 'Source',
    'destination': 'Destination',
    'negate_source': 'NegateSource',
    'negate_destination': 'NegateDestination',
    'action': 'Action',
    'service': 'Service',
    'disable': 'Disabled',
    'application': 'Application',
    'source_user': 'SourceUser',
    'disable_server_response_inspection': 'DisableServerResponseInspection',
    'description': 'Description',
    'target': 'Target',
    'log_forwarding': 'LogForwarding'
}

PAN_OS_ERROR_DICT = {
    '1': 'Unknown command - The specific config or operational command is not recognized.',
    '2': 'Internal errors - Check with technical support when seeing these errors.',
    '3': 'Internal errors - Check with technical support when seeing these errors.',
    '4': 'Internal errors - Check with technical support when seeing these errors.',
    '5': 'Internal errors - Check with technical support when seeing these errors.',
    '6': 'Bad Xpath -The xpath specified in one or more attributes of the command is invalid.'
         'Check the API browser for proper xpath values.',
    '7': 'Object not present - Object specified by the xpath is not present. For example,'
         'entry[@name=value] where no object with name value is present.',
    '8': 'Object not unique - For commands that operate on a single object, the specified object is not unique.',
    '10': 'Reference count not zero - Object cannot be deleted as there are other objects that refer to it.'
          'For example, address object still in use in policy.',
    '11': 'Internal error - Check with technical support when seeing these errors.',
    '12': 'Invalid object - Xpath or element values provided are not complete.',
    '14': 'Operation not possible - Operation is allowed but not possible in this case.'
          'For example, moving a rule up one position when it is already at the top.',
    '15': 'Operation denied - Operation is allowed. For example, Admin not allowed to delete own account,'
          'Running a command that is not allowed on a passive device.',
    '16': 'Unauthorized -The API role does not have access rights to run this query.',
    '17': 'Invalid command -Invalid command or parameters.',
    '18': 'Malformed command - The XML is malformed.',
    # 19,20: success
    '21': 'Internal error - Check with technical support when seeing these errors.',
    '22': 'Session timed out - The session for this query timed out.'
}

''' HELPERS '''


def http_request(uri: str, method: str, headers: Dict = {},
                 body: Dict = {}, params: Dict = {}, files=None) -> Any:
    """
    Makes an API call with the given arguments
    """
    result = requests.request(
        method,
        uri,
        headers=headers,
        data=body,
        verify=USE_SSL,
        params=params,
        files=files
    )

    if result.status_code < 200 or result.status_code >= 300:
        return_error('Request Failed. with status: ' + str(result.status_code) + '. Reason is: ' + str(result.reason))

    # if pcap download
    if params.get('type') == 'export':
        return result
    json_result = json.loads(xml2json(result.text))

    # handle non success
    if json_result['response']['@status'] != 'success':
        if 'msg' in json_result['response'] and 'line' in json_result['response']['msg']:

            # catch non existing object error and display a meaningful message
            if json_result['response']['msg']['line'] == 'No such node':
                return_error(
                    'Object was not found, verify that the name is correct and that the instance was committed.')

            # catch non valid jobID errors and display a meaningful message
            elif isinstance(json_result['response']['msg']['line'], str) and \
                    json_result['response']['msg']['line'].find('job') != -1 and \
                    json_result['response']['msg']['line'].find('not found') != -1:
                return_error('Invalid Job ID error: ' + json_result['response']['msg']['line'])

            # catch already at the top/bottom error for rules and return this as an entry.note
            elif str(json_result['response']['msg']['line']).find('already at the') != -1:
                demisto.results('Rule ' + str(json_result['response']['msg']['line']))
                sys.exit(0)

            # catch already registered ip tags and return this as an entry.note
            elif str(json_result['response']['msg']['line']).find('already exists, ignore') != -1:
                if isinstance(json_result['response']['msg']['line']['uid-response']['payload']['register']['entry'],
                              list):
                    ips = [o['@ip'] for o in
                           json_result['response']['msg']['line']['uid-response']['payload']['register']['entry']]
                else:
                    ips = json_result['response']['msg']['line']['uid-response']['payload']['register']['entry']['@ip']
                demisto.results(
                    'IP ' + str(ips) + ' already exist in the tag. All submitted IPs were not registered to the tag')
                sys.exit(0)

        if '@code' in json_result['response']:
            return_error(
                'Request Failed.\nStatus code: ' + str(json_result['response']['@code']) + '\nWith message: ' + str(
                    json_result['response']['msg']['line']))
        else:
            return_error('Request Failed.\n' + str(json_result['response']))

    # handle @code
    if 'response' in json_result and '@code' in json_result['response']:
        if json_result['response']['@code'] in PAN_OS_ERROR_DICT:
            return_error('Request Failed.\n' + PAN_OS_ERROR_DICT[json_result['response']['@code']])
        if json_result['response']['@code'] not in ['19', '20']:
            # error code non exist in dict and not of success
            if 'msg' in json_result['response']:
                return_error(
                    'Request Failed.\nStatus code: ' + str(json_result['response']['@code']) + '\nWith message: ' + str(
                        json_result['response']['msg']))
            else:
                return_error('Request Failed.\n' + str(json_result['response']))

    return json_result


def add_argument_list(arg: Any, field_name: str, member: Optional[bool]) -> str:
    member_stringify_list = ''
    if arg:
        for item in arg:
            member_stringify_list += '<member>' + item + '</member>'
        if field_name == 'member':
            return member_stringify_list
        elif member:
            return '<' + field_name + '>' + member_stringify_list + '</' + field_name + '>'
        else:
            return '<' + field_name + '>' + arg + '</' + field_name + '>'
    else:
        return ''


def add_argument(arg: Optional[str], field_name: str, member: bool) -> str:
    if arg:
        if member:
            return '<' + field_name + '><member>' + arg + '</member></' + field_name + '>'
        else:
            return '<' + field_name + '>' + arg + '</' + field_name + '>'
    else:
        return ''


def add_argument_open(arg: Optional[str], field_name: str, member: bool) -> str:
    if arg:
        if member:
            return '<' + field_name + '><member>' + arg + '</member></' + field_name + '>'
        else:
            return '<' + field_name + '>' + arg + '</' + field_name + '>'
    else:
        if member:
            return '<' + field_name + '><member>any</member></' + field_name + '>'
        else:
            return '<' + field_name + '>any</' + field_name + '>'


def add_argument_yes_no(arg: Optional[str], field_name: str, option: bool = False) -> str:
    if arg and arg == 'No':
        result = '<' + field_name + '>' + 'no' + '</' + field_name + '>'
    else:
        result = '<' + field_name + '>' + ('yes' if arg else 'no') + '</' + field_name + '>'

    if option:
        result = '<option>' + result + '</option>'

    return result


def add_argument_target(arg: Optional[str], field_name: str) -> str:
    if arg:
        return '<' + field_name + '>' + '<devices>' + '<entry name=\"' + arg + '\"/>' + '</devices>' + '</' + field_name + '>'
    else:
        return ''


def prepare_security_rule_params(api_action: str = None, rulename: str = None, source: str = None,
                                 destination: str = None, negate_source: str = None, negate_destination: str = None,
                                 action: str = None, service: str = None, disable: str = None, application: str = None,
                                 source_user: str = None, category: str = None, from_: str = None, to: str = None,
                                 description: str = None, target: str = None, log_forwarding: str = None,
                                 disable_server_response_inspection: str = None) -> Dict:
    rulename = rulename if rulename else ('demisto-' + (str(uuid.uuid4()))[:8])
    params = {
        'type': 'config',
        'action': api_action,
        'key': API_KEY,
        'element': add_argument_open(action, 'action', False)
        + add_argument_target(target, 'target')
        + add_argument_open(description, 'description', False)
        + add_argument_open(source, 'source', True)
        + add_argument_open(destination, 'destination', True)
        + add_argument_open(application, 'application', True)
        + add_argument_open(category, 'category', True)
        + add_argument_open(source_user, 'source-user', True)
        + add_argument_open(from_, 'from', True)  # default from will always be any
        + add_argument_open(to, 'to', True)  # default to will always be any
        + add_argument_open(service, 'service', True)
        + add_argument_yes_no(negate_source, 'negate-source')
        + add_argument_yes_no(negate_destination, 'negate-destination')
        + add_argument_yes_no(disable, 'disabled')
        + add_argument_yes_no(disable_server_response_inspection, 'disable-server-response-inspection', True)
        + add_argument(log_forwarding, 'log-setting', False)
    }
    if DEVICE_GROUP:
        if 'pre_post' not in demisto.args():
            return_error('Please provide the pre_post argument when configuring a security rule in Panorama instance.')
        else:
            params['xpath'] = XPATH_SECURITY_RULES + demisto.args()[
                'pre_post'] + '/security/rules/entry' + '[@name=\'' + rulename + '\']'
    else:
        params['xpath'] = XPATH_SECURITY_RULES + '[@name=\'' + rulename + '\']'

    return params


''' FUNCTIONS'''


def panorama_test():
    """
    test module
    """
    params = {
        'type': 'op',
        'cmd': '<show><system><info></info></system></show>',
        'key': API_KEY
    }

    http_request(
        URL,
        'GET',
        params=params
    )

    demisto.results('ok')


@logger
def panorama_command():
    """
    Executes a command
    """
    params = {}
    params['key'] = API_KEY
    for arg in demisto.args().keys():
        params[arg] = demisto.args()[arg]

    result = http_request(
        URL,
        'POST',
        params=params
    )

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Command was executed successfully',
    })


@logger
def panorama_commit():
    params = {
        'type': 'commit',
        'cmd': '<commit></commit>',
        'key': API_KEY
    }
    result = http_request(
        URL,
        'POST',
        params=params
    )

    return result


def panorama_commit_command():
    """
    Commit and show message in warroom
    """
    result = panorama_commit()

    if 'result' in result['response']:
        # commit has been given a jobid
        commit_output = {
            'JobID': result['response']['result']['job'],
            'Status': 'Pending'
        }
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': result,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Commit:', commit_output, ['JobID', 'Status'], removeNull=True),
            'EntryContext': {
                "Panorama.Commit(val.JobID == obj.JobID)": commit_output
            }
        })
    else:
        # no changes to commit
        demisto.results(result['response']['msg'])


@logger
def panorama_commit_status():
    params = {
        'type': 'op',
        'cmd': '<show><jobs><id>' + demisto.args()['job_id'] + '</id></jobs></show>',
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params
    )

    return result


def panorama_commit_status_command():
    """
    Check jobID of commit status
    """
    result = panorama_commit_status()

    if result['response']['result']['job']['type'] != 'Commit':
        return_error('JobID given is not of a commit')

    commit_status_output = {'JobID': result['response']['result']['job']['id']}
    if result['response']['result']['job']['status'] == 'FIN':
        if result['response']['result']['job']['result'] == 'OK':
            commit_status_output['Status'] = 'Completed'
        else:
            # result['response']['job']['result'] == 'FAIL'
            commit_status_output['Status'] = 'Failed'
        commit_status_output['Details'] = result['response']['result']['job']['details']['line']

    if result['response']['result']['job']['status'] == 'ACT':
        if result['response']['result']['job']['result'] == 'PEND':
            commit_status_output['Status'] = 'Pending'

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Commit status:', commit_status_output, ['JobID', 'Status', 'Details'],
                                         removeNull=True),
        'EntryContext': {"Panorama.Commit(val.JobID == obj.JobID)": commit_status_output}
    })


@logger
def panorama_push_to_device_group():
    params = {
        'type': 'commit',
        'action': 'all',
        'cmd': '<commit-all><shared-policy><device-group><entry name=\"' + DEVICE_GROUP
               + '\"/></device-group></shared-policy></commit-all>',
        'key': API_KEY
    }
    result = http_request(
        URL,
        'POST',
        params=params
    )

    return result


def panorama_push_to_device_group_command():
    """
    Push Panorama configuration and show message in warroom
    """
    if not DEVICE_GROUP:
        return_error("The 'panorama-push-to-device-group' command is relevant for a Palo Alto Panorama instance.")

    result = panorama_push_to_device_group()
    if 'result' in result['response']:
        # commit has been given a jobid
        push_output = {
            'DeviceGroup': DEVICE_GROUP,
            'JobID': result['response']['result']['job'],
            'Status': 'Pending'
        }
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': result,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Push to Device Group:', push_output, ['JobID', 'Status'],
                                             removeNull=True),
            'EntryContext': {
                "Panorama.Push(val.JobID == obj.JobID)": push_output
            }
        })
    else:
        # no changes to commit
        demisto.results(result['response']['msg']['line'])


@logger
def panorama_push_status():
    params = {
        'type': 'op',
        'cmd': '<show><jobs><id>' + demisto.args()['job_id'] + '</id></jobs></show>',
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params
    )

    return result


def panorama_push_status_command():
    """
    Check jobID of push status
    """
    result = panorama_push_status()
    if result['response']['result']['job']['type'] != 'CommitAll':
        return_error('JobID given is not of a Push')

    push_status_output = {'JobID': result['response']['result']['job']['id']}
    if result['response']['result']['job']['status'] == 'FIN':
        if result['response']['result']['job']['result'] == 'OK':
            push_status_output['Status'] = 'Completed'
        else:
            # result['response']['job']['result'] == 'FAIL'
            push_status_output['Status'] = 'Failed'
        push_status_output['Details'] = result['response']['result']['job']['devices']['entry']['status']

    if result['response']['result']['job']['status'] == 'PEND':
        push_status_output['Status'] = 'Pending'

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Push to Device Group status:', push_status_output,
                                         ['JobID', 'Status', 'Details'], removeNull=True),
        'EntryContext': {"Panorama.Push(val.JobID == obj.JobID)": push_status_output}
    })


''' Addresses Commands '''


def prettify_addresses_arr(addresses_arr: list) -> List:
    pretty_addresses_arr = []
    for address in addresses_arr:
        pretty_address = {
            'Name': address['@name'],
        }
        if 'description' in address:
            pretty_address['Description'] = address['description']

        if 'ip-netmask' in address:
            pretty_address['IP_Netmask'] = address['ip-netmask']

        if 'ip-range' in address:
            pretty_address['IP_Range'] = address['ip-range']

        if 'fqdn' in address:
            pretty_address['FQDN'] = address['fqdn']

        pretty_addresses_arr.append(pretty_address)

    return pretty_addresses_arr


@logger
def panorama_list_addresses():
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "address/entry",
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params,
    )

    return result['response']['result']['entry']


def panorama_list_addresses_command():
    """
    Get all addresses
    """
    addresses_arr = panorama_list_addresses()
    addresses_output = prettify_addresses_arr(addresses_arr)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': addresses_arr,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Addresses:', addresses_output, ['Name', 'IP_Netmask', 'IP_Range', 'FQDN'],
                                         removeNull=True),
        'EntryContext': {
            "Panorama.Addresses(val.Name == obj.Name)": addresses_output
        }
    })


def prettify_address(address: Dict) -> Dict:
    pretty_address = {
        'Name': address['@name'],
    }
    if 'description' in address:
        pretty_address['Description'] = address['description']

    if 'ip-netmask' in address:
        pretty_address['IP_Netmask'] = address['ip-netmask']

    if 'ip-range' in address:
        pretty_address['IP_Range'] = address['ip-range']

    if 'fqdn' in address:
        pretty_address['FQDN'] = address['fqdn']

    return pretty_address


@logger
def panorama_get_address(address_name: Dict) -> Dict:
    params = {
        'action': 'show',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "address/entry[@name='" + address_name + "']",
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params,
    )

    return result['response']['result']['entry']


def panorama_get_address_command():
    """
    Get an address
    """
    address_name = demisto.args()['name']

    address = panorama_get_address(address_name)
    address_output = prettify_address(address)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': address,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Address:', address_output, ['Name', 'IP_Netmask', 'IP_Range', 'FQDN'],
                                         removeNull=True),
        'EntryContext': {
            "Panorama.Addresses(val.Name == obj.Name)": address_output
        }
    })


@logger
def panorama_create_address(address_name: str, fqdn: str = None, ip_netmask: str = None, ip_range: str = None,
                            description: str = None):
    params = {
        'action': 'set',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "address/entry[@name='" + address_name + "']",
        'key': API_KEY
    }

    params['element'] = (add_argument(fqdn, 'fqdn', False)
                         + add_argument(ip_netmask, 'ip-netmask', False)
                         + add_argument(ip_range, 'ip-range', False)
                         + add_argument(description, 'description', False))

    http_request(
        URL,
        'POST',
        params=params,
    )


def panorama_create_address_command():
    """
    Create an address object
    """
    address_name = demisto.args()['name']
    description = demisto.args().get('description')

    fqdn = demisto.args().get('fqdn')
    ip_netmask = demisto.args().get('ip_netmask')
    ip_range = demisto.args().get('ip_range')

    if not fqdn and not ip_netmask and not ip_range:
        return_error('Please specify exactly one of the following: fqdn, ip_netmask, ip_range')

    if (fqdn and ip_netmask) or (fqdn and ip_range) or (ip_netmask and ip_range):
        return_error('Please specify exactly one of the following: fqdn, ip_netmask, ip_range')

    address = panorama_create_address(address_name, fqdn, ip_netmask, ip_range, description)

    address_output = {'Name': address_name}
    if fqdn:
        address_output['FQDN'] = fqdn
    if ip_netmask:
        address_output['IP_Netmask'] = ip_netmask
    if ip_range:
        address_output['IP_Range'] = ip_range
    if description:
        address_output['Description'] = description

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': address,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Address was added successfully',
        'EntryContext': {
            "Panorama.Addresses(val.Name == obj.Name)": address_output
        }
    })


@logger
def panorama_delete_address(address_name: str):
    params = {
        'action': 'delete',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "address/entry[@name='" + address_name + "']",
        'element': "<entry name='" + address_name + "'></entry>",
        'key': API_KEY
    }
    result = http_request(
        URL,
        'POST',
        params=params,
    )

    return result


def panorama_delete_address_command():
    """
    Delete an address
    """
    address_name = demisto.args()['name']

    address = panorama_delete_address(address_name)
    address_output = {'Name': address_name}

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': address,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Address was deleted successfully',
        'EntryContext': {
            "Panorama.Addresses(val.Name == obj.Name)": address_output
        }
    })


''' Address Group Commands '''


def prettify_address_groups_arr(address_groups_arr: list) -> List:
    pretty_address_groups_arr = []
    for address_group in address_groups_arr:
        pretty_address_group = {
            'Name': address_group['@name'],
            'Type': 'static' if 'static' in address_group else 'dynamic',
        }
        if 'description' in address_group:
            pretty_address_group['Description'] = address_group['description']

        if pretty_address_group['Type'] == 'static':
            # static address groups can have empty lists
            if address_group['static']:
                pretty_address_group['Addresses'] = address_group['static']['member']
        else:
            pretty_address_group['Match'] = address_group['dynamic']['filter']

        pretty_address_groups_arr.append(pretty_address_group)

    return pretty_address_groups_arr


@logger
def panorama_list_address_groups():
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "address-group/entry",
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params,
    )

    return result['response']['result']['entry']


def panorama_list_address_groups_command():
    """
    Get all address groups
    """
    address_groups_arr = panorama_list_address_groups()
    address_groups_output = prettify_address_groups_arr(address_groups_arr)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': address_groups_arr,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Address groups:', address_groups_output,
                                         ['Name', 'Type', 'Addresses', 'Match', 'Description'], removeNull=True),
        'EntryContext': {
            "Panorama.AddressGroups(val.Name == obj.Name)": address_groups_output
        }
    })


def prettify_address_group(address_group: Dict) -> Dict:
    pretty_address_group = {
        'Name': address_group['@name'],
        'Type': 'static' if 'static' in address_group else 'dynamic',
    }

    if 'description' in address_group:
        pretty_address_group['Description'] = address_group['description']

    if pretty_address_group['Type'] == 'static':
        pretty_address_group['Addresses'] = address_group['static']['member']
    else:
        pretty_address_group['Match'] = address_group['dynamic']['filter']

    return pretty_address_group


@logger
def panorama_get_address_group(address_group_name: str):
    params = {
        'action': 'show',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "address-group/entry[@name='" + address_group_name + "']",
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params,
    )

    return result['response']['result']['entry']


def panorama_get_address_group_command():
    """
    Get an address group
    """
    address_group_name = demisto.args()['name']

    result = panorama_get_address_group(address_group_name)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Address group:', prettify_address_group(result),
                                         ['Name', 'Type', 'Addresses', 'Match', 'Description'], removeNull=True),
        'EntryContext': {
            "Panorama.AddressGroups(val.Name == obj.Name)": prettify_address_group(result)
        }
    })


@logger
def panorama_create_static_address_group(address_group_name: str, addresses: list, description: str = None):
    params = {
        'action': 'set',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "address-group/entry[@name='" + address_group_name + "']",
        'element': "<static>" + add_argument_list(addresses, 'member', True) + "</static>" + add_argument(description,
                                                                                                          'description',
                                                                                                          False),
        'key': API_KEY
    }
    result = http_request(
        URL,
        'POST',
        params=params,
    )
    return result


def panorama_create_dynamic_address_group(address_group_name: str, match: str, description: str = None):
    params = {
        'action': 'set',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "address-group/entry[@name='" + address_group_name + "']",
        'element': "<dynamic>" + add_argument(match, 'filter', False)
                   + "</dynamic>" + add_argument(description, 'description', False),
        'key': API_KEY
    }
    result = http_request(
        URL,
        'POST',
        params=params,
    )
    return result


def panorama_create_address_group_command():
    """
    Create an address group
    """
    address_group_name = demisto.args()['name']
    type_ = demisto.args()['type']
    description = demisto.args().get('description')
    match = demisto.args().get('match')
    addresses = argToList(demisto.args()['addresses']) if 'addresses' in demisto.args() else None
    if match and addresses:
        return_error('Please specify only one of the following: addresses, match')
    if type_ == 'static':
        if not addresses:
            return_error('Please specify addresses in order to create a static address group')
    if type_ == 'dynamic':
        if not match:
            return_error('Please specify a match in order to create a dynamic address group')

    if type_ == 'static':
        result = panorama_create_static_address_group(address_group_name, addresses, description)
    else:
        result = panorama_create_dynamic_address_group(address_group_name, match, description)

    address_group_output = {
        'Name': address_group_name,
        'Type': type_
    }
    if match:
        address_group_output['Match'] = match
    if addresses:
        address_group_output['Addresses'] = addresses
    if description:
        address_group_output['Description'] = description

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Address group was created successfully',
        'EntryContext': {
            "Panorama.AddressGroups(val.Name == obj.Name)": address_group_output
        }
    })


@logger
def panorama_delete_address_group(address_group_name: str):
    params = {
        'action': 'delete',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "address-group/entry[@name='" + address_group_name + "']",
        'element': "<entry name='" + address_group_name + "'></entry>",
        'key': API_KEY
    }
    result = http_request(
        URL,
        'POST',
        params=params,
    )

    return result


def panorama_delete_address_group_command():
    """
    Delete an address group
    """
    address_group_name = demisto.args()['name']

    address_group = panorama_delete_address_group(address_group_name)
    address_group_output = {'Name': address_group_name}

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': address_group,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Address group was deleted successfully',
        'EntryContext': {
            "Panorama.AddressGroups(val.Name == obj.Name)": address_group_output
        }
    })


def panorama_edit_address_group_command():
    """
    Edit an address group
    """
    address_group_name = demisto.args()['name']
    type_ = demisto.args()['type']
    match = demisto.args().get('match')
    element_to_add = argToList(demisto.args()['element_to_add']) if 'element_to_add' in demisto.args() else None
    element_to_remove = argToList(
        demisto.args()['element_to_remove']) if 'element_to_remove' in demisto.args() else None

    if type_ == 'dynamic':
        if not match:
            return_error('To edit a Dynamic Address group, Please provide a match')
        match_param = add_argument_open(match, 'filter', False)
        match_path = XPATH_OBJECTS + "address-group/entry[@name='" + address_group_name + "']/dynamic/filter"

    if type_ == 'static':
        if (element_to_add and element_to_remove) or (not element_to_add and not element_to_remove):
            return_error('To edit a Static Address group,'
                         'Please specify exactly one of the following: element_to_add, element_to_remove')
        address_group_prev = panorama_get_address_group(address_group_name)
        address_group_list: List[str] = []
        if 'static' in address_group_prev:
            if address_group_prev['static']:
                address_group_list = argToList(address_group_prev['static']['member'])
        if element_to_add:
            addresses = list(set(element_to_add + address_group_list))
        else:
            addresses = [item for item in address_group_list if item not in element_to_remove]
        addresses_param = add_argument_list(addresses, 'member', False)
        addresses_path = XPATH_OBJECTS + "address-group/entry[@name='" + address_group_name + "']/static"

    description = demisto.args().get('description')
    description_param = add_argument_open(description, 'description', False)
    description_path = XPATH_OBJECTS + "address-group/entry[@name='" + address_group_name + "']/description"

    params = {
        'action': 'edit',
        'type': 'config',
        'key': API_KEY,
        'xpath': '',
        'element': ''
    }

    address_group_output = {'Name': address_group_name}

    if match:
        params['xpath'] = match_path
        params['element'] = match_param
        result = http_request(
            URL,
            'POST',
            params=params
        )
        address_group_output['Match'] = match
    if addresses:
        params['xpath'] = addresses_path
        params['element'] = "<static>" + addresses_param + "</static>"
        result = http_request(
            URL,
            'POST',
            params=params
        )
        address_group_output['Addresses'] = addresses
    if description:
        params['xpath'] = description_path
        params['element'] = description_param
        result = http_request(
            URL,
            'POST',
            params=params
        )
        address_group_output['Description'] = description

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Address Group was edited successfully',
        'EntryContext': {
            "Panorama.AddressGroups(val.Name == obj.Name)": address_group_output
        }
    })


''' Services Commands '''


def prettify_services_arr(services_arr: Dict):
    pretty_services_arr = []
    for service in services_arr:
        pretty_service = {
            'Name': service['@name'],
        }
        if 'description' in service:
            pretty_service['Description'] = service['description']

        protocol = ''
        if 'protocol' in service:
            if 'tcp' in service['protocol']:
                protocol = 'tcp'
            elif 'udp' in service['protocol']:
                protocol = 'udp'
            else:
                protocol = 'sctp'
        pretty_service['Protocol'] = protocol

        if 'port' in service['protocol'][protocol]:
            pretty_service['DestinationPort'] = service['protocol'][protocol]['port']
        if 'source-port' in service['protocol'][protocol]:
            pretty_service['SourcePort'] = service['protocol'][protocol]['source-port']

        pretty_services_arr.append(pretty_service)

    return pretty_services_arr


@logger
def panorama_list_services():
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "service/entry",
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params,
    )

    return result['response']['result']['entry']


def panorama_list_services_command():
    """
    Get all Services
    """
    services_arr = panorama_list_services()
    services_output = prettify_services_arr(services_arr)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': services_arr,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Services:', services_output,
                                         ['Name', 'Protocol', 'SourcePort', 'DestinationPort', 'Description'],
                                         removeNull=True),
        'EntryContext': {
            "Panorama.Services(val.Name == obj.Name)": services_output
        }
    })


def prettify_service(service: Dict):
    pretty_service = {
        'Name': service['@name'],
    }
    if 'description' in service:
        pretty_service['Description'] = service['description']

    protocol = ''
    if 'protocol' in service:
        if 'tcp' in service['protocol']:
            protocol = 'tcp'
        elif 'udp' in service['protocol']:
            protocol = 'udp'
        else:
            protocol = 'sctp'
    pretty_service['Protocol'] = protocol

    if 'port' in service['protocol'][protocol]:
        pretty_service['DestinationPort'] = service['protocol'][protocol]['port']
    if 'source-port' in service['protocol'][protocol]:
        pretty_service['SourcePort'] = service['protocol'][protocol]['source-port']

    return pretty_service


@logger
def panorama_get_service(service_name: str):
    params = {
        'action': 'show',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "service/entry[@name='" + service_name + "']",
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params,
    )

    return result['response']['result']['entry']


def panorama_get_service_command():
    """
    Get a service
    """
    service_name = demisto.args()['name']

    service = panorama_get_service(service_name)
    service_output = prettify_service(service)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': service,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Address:', service_output,
                                         ['Name', 'Protocol', 'SourcePort', 'DestinationPort', 'Description'],
                                         removeNull=True),
        'EntryContext': {
            "Panorama.Services(val.Name == obj.Name)": service_output
        }
    })


@logger
def panorama_create_service(service_name: str, protocol: str, destination_port: str,
                            source_port: str = None, description: str = None):
    params = {
        'action': 'set',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "service/entry[@name='" + service_name + "']",
        'key': API_KEY
    }

    params['element'] = '<protocol>' + '<' + protocol + '>' \
                        + add_argument(destination_port, 'port', False) \
                        + add_argument(source_port, 'source-port', False) \
                        + '</' + protocol + '>' + '</protocol>' \
                        + add_argument(description, 'description', False)

    result = http_request(
        URL,
        'POST',
        params=params,
    )

    return result


def panorama_create_service_command():
    """
    Create a service object
    """
    service_name = demisto.args()['name']
    protocol = demisto.args()['protocol']
    destination_port = demisto.args()['destination_port']
    source_port = demisto.args().get('source_port')
    description = demisto.args().get('description')

    service = panorama_create_service(service_name, protocol, destination_port, source_port, description)

    service_output = {
        'Name': service_name,
        'Protocol': protocol,
        'DestinationPort': destination_port
    }
    if source_port:
        service_output['SourcePort'] = source_port
    if description:
        service_output['Description'] = description

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': service,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Service was added successfully',
        'EntryContext': {
            "Panorama.Services(val.Name == obj.Name)": service_output
        }
    })


@logger
def panorama_delete_service(service_name: str):
    params = {
        'action': 'delete',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "service/entry[@name='" + service_name + "']",
        'element': "<entry name='" + service_name + "'></entry>",
        'key': API_KEY
    }
    result = http_request(
        URL,
        'POST',
        params=params,
    )

    return result


def panorama_delete_service_command():
    """
    Delete a service
    """
    service_name = demisto.args()['name']

    service = panorama_delete_service(service_name)
    service_output = {'Name': service_name}

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': service,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Service was deleted successfully',
        'EntryContext': {
            "Panorama.Services(val.Name == obj.Name)": service_output
        }
    })


''' Service Group Commands '''


def prettify_service_groups_arr(service_groups_arr: Dict):
    pretty_service_groups_arr = []
    for service_group in service_groups_arr:
        pretty_service_group = {
            'Name': service_group['@name'],
            'Services': service_group['members']['member']
        }
        pretty_service_groups_arr.append(pretty_service_group)

    return pretty_service_groups_arr


@logger
def panorama_list_service_groups():
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "service-group/entry",
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params,
    )

    return result['response']['result']['entry']


def panorama_list_service_groups_command():
    """
    Get all address groups
    """
    service_groups_arr = panorama_list_service_groups()
    service_groups_output = prettify_service_groups_arr(service_groups_arr)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': service_groups_arr,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Service groups:', service_groups_output, ['Name', 'Services'],
                                         removeNull=True),
        'EntryContext': {
            "Panorama.ServiceGroups(val.Name == obj.Name)": service_groups_output
        }
    })


def prettify_service_group(service_group):
    pretty_service_group = {
        'Name': service_group['@name'],
        'Services': service_group['members']['member']
    }
    return pretty_service_group


@logger
def panorama_get_service_group(service_group_name):
    params = {
        'action': 'show',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "service-group/entry[@name='" + service_group_name + "']",
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params,
    )

    return result['response']['result']['entry']


def panorama_get_service_group_command():
    """
    Get an address group
    """
    service_group_name = demisto.args()['name']

    result = panorama_get_service_group(service_group_name)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Service group:', prettify_service_group(result), ['Name', 'Services'],
                                         removeNull=True),
        'EntryContext': {
            "Panorama.ServiceGroups(val.Name == obj.Name)": prettify_service_group(result)
        }
    })


def panorama_create_service_group(service_group_name, services):
    params = {
        'action': 'set',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "service-group/entry[@name='" + service_group_name + "']",
        'element': '<members>' + add_argument_list(services, 'member', True) + '</members>',
        'key': API_KEY
    }
    result = http_request(
        URL,
        'POST',
        params=params,
    )

    return result


def panorama_create_service_group_command():
    """
    Create a service group
    """
    service_group_name = demisto.args()['name']
    services = argToList(demisto.args()['services'])

    result = panorama_create_service_group(service_group_name, services)

    service_group_output = {
        'Name': service_group_name,
        'Services': services
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Service group was created successfully',
        'EntryContext': {
            "Panorama.ServiceGroups(val.Name == obj.Name)": service_group_output
        }
    })


@logger
def panorama_delete_service_group(service_group_name):
    params = {
        'action': 'delete',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "service-group/entry[@name='" + service_group_name + "']",
        'element': "<entry name='" + service_group_name + "'></entry>",
        'key': API_KEY
    }
    result = http_request(
        URL,
        'POST',
        params=params,
    )

    return result


def panorama_delete_service_group_command():
    """
    Delete a service group
    """
    service_group_name = demisto.args()['name']

    service_group = panorama_delete_service_group(service_group_name)
    service_group_output = {'Name': service_group_name}

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': service_group,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Service group was deleted successfully',
        'EntryContext': {
            "Panorama.ServiceGroups(val.Name == obj.Name)": service_group_output
        }
    })


@logger
def panorama_edit_service_group(service_group_name, services):
    params = {
        'action': 'edit',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "service-group/entry[@name='" + service_group_name + "']/members",
        'element': '<members>' + add_argument_list(services, 'member', False) + '</members>',
        'key': API_KEY,
    }
    result = http_request(
        URL,
        'POST',
        params=params
    )

    return result


def panorama_edit_service_group_command():
    """
    Edit a service group
    """
    service_group_name = demisto.args()['name']
    services_to_add = argToList(demisto.args()['services_to_add']) if 'services_to_add' in demisto.args() else None
    services_to_remove = argToList(
        demisto.args()['services_to_remove']) if 'services_to_remove' in demisto.args() else None

    if (services_to_add and services_to_remove) or (not services_to_add and not services_to_remove):
        return_error('Specify exactly one of the following arguments: services_to_add, services_to_remove')

    service_group_prev = panorama_get_service_group(service_group_name)
    service_group_list = argToList(service_group_prev['members']['member'])

    if services_to_add:
        services = list(set(services_to_add + service_group_list))
    else:
        services = [item for item in service_group_list if item not in services_to_remove]

    if len(services) == 0:
        return_error('A Service group must have at least one service')
    result = panorama_edit_service_group(service_group_name, services)

    service_group_output = {
        'Name': service_group_name,
        'Services': services
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Service group was edited successfully',
        'EntryContext': {
            "Panorama.ServiceGroups(val.Name == obj.Name)": service_group_output
        }
    })


''' Custom URL Category Commands '''


def prettify_custom_url_category(custom_url_category):
    pretty_custom_url_category = {
        'Name': custom_url_category['@name'],
    }

    if 'description' in custom_url_category:
        pretty_custom_url_category['Description'] = custom_url_category['description']

    if 'list' in custom_url_category:
        pretty_custom_url_category['Sites'] = custom_url_category['list']['member']

    return pretty_custom_url_category


@logger
def panorama_get_custom_url_category(name):
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "profiles/custom-url-category/entry[@name='" + name + "']",
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params,
    )

    return result['response']['result']['entry']


def panorama_get_custom_url_category_command():
    """
    Get a custom url category
    """
    name = demisto.args()['name']

    custom_url_category = panorama_get_custom_url_category(name)
    custom_url_category_output = prettify_custom_url_category(custom_url_category)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': custom_url_category,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Custom URL Category:', custom_url_category_output,
                                         ['Name', 'Sites', 'Description'], removeNull=True),
        'EntryContext': {
            "Panorama.CustomURLCategory(val.Name == obj.Name)": custom_url_category_output
        }
    })


@logger
def panorama_create_custom_url_category(custom_url_category_name, sites=None, description=None):
    params = {
        'action': 'set',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "profiles/custom-url-category/entry[@name='" + custom_url_category_name + "']",
        'element': add_argument(description, 'description', False) + add_argument_list(sites, 'list', True),
        'key': API_KEY
    }
    result = http_request(
        URL,
        'POST',
        params=params,
    )

    custom_url_category_output = {'Name': custom_url_category_name}
    if sites:
        custom_url_category_output['Sites'] = sites
    if description:
        custom_url_category_output['Description'] = description

    return result, custom_url_category_output


def panorama_create_custom_url_category_command():
    """
    Create a custom URL category
    """
    custom_url_category_name = demisto.args()['name']
    sites = argToList(demisto.args()['sites']) if 'sites' in demisto.args() else None
    description = demisto.args().get('description')

    custom_url_category, custom_url_category_output = panorama_create_custom_url_category(custom_url_category_name,
                                                                                          sites, description)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': custom_url_category,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Created Custom URL Category:', custom_url_category_output,
                                         ['Name', 'Sites', 'Description'], removeNull=True),
        'EntryContext': {
            "Panorama.CustomURLCategory(val.Name == obj.Name)": custom_url_category_output
        }
    })


@logger
def panorama_delete_custom_url_category(custom_url_category_name):
    params = {
        'action': 'delete',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "profiles/custom-url-category/entry[@name='" + custom_url_category_name + "']",
        'element': "<entry name='" + custom_url_category_name + "'></entry>",
        'key': API_KEY
    }
    result = http_request(
        URL,
        'POST',
        params=params,
    )

    return result


def panorama_delete_custom_url_category_command():
    """
    Delete a custom url category
    """
    custom_url_category_name = demisto.args()['name']

    result = panorama_delete_custom_url_category(custom_url_category_name)
    custom_url_category_output = {'Name': custom_url_category_name}

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Custom URL category was deleted successfully',
        'EntryContext': {
            "Panorama.CustomURLCategory(val.Name == obj.Name)": custom_url_category_output
        }
    })


@logger
def panorama_edit_custom_url_category(custom_url_category_name, sites, description=None):
    params = {
        'action': 'edit',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "profiles/custom-url-category/entry[@name='" + custom_url_category_name + "']",
        'element': "<entry name='" + custom_url_category_name + "'>"
                   + add_argument(description, 'description', False)
                   + add_argument_list(sites, 'list', True) + "</entry>",
        'key': API_KEY
    }
    result = http_request(
        URL,
        'POST',
        params=params,
    )

    custom_url_category_output = {'Name': custom_url_category_name}
    if sites:
        custom_url_category_output['Sites'] = sites
    if description:
        custom_url_category_output['Description'] = description

    return result, custom_url_category_output


def panorama_custom_url_category_add_sites_command():
    """
    Add sites to a configured custom url category
    """
    custom_url_category_name = demisto.args()['name']

    custom_url_category = panorama_get_custom_url_category(custom_url_category_name)

    description = custom_url_category.get('description')

    custom_url_category_sites: List[str] = []
    if 'list' in custom_url_category:
        if custom_url_category['list']:
            custom_url_category_sites = argToList(custom_url_category['list']['member'])

    sites = argToList(demisto.args()['list'])
    merged_sites = list((set(sites)).union(set(custom_url_category_sites)))

    result, custom_url_category_output = panorama_edit_custom_url_category(custom_url_category_name, merged_sites,
                                                                           description)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Updated Custom URL Category:', custom_url_category_output,
                                         ['Name', 'Sites', 'Description'], removeNull=True),
        'EntryContext': {
            "Panorama.CustomURLCategory(val.Name == obj.Name)": custom_url_category_output
        }
    })


def panorama_custom_url_category_remove_sites_command():
    """
    Add sites to a configured custom url category
    """
    custom_url_category_name = demisto.args()['name']

    custom_url_category = panorama_get_custom_url_category(custom_url_category_name)
    description = custom_url_category.get('description')

    if 'list' in custom_url_category:
        if 'member' in custom_url_category['list']:
            custom_url_category_sites = custom_url_category['list']['member']

    if not custom_url_category_sites:
        return_error('Custom url category does not contain sites')

    sites = argToList(demisto.args()['sites'])

    substructed_sites = [item for item in custom_url_category_sites if item not in sites]
    result, custom_url_category_output = panorama_edit_custom_url_category(custom_url_category_name, substructed_sites,
                                                                           description)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Updated Custom URL Category:', custom_url_category_output,
                                         ['Name', 'Sites', 'Description'], removeNull=True),
        'EntryContext': {
            "Panorama.CustomURLCategory(val.Name == obj.Name)": custom_url_category_output
        }
    })


''' URL Filtering '''


@logger
def panorama_get_url_category(url):
    params = {
        'action': 'show',
        'type': 'op',
        'key': API_KEY,
        'cmd': '<test><url>' + url + '</url></test>'
    }
    result = http_request(
        URL,
        'POST',
        params=params,
    )

    s = result['response']['result'].splitlines()[1]
    return s.split(' ')[1]


def populate_url_filter_category_from_context(url_category_hr):
    url_filter_category = demisto.dt(demisto.context(),
                                     'Panorama.URLFilter(val.Category === "{0}")'.format(url_category_hr['Category']))

    if not url_filter_category:
        url_filter_category = {
            'Category': url_category_hr['Category'],
            'URL': []
        }

    if type(url_filter_category) is dict:
        url_filter_category = [url_filter_category]

    url_filter_category[0]['URL'] += [url_category_hr['URL']]

    return url_filter_category


def panorama_get_url_category_command():
    """
    Get the url category from Palo Alto URL Filtering
    """
    url = demisto.args()['url']

    category = panorama_get_url_category(url)

    url_category_hr = {
        'URL': url,
        'Category': category
    }

    url_category_output = populate_url_filter_category_from_context(url_category_hr)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': category,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('URL Filtering:', url_category_hr, ['URL', 'Category'], removeNull=True),
        'EntryContext': {
            "Panorama.URLFilter(val.Category === obj.Category)": url_category_output
        }
    })


def prettify_get_url_filter(url_filter):
    pretty_url_filter = {'Name': url_filter['@name']}
    if 'description' in url_filter:
        pretty_url_filter['Description'] = url_filter['description']

    pretty_url_filter['Category'] = []
    url_category_list: List[str] = []
    action: str
    if 'alert' in url_filter:
        url_category_list = url_filter['alert']['member']
        action = 'alert'
    elif 'allow' in url_filter:
        url_category_list = url_filter['allow']['member']
        action = 'allow'
    elif 'block' in url_filter:
        url_category_list = url_filter['block']['member']
        action = 'block'
    elif 'continue' in url_filter:
        url_category_list = url_filter['continue']['member']
        action = 'continue'
    elif 'override' in url_filter:
        url_category_list = url_filter['override']['member']
        action = 'override'

    for category in url_category_list:
        pretty_url_filter['Category'].append({
            'Name': category,
            'Action': action
        })

    if 'allow-list' in url_filter or 'block-list' in url_filter:
        pretty_url_filter['Overrides'] = []
        if 'allow-list' in url_filter:
            pretty_url_filter['OverrideAllowList'] = url_filter['allow-list']['member']
        else:
            pretty_url_filter['OverrideBlockList'] = url_filter['block-list']['member']

    return pretty_url_filter


@logger
def panorama_get_url_filter(name):
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "profiles/url-filtering/entry[@name='" + name + "']",
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params,
    )

    return result['response']['result']['entry']


def panorama_get_url_filter_command():
    """
    Get a URL Filter
    """
    name = demisto.args()['name']

    url_filter = panorama_get_url_filter(name)

    url_filter_output = prettify_get_url_filter(url_filter)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': url_filter,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('URL Filter:', url_filter_output,
                                         ['Name', 'Category', 'OverrideAllowList', 'OverrideBlockList', 'Description'],
                                         removeNull=True),
        'EntryContext': {
            "Panorama.URLFilter(val.Name == obj.Name)": url_filter_output
        }
    })


@logger
def panorama_create_url_filter(
        url_filter_name, action,
        url_category_list,
        override_allow_list=None,
        override_block_list=None,
        description=None):
    element = add_argument_list(url_category_list, action, True) + add_argument_list(override_allow_list, 'allow-list',
                                                                                     True) + add_argument_list(
        override_block_list, 'block-list', True) + add_argument(description, 'description',
                                                                False) + "<action>block</action>"

    params = {
        'action': 'set',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "profiles/url-filtering/entry[@name='" + url_filter_name + "']",
        'element': element,
        'key': API_KEY
    }
    result = http_request(
        URL,
        'POST',
        params=params,
    )
    return result


def panorama_create_url_filter_command():
    """
    Create a URL Filter
    """
    url_filter_name = demisto.args()['name']
    action = demisto.args()['action']
    url_category_list = argToList(demisto.args()['url_category'])
    override_allow_list = argToList(demisto.args().get('override_allow_list'))
    override_block_list = argToList(demisto.args().get('override_block_list'))
    description = demisto.args().get('description')

    result = panorama_create_url_filter(url_filter_name, action, url_category_list, override_allow_list,
                                        override_block_list, description)

    url_filter_output = {'Name': url_filter_name}
    url_filter_output['Category'] = []
    for category in url_category_list:
        url_filter_output['Category'].append({
            'Name': category,
            'Action': action
        })
    if override_allow_list:
        url_filter_output['OverrideAllowList'] = override_allow_list
    if override_block_list:
        url_filter_output['OverrideBlockList'] = override_block_list
    if description:
        url_filter_output['Description'] = description

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'URL Filter was created successfully',
        'EntryContext': {
            "Panorama.URLFilter(val.Name == obj.Name)": url_filter_output
        }
    })


@logger
def panorama_edit_url_filter(url_filter_name, element_to_change, element_value, add_remove_element=None):
    url_filter_prev = panorama_get_url_filter(url_filter_name)
    if '@dirtyId' in url_filter_prev:
        return_error('Please commit the instance prior to editing the URL Filter')

    url_filter_output = {'Name': url_filter_name}
    params = {
        'action': 'edit',
        'type': 'config',
        'key': API_KEY,
    }

    if element_to_change == 'description':
        params['xpath'] = XPATH_OBJECTS + "profiles/url-filtering/entry[@name='" + url_filter_name + "']/"
        + element_to_change
        params['element'] = add_argument_open(element_value, 'description', False)
        result = http_request(URL, 'POST', params=params)
        url_filter_output['Description'] = element_value

    elif element_to_change == 'override_allow_list':
        prev_override_allow_list = argToList(url_filter_prev['allow-list']['member'])
        if add_remove_element == 'add':
            new_override_allow_list = list((set(prev_override_allow_list)).union(set([element_value])))
        else:
            new_override_allow_list = [url for url in prev_override_allow_list if url != element_value]

        params['xpath'] = XPATH_OBJECTS + "profiles/url-filtering/entry[@name='" + url_filter_name + "']/allow-list"
        params['element'] = add_argument_list(new_override_allow_list, 'allow-list', True)
        result = http_request(URL, 'POST', params=params)
        url_filter_output[element_to_change] = new_override_allow_list

    # element_to_change == 'override_block_list'
    else:
        prev_override_block_list = argToList(url_filter_prev['block-list']['member'])
        if add_remove_element == 'add':
            new_override_block_list = list((set(prev_override_block_list)).union(set([element_value])))
        else:
            new_override_block_list = [url for url in prev_override_block_list if url != element_value]

        params['xpath'] = XPATH_OBJECTS + "profiles/url-filtering/entry[@name='" + url_filter_name + "']/block-list"
        params['element'] = add_argument_list(new_override_block_list, 'block-list', True)
        result = http_request(URL, 'POST', params=params)
        url_filter_output[element_to_change] = new_override_block_list

    return result, url_filter_output


def panorama_edit_url_filter_command():
    """
    Edit a URL Filter
    """
    url_filter_name = demisto.args()['name']
    element_to_change = demisto.args()['element_to_change']
    add_remove_element = demisto.args()['add_remove_element']
    element_value = demisto.args()['element_value']

    result, url_filter_output = panorama_edit_url_filter(url_filter_name, element_to_change, element_value,
                                                         add_remove_element)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'URL Filter was edited successfully',
        'EntryContext': {
            "Panorama.URLFilter(val.Name == obj.Name)": url_filter_output
        }
    })


@logger
def panorama_delete_url_filter(url_filter_name):
    params = {
        'action': 'delete',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "profiles/url-filtering/entry[@name='" + url_filter_name + "']",
        'element': "<entry name='" + url_filter_name + "'></entry>",
        'key': API_KEY
    }

    result = http_request(
        URL,
        'POST',
        params=params,
    )

    return result


def panorama_delete_url_filter_command():
    """
    Delete a custom url category
    """
    url_filter_name = demisto.args()['name']
    result = panorama_delete_url_filter(url_filter_name)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'URL Filter was deleted successfully',
    })


''' Security Rules Managing '''


@logger
def panorama_move_rule_command():
    """
    Move a security rule
    """
    rulename = demisto.args()['rulename']
    params = {
        'type': 'config',
        'action': 'move',
        'key': API_KEY,
        'where': demisto.args()['where'],
    }

    if DEVICE_GROUP:
        if 'pre_post' not in demisto.args():
            return_error('Please provide the pre_post argument when moving a rule in Panorama instance.')
        else:
            params['xpath'] = XPATH_SECURITY_RULES + demisto.args()[
                'pre_post'] + '/security/rules/entry' + '[@name=\'' + rulename + '\']'
    else:
        params['xpath'] = XPATH_SECURITY_RULES + '[@name=\'' + rulename + '\']'

    if 'dst' in demisto.args():
        params['dst'] = demisto.args()['dst']

    result = http_request(URL, 'POST', params=params)
    rule_output = {'Name': rulename}

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Rule ' + rulename + ' moved successfully',
        'EntryContext': {
            "Panorama.SecurityRule(val.Name == obj.Name)": rule_output
        }
    })


''' Security Rule Configuration '''


@logger
def panorama_create_rule_command():
    """
    Create a security rule
    """
    rulename = demisto.args()['rulename'] if 'rulename' in demisto.args() else ('demisto-' + (str(uuid.uuid4()))[:8])
    source = demisto.args().get('source')
    destination = demisto.args().get('destination')
    negate_source = demisto.args().get('negate_source')
    negate_destination = demisto.args().get('negate_destination')
    action = demisto.args().get('action')
    service = demisto.args().get('service')
    disable = demisto.args().get('disable')
    application = demisto.args().get('application')
    source_user = demisto.args().get('source_user')
    disable_server_response_inspection = demisto.args().get('disable_server_response_inspection')
    description = demisto.args().get('description')
    target = demisto.args().get('target')
    log_forwarding = demisto.args().get('log_forwarding', None)

    if not DEVICE_GROUP:
        if target:
            return_error('The target argument is relevant only for a Palo Alto Panorama instance.')
        elif log_forwarding:
            return_error('The log_forwarding argument is relevant only for a Palo Alto Panorama instance.')

    params = prepare_security_rule_params(api_action='set', rulename=rulename, source=source, destination=destination,
                                          negate_source=negate_source, negate_destination=negate_destination,
                                          action=action, service=service,
                                          disable=disable, application=application, source_user=source_user,
                                          disable_server_response_inspection=disable_server_response_inspection,
                                          description=description, target=target, log_forwarding=log_forwarding)

    result = http_request(
        URL,
        'POST',
        params=params
    )

    rule_output = {SECURITY_RULE_ARGS[key]: value for key, value in demisto.args().items() if key in SECURITY_RULE_ARGS}
    rule_output['Name'] = rulename

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Rule configured successfully',
        'EntryContext': {
            "Panorama.SecurityRule(val.Name == obj.Name)": rule_output
        }
    })


@logger
def panorama_edit_rule_command():
    """
    Edit a security rule
    """
    rulename = demisto.args()['rulename']
    element_to_change = demisto.args()['element_to_change']
    element_value = demisto.args()['element_value']
    target = demisto.args().get('target')

    if target and not DEVICE_GROUP:
        return_error('The target argument is relevant only for a Palo Alto Panorama instance.')

    params = {
        'type': 'config',
        'action': 'edit',
        'key': API_KEY
    }

    if element_to_change in ['action', 'description']:
        params['element'] = add_argument_open(element_value, element_to_change, False)
    elif element_to_change in ['source', 'destination', 'application', 'categry', 'source-user', 'service']:
        params['element'] = add_argument_open(element_value, element_to_change, True)
    else:  # element_to_change in ['negate_source', 'negate_destination', 'disable']
        params['element'] = add_argument_yes_no(element_value, element_to_change)

    if target:
        params['element'] += add_argument_target(target, 'target')

    if DEVICE_GROUP:
        if 'pre_post' not in demisto.args():
            return_error('please provide the pre_post argument when moving a rule in Panorama instance.')
        else:
            params['xpath'] = XPATH_SECURITY_RULES + demisto.args()[
                'pre_post'] + '/security/rules/entry' + '[@name=\'' + rulename + '\']'
    else:
        params['xpath'] = XPATH_SECURITY_RULES + '[@name=\'' + rulename + '\']'

    params['xpath'] = params['xpath'] + '/' + element_to_change

    result = http_request(
        URL,
        'POST',
        params=params
    )
    rule_output = {'Name': rulename}
    rule_output[SECURITY_RULE_ARGS[element_to_change]] = element_value

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Rule edited successfully',
        'EntryContext': {
            "Panorama.SecurityRule(val.Name == obj.Name)": rule_output
        }
    })


@logger
def panorama_delete_rule_command():
    """
    Delete a security rule
    """
    rulename = demisto.args()['rulename']

    params = {
        'type': 'config',
        'action': 'delete',
        'key': API_KEY
    }
    if DEVICE_GROUP:
        if 'pre_post' not in demisto.args():
            return_error('Please provide the pre_post argument when moving a rule in Panorama instance.')
        else:
            params['xpath'] = XPATH_SECURITY_RULES + demisto.args()[
                'pre_post'] + '/security/rules/entry' + '[@name=\'' + rulename + '\']'
    else:
        params['xpath'] = XPATH_SECURITY_RULES + '[@name=\'' + rulename + '\']'

    result = http_request(
        URL,
        'POST',
        params=params
    )

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Rule deleted successfully',
    })


@logger
def panorama_custom_block_rule_command():
    """
    Block an object in Panorama
    """
    object_type = demisto.args()['object_type']
    object_value = demisto.args()['object_value']
    direction = demisto.args()['direction'] if 'direction' in demisto.args() else 'both'
    rulename = demisto.args()['rulename'] if 'rulename' in demisto.args() else ('demisto-' + (str(uuid.uuid4()))[:8])
    block_destination = False if direction == 'from' else True
    block_source = False if direction == 'to' else True
    target = demisto.args().get('target')
    log_forwarding = demisto.args().get('log_forwarding', None)

    if not DEVICE_GROUP:
        if target:
            return_error('The target argument is relevant only for a Palo Alto Panorama instance.')
        elif log_forwarding:
            return_error('The log_forwarding argument is relevant only for a Palo Alto Panorama instance.')

    custom_block_output = {
        'Name': rulename,
        'Direction': direction,
        'Disabled': False
    }
    if log_forwarding:
        custom_block_output['LogForwarding'] = log_forwarding
    if target:
        custom_block_output['Traget'] = target

    if object_type == 'ip':
        if block_source:
            params = prepare_security_rule_params(api_action='set', action='drop', source=object_value,
                                                  destination='any', rulename=rulename + '-from', target=target,
                                                  log_forwarding=log_forwarding)
            result = http_request(URL, 'POST', params=params)
        if block_destination:
            params = prepare_security_rule_params(api_action='set', action='drop', destination=object_value,
                                                  source='any', rulename=rulename + '-to', target=target,
                                                  log_forwarding=log_forwarding)
            result = http_request(URL, 'POST', params=params)
        custom_block_output['IP'] = object_value

    elif object_type == 'address-group':
        if block_source:
            params = prepare_security_rule_params(api_action='set', action='drop', source=object_value,
                                                  destination='any', rulename=rulename + '-from', target=target,
                                                  log_forwarding=log_forwarding)
            result = http_request(URL, 'POST', params=params)
        if block_destination:
            params = prepare_security_rule_params(api_action='set', action='drop', destination=object_value,
                                                  source='any', rulename=rulename + '-to', target=target,
                                                  log_forwarding=log_forwarding)
            result = http_request(URL, 'POST', params=params)
        custom_block_output['AddressGroup'] = object_value

    elif object_type == 'url-category':
        params = prepare_security_rule_params(api_action='set', action='drop', source='any', destination='any',
                                              category=object_value, rulename=rulename, target=target,
                                              log_forwarding=log_forwarding)
        result = http_request(URL, 'POST', params=params)
        custom_block_output['CustomURLCategory'] = object_value

    elif object_type == 'application':
        params = prepare_security_rule_params(api_action='set', action='drop', source='any', destination='any',
                                              application=object_value, rulename=rulename, target=target,
                                              log_forwarding=log_forwarding)
        result = http_request(URL, 'POST', params=params)
        custom_block_output['Application'] = object_value

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Object was blocked successfully',
        'EntryContext': {
            "Panorama.SecurityRule(val.Name == obj.Name)": custom_block_output
        }
    })


''' PCAPS '''


@logger
def panorama_list_pcaps_command():
    """
    Get list of pcap files
    """
    params = {
        'type': 'export',
        'key': API_KEY,
        'category': demisto.args()['pcapType']
    }

    if 'password' in demisto.args():
        params['dlp-password'] = demisto.args()['password']
    elif demisto.args()['pcapType'] == 'dlp-pcap':
        return_error('can not provide dlp-pcap without password')

    result = http_request(URL, 'GET', params=params)

    json_result = json.loads(xml2json(result.text))['response']
    if json_result['@status'] != 'success':
        return_error('Request to get list of Pcaps Failed.\nStatus code: ' + str(
            json_result['response']['@code']) + '\nWith message: ' + str(json_result['response']['msg']['line']))

    pcap_list = json_result['result']['dir-listing']['file']
    pcap_list = [pcap[1:] for pcap in pcap_list]

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': json_result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('List of Pcaps:', pcap_list, ['Pcap name']),
        'EntryContext': {
            "Panorama.Pcaps(val.Name == obj.Name)": pcap_list
        }
    })


@logger
def panorama_get_pcap_command():
    """
    Get pcap file
    """
    params = {
        'type': 'export',
        'key': API_KEY,
        'category': demisto.args()['pcapType']
    }

    if 'password' in demisto.args():
        params['dlp-password'] = demisto.args()['password']
    elif demisto.args()['pcapType'] == 'dlp-pcap':
        return_error('can not provide dlp-pcap without password')

    if 'pcapID' in demisto.args():
        params['pcap-id'] = demisto.args()['pcapID']
    elif demisto.args()['pcapType'] == 'threat-pcap':
        return_error('can not provide threat-pcap without pcap-id')

    pcap_name = demisto.args().get('from')
    local_name = demisto.args().get('localName')
    serial_no = demisto.args().get('serialNo')
    search_time = demisto.args().get('searchTime')

    file_name = None
    if pcap_name:
        params['from'] = pcap_name
        file_name = pcap_name
    if local_name:
        params['to'] = local_name
        file_name = local_name
    if serial_no:
        params['serialno'] = serial_no
    if search_time:
        params['search-time'] = search_time

    # set file name to the current time if from/to were not specified
    if not file_name:
        file_name = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')

    result = http_request(URL, 'GET', params=params)

    # due pcap file size limitation in the product, for more details, please see the documentation.
    if result.headers['Content-Type'] != 'application/octet-stream':
        return_error(
            'PCAP download failed. Most likely cause is the file size limitation.'
            'For information on how to download manually, see the documentation for this integration.')

    file = fileResult(file_name + ".pcap", result.content)
    demisto.results(file)


''' Applications '''


def prettify_applications_arr(applications_arr):
    pretty_application_arr = []
    for i in range(len(applications_arr)):
        application = applications_arr[i]
        pretty_application_arr.append({
            'SubCategory': application['subcategory'],
            'Risk': application['risk'],
            'Technology': application['technology'],
            'Name': application['@name'],
            'Description': application['description'],
            'Id': application['@id']
        })
    return pretty_application_arr


@logger
def panorama_list_applications():
    params = {
        'type': 'op',
        'command': '<show><objects></objects></show>',
        'key': API_KEY
    }
    result = http_request(
        URL,
        'POST',
        params=params
    )
    return result['response']['result']['config']['shared']['content-preview']['application']['entry']


def panorama_list_applications_command():
    """
    List all applications
    """
    applications_arr = panorama_list_applications()

    applications_arr_output = prettify_applications_arr(applications_arr)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': applications_arr,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Applications', applications_arr_output,
                                         ['Name', 'Id', 'Risk', 'Category', 'SubCategory', 'Technology',
                                          'Description']),
        'EntryContext': {
            "Panorama.Applications(val.Id == obj.Id)": applications_arr_output
        }
    })


''' External Dynamic Lists Commands '''


def prettify_edls_arr(edls_arr):
    pretty_edls_arr = []
    if not isinstance(edls_arr, list):  # handle case of only one edl in the instance
        return prettify_edl(edls_arr)
    for edl in edls_arr:
        pretty_edl = {
            'Name': edl['@name'],
            'Type': ''.join(edl['type'].keys())
        }
        edl_type = pretty_edl['Type']

        if edl['type'][edl_type]:
            if 'url' in edl['type'][edl_type]:
                pretty_edl['URL'] = edl['type'][edl_type]['url']
            if 'certificate-profile' in edl['type'][edl_type]:
                pretty_edl['CertificateProfile'] = edl['type'][edl_type]['certificate-profile']
            if 'recurring' in edl['type'][edl_type]:
                pretty_edl['Recurring'] = ''.join(edl['type'][edl_type]['recurring'].keys())
            if 'description' in edl['type'][edl_type]:
                pretty_edl['Description'] = edl['type'][edl_type]['description']

        pretty_edls_arr.append(pretty_edl)

    return pretty_edls_arr


@logger
def panorama_list_edls():
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "external-list/entry",
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params,
    )
    return result['response']['result']['entry']


def panorama_list_edls_command():
    """
    Get all EDLs
    """
    edls_arr = panorama_list_edls()
    edls_output = prettify_edls_arr(edls_arr)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': edls_arr,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('External Dynamic Lists:', edls_output,
                                         ['Name', 'Type', 'URL', 'Recurring', 'CertificateProfile', 'Description'],
                                         removeNull=True),
        'EntryContext': {
            "Panorama.EDL(val.Name == obj.Name)": edls_output
        }
    })


def prettify_edl(edl):
    pretty_edl = {
        'Name': edl['@name'],
        'Type': ''.join(edl['type'].keys())
    }
    edl_type = pretty_edl['Type']

    if edl['type'][edl_type]:
        if 'url' in edl['type'][edl_type]:
            pretty_edl['URL'] = edl['type'][edl_type]['url']
        if 'certificate-profile' in edl['type'][edl_type]:
            pretty_edl['CertificateProfile'] = edl['type'][edl_type]['certificate-profile']
        if 'recurring' in edl['type'][edl_type]:
            pretty_edl['Recurring'] = ''.join(edl['type'][edl_type]['recurring'].keys())
        if 'description' in edl['type'][edl_type]:
            pretty_edl['Description'] = edl['type'][edl_type]['description']

    return pretty_edl


@logger
def panorama_get_edl(edl_name):
    params = {
        'action': 'show',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "external-list/entry[@name='" + edl_name + "']",
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params,
    )

    return result['response']['result']['entry']


def panorama_get_edl_command():
    """
    Get an EDL
    """
    edl_name = demisto.args()['name']
    edl = panorama_get_edl(edl_name)
    edl_output = prettify_edl(edl)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': edl,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('External Dynamic List:', edl_output,
                                         ['Name', 'Type', 'URL', 'Recurring', 'CertificateProfile', 'Description'],
                                         None, True),
        'EntryContext': {
            "Panorama.EDL(val.Name == obj.Name)": edl_output
        }
    })


@logger
def panorama_create_edl(edl_name, url, type_, recurring, certificate_profile=None, description=None):
    params = {
        'action': 'set',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "external-list/entry[@name='" + edl_name + "']/type/" + type_,
        'key': API_KEY
    }

    params['element'] = add_argument(url, 'url', False) + '<recurring><' + recurring + '/></recurring>' + add_argument(
        certificate_profile, 'certificate-profile', False) + add_argument(description, 'description', False)

    result = http_request(
        URL,
        'POST',
        params=params,
    )

    return result


def panorama_create_edl_command():
    """
    Create an edl object
    """
    edl_name = demisto.args().get('name')
    url = demisto.args().get('url')
    type_ = demisto.args().get('type')
    recurring = demisto.args().get('recurring')
    certificate_profile = demisto.args().get('certificate_profile')
    description = demisto.args().get('description')

    edl = panorama_create_edl(edl_name, url, type_, recurring, certificate_profile, description)

    edl_output = {
        'Name': edl_name,
        'URL': url,
        'Type': type_,
        'Recurring': recurring
    }

    if description:
        edl_output['Description'] = description
    if certificate_profile:
        edl_output['CertificateProfile'] = certificate_profile

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': edl,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'External Dynamic List was added successfully',
        'EntryContext': {
            "Panorama.EDL(val.Name == obj.Name)": edl_output
        }
    })


@logger
def panorama_edit_edl(edl_name, element_to_change, element_value):
    edl_prev = panorama_get_edl(edl_name)
    if '@dirtyId' in edl_prev:
        return_error('Please commit the instance prior to editing the External Dynamic List')
    edl_type = ''.join(edl_prev['type'].keys())
    edl_output = {'Name': edl_name}
    params = {
        'action': 'edit',
        'type': 'config',
        'key': API_KEY,
        'xpath': XPATH_OBJECTS + "external-list/entry[@name='" + edl_name + "']/type/" + edl_type + "/"
        + element_to_change
    }

    if element_to_change == 'url':
        params['element'] = add_argument_open(element_value, 'url', False)
        result = http_request(URL, 'POST', params=params)
        edl_output['URL'] = element_value

    elif element_to_change == 'certificate_profile':
        params['element'] = add_argument_open(element_value, 'certificate-profile', False)
        result = http_request(URL, 'POST', params=params)
        edl_output['CertificateProfile'] = element_value

    elif element_to_change == 'description':
        params['element'] = add_argument_open(element_value, 'description', False)
        result = http_request(URL, 'POST', params=params)
        edl_output['Description'] = element_value

    # element_to_change == 'recurring'
    else:
        if element_value not in ['five-minute', 'hourly']:
            return_error('Recurring segment must be five-minute or hourly')
        params['element'] = '<recurring><' + element_value + '/></recurring>'
        result = http_request(URL, 'POST', params=params)
        edl_output['Recurring'] = element_value

    return result, edl_output


def panorama_edit_edl_command():
    """
    Edit an EDL
    """
    edl_name = demisto.args()['name']
    element_to_change = demisto.args()['element_to_change']
    element_value = demisto.args()['element_value']

    result, edl_output = panorama_edit_edl(edl_name, element_to_change, element_value)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'External Dynamic List was edited successfully',
        'EntryContext': {
            "Panorama.EDL(val.Name == obj.Name)": edl_output
        }
    })


@logger
def panorama_delete_edl(edl_name):
    params = {
        'action': 'delete',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "external-list/entry[@name='" + edl_name + "']",
        'element': "<entry name='" + edl_name + "'></entry>",
        'key': API_KEY
    }

    result = http_request(
        URL,
        'POST',
        params=params,
    )

    return result


def panorama_delete_edl_command():
    """
    Delete an EDL
    """
    edl_name = demisto.args()['name']

    edl = panorama_delete_edl(edl_name)
    edl_output = {'Name': edl_name}

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': edl,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'External Dynamic List was deleted successfully',
        'EntryContext': {
            "Panorama.EDL(val.Name == obj.Name)": edl_output
        }
    })


def panorama_refresh_edl(edl_name):
    edl = panorama_get_edl(edl_name)
    edl_type = ''.join(edl['type'].keys())

    params = {
        'type': 'op',
        'cmd': '<request><system><external-list><refresh><type><' + edl_type + '><name>' + edl_name + '</name></'
               + edl_type + '></type></refresh></external-list></system></request>',
        'key': API_KEY
    }
    result = http_request(
        URL,
        'POST',
        params=params,
    )

    return result


def panorama_refresh_edl_command():
    """
    Refresh an EDL
    """
    edl_name = demisto.args()['name']

    result = panorama_refresh_edl(edl_name)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Refreshed External Dynamic List successfully',
    })


@logger
def panorama_register_ip_tag(tag: str, ips: List, persistent: str):
    entry: str = ''
    for ip in ips:
        entry += f'<entry ip=\"{ip}\" persistent=\"{persistent}\"><tag><member>{tag}</member></tag></entry>'

    params = {
        'type': 'user-id',
        'cmd': '<uid-message><version>2.0</version><type>update</type><payload><register>' + entry
               + '</register></payload></uid-message>',
        'key': API_KEY
    }

    result = http_request(
        URL,
        'POST',
        params=params,
    )

    return result


def panorama_register_ip_tag_command():
    """
    Register IPs to a Tag
    """
    tag = demisto.args()['tag']
    ips = argToList(demisto.args()['IPs'])

    persistent = demisto.args()['persistent'] if 'persistent' in demisto.args() else 'true'
    persistent = '1' if persistent == 'true' else '0'

    result = panorama_register_ip_tag(tag, ips, str(persistent))

    registered_ip: Dict[str, str] = {}
    # update context only if IPs are persistent
    if persistent == '1':
        # get existing IPs for this tag
        context_ips = demisto.dt(demisto.context(), 'Panorama.DynamicTags(val.Tag ==\"' + tag + '\").IPs')

        if context_ips:
            all_ips = ips + context_ips
        else:
            all_ips = ips

        registered_ip = {
            'Tag': tag,
            'IPs': all_ips
        }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Registered ip-tag successfully',
        'EntryContext': {
            "Panorama.DynamicTags(val.Tag == obj.Tag)": registered_ip
        }
    })


@logger
def panorama_unregister_ip_tag(tag: str, ips: list):
    entry = ''
    for ip in ips:
        entry += '<entry ip=\"' + ip + '\"><tag><member>' + tag + '</member></tag></entry>'

    params = {
        'type': 'user-id',
        'cmd': '<uid-message><version>2.0</version><type>update</type><payload><unregister>' + entry
               + '</unregister></payload></uid-message>',
        'key': API_KEY
    }
    result = http_request(
        URL,
        'POST',
        params=params,
    )

    return result


def panorama_unregister_ip_tag_command():
    """
    Register IPs to a Tag
    """
    tag = demisto.args()['tag']
    ips = argToList(demisto.args()['IPs'])

    result = panorama_unregister_ip_tag(tag, ips)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Unregistered ip-tag successfully'
    })


''' EXECUTION '''


def main():
    LOG('command is %s' % (demisto.command(),))

    try:
        # Remove proxy if not set to true in params
        handle_proxy()

        if demisto.command() == 'test-module':
            panorama_test()

        elif demisto.command() == 'panorama':
            panorama_command()

        elif demisto.command() == 'panorama-commit':
            panorama_commit_command()

        elif demisto.command() == 'panorama-commit-status':
            panorama_commit_status_command()

        elif demisto.command() == 'panorama-push-to-device-group':
            panorama_push_to_device_group_command()

        elif demisto.command() == 'panorama-push-status':
            panorama_push_status_command()

        # Addresses commands
        elif demisto.command() == 'panorama-list-addresses':
            panorama_list_addresses_command()

        elif demisto.command() == 'panorama-get-address':
            panorama_get_address_command()

        elif demisto.command() == 'panorama-create-address':
            panorama_create_address_command()

        elif demisto.command() == 'panorama-delete-address':
            panorama_delete_address_command()

        # Address groups commands
        elif demisto.command() == 'panorama-list-address-groups':
            panorama_list_address_groups_command()

        elif demisto.command() == 'panorama-get-address-group':
            panorama_get_address_group_command()

        elif demisto.command() == 'panorama-create-address-group':
            panorama_create_address_group_command()

        elif demisto.command() == 'panorama-delete-address-group':
            panorama_delete_address_group_command()

        elif demisto.command() == 'panorama-edit-address-group':
            panorama_edit_address_group_command()

        # Services commands
        elif demisto.command() == 'panorama-list-services':
            panorama_list_services_command()

        elif demisto.command() == 'panorama-get-service':
            panorama_get_service_command()

        elif demisto.command() == 'panorama-create-service':
            panorama_create_service_command()

        elif demisto.command() == 'panorama-delete-service':
            panorama_delete_service_command()

        # Service groups commands
        elif demisto.command() == 'panorama-list-service-groups':
            panorama_list_service_groups_command()

        elif demisto.command() == 'panorama-get-service-group':
            panorama_get_service_group_command()

        elif demisto.command() == 'panorama-create-service-group':
            panorama_create_service_group_command()

        elif demisto.command() == 'panorama-delete-service-group':
            panorama_delete_service_group_command()

        elif demisto.command() == 'panorama-edit-service-group':
            panorama_edit_service_group_command()

        # Custom Url Category commands
        elif demisto.command() == 'panorama-get-custom-url-category':
            panorama_get_custom_url_category_command()

        elif demisto.command() == 'panorama-create-custom-url-category':
            panorama_create_custom_url_category_command()

        elif demisto.command() == 'panorama-delete-custom-url-category':
            panorama_delete_custom_url_category_command()

        elif demisto.command() == 'panorama-edit-custom-url-category':
            if demisto.args()['action'] == 'remove':
                panorama_custom_url_category_remove_sites_command()
            else:
                panorama_custom_url_category_add_sites_command()

        # URL Filtering capabilities
        elif demisto.command() == 'panorama-get-url-category':
            panorama_get_url_category_command()

        elif demisto.command() == 'panorama-get-url-filter':
            panorama_get_url_filter_command()

        elif demisto.command() == 'panorama-create-url-filter':
            panorama_create_url_filter_command()

        elif demisto.command() == 'panorama-edit-url-filter':
            panorama_edit_url_filter_command()

        elif demisto.command() == 'panorama-delete-url-filter':
            panorama_delete_url_filter_command()

        # EDL
        elif demisto.command() == 'panorama-list-edls':
            panorama_list_edls_command()

        elif demisto.command() == 'panorama-get-edl':
            panorama_get_edl_command()

        elif demisto.command() == 'panorama-create-edl':
            panorama_create_edl_command()

        elif demisto.command() == 'panorama-edit-edl':
            panorama_edit_edl_command()

        elif demisto.command() == 'panorama-delete-edl':
            panorama_delete_edl_command()

        elif demisto.command() == 'panorama-refresh-edl':
            panorama_refresh_edl_command()

        # Registered IPs
        elif demisto.command() == 'panorama-register-ip-tag':
            panorama_register_ip_tag_command()

        elif demisto.command() == 'panorama-unregister-ip-tag':
            panorama_unregister_ip_tag_command()

        # Security Rules Managing
        elif demisto.command() == 'panorama-move-rule':
            panorama_move_rule_command()

        # Security Rules Configuration
        elif demisto.command() == 'panorama-create-rule':
            panorama_create_rule_command()

        elif demisto.command() == 'panorama-custom-block-rule':
            panorama_custom_block_rule_command()

        elif demisto.command() == 'panorama-edit-rule':
            panorama_edit_rule_command()

        elif demisto.command() == 'panorama-delete-rule':
            panorama_delete_rule_command()

        # Pcaps
        elif demisto.command() == 'panorama-list-pcaps':
            panorama_list_pcaps_command()

        elif demisto.command() == 'panorama-get-pcap':
            panorama_get_pcap_command()

        # Application
        elif demisto.command() == 'panorama-list-applications':
            panorama_list_applications_command()

    except Exception as ex:
        return_error(str(ex))

    finally:
        LOG.print_log()


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
