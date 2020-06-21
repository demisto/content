import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
import uuid
import json
import requests

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
if demisto.args() and demisto.args().get('device-group', None):
    DEVICE_GROUP = demisto.args().get('device-group')
else:
    DEVICE_GROUP = demisto.params().get('device_group', None)

# configuration check
if DEVICE_GROUP and VSYS:
    return_error('Cannot configure both vsys and Device group. Set vsys for firewall, set Device group for Panorama.')
if not DEVICE_GROUP and not VSYS:
    return_error('Set vsys for firewall or Device group for Panorama.')

# setting security xpath relevant to FW or panorama management
if DEVICE_GROUP:
    device_group_shared = DEVICE_GROUP.lower()
    if device_group_shared == 'shared':
        XPATH_SECURITY_RULES = "/config/shared/"
        DEVICE_GROUP = device_group_shared
    else:
        XPATH_SECURITY_RULES = "/config/devices/entry/device-group/entry[@name=\'" + DEVICE_GROUP + "\']/"
else:
    XPATH_SECURITY_RULES = "/config/devices/entry/vsys/entry[@name=\'" + VSYS + "\']/rulebase/security/rules/entry"

# setting objects xpath relevant to FW or panorama management
if DEVICE_GROUP:
    device_group_shared = DEVICE_GROUP.lower()
    if DEVICE_GROUP == 'shared':
        XPATH_OBJECTS = "/config/shared/"
        DEVICE_GROUP = device_group_shared
    else:
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
    'log_forwarding': 'LogForwarding',
    'log-setting': 'LogForwarding',
    'tag': 'Tags'
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


class PAN_OS_Not_Found(Exception):
    """ PAN-OS Error. """
    def __init__(self, *args):  # real signature unknown
        pass


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
        raise Exception('Request Failed. with status: ' + str(result.status_code) + '. Reason is: ' + str(result.reason))

    # if pcap download
    if params.get('type') == 'export':
        return result

    json_result = json.loads(xml2json(result.text))

    # handle non success
    if json_result['response']['@status'] != 'success':
        if 'msg' in json_result['response'] and 'line' in json_result['response']['msg']:
            # catch non existing object error and display a meaningful message
            if json_result['response']['msg']['line'] == 'No such node':
                raise Exception(
                    'Object was not found, verify that the name is correct and that the instance was committed.')

            #  catch urlfiltering error and display a meaningful message
            elif str(json_result['response']['msg']['line']).find('test -> url') != -1:
                raise Exception('The URL filtering license is either expired or not active.'
                                ' Please contact your PAN-OS representative.')

            # catch non valid jobID errors and display a meaningful message
            elif isinstance(json_result['response']['msg']['line'], str) and \
                    json_result['response']['msg']['line'].find('job') != -1 and \
                    (json_result['response']['msg']['line'].find('not found') != -1
                     or json_result['response']['msg']['line'].find('No such query job')) != -1:
                raise Exception('Invalid Job ID error: ' + json_result['response']['msg']['line'])

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
                    'IP ' + str(ips) + ' already exist in the tag. All submitted IPs were not registered to the tag.')
                sys.exit(0)

            # catch timed out log queries and return this as an entry.note
            elif str(json_result['response']['msg']['line']).find('Query timed out') != -1:
                demisto.results(str(json_result['response']['msg']['line']) + '. Rerun the query.')
                sys.exit(0)

        if '@code' in json_result['response']:
            raise Exception(
                'Request Failed.\nStatus code: ' + str(json_result['response']['@code']) + '\nWith message: ' + str(
                    json_result['response']['msg']['line']))
        else:
            raise Exception('Request Failed.\n' + str(json_result['response']))

    # handle @code
    if 'response' in json_result and '@code' in json_result['response']:
        if json_result['response']['@code'] in PAN_OS_ERROR_DICT:
            error_message = 'Request Failed.\n' + PAN_OS_ERROR_DICT[json_result['response']['@code']]
            if json_result['response']['@code'] == '7' and DEVICE_GROUP:
                device_group_names = get_device_groups_names()
                if DEVICE_GROUP not in device_group_names:
                    error_message += (f'\nDevice Group: {DEVICE_GROUP} does not exist.'
                                      f' The available Device Groups for this instance:'
                                      f' {", ".join(device_group_names)}.')
                    raise PAN_OS_Not_Found(error_message)
            return_warning('List not found and might be empty', True)
        if json_result['response']['@code'] not in ['19', '20']:
            # error code non exist in dict and not of success
            if 'msg' in json_result['response']:
                raise Exception(
                    'Request Failed.\nStatus code: ' + str(json_result['response']['@code']) + '\nWith message: ' + str(
                        json_result['response']['msg']))
            else:
                raise Exception('Request Failed.\n' + str(json_result['response']))

    return json_result


def add_argument_list(arg: Any, field_name: str, member: Optional[bool], any_: Optional[bool] = False) -> str:
    member_stringify_list = ''
    if arg:
        if isinstance(arg, str):
            arg = [arg]

        for item in arg:
            member_stringify_list += '<member>' + item + '</member>'
        if field_name == 'member':
            return member_stringify_list
        elif member:
            return '<' + field_name + '>' + member_stringify_list + '</' + field_name + '>'
        else:
            return '<' + field_name + '>' + arg + '</' + field_name + '>'
    if any_:
        if member:
            return '<' + field_name + '><member>any</member></' + field_name + '>'
        else:
            return '<' + field_name + '>any</' + field_name + '>'
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


def set_xpath_network(template: str = None) -> Tuple[str, Optional[str]]:
    """
    Setting template xpath relevant to panorama instances.
    """
    if template:
        if not DEVICE_GROUP or VSYS:
            raise Exception('Template is only relevant for Panorama instances.')
    if not template:
        template = demisto.params().get('template', None)
    # setting network xpath relevant to FW or panorama management
    if DEVICE_GROUP:
        xpath_network = f'/config/devices/entry[@name=\'localhost.localdomain\']/template/entry[@name=\'{template}\']' \
                        f'/config/devices/entry[@name=\'localhost.localdomain\']/network'
    else:
        xpath_network = "/config/devices/entry[@name='localhost.localdomain']/network"
    return xpath_network, template


def prepare_security_rule_params(api_action: str = None, rulename: str = None, source: Any = None,
                                 destination: Any = None, negate_source: str = None,
                                 negate_destination: str = None, action: str = None, service: List[str] = None,
                                 disable: str = None, application: List[str] = None, source_user: str = None,
                                 category: List[str] = None, from_: str = None, to: str = None, description: str = None,
                                 target: str = None, log_forwarding: str = None,
                                 disable_server_response_inspection: str = None, tags: List[str] = None) -> Dict:
    if application is None or len(application) == 0:
        # application always must be specified and the default should be any
        application = ['any']

    rulename = rulename if rulename else ('demisto-' + (str(uuid.uuid4()))[:8])
    params = {
        'type': 'config',
        'action': api_action,
        'key': API_KEY,
        'element': add_argument_open(action, 'action', False)
                + add_argument_target(target, 'target')
                + add_argument_open(description, 'description', False)
                + add_argument_list(source, 'source', True, True)
                + add_argument_list(destination, 'destination', True, True)
                + add_argument_list(application, 'application', True)
                + add_argument_list(category, 'category', True)
                + add_argument_open(source_user, 'source-user', True)
                + add_argument_open(from_, 'from', True)  # default from will always be any
                + add_argument_open(to, 'to', True)  # default to will always be any
                + add_argument_list(service, 'service', True, True)
                + add_argument_yes_no(negate_source, 'negate-source')
                + add_argument_yes_no(negate_destination, 'negate-destination')
                + add_argument_yes_no(disable, 'disabled')
                + add_argument_yes_no(disable_server_response_inspection, 'disable-server-response-inspection', True)
                + add_argument(log_forwarding, 'log-setting', False)
                + add_argument_list(tags, 'tag', True)
    }
    if DEVICE_GROUP:
        if 'pre_post' not in demisto.args():
            raise Exception('Please provide the pre_post argument when configuring'
                            ' a security rule in Panorama instance.')
        else:
            params['xpath'] = XPATH_SECURITY_RULES + demisto.args()[
                'pre_post'] + '/security/rules/entry' + '[@name=\'' + rulename + '\']'
    else:
        params['xpath'] = XPATH_SECURITY_RULES + '[@name=\'' + rulename + '\']'
    return params


def get_pan_os_version() -> str:
    """Retrieves pan-os version

       Returns:
           String representation of the version
       """
    params = {
        'type': 'version',
        'key': API_KEY
    }
    result = http_request(URL, 'GET', params=params)
    version = result['response']['result']['sw-version']
    return version


def get_pan_os_major_version() -> int:
    """Retrieves pan-os major version

    Returns:
        String representation of the major version
    """
    major_version = int(get_pan_os_version().split('.')[0])
    return major_version


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

    if DEVICE_GROUP and DEVICE_GROUP != 'shared':
        device_group_test()

    _, template = set_xpath_network()
    if template:
        template_test(template)

    demisto.results('ok')


def get_device_groups_names():
    """
    Get device group names in the Panorama
    """
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': "/config/devices/entry/device-group/entry",
        'key': API_KEY
    }

    result = http_request(
        URL,
        'GET',
        params=params
    )

    device_groups = result['response']['result']['entry']
    device_group_names = []
    if isinstance(device_groups, dict):
        # only one device group in the panorama
        device_group_names.append(device_groups.get('@name'))
    else:
        for device_group in device_groups:
            device_group_names.append(device_group.get('@name'))

    return device_group_names


def device_group_test():
    """
    Test module for the Device group specified
    """
    device_group_names = get_device_groups_names()
    if DEVICE_GROUP not in device_group_names:
        raise Exception(f'Device Group: {DEVICE_GROUP} does not exist.'
                        f' The available Device Groups for this instance: {", ".join(device_group_names)}.')


def get_templates_names():
    """
    Get templates names in the Panorama
    """
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': "/config/devices/entry[@name=\'localhost.localdomain\']/template/entry",
        'key': API_KEY
    }

    result = http_request(
        URL,
        'GET',
        params=params
    )

    templates = result['response']['result']['entry']
    template_names = []
    if isinstance(templates, dict):
        # only one device group in the panorama
        template_names.append(templates.get('@name'))
    else:
        for template in templates:
            template_names.append(template.get('@name'))

    return template_names


def template_test(template):
    """
    Test module for the Template specified
    """
    template_names = get_templates_names()
    if template not in template_names:
        raise Exception(f'Template: {template} does not exist.'
                        f' The available Templates for this instance: {", ".join(template_names)}.')


@logger
def panorama_command():
    """
    Executes a command
    """
    params = {}
    for arg in demisto.args().keys():
        params[arg] = demisto.args()[arg]
    params['key'] = API_KEY

    result = http_request(
        URL,
        'POST',
        body=params
    )

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Command was executed successfully.',
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
        body=params
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
        raise Exception('JobID given is not of a commit.')

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

    # WARNINGS - Job warnings
    status_warnings = []
    if result.get("response", {}).get('result', {}).get('job', {}).get('warnings', {}):
        status_warnings = result.get("response", {}).get('result', {}).get('job', {}).get('warnings', {}).get('line', [])
    ignored_error = 'configured with no certificate profile'
    commit_status_output["Warnings"] = [item for item in status_warnings if item not in ignored_error]

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Commit status:', commit_status_output, ['JobID', 'Status', 'Details', 'Warnings'],
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
        body=params
    )

    return result


def panorama_push_to_device_group_command():
    """
    Push Panorama configuration and show message in warroom
    """
    if not DEVICE_GROUP:
        raise Exception("The 'panorama-push-to-device-group' command is relevant for a Palo Alto Panorama instance.")

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


def safeget(dct, keys):
    # Safe get from dictionary
    for key in keys:
        try:
            if isinstance(dct, dict):
                dct = dct[key]
            else:
                return None
        except KeyError:
            return None
    return dct


def panorama_push_status_command():
    """
    Check jobID of push status
    """
    result = panorama_push_status()
    job = result.get('response', {}).get('result', {}).get('job', {})
    if job.get('type', '') != 'CommitAll':
        raise Exception('JobID given is not of a Push.')

    push_status_output = {'JobID': job.get('id')}
    if job.get('status', '') == 'FIN':
        if job.get('result', '') == 'OK':
            push_status_output['Status'] = 'Completed'
        else:
            push_status_output['Status'] = 'Failed'

        devices = job.get('devices')
        devices = devices.get('entry') if devices else devices
        if isinstance(devices, list):
            devices_details = [device.get('status') for device in devices if device]
            push_status_output['Details'] = devices_details
        elif isinstance(devices, dict):
            push_status_output['Details'] = devices.get('status')

    if job.get('status') == 'PEND':
        push_status_output['Status'] = 'Pending'

    # WARNINGS - Job warnings
    status_warnings = []  # type: ignore
    devices = safeget(result, ["response", "result", "job", "devices", "entry"])
    if devices:
        for device in devices:
            device_warnings = safeget(device, ["details", "msg", "warnings", "line"])
            status_warnings.extend([] if not device_warnings else device_warnings)
    push_status_output["Warnings"] = status_warnings

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Push to Device Group status:', push_status_output,
                                         ['JobID', 'Status', 'Details', 'Warnings'], removeNull=True),
        'EntryContext': {"Panorama.Push(val.JobID == obj.JobID)": push_status_output}
    })


''' Addresses Commands '''


def prettify_addresses_arr(addresses_arr: list) -> List:
    if not isinstance(addresses_arr, list):
        return prettify_address(addresses_arr)
    pretty_addresses_arr = []
    for address in addresses_arr:
        pretty_address = {'Name': address['@name']}
        if DEVICE_GROUP:
            pretty_address['DeviceGroup'] = DEVICE_GROUP
        if 'description' in address:
            pretty_address['Description'] = address['description']

        if 'ip-netmask' in address:
            pretty_address['IP_Netmask'] = address['ip-netmask']

        if 'ip-range' in address:
            pretty_address['IP_Range'] = address['ip-range']

        if 'fqdn' in address:
            pretty_address['FQDN'] = address['fqdn']

        if 'tag' in address and 'member' in address['tag']:
            pretty_address['Tags'] = address['tag']['member']

        pretty_addresses_arr.append(pretty_address)

    return pretty_addresses_arr


@logger
def panorama_list_addresses(tag=None):
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "address/entry",
        'key': API_KEY
    }

    if tag:
        params['xpath'] += f'[( tag/member = \'{tag}\')]'

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
    tag = demisto.args().get('tag')

    addresses_arr = panorama_list_addresses(tag)
    addresses_output = prettify_addresses_arr(addresses_arr)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': addresses_arr,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Addresses:', addresses_output,
                                         ['Name', 'IP_Netmask', 'IP_Range', 'FQDN', 'Tags'], removeNull=True),
        'EntryContext': {
            "Panorama.Addresses(val.Name == obj.Name)": addresses_output
        }
    })


def prettify_address(address: Dict) -> Dict:
    pretty_address = {'Name': address['@name']}
    if DEVICE_GROUP:
        pretty_address['DeviceGroup'] = DEVICE_GROUP
    if 'description' in address:
        pretty_address['Description'] = address['description']

    if 'ip-netmask' in address:
        pretty_address['IP_Netmask'] = address['ip-netmask']

    if 'ip-range' in address:
        pretty_address['IP_Range'] = address['ip-range']

    if 'fqdn' in address:
        pretty_address['FQDN'] = address['fqdn']

    if 'tag' in address and 'member' in address['tag']:
        pretty_address['Tags'] = address['tag']['member']

    return pretty_address


@logger
def panorama_get_address(address_name: str) -> Dict:
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
        'HumanReadable': tableToMarkdown('Address:', address_output,
                                         ['Name', 'IP_Netmask', 'IP_Range', 'FQDN', 'Tags'], removeNull=True),
        'EntryContext': {
            "Panorama.Addresses(val.Name == obj.Name)": address_output
        }
    })


@logger
def panorama_create_address(address_name: str, fqdn: str = None, ip_netmask: str = None, ip_range: str = None,
                            description: str = None, tags: list = None):
    params = {'action': 'set',
              'type': 'config',
              'xpath': XPATH_OBJECTS + "address/entry[@name='" + address_name + "']",
              'key': API_KEY,
              'element': (add_argument(fqdn, 'fqdn', False)
                          + add_argument(ip_netmask, 'ip-netmask', False)
                          + add_argument(ip_range, 'ip-range', False)
                          + add_argument(description, 'description', False)
                          + add_argument_list(tags, 'tag', True))
              }

    http_request(
        URL,
        'POST',
        body=params,
    )


def panorama_create_address_command():
    """
    Create an address object
    """
    address_name = demisto.args()['name']
    description = demisto.args().get('description')
    tags = argToList(demisto.args()['tag']) if 'tag' in demisto.args() else None

    fqdn = demisto.args().get('fqdn')
    ip_netmask = demisto.args().get('ip_netmask')
    ip_range = demisto.args().get('ip_range')

    if not fqdn and not ip_netmask and not ip_range:
        raise Exception('Please specify exactly one of the following: fqdn, ip_netmask, ip_range.')

    if (fqdn and ip_netmask) or (fqdn and ip_range) or (ip_netmask and ip_range):
        raise Exception('Please specify exactly one of the following: fqdn, ip_netmask, ip_range.')

    address = panorama_create_address(address_name, fqdn, ip_netmask, ip_range, description, tags)

    address_output = {'Name': address_name}
    if DEVICE_GROUP:
        address_output['DeviceGroup'] = DEVICE_GROUP
    if fqdn:
        address_output['FQDN'] = fqdn
    if ip_netmask:
        address_output['IP_Netmask'] = ip_netmask
    if ip_range:
        address_output['IP_Range'] = ip_range
    if description:
        address_output['Description'] = description
    if tags:
        address_output['Tags'] = tags

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': address,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Address was created successfully.',
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
        body=params,
    )

    return result


def panorama_delete_address_command():
    """
    Delete an address
    """
    address_name = demisto.args()['name']

    address = panorama_delete_address(address_name)
    address_output = {'Name': address_name}
    if DEVICE_GROUP:
        address_output['DeviceGroup'] = DEVICE_GROUP

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': address,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Address was deleted successfully.',
        'EntryContext': {
            "Panorama.Addresses(val.Name == obj.Name)": address_output
        }
    })


''' Address Group Commands '''


def prettify_address_groups_arr(address_groups_arr: list) -> List:
    if not isinstance(address_groups_arr, list):
        return prettify_address_group(address_groups_arr)
    pretty_address_groups_arr = []
    for address_group in address_groups_arr:
        pretty_address_group = {
            'Name': address_group['@name'],
            'Type': 'static' if 'static' in address_group else 'dynamic'
        }
        if DEVICE_GROUP:
            pretty_address_group['DeviceGroup'] = DEVICE_GROUP
        if 'description' in address_group:
            pretty_address_group['Description'] = address_group['description']
        if 'tag' in address_group and 'member' in address_group['tag']:
            pretty_address_group['Tags'] = address_group['tag']['member']

        if pretty_address_group['Type'] == 'static':
            # static address groups can have empty lists
            if address_group['static']:
                pretty_address_group['Addresses'] = address_group['static']['member']
        else:
            pretty_address_group['Match'] = address_group['dynamic']['filter']

        pretty_address_groups_arr.append(pretty_address_group)

    return pretty_address_groups_arr


@logger
def panorama_list_address_groups(tag: str = None):
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "address-group/entry",
        'key': API_KEY
    }

    if tag:
        params['xpath'] += f'[( tag/member = \'{tag}\')]'

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
    tag = demisto.args().get('tag')
    address_groups_arr = panorama_list_address_groups(tag)
    address_groups_output = prettify_address_groups_arr(address_groups_arr)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': address_groups_arr,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Address groups:', address_groups_output,
                                         ['Name', 'Type', 'Addresses', 'Match', 'Description', 'Tags'],
                                         removeNull=True),
        'EntryContext': {
            "Panorama.AddressGroups(val.Name == obj.Name)": address_groups_output
        }
    })


def prettify_address_group(address_group: Dict) -> Dict:
    pretty_address_group = {
        'Name': address_group['@name'],
        'Type': 'static' if 'static' in address_group else 'dynamic'
    }
    if DEVICE_GROUP:
        pretty_address_group['DeviceGroup'] = DEVICE_GROUP

    if 'description' in address_group:
        pretty_address_group['Description'] = address_group['description']
    if 'tag' in address_group and 'member' in address_group['tag']:
        pretty_address_group['Tags'] = address_group['tag']['member']

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
                                         ['Name', 'Type', 'Addresses', 'Match', 'Description', 'Tags'],
                                         removeNull=True),
        'EntryContext': {
            "Panorama.AddressGroups(val.Name == obj.Name)": prettify_address_group(result)
        }
    })


@logger
def panorama_create_static_address_group(address_group_name: str, addresses: list,
                                         description: str = None, tags: list = None):
    params = {'action': 'set',
              'type': 'config',
              'xpath': XPATH_OBJECTS + "address-group/entry[@name='" + address_group_name + "']",
              'key': API_KEY,
              'element': (
                      "<static>" + add_argument_list(addresses, 'member', True)
                      + "</static>" + add_argument(description, 'description', False)
                      + add_argument_list(tags, 'tag', True)
              )}

    result = http_request(
        URL,
        'POST',
        body=params,
    )

    return result


def panorama_create_dynamic_address_group(address_group_name: str, match: str,
                                          description: str = None, tags: list = None):
    params = {
        'action': 'set',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "address-group/entry[@name='" + address_group_name + "']",
        'element': "<dynamic>" + add_argument(match, 'filter', False)
                   + "</dynamic>" + add_argument(description, 'description', False)
                   + add_argument_list(tags, 'tag', True),
        'key': API_KEY
    }

    result = http_request(
        URL,
        'POST',
        body=params,
    )

    return result


def panorama_create_address_group_command():
    """
    Create an address group
    """
    address_group_name = demisto.args()['name']
    type_ = demisto.args()['type']
    description = demisto.args().get('description')
    tags = argToList(demisto.args()['tags']) if 'tags' in demisto.args() else None
    match = demisto.args().get('match')
    addresses = argToList(demisto.args()['addresses']) if 'addresses' in demisto.args() else None
    if match and addresses:
        raise Exception('Please specify only one of the following: addresses, match.')
    if type_ == 'static':
        if not addresses:
            raise Exception('Please specify addresses in order to create a static address group.')
    if type_ == 'dynamic':
        if not match:
            raise Exception('Please specify a match in order to create a dynamic address group.')

    if type_ == 'static':
        result = panorama_create_static_address_group(address_group_name, addresses, description, tags)
    else:
        result = panorama_create_dynamic_address_group(address_group_name, match, description, tags)

    address_group_output = {
        'Name': address_group_name,
        'Type': type_
    }
    if DEVICE_GROUP:
        address_group_output['DeviceGroup'] = DEVICE_GROUP
    if match:
        address_group_output['Match'] = match
    if addresses:
        address_group_output['Addresses'] = addresses
    if description:
        address_group_output['Description'] = description
    if tags:
        address_group_output['Tags'] = tags

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Address group was created successfully.',
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
        body=params,
    )

    return result


def panorama_delete_address_group_command():
    """
    Delete an address group
    """
    address_group_name = demisto.args()['name']

    address_group = panorama_delete_address_group(address_group_name)
    address_group_output = {'Name': address_group_name}
    if DEVICE_GROUP:
        address_group_output['DeviceGroup'] = DEVICE_GROUP

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': address_group,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Address group was deleted successfully.',
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
            raise Exception('To edit a Dynamic Address group, Please provide a match.')
        match_param = add_argument_open(match, 'filter', False)
        match_path = XPATH_OBJECTS + "address-group/entry[@name='" + address_group_name + "']/dynamic/filter"

    if type_ == 'static':
        if (element_to_add and element_to_remove) or (not element_to_add and not element_to_remove):
            raise Exception('To edit a Static Address group,'
                            'Please specify exactly one of the following: element_to_add, element_to_remove.')
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
    tags = argToList(demisto.args()['tags']) if 'tags' in demisto.args() else None

    params = {
        'action': 'edit',
        'type': 'config',
        'key': API_KEY,
        'xpath': '',
        'element': ''
    }

    address_group_output = {'Name': address_group_name}

    if DEVICE_GROUP:
        address_group_output['DeviceGroup'] = DEVICE_GROUP

    if type_ == 'dynamic' and match:
        params['xpath'] = match_path
        params['element'] = match_param
        result = http_request(
            URL,
            'POST',
            body=params
        )
        address_group_output['Match'] = match

    if type_ == 'static' and addresses:
        params['xpath'] = addresses_path
        params['element'] = "<static>" + addresses_param + "</static>"
        result = http_request(
            URL,
            'POST',
            body=params
        )
        address_group_output['Addresses'] = addresses

    if description:
        description_param = add_argument_open(description, 'description', False)
        description_path = XPATH_OBJECTS + "address-group/entry[@name='" + address_group_name + "']/description"
        params['xpath'] = description_path
        params['element'] = description_param
        result = http_request(
            URL,
            'POST',
            body=params
        )
        address_group_output['Description'] = description

    if tags:
        tag_param = add_argument_list(tags, 'tag', True)
        tag_path = XPATH_OBJECTS + "address-group/entry[@name='" + address_group_name + "']/tag"
        params['xpath'] = tag_path
        params['element'] = tag_param
        result = http_request(
            URL,
            'POST',
            body=params
        )
        address_group_output['Tags'] = tags

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Address Group was edited successfully.',
        'EntryContext': {
            "Panorama.AddressGroups(val.Name == obj.Name)": address_group_output
        }
    })


''' Services Commands '''


def prettify_services_arr(services_arr: list):
    if not isinstance(services_arr, list):
        return prettify_service(services_arr)

    pretty_services_arr = []
    for service in services_arr:
        pretty_service = {'Name': service['@name']}
        if DEVICE_GROUP:
            pretty_service['DeviceGroup'] = DEVICE_GROUP
        if 'description' in service:
            pretty_service['Description'] = service['description']
        if 'tag' in service and 'member' in service['tag']:
            pretty_service['Tags'] = service['tag']['member']

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
def panorama_list_services(tag: str = None):
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "service/entry",
        'key': API_KEY
    }

    if tag:
        params['xpath'] += f'[( tag/member = \'{tag}\')]'

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
    tag = demisto.args().get('tag')

    services_arr = panorama_list_services(tag)
    services_output = prettify_services_arr(services_arr)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': services_arr,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Services:', services_output,
                                         ['Name', 'Protocol', 'SourcePort', 'DestinationPort', 'Description', 'Tags'],
                                         removeNull=True),
        'EntryContext': {
            "Panorama.Services(val.Name == obj.Name)": services_output
        }
    })


def prettify_service(service: Dict):
    pretty_service = {
        'Name': service['@name'],
    }
    if DEVICE_GROUP:
        pretty_service['DeviceGroup'] = DEVICE_GROUP
    if 'description' in service:
        pretty_service['Description'] = service['description']
    if 'tag' in service and 'member' in service['tag']:
        pretty_service['Tags'] = service['tag']['member']

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
                                         ['Name', 'Protocol', 'SourcePort', 'DestinationPort', 'Description', 'Tags'],
                                         removeNull=True),
        'EntryContext': {
            "Panorama.Services(val.Name == obj.Name)": service_output
        }
    })


@logger
def panorama_create_service(service_name: str, protocol: str, destination_port: str,
                            source_port: str = None, description: str = None, tags: list = None):
    params = {
        'action': 'set',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "service/entry[@name='" + service_name + "']",
        'key': API_KEY,
        'element': '<protocol>' + '<' + protocol + '>'
                   + add_argument(destination_port, 'port', False)
                   + add_argument(source_port, 'source-port', False)
                   + '</' + protocol + '>' + '</protocol>'
                   + add_argument(description, 'description', False)
                   + add_argument_list(tags, 'tag', True)
    }

    result = http_request(
        URL,
        'POST',
        body=params,
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
    tags = argToList(demisto.args()['tags']) if 'tags' in demisto.args() else None

    service = panorama_create_service(service_name, protocol, destination_port, source_port, description, tags)

    service_output = {
        'Name': service_name,
        'Protocol': protocol,
        'DestinationPort': destination_port
    }
    if DEVICE_GROUP:
        service_output['DeviceGroup'] = DEVICE_GROUP
    if source_port:
        service_output['SourcePort'] = source_port
    if description:
        service_output['Description'] = description
    if tags:
        service_output['Tags'] = tags

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': service,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Service was created successfully.',
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
        body=params,
    )

    return result


def panorama_delete_service_command():
    """
    Delete a service
    """
    service_name = demisto.args()['name']

    service = panorama_delete_service(service_name)
    service_output = {'Name': service_name}
    if DEVICE_GROUP:
        service_output['DeviceGroup'] = DEVICE_GROUP

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': service,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Service was deleted successfully.',
        'EntryContext': {
            "Panorama.Services(val.Name == obj.Name)": service_output
        }
    })


''' Service Group Commands '''


def prettify_service_groups_arr(service_groups_arr: list):
    if not isinstance(service_groups_arr, list):
        return prettify_service_group(service_groups_arr)

    pretty_service_groups_arr = []
    for service_group in service_groups_arr:
        pretty_service_group = {
            'Name': service_group['@name'],
            'Services': service_group['members']['member']
        }
        if DEVICE_GROUP:
            pretty_service_group['DeviceGroup'] = DEVICE_GROUP
        if 'tag' in service_group and 'member' in service_group['tag']:
            pretty_service_group['Tags'] = service_group['tag']['member']

        pretty_service_groups_arr.append(pretty_service_group)

    return pretty_service_groups_arr


@logger
def panorama_list_service_groups(tag: str = None):
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "service-group/entry",
        'key': API_KEY
    }

    if tag:
        params['xpath'] += f'[( tag/member = \'{tag}\')]'

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
    tag = demisto.args().get('tag')
    service_groups_arr = panorama_list_service_groups(tag)
    service_groups_output = prettify_service_groups_arr(service_groups_arr)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': service_groups_arr,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Service groups:', service_groups_output, ['Name', 'Services', 'Tags'],
                                         removeNull=True),
        'EntryContext': {
            "Panorama.ServiceGroups(val.Name == obj.Name)": service_groups_output
        }
    })


def prettify_service_group(service_group: dict):
    pretty_service_group = {
        'Name': service_group['@name'],
        'Services': service_group['members']['member']
    }
    if DEVICE_GROUP:
        pretty_service_group['DeviceGroup'] = DEVICE_GROUP
    if 'tag' in service_group and 'member' in service_group['tag']:
        pretty_service_group['Tags'] = service_group['tag']['member']

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
    pretty_service_group = prettify_service_group(result)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Service group:', pretty_service_group, ['Name', 'Services', 'Tags'],
                                         removeNull=True),
        'EntryContext': {
            "Panorama.ServiceGroups(val.Name == obj.Name)": pretty_service_group
        }
    })


def panorama_create_service_group(service_group_name, services, tags):
    params = {
        'action': 'set',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "service-group/entry[@name='" + service_group_name + "']",
        'element': '<members>' + add_argument_list(services, 'member', True) + '</members>'
                   + add_argument_list(tags, 'tag', True),
        'key': API_KEY
    }

    result = http_request(
        URL,
        'POST',
        body=params,
    )

    return result


def panorama_create_service_group_command():
    """
    Create a service group
    """
    service_group_name = demisto.args()['name']
    services = argToList(demisto.args()['services'])
    tags = argToList(demisto.args()['tags']) if 'tags' in demisto.args() else None

    result = panorama_create_service_group(service_group_name, services, tags)

    service_group_output = {
        'Name': service_group_name,
        'Services': services
    }
    if DEVICE_GROUP:
        service_group_output['DeviceGroup'] = DEVICE_GROUP
    if tags:
        service_group_output['Tags'] = tags

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Service group was created successfully.',
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
        body=params,
    )

    return result


def panorama_delete_service_group_command():
    """
    Delete a service group
    """
    service_group_name = demisto.args()['name']

    service_group = panorama_delete_service_group(service_group_name)
    service_group_output = {'Name': service_group_name}
    if DEVICE_GROUP:
        service_group_output['DeviceGroup'] = DEVICE_GROUP

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': service_group,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Service group was deleted successfully.',
        'EntryContext': {
            "Panorama.ServiceGroups(val.Name == obj.Name)": service_group_output
        }
    })


@logger
def panorama_edit_service_group(service_group_name, services, tag):
    params = {
        'action': 'edit',
        'type': 'config',
        'xpath': '',
        'element': '',
        'key': API_KEY,
    }

    if services:
        services_xpath = XPATH_OBJECTS + "service-group/entry[@name='" + service_group_name + "']/members"
        services_element = '<members>' + add_argument_list(services, 'member', False) + '</members>'
        params['xpath'] = services_xpath
        params['element'] = services_element
        result = http_request(
            URL,
            'POST',
            body=params
        )

    if tag:
        tag_xpath = XPATH_OBJECTS + "service-group/entry[@name='" + service_group_name + "']/tag"
        tag_element = add_argument_list(tag, 'tag', True)
        params['xpath'] = tag_xpath
        params['element'] = tag_element
        result = http_request(
            URL,
            'POST',
            body=params
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
    tag = argToList(demisto.args()['tag']) if 'tag' in demisto.args() else None

    if not services_to_add and not services_to_remove and not tag:
        raise Exception('Specify at least one of the following arguments: services_to_add, services_to_remove, tag')

    if services_to_add and services_to_remove:
        raise Exception('Specify at most one of the following arguments: services_to_add, services_to_remove')

    services: List[str] = []
    if services_to_add or services_to_remove:
        service_group_prev = panorama_get_service_group(service_group_name)
        service_group_list = argToList(service_group_prev['members']['member'])
        if services_to_add:
            services = list(set(services_to_add + service_group_list))
        else:
            services = [item for item in service_group_list if item not in services_to_remove]

        if len(services) == 0:
            raise Exception('A Service group must have at least one service.')

    result = panorama_edit_service_group(service_group_name, services, tag)

    service_group_output = {'Name': service_group_name}
    if DEVICE_GROUP:
        service_group_output['DeviceGroup'] = DEVICE_GROUP
    if len(services) > 0:
        service_group_output['Services'] = services
    if tag:
        service_group_output['Tag'] = tag

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Service group was edited successfully.',
        'EntryContext': {
            "Panorama.ServiceGroups(val.Name == obj.Name)": service_group_output
        }
    })


''' Custom URL Category Commands '''


def prettify_custom_url_category(custom_url_category):
    pretty_custom_url_category = {
        'Name': custom_url_category['@name'],
    }
    if DEVICE_GROUP:
        pretty_custom_url_category['DeviceGroup'] = DEVICE_GROUP

    if 'description' in custom_url_category:
        pretty_custom_url_category['Description'] = custom_url_category['description']

    #  In PAN-OS 9.X changes to the default behavior were introduced regarding custom url categories.
    if 'type' in custom_url_category:
        pretty_custom_url_category['Type'] = custom_url_category['type']
        if pretty_custom_url_category['Type'] == 'Category Match':
            pretty_custom_url_category['Categories'] = custom_url_category['list']['member']
        else:
            pretty_custom_url_category['Sites'] = custom_url_category['list']['member']
    else:
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
                                         ['Name', 'Type', 'Categories', 'Sites', 'Description'], removeNull=True),
        'EntryContext': {
            "Panorama.CustomURLCategory(val.Name == obj.Name)": custom_url_category_output
        }
    })


@logger
def panorama_create_custom_url_category(custom_url_category_name: str, type_: Any = None,
                                        sites=None, categories=None, description: str = None):
    #  In PAN-OS 9.X changes to the default behavior were introduced regarding custom url categories.
    major_version = get_pan_os_major_version()
    element = add_argument(description, 'description', False)
    if major_version <= 8:
        if type_ or categories:
            raise Exception('The type and categories arguments are only relevant for PAN-OS 9.x versions.')
        element += add_argument_list(sites, 'list', True)
    else:  # major is 9.x
        if not type_:
            raise Exception('The type argument is mandatory for PAN-OS 9.x versions.')
        if (not sites and not categories) or (sites and categories):
            raise Exception('Exactly one of the sites and categories arguments should be defined.')
        if (type_ == 'URL List' and categories) or (type_ == 'Category Match' and sites):
            raise Exception('URL List type is only for sites, Category Match is only for categories.')

        if type_ == 'URL List':
            element += add_argument_list(sites, 'list', True)
        else:
            element += add_argument_list(categories, 'list', True)
        element += add_argument(type_, 'type', False)

    params = {
        'action': 'set',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "profiles/custom-url-category/entry[@name='" + custom_url_category_name + "']",
        'element': element,
        'key': API_KEY
    }
    result = http_request(
        URL,
        'POST',
        body=params,
    )

    custom_url_category_output = {'Name': custom_url_category_name}
    if DEVICE_GROUP:
        custom_url_category_output['DeviceGroup'] = DEVICE_GROUP
    if description:
        custom_url_category_output['Description'] = description
    if type_:
        custom_url_category_output['Type'] = type_
    if sites:
        custom_url_category_output['Sites'] = sites
    else:
        custom_url_category_output['Categories'] = categories
    return result, custom_url_category_output


def panorama_create_custom_url_category_command():
    """
    Create a custom URL category
    """
    custom_url_category_name = demisto.args()['name']
    type_ = demisto.args()['type'] if 'type' in demisto.args() else None
    sites = argToList(demisto.args()['sites']) if 'sites' in demisto.args() else None
    categories = argToList(demisto.args()['categories']) if 'categories' in demisto.args() else None
    description = demisto.args().get('description')

    custom_url_category, custom_url_category_output = panorama_create_custom_url_category(custom_url_category_name,
                                                                                          type_, sites, categories,
                                                                                          description)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': custom_url_category,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Created Custom URL Category:', custom_url_category_output,
                                         ['Name', 'Type', 'Categories', 'Sites', 'Description'], removeNull=True),
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
        body=params,
    )

    return result


def panorama_delete_custom_url_category_command():
    """
    Delete a custom url category
    """
    custom_url_category_name = demisto.args()['name']

    result = panorama_delete_custom_url_category(custom_url_category_name)
    custom_url_category_output = {'Name': custom_url_category_name}
    if DEVICE_GROUP:
        custom_url_category_output['DeviceGroup'] = DEVICE_GROUP

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Custom URL category was deleted successfully.',
        'EntryContext': {
            "Panorama.CustomURLCategory(val.Name == obj.Name)": custom_url_category_output
        }
    })


@logger
def panorama_edit_custom_url_category(custom_url_category_name, type_, items, description=None):
    major_version = get_pan_os_major_version()
    description_element = add_argument(description, 'description', False)
    items_element = add_argument_list(items, 'list', True)

    if major_version <= 8:
        if type_ == 'Category Match':
            raise Exception('The Categories argument is only relevant for PAN-OS 9.x versions.')
        element = f"<entry name='{custom_url_category_name}'>{description_element}{items_element}</entry>"
    else:
        type_element = add_argument(type_, 'type', False)
        element = f"<entry name='{custom_url_category_name}'>{description_element}{items_element}{type_element}</entry>"

    params = {
        'action': 'edit',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "profiles/custom-url-category/entry[@name='" + custom_url_category_name + "']",
        'element': element,
        'key': API_KEY
    }
    result = http_request(
        URL,
        'POST',
        body=params,
    )

    custom_url_category_output = {'Name': custom_url_category_name,
                                  'Type': type_}
    if DEVICE_GROUP:
        custom_url_category_output['DeviceGroup'] = DEVICE_GROUP
    if description:
        custom_url_category_output['Description'] = description
    if type_ == 'Category Match':
        custom_url_category_output['Categories'] = items
    else:
        custom_url_category_output['Sites'] = items

    return result, custom_url_category_output


def panorama_custom_url_category_add_items(custom_url_category_name, items, type_):
    """
    Add sites or categories to a configured custom url category
    """
    custom_url_category = panorama_get_custom_url_category(custom_url_category_name)
    if '@dirtyId' in custom_url_category:
        LOG(f'Found uncommitted item:\n{custom_url_category}')
        raise Exception('Please commit the instance prior to editing the Custom URL Category.')
    description = custom_url_category.get('description')

    custom_url_category_items: List[str] = []
    if 'list' in custom_url_category:
        if custom_url_category['list']:
            custom_url_category_items = argToList(custom_url_category['list']['member'])

    merged_items = list((set(items)).union(set(custom_url_category_items)))

    result, custom_url_category_output = panorama_edit_custom_url_category(custom_url_category_name, type_,
                                                                           merged_items, description)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Updated Custom URL Category:', custom_url_category_output,
                                         ['Name', 'Type', 'Categories', 'Sites', 'Description'], removeNull=True),
        'EntryContext': {
            "Panorama.CustomURLCategory(val.Name == obj.Name)": custom_url_category_output
        }
    })


def panorama_custom_url_category_remove_items(custom_url_category_name, items, type_):
    """
    Add sites or categories to a configured custom url category
    """
    custom_url_category = panorama_get_custom_url_category(custom_url_category_name)
    if '@dirtyId' in custom_url_category:
        LOG(f'Found uncommitted item:\n{custom_url_category}')
        raise Exception('Please commit the instance prior to editing the Custom URL Category.')
    description = custom_url_category.get('description')

    if 'list' in custom_url_category:
        if 'member' in custom_url_category['list']:
            custom_url_category_items = custom_url_category['list']['member']
    if not custom_url_category_items:
        raise Exception('Custom url category does not contain sites or categories.')

    subtracted_items = [item for item in custom_url_category_items if item not in items]
    result, custom_url_category_output = panorama_edit_custom_url_category(custom_url_category_name, type_,
                                                                           subtracted_items, description)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Updated Custom URL Category:', custom_url_category_output,
                                         ['Name', 'Categories', 'Sites', 'Description'], removeNull=True),
        'EntryContext': {
            "Panorama.CustomURLCategory(val.Name == obj.Name)": custom_url_category_output
        }
    })


def panorama_edit_custom_url_category_command():
    custom_url_category_name = demisto.args()['name']
    items = argToList(demisto.args()['sites']) if 'sites' in demisto.args() else argToList(demisto.args()['categories'])
    type_ = "URL List" if 'sites' in demisto.args() else "Category Match"
    if demisto.args()['action'] == 'remove':
        panorama_custom_url_category_remove_items(custom_url_category_name, items, type_)
    else:
        panorama_custom_url_category_add_items(custom_url_category_name, items, type_)


''' URL Filtering '''


@logger
def panorama_get_url_category(url_cmd, url):
    params = {
        'action': 'show',
        'type': 'op',
        'key': API_KEY,
        'cmd': f'<test><{url_cmd}>{url}</{url_cmd}></test>'
    }
    raw_result = http_request(
        URL,
        'POST',
        body=params,
    )
    result = raw_result['response']['result']
    if url_cmd == 'url-info-host':
        category = result.split(': ')[1]
    else:
        result = result.splitlines()[1]
        if url_cmd == 'url':
            category = result.split(' ')[1]
        else:  # url-info-cloud
            category = result.split(',')[3]
    return category


def populate_url_filter_category_from_context(category):
    url_filter_category = demisto.dt(demisto.context(), f'Panorama.URLFilter(val.Category === "{category}")')
    if not url_filter_category:
        return []

    if type(url_filter_category) is list:
        return url_filter_category[0].get("URL")
    else:  # url_filter_category is a dict
        context_urls = url_filter_category.get("URL", None)  # pylint: disable=no-member
        if type(context_urls) is str:
            return [context_urls]
        else:
            return context_urls


def panorama_get_url_category_command(url_cmd: str):
    """
    Get the url category from Palo Alto URL Filtering
    """
    urls = argToList(demisto.args()['url'])

    categories_dict: Dict[str, list] = {}
    categories_dict_hr: Dict[str, list] = {}
    for url in urls:
        category = panorama_get_url_category(url_cmd, url)
        if category in categories_dict:
            categories_dict[category].append(url)
            categories_dict_hr[category].append(url)
        else:
            categories_dict[category] = [url]
            categories_dict_hr[category] = [url]
        context_urls = populate_url_filter_category_from_context(category)
        categories_dict[category] = list((set(categories_dict[category])).union(set(context_urls)))

    url_category_output_hr = []
    for key, value in categories_dict_hr.items():
        url_category_output_hr.append({
            'Category': key,
            'URL': value
        })

    url_category_output = []
    for key, value in categories_dict.items():
        url_category_output.append({
            'Category': key,
            'URL': value
        })

    title = 'URL Filtering'
    if url_cmd == 'url-info-cloud':
        title += ' from cloud'
    elif url_cmd == 'url-info-host':
        title += ' from host'
    human_readable = tableToMarkdown(f'{title}:', url_category_output_hr, ['URL', 'Category'], removeNull=True)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': categories_dict,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            "Panorama.URLFilter(val.Category === obj.Category)": url_category_output
        }
    })


''' URL Filter '''


def prettify_get_url_filter(url_filter):
    pretty_url_filter = {'Name': url_filter['@name']}
    if DEVICE_GROUP:
        pretty_url_filter['DeviceGroup'] = DEVICE_GROUP
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
        body=params,
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
    if DEVICE_GROUP:
        url_filter_output['DeviceGroup'] = DEVICE_GROUP
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
        'HumanReadable': 'URL Filter was created successfully.',
        'EntryContext': {
            "Panorama.URLFilter(val.Name == obj.Name)": url_filter_output
        }
    })


@logger
def panorama_edit_url_filter(url_filter_name, element_to_change, element_value, add_remove_element=None):
    url_filter_prev = panorama_get_url_filter(url_filter_name)
    if '@dirtyId' in url_filter_prev:
        LOG(f'Found uncommitted item:\n{url_filter_prev}')
        raise Exception('Please commit the instance prior to editing the URL Filter.')

    url_filter_output = {'Name': url_filter_name}
    if DEVICE_GROUP:
        url_filter_output['DeviceGroup'] = DEVICE_GROUP
    params = {
        'action': 'edit',
        'type': 'config',
        'key': API_KEY,
    }

    if element_to_change == 'description':
        params['xpath'] = XPATH_OBJECTS + "profiles/url-filtering/entry[@name='" + url_filter_name + "']/"
        + element_to_change
        params['element'] = add_argument_open(element_value, 'description', False)
        result = http_request(URL, 'POST', body=params)
        url_filter_output['Description'] = element_value

    elif element_to_change == 'override_allow_list':
        prev_override_allow_list = argToList(url_filter_prev['allow-list']['member'])
        if add_remove_element == 'add':
            new_override_allow_list = list((set(prev_override_allow_list)).union(set([element_value])))
        else:
            new_override_allow_list = [url for url in prev_override_allow_list if url != element_value]

        params['xpath'] = XPATH_OBJECTS + "profiles/url-filtering/entry[@name='" + url_filter_name + "']/allow-list"
        params['element'] = add_argument_list(new_override_allow_list, 'allow-list', True)
        result = http_request(URL, 'POST', body=params)
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
        result = http_request(URL, 'POST', body=params)
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
        'HumanReadable': 'URL Filter was edited successfully.',
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
        body=params,
    )

    return result


def panorama_delete_url_filter_command():
    """
    Delete a custom url category
    """
    url_filter_name = demisto.args()['name']
    result = panorama_delete_url_filter(url_filter_name)

    url_filter_output = {'Name': url_filter_name}
    if DEVICE_GROUP:
        url_filter_output['DeviceGroup'] = DEVICE_GROUP

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'URL Filter was deleted successfully.',
        'EntryContext': {
            "Panorama.URLFilter(val.Name == obj.Name)": url_filter_output
        }
    })


''' Security Rules Managing '''


def prettify_rule(rule):
    pretty_rule = {
        'Name': rule['@name'],
        'Action': rule['action']
    }
    if DEVICE_GROUP:
        pretty_rule['DeviceGroup'] = DEVICE_GROUP
    if '@loc' in rule:
        pretty_rule['Location'] = rule['@loc']
    if 'category' in rule and 'member' in rule['category']:
        pretty_rule['CustomUrlCategory'] = rule['category']['member']
    if 'application' in rule and 'member' in rule['application']:
        pretty_rule['Application'] = rule['application']['member']
    if 'destination' in rule and 'member' in rule['destination']:
        pretty_rule['Destination'] = rule['destination']['member']
    if 'from' in rule and 'member' in rule['from']:
        pretty_rule['From'] = rule['from']['member']
    if 'service' in rule and 'member' in rule['service']:
        pretty_rule['Service'] = rule['service']['member']
    if 'to' in rule and 'member' in rule['to']:
        pretty_rule['To'] = rule['to']['member']
    if 'source' in rule and 'member' in rule['source']:
        pretty_rule['Source'] = rule['source']['member']
    if 'tag' in rule and 'member' in rule['tag']:
        pretty_rule['Tags'] = rule['tag']['member']
    if 'log-setting' in rule and '#text' in rule['log-setting']:
        pretty_rule['LogForwardingProfile'] = rule['log-setting']['#text']

    return pretty_rule


def prettify_rules(rules):
    if not isinstance(rules, list):
        return prettify_rule(rules)
    pretty_rules_arr = []
    for rule in rules:
        pretty_rule = prettify_rule(rule)
        pretty_rules_arr.append(pretty_rule)

    return pretty_rules_arr


@logger
def panorama_list_rules(xpath: str, tag: str = None):
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': xpath,
        'key': API_KEY
    }

    if tag:
        params['xpath'] += f'[( tag/member = \'{tag}\')]'

    result = http_request(
        URL,
        'GET',
        params=params,
    )

    return result['response']['result']['entry']


def panorama_list_rules_command():
    """
    List security rules
    """
    if DEVICE_GROUP:
        if 'pre_post' not in demisto.args():
            raise Exception('Please provide the pre_post argument when listing rules in Panorama instance.')
        else:
            xpath = XPATH_SECURITY_RULES + demisto.args()['pre_post'] + '/security/rules/entry'
    else:
        xpath = XPATH_SECURITY_RULES

    tag = demisto.args().get('tag')

    rules = panorama_list_rules(xpath, tag)
    pretty_rules = prettify_rules(rules)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': rules,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Security Rules:', pretty_rules,
                                         ['Name', 'Location', 'Action', 'From', 'To',
                                          'CustomUrlCategory', 'Service', 'Tags'],
                                         removeNull=True),
        'EntryContext': {
            "Panorama.SecurityRule(val.Name == obj.Name)": pretty_rules
        }
    })


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
            raise Exception('Please provide the pre_post argument when moving a rule in Panorama instance.')
        else:
            params['xpath'] = XPATH_SECURITY_RULES + demisto.args()[
                'pre_post'] + '/security/rules/entry' + '[@name=\'' + rulename + '\']'
    else:
        params['xpath'] = XPATH_SECURITY_RULES + '[@name=\'' + rulename + '\']'

    if 'dst' in demisto.args():
        params['dst'] = demisto.args()['dst']

    result = http_request(URL, 'POST', body=params)
    rule_output = {'Name': rulename}
    if DEVICE_GROUP:
        rule_output['DeviceGroup'] = DEVICE_GROUP

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Rule ' + rulename + ' moved successfully.',
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
    source = argToList(demisto.args().get('source'))
    destination = argToList(demisto.args().get('destination'))
    negate_source = demisto.args().get('negate_source')
    negate_destination = demisto.args().get('negate_destination')
    action = demisto.args().get('action')
    service = demisto.args().get('service')
    disable = demisto.args().get('disable')
    categories = argToList(demisto.args().get('category'))
    application = argToList(demisto.args().get('application'))
    source_user = demisto.args().get('source_user')
    disable_server_response_inspection = demisto.args().get('disable_server_response_inspection')
    description = demisto.args().get('description')
    target = demisto.args().get('target')
    log_forwarding = demisto.args().get('log_forwarding', None)
    tags = argToList(demisto.args()['tags']) if 'tags' in demisto.args() else None

    if not DEVICE_GROUP:
        if target:
            raise Exception('The target argument is relevant only for a Palo Alto Panorama instance.')
        elif log_forwarding:
            raise Exception('The log_forwarding argument is relevant only for a Palo Alto Panorama instance.')

    params = prepare_security_rule_params(api_action='set', rulename=rulename, source=source, destination=destination,
                                          negate_source=negate_source, negate_destination=negate_destination,
                                          action=action, service=service,
                                          disable=disable, application=application, source_user=source_user,
                                          disable_server_response_inspection=disable_server_response_inspection,
                                          description=description, target=target,
                                          log_forwarding=log_forwarding, tags=tags, category=categories)
    result = http_request(
        URL,
        'POST',
        body=params
    )

    rule_output = {SECURITY_RULE_ARGS[key]: value for key, value in demisto.args().items() if key in SECURITY_RULE_ARGS}
    rule_output['Name'] = rulename
    if DEVICE_GROUP:
        rule_output['DeviceGroup'] = DEVICE_GROUP

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Rule configured successfully.',
        'EntryContext': {
            "Panorama.SecurityRule(val.Name == obj.Name)": rule_output
        }
    })


@logger
def panorama_get_current_element(element_to_change: str, xpath: str) -> list:
    """
    Get the current element value from
    """
    params = {
        'type': 'config',
        'action': 'get',
        'xpath': xpath,
        'key': API_KEY
    }
    try:
        response = http_request(URL, 'GET', params=params)
    except PAN_OS_Not_Found:
        return []

    result = response.get('response').get('result')
    if '@dirtyId' in result:
        LOG(f'Found uncommitted item:\n{result}')
        raise Exception('Please commit the instance prior to editing the Security rule.')
    current_object = result.get(element_to_change)
    if 'list' in current_object:
        current_objects_items = argToList(current_object['list']['member'])
    elif 'member' in current_object:
        current_objects_items = argToList(current_object.get('member'))

    return current_objects_items


@logger
def panorama_edit_rule_items(rulename: str, element_to_change: str, element_value: List[str], behaviour: str):
    listable_elements = ['source', 'destination', 'application', 'category', 'source-user', 'service', 'tag']
    if element_to_change not in listable_elements:
        raise Exception(f'Adding objects is only available for the following Objects types:{listable_elements}')
    if element_to_change == 'target' and not DEVICE_GROUP:
        raise Exception('The target argument is relevant only for a Palo Alto Panorama instance.')

    params = {
        'type': 'config',
        'action': 'edit',
        'key': API_KEY
    }

    if DEVICE_GROUP:
        if 'pre_post' not in demisto.args():
            raise Exception('please provide the pre_post argument when editing a rule in Panorama instance.')
        else:
            params['xpath'] = XPATH_SECURITY_RULES + demisto.args()[
                'pre_post'] + '/security/rules/entry' + '[@name=\'' + rulename + '\']'
    else:
        params['xpath'] = XPATH_SECURITY_RULES + '[@name=\'' + rulename + '\']'
    params['xpath'] += '/' + element_to_change

    current_objects_items = panorama_get_current_element(element_to_change, params['xpath'])
    if behaviour == 'add':
        values = list((set(current_objects_items)).union(set(element_value)))
    else:  # remove
        values = [item for item in current_objects_items if item not in element_value]
        if not values:
            raise Exception(f'The object: {element_to_change} must have at least one item.')

    params['element'] = add_argument_list(values, element_to_change, True)
    result = http_request(URL, 'POST', body=params)
    rule_output = {
        'Name': rulename,
        SECURITY_RULE_ARGS[element_to_change]: values
    }
    if DEVICE_GROUP:
        rule_output['DeviceGroup'] = DEVICE_GROUP

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Rule edited successfully.',
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
    if element_to_change == 'log-forwarding':
        element_to_change = 'log-setting'
    element_value = demisto.args()['element_value']

    if element_to_change == 'target' and not DEVICE_GROUP:
        raise Exception('The target argument is relevant only for a Palo Alto Panorama instance.')

    behaviour = demisto.args().get('behaviour') if 'behaviour' in demisto.args() else 'replace'
    if behaviour != 'replace':
        panorama_edit_rule_items(rulename, element_to_change, argToList(element_value), behaviour)
    else:
        params = {
            'type': 'config',
            'action': 'edit',
            'key': API_KEY
        }

        if element_to_change in ['action', 'description', 'log-setting']:
            params['element'] = add_argument_open(element_value, element_to_change, False)
        elif element_to_change in ['source', 'destination', 'application', 'category', 'source-user', 'service', 'tag']:
            element_value = argToList(element_value)
            params['element'] = add_argument_list(element_value, element_to_change, True)
        elif element_to_change == 'target':
            params['element'] = add_argument_target(element_value, 'target')
        else:
            params['element'] = add_argument_yes_no(element_value, element_to_change)

        if DEVICE_GROUP:
            if 'pre_post' not in demisto.args():
                raise Exception('please provide the pre_post argument when editing a rule in Panorama instance.')
            else:
                params['xpath'] = XPATH_SECURITY_RULES + demisto.args()[
                    'pre_post'] + '/security/rules/entry' + '[@name=\'' + rulename + '\']'
        else:
            params['xpath'] = XPATH_SECURITY_RULES + '[@name=\'' + rulename + '\']'
        params['xpath'] += '/' + element_to_change

        result = http_request(URL, 'POST', body=params)

        rule_output = {
            'Name': rulename,
            SECURITY_RULE_ARGS[element_to_change]: element_value
        }
        if DEVICE_GROUP:
            rule_output['DeviceGroup'] = DEVICE_GROUP

        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': result,
            'ReadableContentsFormat': formats['text'],
            'HumanReadable': 'Rule edited successfully.',
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
            raise Exception('Please provide the pre_post argument when moving a rule in Panorama instance.')
        else:
            params['xpath'] = XPATH_SECURITY_RULES + demisto.args()[
                'pre_post'] + '/security/rules/entry' + '[@name=\'' + rulename + '\']'
    else:
        params['xpath'] = XPATH_SECURITY_RULES + '[@name=\'' + rulename + '\']'

    result = http_request(
        URL,
        'POST',
        body=params
    )

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Rule deleted successfully.',
    })


@logger
def panorama_custom_block_rule_command():
    """
    Block an object in Panorama
    """
    object_type = demisto.args()['object_type']
    object_value = argToList(demisto.args()['object_value'])
    direction = demisto.args()['direction'] if 'direction' in demisto.args() else 'both'
    rulename = demisto.args()['rulename'] if 'rulename' in demisto.args() else ('demisto-' + (str(uuid.uuid4()))[:8])
    block_destination = False if direction == 'from' else True
    block_source = False if direction == 'to' else True
    target = argToList(demisto.args().get('target')) if 'target' in demisto.args() else None
    log_forwarding = demisto.args().get('log_forwarding', None)
    tags = argToList(demisto.args()['tags']) if 'tags' in demisto.args() else None

    if not DEVICE_GROUP:
        if target:
            raise Exception('The target argument is relevant only for a Palo Alto Panorama instance.')
        elif log_forwarding:
            raise Exception('The log_forwarding argument is relevant only for a Palo Alto Panorama instance.')

    custom_block_output = {
        'Name': rulename,
        'Direction': direction,
        'Disabled': False
    }
    if DEVICE_GROUP:
        custom_block_output['DeviceGroup'] = DEVICE_GROUP
    if log_forwarding:
        custom_block_output['LogForwarding'] = log_forwarding
    if target:
        custom_block_output['Target'] = target
    if tags:
        custom_block_output['Tags'] = tags

    if object_type == 'ip':
        if block_source:
            params = prepare_security_rule_params(api_action='set', action='drop', source=object_value,
                                                  destination=['any'], rulename=rulename + '-from', target=target,
                                                  log_forwarding=log_forwarding, tags=tags)
            result = http_request(URL, 'POST', body=params)
        if block_destination:
            params = prepare_security_rule_params(api_action='set', action='drop', destination=object_value,
                                                  source=['any'], rulename=rulename + '-to', target=target,
                                                  log_forwarding=log_forwarding, tags=tags)
            result = http_request(URL, 'POST', body=params)
        custom_block_output['IP'] = object_value

    elif object_type in ['address-group', 'edl']:
        if block_source:
            params = prepare_security_rule_params(api_action='set', action='drop', source=object_value,
                                                  destination=['any'], rulename=rulename + '-from', target=target,
                                                  log_forwarding=log_forwarding, tags=tags)
            result = http_request(URL, 'POST', body=params)
        if block_destination:
            params = prepare_security_rule_params(api_action='set', action='drop', destination=object_value,
                                                  source=['any'], rulename=rulename + '-to', target=target,
                                                  log_forwarding=log_forwarding, tags=tags)
            result = http_request(URL, 'POST', body=params)
        custom_block_output['AddressGroup'] = object_value

    elif object_type == 'url-category':
        params = prepare_security_rule_params(api_action='set', action='drop', source=['any'], destination=['any'],
                                              category=object_value, rulename=rulename, target=target,
                                              log_forwarding=log_forwarding, tags=tags)
        result = http_request(URL, 'POST', body=params)
        custom_block_output['CustomURLCategory'] = object_value

    elif object_type == 'application':
        params = prepare_security_rule_params(api_action='set', action='drop', source=['any'], destination=['any'],
                                              application=object_value, rulename=rulename, target=target,
                                              log_forwarding=log_forwarding, tags=tags)
        result = http_request(URL, 'POST', body=params)
        custom_block_output['Application'] = object_value

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Object was blocked successfully.',
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
    if DEVICE_GROUP:
        raise Exception('PCAP listing is only supported on Firewall (not Panorama).')
    pcap_type = demisto.args()['pcapType']
    params = {
        'type': 'export',
        'key': API_KEY,
        'category': pcap_type
    }

    if 'password' in demisto.args():
        params['dlp-password'] = demisto.args()['password']
    elif demisto.args()['pcapType'] == 'dlp-pcap':
        raise Exception('can not provide dlp-pcap without password')

    result = http_request(URL, 'GET', params=params)
    json_result = json.loads(xml2json(result.text))['response']
    if json_result['@status'] != 'success':
        raise Exception('Request to get list of Pcaps Failed.\nStatus code: ' + str(
            json_result['response']['@code']) + '\nWith message: ' + str(json_result['response']['msg']['line']))

    dir_listing = json_result['result']['dir-listing']
    if 'file' not in dir_listing:
        demisto.results(f'PAN-OS has no Pcaps of type: {pcap_type}.')
    else:
        pcaps = dir_listing['file']
        pcap_list = [pcap[1:] for pcap in pcaps]
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


def validate_search_time(search_time: str) -> str:
    """
    Validate search_time is of format YYYY/MM/DD HH:MM:SS or YYYY/MM/DD and pad with zeroes
    """
    try:
        datetime.strptime(search_time, '%Y/%m/%d')
        search_time += ' 00:00:00'
        return search_time
    except ValueError:
        pass
    try:
        datetime.strptime(search_time, '%Y/%m/%d %H:%M:%S')
        return search_time
    except ValueError as err:
        raise ValueError(f"Incorrect data format. searchTime should be of: YYYY/MM/DD HH:MM:SS or YYYY/MM/DD.\n"
                         f"Error is: {str(err)}")


@logger
def panorama_get_pcap_command():
    """
    Get pcap file
    """
    if DEVICE_GROUP:
        raise Exception('Getting a PCAP file is only supported on Firewall (not Panorama).')
    pcap_type = demisto.args()['pcapType']
    params = {
        'type': 'export',
        'key': API_KEY,
        'category': pcap_type
    }

    password = demisto.args().get('password')
    pcap_id = demisto.args().get('pcapID')
    search_time = demisto.args().get('searchTime')
    if pcap_type == 'dlp-pcap' and not password:
        raise Exception('Can not provide dlp-pcap without password.')
    else:
        params['dlp-password'] = password
    if pcap_type == 'threat-pcap' and (not pcap_id or not search_time):
        raise Exception('Can not provide threat-pcap without pcap-id and the searchTime arguments.')

    pcap_name = demisto.args().get('from')
    local_name = demisto.args().get('localName')
    serial_no = demisto.args().get('serialNo')
    search_time = demisto.args().get('searchTime')

    file_name = None
    if pcap_id:
        params['pcap-id'] = pcap_id
    if pcap_name:
        params['from'] = pcap_name
        file_name = pcap_name
    if local_name:
        params['to'] = local_name
        file_name = local_name
    if serial_no:
        params['serialno'] = serial_no
    if search_time:
        search_time = validate_search_time(search_time)
        params['search-time'] = search_time
    # set file name to the current time if from/to were not specified
    if not file_name:
        file_name = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')

    result = http_request(URL, 'GET', params=params)

    # due pcap file size limitation in the product, for more details, please see the documentation.
    if result.headers['Content-Type'] != 'application/octet-stream':
        raise Exception(
            'PCAP download failed. Most likely cause is the file size limitation.\n'
            'For information on how to download manually, see the documentation for this integration.')

    file = fileResult(file_name + ".pcap", result.content)
    demisto.results(file)


''' Applications '''


def prettify_applications_arr(applications_arr):
    pretty_application_arr = []
    if not isinstance(applications_arr, list):
        applications_arr = [applications_arr]
    for i in range(len(applications_arr)):
        application = applications_arr[i]
        pretty_application_arr.append({
            'SubCategory': application.get('subcategory'),
            'Risk': application.get('risk'),
            'Technology': application.get('technology'),
            'Name': application.get('@name'),
            'Description': application.get('description'),
            'Id': application.get('@id'),
        })
    return pretty_application_arr


@logger
def panorama_list_applications(predefined: bool):
    major_version = get_pan_os_major_version()
    params = {
        'type': 'config',
        'action': 'get',
        'key': API_KEY
    }
    if predefined:
        if major_version < 9:
            raise Exception('Listing predefined applications is only available for PAN-OS 9.X and above versions.')
        else:
            params['xpath'] = '/config/predefined/application'
    else:
        params['xpath'] = XPATH_OBJECTS + "application/entry"

    result = http_request(
        URL,
        'POST',
        body=params
    )
    applications = result['response']['result']
    if predefined:
        application_arr = applications.get('application', {}).get('entry')
    else:
        if major_version < 9:
            application_arr = applications.get('entry')
        else:
            application_arr = applications.get('application')

    return application_arr


def panorama_list_applications_command():
    """
    List all applications
    """
    predefined = str(demisto.args().get('predefined', '')) == 'true'
    applications_arr = panorama_list_applications(predefined)
    applications_arr_output = prettify_applications_arr(applications_arr)
    headers = ['Id', 'Name', 'Risk', 'Category', 'SubCategory', 'Technology', 'Description']

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': applications_arr,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Applications', t=applications_arr_output, headers=headers),
        'EntryContext': {
            "Panorama.Applications(val.Name == obj.Name)": applications_arr_output
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

        if DEVICE_GROUP:
            pretty_edl['DeviceGroup'] = DEVICE_GROUP

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

    if DEVICE_GROUP:
        pretty_edl['DeviceGroup'] = DEVICE_GROUP

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
        body=params,
    )

    return result


def panorama_create_edl_command():
    """
    Create an edl object
    """
    edl_name = demisto.args().get('name')
    url = demisto.args().get('url').replace(' ', '%20')
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

    if DEVICE_GROUP:
        edl_output['DeviceGroup'] = DEVICE_GROUP
    if description:
        edl_output['Description'] = description
    if certificate_profile:
        edl_output['CertificateProfile'] = certificate_profile

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': edl,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'External Dynamic List was created successfully.',
        'EntryContext': {
            "Panorama.EDL(val.Name == obj.Name)": edl_output
        }
    })


@logger
def panorama_edit_edl(edl_name, element_to_change, element_value):
    edl_prev = panorama_get_edl(edl_name)
    if '@dirtyId' in edl_prev:
        LOG(f'Found uncommitted item:\n{edl_prev}')
        raise Exception('Please commit the instance prior to editing the External Dynamic List')
    edl_type = ''.join(edl_prev['type'].keys())
    edl_output = {'Name': edl_name}
    if DEVICE_GROUP:
        edl_output['DeviceGroup'] = DEVICE_GROUP
    params = {'action': 'edit', 'type': 'config', 'key': API_KEY,
              'xpath': XPATH_OBJECTS + "external-list/entry[@name='" + edl_name + "']/type/"
                        + edl_type + "/" + element_to_change}

    if element_to_change == 'url':
        params['element'] = add_argument_open(element_value, 'url', False)
        result = http_request(URL, 'POST', body=params)
        edl_output['URL'] = element_value

    elif element_to_change == 'certificate_profile':
        params['element'] = add_argument_open(element_value, 'certificate-profile', False)
        result = http_request(URL, 'POST', body=params)
        edl_output['CertificateProfile'] = element_value

    elif element_to_change == 'description':
        params['element'] = add_argument_open(element_value, 'description', False)
        result = http_request(URL, 'POST', body=params)
        edl_output['Description'] = element_value

    # element_to_change == 'recurring'
    else:
        if element_value not in ['five-minute', 'hourly']:
            raise Exception('Recurring segment must be five-minute or hourly')
        params['element'] = '<recurring><' + element_value + '/></recurring>'
        result = http_request(URL, 'POST', body=params)
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
        body=params,
    )

    return result


def panorama_delete_edl_command():
    """
    Delete an EDL
    """
    edl_name = demisto.args()['name']

    edl = panorama_delete_edl(edl_name)
    edl_output = {'Name': edl_name}
    if DEVICE_GROUP:
        edl_output['DeviceGroup'] = DEVICE_GROUP

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
        body=params,
    )

    return result


def panorama_refresh_edl_command():
    """
    Refresh an EDL
    """
    if DEVICE_GROUP:
        raise Exception('EDL refresh is only supported on Firewall (not Panorama).')

    edl_name = demisto.args()['name']

    result = panorama_refresh_edl(edl_name)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Refreshed External Dynamic List successfully',
    })


''' IP Tags '''


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
        body=params,
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
        body=params,
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


''' User Tags '''


@logger
def panorama_register_user_tag(tag: str, users: List):
    entry: str = ''
    for user in users:
        entry += f'<entry user=\"{user}\"><tag><member>{tag}</member></tag></entry>'

    params = {
        'type': 'user-id',
        'cmd': f'<uid-message><version>2.0</version><type>update</type><payload><register-user>{entry}'
               f'</register-user></payload></uid-message>',
        'key': API_KEY
    }

    result = http_request(
        URL,
        'POST',
        body=params,
    )

    return result


def panorama_register_user_tag_command():
    """
    Register Users to a Tag
    """
    major_version = get_pan_os_major_version()
    if major_version <= 8:
        raise Exception('The panorama-register-user-tag command is only available for PAN-OS 9.X and above versions.')
    tag = demisto.args()['tag']
    users = argToList(demisto.args()['Users'])

    result = panorama_register_user_tag(tag, users)

    # get existing Users for this tag
    context_users = demisto.dt(demisto.context(), 'Panorama.DynamicTags(val.Tag ==\"' + tag + '\").Users')

    if context_users:
        all_users = users + context_users
    else:
        all_users = users

    registered_user = {
        'Tag': tag,
        'Users': all_users
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Registered user-tag successfully',
        'EntryContext': {
            "Panorama.DynamicTags(val.Tag == obj.Tag)": registered_user
        }
    })


@logger
def panorama_unregister_user_tag(tag: str, users: list):
    entry = ''
    for user in users:
        entry += f'<entry user=\"{user}\"><tag><member>{tag}</member></tag></entry>'

    params = {
        'type': 'user-id',
        'cmd': f'<uid-message><version>2.0</version><type>update</type><payload><unregister-user>{entry}'
               f'</unregister-user></payload></uid-message>',
        'key': API_KEY
    }
    result = http_request(
        URL,
        'POST',
        body=params,
    )

    return result


def panorama_unregister_user_tag_command():
    """
    Unregister Users from a Tag
    """
    major_version = get_pan_os_major_version()
    if major_version <= 8:
        raise Exception('The panorama-unregister-user-tag command is only available for PAN-OS 9.X and above versions.')
    tag = demisto.args()['tag']
    users = argToList(demisto.args()['Users'])

    result = panorama_unregister_user_tag(tag, users)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Unregistered user-tag successfully'
    })


''' Traffic Logs '''


def build_traffic_logs_query(source=None, destination=None, receive_time=None,
                             application=None, to_port=None, action=None):
    query = ''
    if source and len(source) > 0:
        query += '(addr.src in ' + source + ')'
    if destination and len(destination) > 0:
        if len(query) > 0 and query[-1] == ')':
            query += ' and '
        query += '(addr.dst in ' + source + ')'
    if receive_time and len(receive_time) > 0:
        if len(query) > 0 and query[-1] == ')':
            query += ' and '
        query += '(receive_time geq ' + receive_time + ')'
    if application and len(application) > 0:
        if len(query) > 0 and query[-1] == ')':
            query += ' and '
        query += '(app eq ' + application + ')'
    if to_port and len(to_port) > 0:
        if len(query) > 0 and query[-1] == ')':
            query += ' and '
        query += '(port.dst eq ' + to_port + ')'
    if action and len(action) > 0:
        if len(query) > 0 and query[-1] == ')':
            query += ' and '
        query += '(action eq ' + action + ')'
    return query


@logger
def panorama_query_traffic_logs(number_of_logs, direction, query,
                                source, destination, receive_time, application, to_port, action):
    params = {
        'type': 'log',
        'log-type': 'traffic',
        'key': API_KEY
    }

    if query and len(query) > 0:
        params['query'] = query
    else:
        params['query'] = build_traffic_logs_query(source, destination, receive_time, application, to_port, action)
    if number_of_logs:
        params['nlogs'] = number_of_logs
    if direction:
        params['dir'] = direction
    result = http_request(
        URL,
        'GET',
        params=params,
    )

    return result


def panorama_query_traffic_logs_command():
    """
    Query the traffic logs
    """
    number_of_logs = demisto.args().get('number_of_logs')
    direction = demisto.args().get('direction')
    query = demisto.args().get('query')
    source = demisto.args().get('source')
    destination = demisto.args().get('destination')
    receive_time = demisto.args().get('receive_time')
    application = demisto.args().get('application')
    to_port = demisto.args().get('to_port')
    action = demisto.args().get('action')

    if query and (source or destination or receive_time or application or to_port or action):
        raise Exception('Use the query argument or the '
                        'source, destination, receive_time, application, to_port, action arguments to build your query')

    result = panorama_query_traffic_logs(number_of_logs, direction, query,
                                         source, destination, receive_time, application, to_port, action)

    if result['response']['@status'] == 'error':
        if 'msg' in result['response'] and 'line' in result['response']['msg']:
            message = '. Reason is: ' + result['response']['msg']['line']
            raise Exception('Query traffic logs failed' + message)
        else:
            raise Exception('Query traffic logs failed.')

    if 'response' not in result or 'result' not in result['response'] or 'job' not in result['response']['result']:
        raise Exception('Missing JobID in response.')
    query_traffic_output = {
        'JobID': result['response']['result']['job'],
        'Status': 'Pending'
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Query Traffic Logs:', query_traffic_output, ['JobID', 'Status'],
                                         removeNull=True),
        'EntryContext': {"Panorama.TrafficLogs(val.JobID == obj.JobID)": query_traffic_output}
    })


@logger
def panorama_get_traffic_logs(job_id):
    params = {
        'action': 'get',
        'type': 'log',
        'job-id': job_id,
        'key': API_KEY
    }

    result = http_request(
        URL,
        'GET',
        params=params,
    )

    return result


def panorama_check_traffic_logs_status_command():
    job_id = demisto.args().get('job_id')
    result = panorama_get_traffic_logs(job_id)

    if result['response']['@status'] == 'error':
        if 'msg' in result['response'] and 'line' in result['response']['msg']:
            message = '. Reason is: ' + result['response']['msg']['line']
            raise Exception('Query traffic logs failed' + message)
        else:
            raise Exception('Query traffic logs failed.')

    query_traffic_status_output = {
        'JobID': job_id,
        'Status': 'Pending'
    }

    if 'response' not in result or 'result' not in result['response'] or 'job' not in result['response']['result'] \
            or 'status' not in result['response']['result']['job']:
        raise Exception('Missing JobID status in response.')
    if result['response']['result']['job']['status'] == 'FIN':
        query_traffic_status_output['Status'] = 'Completed'

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Query Traffic Logs status:', query_traffic_status_output, ['JobID', 'Status'],
                                         removeNull=True),
        'EntryContext': {"Panorama.TrafficLogs(val.JobID == obj.JobID)": query_traffic_status_output}
    })


def prettify_traffic_logs(traffic_logs):
    pretty_traffic_logs_arr = []
    for traffic_log in traffic_logs:
        pretty_traffic_log = {}
        if 'action' in traffic_log:
            pretty_traffic_log['Action'] = traffic_log['action']
        if 'action_source' in traffic_log:
            pretty_traffic_log['ActionSource'] = traffic_log['action_source']
        if 'application' in traffic_log:
            pretty_traffic_log['Application'] = traffic_log['application']
        if 'category' in traffic_log:
            pretty_traffic_log['Category'] = traffic_log['category']
        if 'device_name' in traffic_log:
            pretty_traffic_log['DeviceName'] = traffic_log['device_name']
        if 'dst' in traffic_log:
            pretty_traffic_log['Destination'] = traffic_log['dst']
        if 'dport' in traffic_log:
            pretty_traffic_log['DestinationPort'] = traffic_log['dport']
        if 'from' in traffic_log:
            pretty_traffic_log['FromZone'] = traffic_log['from']
        if 'proto' in traffic_log:
            pretty_traffic_log['Protocol'] = traffic_log['proto']
        if 'rule' in traffic_log:
            pretty_traffic_log['Rule'] = traffic_log['rule']
        if 'receive_time' in traffic_log:
            pretty_traffic_log['ReceiveTime'] = traffic_log['receive_time']
        if 'session_end_reason' in traffic_log:
            pretty_traffic_log['SessionEndReason'] = traffic_log['session_end_reason']
        if 'src' in traffic_log:
            pretty_traffic_log['Source'] = traffic_log['src']
        if 'sport' in traffic_log:
            pretty_traffic_log['SourcePort'] = traffic_log['sport']
        if 'start' in traffic_log:
            pretty_traffic_log['StartTime'] = traffic_log['start']
        if 'to' in traffic_log:
            pretty_traffic_log['ToZone'] = traffic_log['to']

        pretty_traffic_logs_arr.append(pretty_traffic_log)
    return pretty_traffic_logs_arr


def panorama_get_traffic_logs_command():
    job_id = demisto.args().get('job_id')
    result = panorama_get_traffic_logs(job_id)

    if result['response']['@status'] == 'error':
        if 'msg' in result['response'] and 'line' in result['response']['msg']:
            message = '. Reason is: ' + result['response']['msg']['line']
            raise Exception('Query traffic logs failed' + message)
        else:
            raise Exception('Query traffic logs failed.')

    query_traffic_logs_output = {
        'JobID': job_id,
        'Status': 'Pending'
    }

    if 'response' not in result or 'result' not in result['response'] or 'job' not in result['response']['result'] \
            or 'status' not in result['response']['result']['job']:
        raise Exception('Missing JobID status in response.')

    if result['response']['result']['job']['status'] != 'FIN':
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': result,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Query Traffic Logs status:', query_traffic_logs_output,
                                             ['JobID', 'Status'], removeNull=True),
            'EntryContext': {"Panorama.TrafficLogs(val.JobID == obj.JobID)": query_traffic_logs_output}
        })
    else:  # FIN
        query_traffic_logs_output['Status'] = 'Completed'
        if 'response' not in result or 'result' not in result['response'] or 'log' not in result['response']['result'] \
                or 'logs' not in result['response']['result']['log']:
            raise Exception('Missing logs in response.')

        logs = result['response']['result']['log']['logs']
        if logs['@count'] == '0':
            demisto.results('No traffic logs matched the query')
        else:
            pretty_traffic_logs = prettify_traffic_logs(logs['entry'])
            query_traffic_logs_output['Logs'] = pretty_traffic_logs
            demisto.results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': result,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': tableToMarkdown('Query Traffic Logs:', pretty_traffic_logs,
                                                 ['JobID', 'Source', 'SourcePort', 'Destination', 'DestinationPort',
                                                  'Application', 'Action'], removeNull=True),
                'EntryContext': {"Panorama.TrafficLogs(val.JobID == obj.JobID)": query_traffic_logs_output}
            })


''' Logs '''


def build_array_query(query, arg_string, string, operator):
    list_string = argToList(arg_string)
    list_string_length = len(list_string)

    if list_string_length > 1:
        query += '('

    for i, item in enumerate(list_string):
        query += f'({string} {operator} \'{item}\')'
        if i < list_string_length - 1:
            query += ' or '

    if list_string_length > 1:
        query += ')'

    return query


def build_logs_query(address_src=None, address_dst=None, ip_=None,
                     zone_src=None, zone_dst=None, time_generated=None, action=None,
                     port_dst=None, rule=None, url=None, filedigest=None):
    query = ''
    if address_src:
        query += build_array_query(query, address_src, 'addr.src', 'in')
    if address_dst:
        if len(query) > 0 and query[-1] == ')':
            query += ' and '
        query += build_array_query(query, address_dst, 'addr.dst', 'in')
    if ip_:
        if len(query) > 0 and query[-1] == ')':
            query += ' and '
        query = build_array_query(query, ip_, 'addr.src', 'in')
        query += ' or '
        query = build_array_query(query, ip_, 'addr.dst', 'in')
    if zone_src:
        if len(query) > 0 and query[-1] == ')':
            query += ' and '
        query += build_array_query(query, zone_src, 'zone.src', 'eq')
    if zone_dst:
        if len(query) > 0 and query[-1] == ')':
            query += ' and '
        query += build_array_query(query, zone_dst, 'zone.dst', 'eq')
    if port_dst:
        if len(query) > 0 and query[-1] == ')':
            query += ' and '
        query += build_array_query(query, port_dst, 'port.dst', 'eq')
    if time_generated:
        if len(query) > 0 and query[-1] == ')':
            query += ' and '
        query += '(time_generated leq ' + time_generated + ')'
    if action:
        if len(query) > 0 and query[-1] == ')':
            query += ' and '
        query += build_array_query(query, action, 'action', 'eq')
    if rule:
        if len(query) > 0 and query[-1] == ')':
            query += ' and '
        query += build_array_query(query, rule, 'rule', 'eq')
    if url:
        if len(query) > 0 and query[-1] == ')':
            query += ' and '
        query += build_array_query(query, url, 'url', 'contains')
    if filedigest:
        if len(query) > 0 and query[-1] == ')':
            query += ' and '
        query += build_array_query(query, filedigest, 'filedigest', 'eq')

    return query


@logger
def panorama_query_logs(log_type, number_of_logs, query, address_src, address_dst, ip_,
                        zone_src, zone_dst, time_generated, action,
                        port_dst, rule, url, filedigest):
    params = {
        'type': 'log',
        'log-type': log_type,
        'key': API_KEY
    }

    if filedigest and log_type != 'wildfire':
        raise Exception('The filedigest argument is only relevant to wildfire log type.')
    if url and log_type == 'traffic':
        raise Exception('The url argument is not relevant to traffic log type.')

    if query:
        params['query'] = query
    else:
        if ip_ and (address_src or address_dst):
            raise Exception('The ip argument cannot be used with the address-source or the address-destination arguments.')
        params['query'] = build_logs_query(address_src, address_dst, ip_,
                                           zone_src, zone_dst, time_generated, action,
                                           port_dst, rule, url, filedigest)
    if number_of_logs:
        params['nlogs'] = number_of_logs

    result = http_request(
        URL,
        'GET',
        params=params,
    )

    return result


def panorama_query_logs_command():
    """
    Query logs
    """
    log_type = demisto.args().get('log-type')
    number_of_logs = demisto.args().get('number_of_logs')
    query = demisto.args().get('query')
    address_src = demisto.args().get('addr-src')
    address_dst = demisto.args().get('addr-dst')
    ip_ = demisto.args().get('ip')
    zone_src = demisto.args().get('zone-src')
    zone_dst = demisto.args().get('zone-dst')
    time_generated = demisto.args().get('time-generated')
    action = demisto.args().get('action')
    port_dst = demisto.args().get('port-dst')
    rule = demisto.args().get('rule')
    filedigest = demisto.args().get('filedigest')
    url = demisto.args().get('url')
    if url and url[-1] != '/':
        url += '/'

    if query and (address_src or address_dst or zone_src or zone_dst
                  or time_generated or action or port_dst or rule or url or filedigest):
        raise Exception('Use the free query argument or the fixed search parameters arguments to build your query.')

    result = panorama_query_logs(log_type, number_of_logs, query, address_src, address_dst, ip_,
                                 zone_src, zone_dst, time_generated, action,
                                 port_dst, rule, url, filedigest)

    if result['response']['@status'] == 'error':
        if 'msg' in result['response'] and 'line' in result['response']['msg']:
            message = '. Reason is: ' + result['response']['msg']['line']
            raise Exception('Query logs failed' + message)
        else:
            raise Exception('Query logs failed.')

    if 'response' not in result or 'result' not in result['response'] or 'job' not in result['response']['result']:
        raise Exception('Missing JobID in response.')

    query_logs_output = {
        'JobID': result['response']['result']['job'],
        'Status': 'Pending',
        'LogType': log_type,
        'Message': result['response']['result']['msg']['line']
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Query Logs:', query_logs_output, ['JobID', 'Status'], removeNull=True),
        'EntryContext': {"Panorama.Monitor(val.JobID == obj.JobID)": query_logs_output}
    })


def panorama_check_logs_status_command():
    """
    Check query logs status
    """
    job_ids = argToList(demisto.args().get('job_id'))
    for job_id in job_ids:
        result = panorama_get_traffic_logs(job_id)

        if result['response']['@status'] == 'error':
            if 'msg' in result['response'] and 'line' in result['response']['msg']:
                message = '. Reason is: ' + result['response']['msg']['line']
                raise Exception('Query logs failed' + message)
            else:
                raise Exception('Query logs failed.')

        query_logs_status_output = {
            'JobID': job_id,
            'Status': 'Pending'
        }

        if 'response' not in result or 'result' not in result['response'] or 'job' not in result['response']['result'] \
                or 'status' not in result['response']['result']['job']:
            raise Exception('Missing JobID status in response.')
        if result['response']['result']['job']['status'] == 'FIN':
            query_logs_status_output['Status'] = 'Completed'

        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': result,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Query Logs status:', query_logs_status_output, ['JobID', 'Status'],
                                             removeNull=True),
            'EntryContext': {"Panorama.Monitor(val.JobID == obj.JobID)": query_logs_status_output}
        })


def prettify_log(log):
    pretty_log = {}

    if 'action' in log:
        pretty_log['Action'] = log['action']
    if 'app' in log:
        pretty_log['Application'] = log['app']
    if 'category' in log:
        pretty_log['CategoryOrVerdict'] = log['category']
    if 'device_name' in log:
        pretty_log['DeviceName'] = log['device_name']
    if 'dst' in log:
        pretty_log['DestinationAddress'] = log['dst']
    if 'dstuser' in log:
        pretty_log['DestinationUser'] = log['dstuser']
    if 'dstloc' in log:
        pretty_log['DestinationCountry'] = log['dstloc']
    if 'dport' in log:
        pretty_log['DestinationPort'] = log['dport']
    if 'filedigest' in log:
        pretty_log['FileDigest'] = log['filedigest']
    if 'filename' in log:
        pretty_log['FileName'] = log['filename']
    if 'filetype' in log:
        pretty_log['FileType'] = log['filetype']
    if 'from' in log:
        pretty_log['FromZone'] = log['from']
    if 'misc' in log:
        pretty_log['URLOrFilename'] = log['misc']
    if 'natdst' in log:
        pretty_log['NATDestinationIP'] = log['natdst']
    if 'natdport' in log:
        pretty_log['NATDestinationPort'] = log['natdport']
    if 'natsrc' in log:
        pretty_log['NATSourceIP'] = log['natsrc']
    if 'natsport' in log:
        pretty_log['NATSourcePort'] = log['natsport']
    if 'pcap_id' in log:
        pretty_log['PCAPid'] = log['pcap_id']
    if 'proto' in log:
        pretty_log['IPProtocol'] = log['proto']
    if 'recipient' in log:
        pretty_log['Recipient'] = log['recipient']
    if 'rule' in log:
        pretty_log['Rule'] = log['rule']
    if 'rule_uuid' in log:
        pretty_log['RuleID'] = log['rule_uuid']
    if 'receive_time' in log:
        pretty_log['ReceiveTime'] = log['receive_time']
    if 'sender' in log:
        pretty_log['Sender'] = log['sender']
    if 'sessionid' in log:
        pretty_log['SessionID'] = log['sessionid']
    if 'serial' in log:
        pretty_log['DeviceSN'] = log['serial']
    if 'severity' in log:
        pretty_log['Severity'] = log['severity']
    if 'src' in log:
        pretty_log['SourceAddress'] = log['src']
    if 'srcloc' in log:
        pretty_log['SourceCountry'] = log['srcloc']
    if 'srcuser' in log:
        pretty_log['SourceUser'] = log['srcuser']
    if 'sport' in log:
        pretty_log['SourcePort'] = log['sport']
    if 'thr_category' in log:
        pretty_log['ThreatCategory'] = log['thr_category']
    if 'threatid' in log:
        pretty_log['Name'] = log['threatid']
    if 'tid' in log:
        pretty_log['ID'] = log['tid']
    if 'to' in log:
        pretty_log['ToZone'] = log['to']
    if 'time_generated' in log:
        pretty_log['TimeGenerated'] = log['time_generated']
    if 'url_category_list' in log:
        pretty_log['URLCategoryList'] = log['url_category_list']

    return pretty_log


def prettify_logs(logs):
    if not isinstance(logs, list):  # handle case of only one log that matched the query
        return prettify_log(logs)
    pretty_logs_arr = []
    for log in logs:
        pretty_log = prettify_log(log)
        pretty_logs_arr.append(pretty_log)
    return pretty_logs_arr


def panorama_get_logs_command():
    ignore_auto_extract = demisto.args().get('ignore_auto_extract') == 'true'
    job_ids = argToList(demisto.args().get('job_id'))
    for job_id in job_ids:
        result = panorama_get_traffic_logs(job_id)
        log_type_dt = demisto.dt(demisto.context(), f'Panorama.Monitor(val.JobID === "{job_id}").LogType')
        if isinstance(log_type_dt, list):
            log_type = log_type_dt[0]
        else:
            log_type = log_type_dt

        if result['response']['@status'] == 'error':
            if 'msg' in result['response'] and 'line' in result['response']['msg']:
                message = '. Reason is: ' + result['response']['msg']['line']
                raise Exception('Query logs failed' + message)
            else:
                raise Exception('Query logs failed.')

        query_logs_output = {
            'JobID': job_id,
            'Status': 'Pending'
        }

        if 'response' not in result or 'result' not in result['response'] or 'job' not in result['response']['result'] \
                or 'status' not in result['response']['result']['job']:
            raise Exception('Missing JobID status in response.')

        if result['response']['result']['job']['status'] != 'FIN':
            demisto.results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': result,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': tableToMarkdown('Query Logs status:', query_logs_output,
                                                 ['JobID', 'Status'], removeNull=True),
                'EntryContext': {"Panorama.Monitor(val.JobID == obj.JobID)": query_logs_output}
            })
        else:  # FIN
            query_logs_output['Status'] = 'Completed'
            if 'response' not in result or 'result' not in result['response'] or 'log' not in result['response']['result'] \
                    or 'logs' not in result['response']['result']['log']:
                raise Exception('Missing logs in response.')

            logs = result['response']['result']['log']['logs']
            if logs['@count'] == '0':
                human_readable = f'No {log_type} logs matched the query.'
            else:
                pretty_logs = prettify_logs(logs['entry'])
                query_logs_output['Logs'] = pretty_logs
                human_readable = tableToMarkdown('Query ' + log_type + ' Logs:', query_logs_output['Logs'],
                                                 ['TimeGenerated', 'SourceAddress', 'DestinationAddress', 'Application',
                                                  'Action', 'Rule', 'URLOrFilename'], removeNull=True)
            demisto.results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': result,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': human_readable,
                'IgnoreAutoExtract': ignore_auto_extract,
                'EntryContext': {"Panorama.Monitor(val.JobID == obj.JobID)": query_logs_output}
            })


''' Security Policy Match'''


def build_policy_match_query(application=None, category=None,
                             destination=None, destination_port=None, from_=None, to_=None,
                             protocol=None, source=None, source_user=None):
    query = '<test><security-policy-match>'
    if from_:
        query += f'<from>{from_}</from>'
    if to_:
        query += f'<to>{to_}</to>'
    if source:
        query += f'<source>{source}</source>'
    if destination:
        query += f'<destination>{destination}</destination>'
    if destination_port:
        query += f'<destination-port>{destination_port}</destination-port>'
    if protocol:
        query += f'<protocol>{protocol}</protocol>'
    if source_user:
        query += f'<source-user>{source_user}</source-user>'
    if application:
        query += f'<application>{application}</application>'
    if category:
        query += f'<category>{category}</category>'
    query += '</security-policy-match></test>'

    return query


def panorama_security_policy_match(application=None, category=None, destination=None,
                                   destination_port=None, from_=None, to_=None,
                                   protocol=None, source=None, source_user=None):
    params = {'type': 'op', 'key': API_KEY,
              'cmd': build_policy_match_query(application, category, destination, destination_port, from_, to_,
                                              protocol, source, source_user)}

    result = http_request(
        URL,
        'GET',
        params=params
    )

    return result['response']['result']


def prettify_matching_rule(matching_rule):
    pretty_matching_rule = {}

    if '@name' in matching_rule:
        pretty_matching_rule['Name'] = matching_rule['@name']
    if 'from' in matching_rule:
        pretty_matching_rule['From'] = matching_rule['from']
    if 'source' in matching_rule:
        pretty_matching_rule['Source'] = matching_rule['source']
    if 'to' in matching_rule:
        pretty_matching_rule['To'] = matching_rule['to']
    if 'destination' in matching_rule:
        pretty_matching_rule['Destination'] = matching_rule['destination']
    if 'category' in matching_rule:
        pretty_matching_rule['Category'] = matching_rule['category']
    if 'action' in matching_rule:
        pretty_matching_rule['Action'] = matching_rule['action']

    return pretty_matching_rule


def prettify_matching_rules(matching_rules):
    if not isinstance(matching_rules, list):  # handle case of only one log that matched the query
        return prettify_matching_rule(matching_rules)

    pretty_matching_rules_arr = []
    for matching_rule in matching_rules:
        pretty_matching_rule = prettify_matching_rule(matching_rule)
        pretty_matching_rules_arr.append(pretty_matching_rule)

    return pretty_matching_rules_arr


def prettify_query_fields(application=None, category=None,
                          destination=None, destination_port=None, from_=None, to_=None,
                          protocol=None, source=None, source_user=None):
    pretty_query_fields = {'Source': source, 'Destination': destination, 'Protocol': protocol}
    if application:
        pretty_query_fields['Application'] = application
    if category:
        pretty_query_fields['Category'] = category
    if destination_port:
        pretty_query_fields['DestinationPort'] = destination_port
    if from_:
        pretty_query_fields['From'] = from_
    if to_:
        pretty_query_fields['To'] = to_
    if source_user:
        pretty_query_fields['SourceUser'] = source_user
    return pretty_query_fields


def panorama_security_policy_match_command():
    if not VSYS:
        raise Exception("The 'panorama-security-policy-match' command is only relevant for a Firewall instance.")

    application = demisto.args().get('application')
    category = demisto.args().get('category')
    destination = demisto.args().get('destination')
    destination_port = demisto.args().get('destination-port')
    from_ = demisto.args().get('from')
    to_ = demisto.args().get('to')
    protocol = demisto.args().get('protocol')
    source = demisto.args().get('source')
    source_user = demisto.args().get('source-user')

    matching_rules = panorama_security_policy_match(application, category, destination, destination_port, from_, to_,
                                                    protocol, source, source_user)
    if not matching_rules:
        demisto.results('The query did not match a Security policy.')
    else:
        ec_ = {'Rules': prettify_matching_rules(matching_rules['rules']['entry']),
               'QueryFields': prettify_query_fields(application, category, destination, destination_port,
                                                    from_, to_, protocol, source, source_user),
               'Query': build_policy_match_query(application, category, destination, destination_port,
                                                 from_, to_, protocol, source, source_user)}
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': matching_rules,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Matching Security Policies:', ec_['Rules'],
                                             ['Name', 'Action', 'From', 'To', 'Source', 'Destination', 'Application'],
                                             removeNull=True),
            'EntryContext': {"Panorama.SecurityPolicyMatch(val.Query == obj.Query)": ec_}
        })


''' Static Routes'''


def prettify_static_route(static_route: Dict, virtual_router: str, template: Optional[str] = None) -> Dict[str, str]:
    pretty_static_route: Dict = {}

    if '@name' in static_route:
        pretty_static_route['Name'] = static_route['@name']
    if 'bfd' in static_route and 'profile' in static_route['bfd']:
        pretty_static_route['BFDprofile'] = static_route['bfd']['profile']
    if 'destination' in static_route:
        if '@dirtyId' in static_route['destination']:
            pretty_static_route['Uncommitted'] = True
        else:
            pretty_static_route['Destination'] = static_route['destination']
    if 'metric' in static_route:
        pretty_static_route['Metric'] = int(static_route['metric'])
    if 'nexthop' in static_route:
        if '@dirtyId' in static_route['destination']:
            pretty_static_route['Uncommitted'] = True
        else:
            nexthop: Dict[str, str] = static_route['nexthop']
            if 'ip-address' in nexthop:
                pretty_static_route['NextHop'] = nexthop['ip-address']
            elif 'next-vr' in static_route['nexthop']:
                pretty_static_route['NextHop'] = nexthop['next-vr']
            elif 'fqdn' in static_route['nexthop']:
                pretty_static_route['NextHop'] = nexthop['fqdn']
            elif 'discard' in static_route['nexthop']:
                pretty_static_route['NextHop'] = nexthop['discard']
    if 'route-table' in static_route:
        route_table = static_route['route-table']
        if 'unicast' in route_table:
            pretty_static_route['RouteTable'] = 'Unicast'
        elif 'multicast' in route_table:
            pretty_static_route['RouteTable'] = 'Multicast'
        elif 'both' in route_table:
            pretty_static_route['RouteTable'] = 'Both'
        else:  # route table is no-install
            pretty_static_route['RouteTable'] = 'No install'
    pretty_static_route['VirtualRouter'] = virtual_router
    if template:
        pretty_static_route['Template'] = template

    return pretty_static_route


def prettify_static_routes(static_routes, virtual_router: str, template: Optional[str] = None):
    if not isinstance(static_routes, list):  # handle case of only one static route in a virtual router
        return prettify_static_route(static_routes, virtual_router, template)

    pretty_static_route_arr = []
    for static_route in static_routes:
        pretty_static_route = prettify_static_route(static_route, virtual_router, template)
        pretty_static_route_arr.append(pretty_static_route)

    return pretty_static_route_arr


@logger
def panorama_list_static_routes(xpath_network: str, virtual_router: str, show_uncommitted: str) -> Dict[str, str]:
    action = 'get' if show_uncommitted else 'show'
    params = {
        'action': action,
        'type': 'config',
        'xpath': f'{xpath_network}/virtual-router/entry[@name=\'{virtual_router}\']/routing-table/ip/static-route',
        'key': API_KEY
    }
    result = http_request(URL, 'GET', params=params)
    return result['response']['result']


def panorama_list_static_routes_command():
    """
    List all static routes of a virtual Router
    """
    template = demisto.args().get('template')
    xpath_network, template = set_xpath_network(template)
    virtual_router = demisto.args()['virtual_router']
    show_uncommitted = demisto.args().get('show_uncommitted') == 'true'
    virtual_router_object = panorama_list_static_routes(xpath_network, virtual_router, show_uncommitted)

    if 'static-route' not in virtual_router_object or 'entry' not in virtual_router_object['static-route']:
        human_readable = 'The Virtual Router has does not exist or has no static routes configured.'
        static_routes = virtual_router_object
    else:
        static_routes = prettify_static_routes(virtual_router_object['static-route']['entry'], virtual_router, template)
        table_header = f'Displaying all Static Routes for the Virtual Router: {virtual_router}'
        headers = ['Name', 'Destination', 'NextHop', 'Uncommitted', 'RouteTable', 'Metric', 'BFDprofile']
        human_readable = tableToMarkdown(name=table_header, t=static_routes, headers=headers, removeNull=True)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': virtual_router_object,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {"Panorama.StaticRoutes(val.Name == obj.Name)": static_routes}
    })


@logger
def panorama_get_static_route(xpath_network: str, virtual_router: str, static_route_name: str) -> Dict[str, str]:
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': f'{xpath_network}/virtual-router/entry[@name=\'{virtual_router}\']/routing-table/ip/'
                 f'static-route/entry[@name=\'{static_route_name}\']',
        'key': API_KEY
    }
    result = http_request(URL, 'GET', params=params)
    return result['response']['result']


def panorama_get_static_route_command():
    """
    Get a static route of a virtual router
    """
    template = demisto.args().get('template')
    xpath_network, template = set_xpath_network(template)
    virtual_router = demisto.args()['virtual_router']
    static_route_name = demisto.args()['static_route']
    static_route_object = panorama_get_static_route(xpath_network, virtual_router, static_route_name)
    if '@count' in static_route_object and int(static_route_object['@count']) < 1:
        raise Exception('Static route does not exist.')
    static_route = prettify_static_route(static_route_object['entry'], virtual_router, template)
    table_header = f'Static route: {static_route_name}'

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': static_route_object,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(name=table_header, t=static_route, removeNull=True),
        'EntryContext': {
            "Panorama.StaticRoutes(val.Name == obj.Name)": static_route
        }
    })


@logger
def panorama_add_static_route(xpath_network: str, virtual_router: str, static_route_name: str, destination: str,
                              nexthop_type: str, nexthop_value: str, interface: str = None,
                              metric: str = None) -> Dict[str, str]:
    params = {
        'action': 'set',
        'type': 'config',
        'key': API_KEY,
        'xpath': f'{xpath_network}/virtual-router/entry[@name=\'{virtual_router}\']/'
                f'routing-table/ip/static-route/entry[@name=\'{static_route_name}\']',
        'element': f'<destination>{destination}</destination>'
                   f'<nexthop><{nexthop_type}>{nexthop_value}</{nexthop_type}></nexthop>'
    }
    if interface:
        params['element'] += f'<interface>{interface}</interface>'
    if metric:
        params['element'] += f'<metric>{metric}</metric>'

    result = http_request(URL, 'GET', params=params)
    return result['response']


def panorama_add_static_route_command():
    """
    Add a Static Route
    """
    template = demisto.args().get('template')
    xpath_network, template = set_xpath_network(template)
    virtual_router = demisto.args().get('virtual_router')
    static_route_name = demisto.args().get('static_route')
    destination = demisto.args().get('destination')
    nexthop_type = demisto.args().get('nexthop_type')
    nexthop_value = demisto.args().get('nexthop_value')
    interface = demisto.args().get('interface', None)
    metric = demisto.args().get('metric', None)

    if nexthop_type == 'fqdn':
        # Only from PAN-OS 9.x, creating a static route based on FQDN nexthop is available.
        major_version = get_pan_os_major_version()

        if major_version <= 8:
            raise Exception('Next Hop of type FQDN is only available for PAN-OS 9.x instances.')
    static_route = panorama_add_static_route(xpath_network, virtual_router, static_route_name, destination,
                                             nexthop_type, nexthop_value, interface, metric)
    human_readable = f'New uncommitted static route {static_route_name} configuration added.'
    entry_context = {
        'Name': static_route_name,
        'VirtualRouter': virtual_router,
        'Destination': destination,
        'NextHop': nexthop_value,
    }
    if interface:
        entry_context['Interface'] = interface
    if metric:
        entry_context['Metric'] = metric
    if template:
        entry_context['Template'] = template

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': static_route,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {"Panorama.StaticRoutes(val.Name == obj.Name)": static_route}
    })


@logger
def panorama_delete_static_route(xpath_network: str, virtual_router: str, route_name: str) -> Dict[str, str]:
    params = {
        'action': 'delete',
        'type': 'config',
        'xpath': f'{xpath_network}/virtual-router/entry[@name=\'{virtual_router}\']/'
                 f'routing-table/ip/static-route/entry[@name=\'{route_name}\']',
        'key': API_KEY
    }
    result = http_request(URL, 'DELETE', params=params)
    return result


def panorama_delete_static_route_command():
    """
    Delete a Static Route
    """
    template = demisto.args().get('template')
    xpath_network, template = set_xpath_network(template)
    virtual_router = demisto.args()['virtual_router']
    route_name = demisto.args()['route_name']
    deleted_static_route = panorama_delete_static_route(xpath_network, virtual_router, route_name)
    entry_context = {
        'Name': route_name,
        'Deleted': True
    }
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': deleted_static_route,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': f'The static route: {route_name} was deleted. Changes are not committed.',
        'EntryContext': {"Panorama.StaticRoutes(val.Name == obj.Name)": entry_context}  # add key -> deleted: true
    })


def panorama_show_device_version(target: str = None):
    params = {
        'type': 'op',
        'cmd': '<show><system><info/></system></show>',
        'key': API_KEY
    }
    if target:
        params['target'] = target

    result = http_request(
        URL,
        'GET',
        params=params
    )

    return result['response']['result']['system']


def panorama_show_device_version_command():
    """
    Get device details and show message in war room
    """
    target = str(demisto.args()['target']) if 'target' in demisto.args() else None

    response = panorama_show_device_version(target)

    info_data = {
        'Devicename': response['devicename'],
        'Model': response['model'],
        'Serial': response['serial'],
        'Version': response['sw-version']
    }
    entry_context = {"Panorama.Device.Info(val.Devicename === obj.Devicename)": info_data}
    headers = ['Devicename', 'Model', 'Serial', 'Version']
    human_readable = tableToMarkdown('Device Version:', info_data, headers=headers, removeNull=True)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': entry_context
    })


@logger
def panorama_download_latest_content_update_content(target: str):
    params = {
        'type': 'op',
        'target': target,
        'cmd': '<request><content><upgrade><download><latest/></download></upgrade></content></request>',
        'key': API_KEY
    }
    result = http_request(
        URL,
        'POST',
        body=params
    )

    return result


def panorama_download_latest_content_update_command():
    """
    Download content and show message in war room
    """
    if DEVICE_GROUP:
        raise Exception('Download latest content is only supported on Firewall (not Panorama).')
    target = str(demisto.args()['target']) if 'target' in demisto.args() else None
    result = panorama_download_latest_content_update_content(target)

    if 'result' in result['response']:
        # download has been given a jobid
        download_status_output = {
            'JobID': result['response']['result']['job'],
            'Status': 'Pending'
        }
        entry_context = {"Panorama.Content.Download(val.JobID == obj.JobID)": download_status_output}
        human_readable = tableToMarkdown('Content download:',
                                         download_status_output, ['JobID', 'Status'], removeNull=True)

        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': result,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': human_readable,
            'EntryContext': entry_context
        })
    else:
        # no download took place
        demisto.results(result['response']['msg'])


@logger
def panorama_content_update_download_status(target: str, job_id: str):
    params = {
        'type': 'op',
        'cmd': f'<show><jobs><id>{job_id}</id></jobs></show>',
        'target': target,
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params
    )

    return result


def panorama_content_update_download_status_command():
    """
    Check jobID of content update download status
    """
    if DEVICE_GROUP:
        raise Exception('Content download status is only supported on Firewall (not Panorama).')
    target = str(demisto.args()['target']) if 'target' in demisto.args() else None
    job_id = demisto.args()['job_id']
    result = panorama_content_update_download_status(target, job_id)

    content_download_status = {
        'JobID': result['response']['result']['job']['id']
    }
    if result['response']['result']['job']['status'] == 'FIN':
        if result['response']['result']['job']['result'] == 'OK':
            content_download_status['Status'] = 'Completed'
        else:
            content_download_status['Status'] = 'Failed'
        content_download_status['Details'] = result['response']['result']['job']

    if result['response']['result']['job']['status'] == 'PEND':
        content_download_status['Status'] = 'Pending'

    entry_context = {"Panorama.Content.Download(val.JobID == obj.JobID)": content_download_status}
    human_readable = tableToMarkdown('Content download status:', content_download_status,
                                     ['JobID', 'Status', 'Details'], removeNull=True)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': entry_context
    })


@logger
def panorama_install_latest_content_update(target: str):
    params = {
        'type': 'op',
        'cmd': '<request><content><upgrade><install><version>latest</version></install></upgrade></content></request>',
        'target': target,
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params
    )

    return result


def panorama_install_latest_content_update_command():
    """
        Check jobID of content content install status
    """
    if DEVICE_GROUP:
        raise Exception('Content download status is only supported on Firewall (not Panorama).')
    target = str(demisto.args()['target']) if 'target' in demisto.args() else None
    result = panorama_install_latest_content_update(target)

    if 'result' in result['response']:
        # installation has been given a jobid
        content_install_info = {
            'JobID': result['response']['result']['job'],
            'Status': 'Pending'
        }
        entry_context = {"Panorama.Content.Install(val.JobID == obj.JobID)": content_install_info}
        human_readable = tableToMarkdown('Result:', content_install_info, ['JobID', 'Status'], removeNull=True)

        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': result,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': human_readable,
            'EntryContext': entry_context
        })
    else:
        # no content install took place
        demisto.results(result['response']['msg'])


@logger
def panorama_content_update_install_status(target: str, job_id: str):
    params = {
        'type': 'op',
        'cmd': f'<show><jobs><id>{job_id}</id></jobs></show>',
        'target': target,
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params
    )

    return result


def panorama_content_update_install_status_command():
    """
    Check jobID of content update install status
    """
    if DEVICE_GROUP:
        raise Exception('Content download status is only supported on Firewall (not Panorama).')
    target = str(demisto.args()['target']) if 'target' in demisto.args() else None
    job_id = demisto.args()['job_id']
    result = panorama_content_update_install_status(target, job_id)

    content_install_status = {
        'JobID': result['response']['result']['job']['id']
    }
    if result['response']['result']['job']['status'] == 'FIN':
        if result['response']['result']['job']['result'] == 'OK':
            content_install_status['Status'] = 'Completed'
        else:
            # result['response']['job']['result'] == 'FAIL'
            content_install_status['Status'] = 'Failed'
        content_install_status['Details'] = result['response']['result']['job']

    if result['response']['result']['job']['status'] == 'PEND':
        content_install_status['Status'] = 'Pending'

    entry_context = {"Panorama.Content.Install(val.JobID == obj.JobID)": content_install_status}
    human_readable = tableToMarkdown('Content install status:', content_install_status,
                                     ['JobID', 'Status', 'Details'], removeNull=True)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': entry_context
    })


def panorama_check_latest_panos_software_command():
    if DEVICE_GROUP:
        raise Exception('Checking latest PAN-OS version is only supported on Firewall (not Panorama).')
    target = str(demisto.args()['target']) if 'target' in demisto.args() else None
    params = {
        'type': 'op',
        'cmd': '<request><system><software><check></check></software></system></request>',
        'target': target,
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params
    )
    demisto.results(result['response']['result'])


@logger
def panorama_download_panos_version(target: str, target_version: str):
    params = {
        'type': 'op',
        'cmd': f'<request><system><software><download><version>{target_version}'
               f'</version></download></software></system></request>',
        'target': target,
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params
    )
    return result


def panorama_download_panos_version_command():
    """
    Check jobID of pan-os version download
    """
    if DEVICE_GROUP:
        raise Exception('Downloading PAN-OS version is only supported on Firewall (not Panorama).')
    target = str(demisto.args()['target']) if 'target' in demisto.args() else None
    target_version = str(demisto.args()['target_version'])
    result = panorama_download_panos_version(target, target_version)

    if 'result' in result['response']:
        # download has been given a jobid
        panos_version_download = {
            'JobID': result['response']['result']['job']
        }
        entry_context = {"Panorama.PANOS.Download(val.JobID == obj.JobID)": panos_version_download}
        human_readable = tableToMarkdown('Result:', panos_version_download, ['JobID', 'Status'], removeNull=True)

        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': result,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': human_readable,
            'EntryContext': entry_context
        })
    else:
        # no panos download took place
        demisto.results(result['response']['msg'])


@logger
def panorama_download_panos_status(target: str, job_id: str):
    params = {
        'type': 'op',
        'cmd': f'<show><jobs><id>{job_id}</id></jobs></show>',
        'target': target,
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params
    )
    return result


def panorama_download_panos_status_command():
    """
    Check jobID of panos download status
    """
    if DEVICE_GROUP:
        raise Exception('PAN-OS version download status is only supported on Firewall (not Panorama).')
    target = str(demisto.args()['target']) if 'target' in demisto.args() else None
    job_id = demisto.args()['job_id']
    result = panorama_download_panos_status(target, job_id)
    panos_download_status = {
        'JobID': result['response']['result']['job']['id']
    }
    if result['response']['result']['job']['status'] == 'FIN':
        if result['response']['result']['job']['result'] == 'OK':
            panos_download_status['Status'] = 'Completed'
        else:
            # result['response']['job']['result'] == 'FAIL'
            panos_download_status['Status'] = 'Failed'
        panos_download_status['Details'] = result['response']['result']['job']

    if result['response']['result']['job']['status'] == 'PEND':
        panos_download_status['Status'] = 'Pending'

    human_readable = tableToMarkdown('PAN-OS download status:', panos_download_status,
                                     ['JobID', 'Status', 'Details'], removeNull=True)
    entry_context = {"Panorama.PANOS.Download(val.JobID == obj.JobID)": panos_download_status}

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': entry_context
    })


@logger
def panorama_install_panos_version(target: str, target_version: str):
    params = {
        'type': 'op',
        'cmd': f'<request><system><software><install><version>{target_version}'
               '</version></install></software></system></request>',
        'target': target,
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params
    )
    return result


def panorama_install_panos_version_command():
    """
    Check jobID of panos install
    """
    if DEVICE_GROUP:
        raise Exception('PAN-OS installation is only supported on Firewall (not Panorama).')
    target = str(demisto.args()['target']) if 'target' in demisto.args() else None
    target_version = str(demisto.args()['target_version'])
    result = panorama_install_panos_version(target, target_version)

    if 'result' in result['response']:
        # panos install has been given a jobid
        panos_install = {
            'JobID': result['response']['result']['job']
        }
        entry_context = {"Panorama.PANOS.Install(val.JobID == obj.JobID)": panos_install}
        human_readable = tableToMarkdown('PAN-OS Installation:', panos_install, ['JobID', 'Status'], removeNull=True)

        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': result,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': human_readable,
            'EntryContext': entry_context
        })
    else:
        # no panos install took place
        demisto.results(result['response']['msg'])


@logger
def panorama_install_panos_status(target: str, job_id: str):
    params = {
        'type': 'op',
        'cmd': f'<show><jobs><id>{job_id}</id></jobs></show>',
        'target': target,
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params
    )
    return result


def panorama_install_panos_status_command():
    """
    Check jobID of panos install status
    """
    if DEVICE_GROUP:
        raise Exception('PAN-OS installation status status is only supported on Firewall (not Panorama).')
    target = str(demisto.args()['target']) if 'target' in demisto.args() else None
    job_id = demisto.args()['job_id']
    result = panorama_install_panos_status(target, job_id)

    panos_install_status = {
        'JobID': result['response']['result']['job']['id']
    }
    if result['response']['result']['job']['status'] == 'FIN':
        if result['response']['result']['job']['result'] == 'OK':
            panos_install_status['Status'] = 'Completed'
        else:
            # result['response']['job']['result'] == 'FAIL'
            panos_install_status['Status'] = 'Failed'
        panos_install_status['Details'] = result['response']['result']['job']

    if result['response']['result']['job']['status'] == 'PEND':
        panos_install_status['Status'] = 'Pending'

    entry_context = {"Panorama.PANOS.Install(val.JobID == obj.JobID)": panos_install_status}
    human_readable = tableToMarkdown('PAN-OS installation status:', panos_install_status,
                                     ['JobID', 'Status', 'Details'], removeNull=True)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': entry_context
    })


def panorama_device_reboot_command():
    if DEVICE_GROUP:
        raise Exception('Device reboot is only supported on Firewall (not Panorama).')
    target = str(demisto.args()['target']) if 'target' in demisto.args() else None
    params = {
        'type': 'op',
        'cmd': '<request><restart><system></system></restart></request>',
        'target': target,
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params
    )
    demisto.results(result['response']['result'])


def main():
    LOG(f'Command being called is: {demisto.command()}')

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
            panorama_edit_custom_url_category_command()

        # URL Filtering capabilities
        elif demisto.command() == 'panorama-get-url-category':
            panorama_get_url_category_command(url_cmd='url')

        elif demisto.command() == 'panorama-get-url-category-from-cloud':
            panorama_get_url_category_command(url_cmd='url-info-cloud')

        elif demisto.command() == 'panorama-get-url-category-from-host':
            panorama_get_url_category_command(url_cmd='url-info-host')

        # URL Filter
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

        # Registered Users
        elif demisto.command() == 'panorama-register-user-tag':
            panorama_register_user_tag_command()

        elif demisto.command() == 'panorama-unregister-user-tag':
            panorama_unregister_user_tag_command()

        # Security Rules Managing
        elif demisto.command() == 'panorama-list-rules':
            panorama_list_rules_command()

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

        # Traffic Logs - deprecated
        elif demisto.command() == 'panorama-query-traffic-logs':
            panorama_query_traffic_logs_command()

        elif demisto.command() == 'panorama-check-traffic-logs-status':
            panorama_check_traffic_logs_status_command()

        elif demisto.command() == 'panorama-get-traffic-logs':
            panorama_get_traffic_logs_command()

        # Logs
        elif demisto.command() == 'panorama-query-logs':
            panorama_query_logs_command()

        elif demisto.command() == 'panorama-check-logs-status':
            panorama_check_logs_status_command()

        elif demisto.command() == 'panorama-get-logs':
            panorama_get_logs_command()

        # Pcaps
        elif demisto.command() == 'panorama-list-pcaps':
            panorama_list_pcaps_command()

        elif demisto.command() == 'panorama-get-pcap':
            panorama_get_pcap_command()

        # Application
        elif demisto.command() == 'panorama-list-applications':
            panorama_list_applications_command()

        # Test security policy match
        elif demisto.command() == 'panorama-security-policy-match':
            panorama_security_policy_match_command()

        # Static Routes
        elif demisto.command() == 'panorama-list-static-routes':
            panorama_list_static_routes_command()

        elif demisto.command() == 'panorama-get-static-route':
            panorama_get_static_route_command()

        elif demisto.command() == 'panorama-add-static-route':
            panorama_add_static_route_command()

        elif demisto.command() == 'panorama-delete-static-route':
            panorama_delete_static_route_command()

        # Firewall Upgrade
        # Check device software version
        elif demisto.command() == 'panorama-show-device-version':
            panorama_show_device_version_command()

        # Download the latest content update
        elif demisto.command() == 'panorama-download-latest-content-update':
            panorama_download_latest_content_update_command()

        # Download the latest content update
        elif demisto.command() == 'panorama-content-update-download-status':
            panorama_content_update_download_status_command()

        # Install the latest content update
        elif demisto.command() == 'panorama-install-latest-content-update':
            panorama_install_latest_content_update_command()

        # Content update install status
        elif demisto.command() == 'panorama-content-update-install-status':
            panorama_content_update_install_status_command()

        # Check PAN-OS latest software update
        elif demisto.command() == 'panorama-check-latest-panos-software':
            panorama_check_latest_panos_software_command()

        # Download target PAN-OS version
        elif demisto.command() == 'panorama-download-panos-version':
            panorama_download_panos_version_command()

        # PAN-OS download status
        elif demisto.command() == 'panorama-download-panos-status':
            panorama_download_panos_status_command()

        # PAN-OS software install
        elif demisto.command() == 'panorama-install-panos-version':
            panorama_install_panos_version_command()

        # PAN-OS install status
        elif demisto.command() == 'panorama-install-panos-status':
            panorama_install_panos_status_command()

        # Reboot Panorama Device
        elif demisto.command() == 'panorama-device-reboot':
            panorama_device_reboot_command()

        else:
            raise NotImplementedError(f'Command {demisto.command()} was not implemented.')

    except Exception as err:
        return_error(str(err))

    finally:
        LOG.print_log()


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
