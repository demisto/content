from CommonServerPython import *

''' IMPORTS '''
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union
import uuid
import json
import requests

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS '''
URL = ''
API_KEY = None
USE_SSL = None
USE_URL_FILTERING = None
TEMPLATE = None
VSYS = ''
PRE_POST = ''

XPATH_SECURITY_RULES = ''
DEVICE_GROUP = ''

XPATH_OBJECTS = ''

XPATH_RULEBASE = ''

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
    'tag': 'Tags',
    'profile-setting': 'ProfileSetting',
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


def http_request(uri: str, method: str, headers: dict = {},
                 body: dict = {}, params: dict = {}, files: dict = None, is_pcap: bool = False) -> Any:
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
        raise Exception(
            'Request Failed. with status: ' + str(result.status_code) + '. Reason is: ' + str(result.reason))

    # if pcap download
    if is_pcap:
        return result

    json_result = json.loads(xml2json(result.text))

    # handle raw response that doe not contain the response key, e.g xonfiguration export
    if 'response' not in json_result or '@code' not in json_result['response']:
        return json_result

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
                return_results('Rule ' + str(json_result['response']['msg']['line']))
                sys.exit(0)

            # catch already registered ip tags and return this as an entry.note
            elif str(json_result['response']['msg']['line']).find('already exists, ignore') != -1:
                if isinstance(json_result['response']['msg']['line']['uid-response']['payload']['register']['entry'],
                              list):
                    ips = [o['@ip'] for o in
                           json_result['response']['msg']['line']['uid-response']['payload']['register']['entry']]
                else:
                    ips = json_result['response']['msg']['line']['uid-response']['payload']['register']['entry']['@ip']
                return_results(
                    'IP ' + str(ips) + ' already exist in the tag. All submitted IPs were not registered to the tag.')
                sys.exit(0)

            # catch timed out log queries and return this as an entry.note
            elif str(json_result['response']['msg']['line']).find('Query timed out') != -1:
                return_results(str(json_result['response']['msg']['line']) + '. Rerun the query.')
                sys.exit(0)

        if '@code' in json_result['response']:
            raise Exception(
                'Request Failed.\nStatus code: ' + str(json_result['response']['@code']) + '\nWith message: ' + str(
                    json_result['response']['msg']['line']))
        else:
            raise Exception('Request Failed.\n' + str(json_result['response']))

    # handle @code
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
        return '<' + field_name + '>' + '<devices>' + '<entry name=\"' + arg + '\"/>' + '</devices>' + '</' + \
               field_name + '>'
    else:
        return ''


def add_argument_profile_setting(arg: Optional[str], field_name: str) -> str:
    if not arg:
        return ''
    member_stringify_list = '<member>' + arg + '</member>'
    return '<' + field_name + '>' + '<group>' + member_stringify_list + '</group>' + '</' + field_name + '>'


def set_xpath_network(template: str = None) -> Tuple[str, Optional[str]]:
    """
    Setting template xpath relevant to panorama instances.
    """
    if template:
        if not DEVICE_GROUP or VSYS:
            raise Exception('Template is only relevant for Panorama instances.')
    if not template:
        template = TEMPLATE
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
                                 disable_server_response_inspection: str = None, tags: List[str] = None,
                                 profile_setting: str = None) -> Dict:
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
                + add_argument_list(from_, 'from', True, True)  # default from will always be any
                + add_argument_list(to, 'to', True, True)  # default to will always be any
                + add_argument_list(service, 'service', True, True)
                + add_argument_yes_no(negate_source, 'negate-source')
                + add_argument_yes_no(negate_destination, 'negate-destination')
                + add_argument_yes_no(disable, 'disabled')
                + add_argument_yes_no(disable_server_response_inspection, 'disable-server-response-inspection', True)
                + add_argument(log_forwarding, 'log-setting', False)
                + add_argument_list(tags, 'tag', True)
                + add_argument_profile_setting(profile_setting, 'profile-setting')
    }
    if DEVICE_GROUP:
        if not PRE_POST:
            raise Exception('Please provide the pre_post argument when configuring'
                            ' a security rule in Panorama instance.')
        else:
            params['xpath'] = XPATH_SECURITY_RULES + PRE_POST + '/security/rules/entry' + '[@name=\'' + rulename + '\']'
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

    return_results('ok')


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


def template_test(template: str):
    """
    Test module for the Template specified
    """
    template_names = get_templates_names()
    if template not in template_names:
        raise Exception(f'Template: {template} does not exist.'
                        f' The available Templates for this instance: {", ".join(template_names)}.')


@logger
def panorama_command(args: dict):
    """
    Executes a command
    """
    params = {}
    for arg in args.keys():
        params[arg] = args[arg]
    params['key'] = API_KEY

    result = http_request(
        URL,
        'POST',
        body=params
    )

    return_results({
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
        return_results({
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
        return_results(result['response']['msg'])


@logger
def panorama_commit_status(args: dict):
    params = {
        'type': 'op',
        'cmd': '<show><jobs><id>' + args['job_id'] + '</id></jobs></show>',
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params
    )

    return result


def panorama_commit_status_command(args: dict):
    """
    Check jobID of commit status
    """
    result = panorama_commit_status(args)

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
        status_warnings = result.get("response", {}).get('result', {}).get('job', {}).get('warnings', {}).get('line',
                                                                                                              [])
    ignored_error = 'configured with no certificate profile'
    commit_status_output["Warnings"] = [item for item in status_warnings if item not in ignored_error]

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Commit status:', commit_status_output,
                                         ['JobID', 'Status', 'Details', 'Warnings'],
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
        return_results({
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
        return_results(result['response']['msg']['line'])


@logger
def panorama_push_status(job_id: str):
    params = {
        'type': 'op',
        'cmd': '<show><jobs><id>' + job_id + '</id></jobs></show>',
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params
    )

    return result


def safeget(dct: dict, keys: List[str]):
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


def panorama_push_status_command(job_id: str):
    """
    Check jobID of push status
    """
    result = panorama_push_status(job_id)
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

    return_results({
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
def panorama_list_addresses(tag: Optional[str] = None):
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "address/entry",
        'key': API_KEY
    }

    if tag:
        params['xpath'] = f'{params["xpath"]}[( tag/member = \'{tag}\')]'

    result = http_request(
        URL,
        'GET',
        params=params,
    )

    return result['response']['result']['entry']


def panorama_list_addresses_command(tag: Optional[str] = None):
    """
    Get all addresses
    """
    addresses_arr = panorama_list_addresses(tag)
    addresses_output = prettify_addresses_arr(addresses_arr)

    return_results({
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


def panorama_get_address_command(name: str):
    """
    Get an address
    """
    address_name = name

    address = panorama_get_address(address_name)
    address_output = prettify_address(address)

    return_results({
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


def panorama_create_address_command(args: dict):
    """
    Create an address object
    """
    address_name = args['name']
    description = args.get('description')
    tags = argToList(args['tag']) if 'tag' in args else None

    fqdn = args.get('fqdn')
    ip_netmask = args.get('ip_netmask')
    ip_range = args.get('ip_range')

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

    return_results({
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


def panorama_delete_address_command(name: str):
    """
    Delete an address
    """
    address_name = name

    address = panorama_delete_address(address_name)
    address_output = {'Name': address_name}
    if DEVICE_GROUP:
        address_output['DeviceGroup'] = DEVICE_GROUP

    return_results({
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
        params['xpath'] = f'{params["xpath"]}[( tag/member = \'{tag}\')]'

    result = http_request(
        URL,
        'GET',
        params=params,
    )

    return result['response']['result']['entry']


def panorama_list_address_groups_command(tag: Optional[str] = None):
    """
    Get all address groups
    """
    address_groups_arr = panorama_list_address_groups(tag)
    address_groups_output = prettify_address_groups_arr(address_groups_arr)

    return_results({
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


def panorama_get_address_group_command(name: str):
    """
    Get an address group
    """
    address_group_name = name

    result = panorama_get_address_group(address_group_name)

    return_results({
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


def panorama_create_dynamic_address_group(address_group_name: str, match: Optional[str],
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


def panorama_create_address_group_command(args: dict):
    """
    Create an address group
    """
    address_group_name = args['name']
    type_ = args['type']
    description = args.get('description')
    tags = argToList(args['tags']) if 'tags' in args else None
    match = args.get('match')
    addresses = argToList(args['addresses']) if 'addresses' in args else None
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

    return_results({
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


def panorama_delete_address_group_command(address_group_name: str):
    """
    Delete an address group
    """

    address_group = panorama_delete_address_group(address_group_name)
    address_group_output = {'Name': address_group_name}
    if DEVICE_GROUP:
        address_group_output['DeviceGroup'] = DEVICE_GROUP

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': address_group,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Address group was deleted successfully.',
        'EntryContext': {
            "Panorama.AddressGroups(val.Name == obj.Name)": address_group_output
        }
    })


def panorama_edit_address_group_command(args: dict):
    """
    Edit an address group
    """
    address_group_name = args['name']
    type_ = args['type']
    match = args.get('match')
    element_to_add = argToList(args['element_to_add']) if 'element_to_add' in args else None
    element_to_remove = argToList(
        args['element_to_remove']) if 'element_to_remove' in args else None

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

    description = args.get('description')
    tags = argToList(args['tags']) if 'tags' in args else None

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

    return_results({
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


def prettify_services_arr(services_arr: Union[dict, list]):
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
        params['xpath'] = f'{params["xpath"]}[( tag/member = \'{tag}\')]'

    result = http_request(
        URL,
        'GET',
        params=params,
    )

    return result['response']['result']['entry']


def panorama_list_services_command(tag: Optional[str]):
    """
    Get all Services
    """
    services_arr = panorama_list_services(tag)
    services_output = prettify_services_arr(services_arr)

    return_results({
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


def panorama_get_service_command(service_name: str):
    """
    Get a service
    """

    service = panorama_get_service(service_name)
    service_output = prettify_service(service)

    return_results({
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


def panorama_create_service_command(args: dict):
    """
    Create a service object
    """
    service_name = args['name']
    protocol = args['protocol']
    destination_port = args['destination_port']
    source_port = args.get('source_port')
    description = args.get('description')
    tags = argToList(args['tags']) if 'tags' in args else None

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

    return_results({
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


def panorama_delete_service_command(service_name: str):
    """
    Delete a service
    """

    service = panorama_delete_service(service_name)
    service_output = {'Name': service_name}
    if DEVICE_GROUP:
        service_output['DeviceGroup'] = DEVICE_GROUP

    return_results({
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
        params["xpath"] = f'{params["xpath"]}[( tag/member = \'{tag}\')]'

    result = http_request(
        URL,
        'GET',
        params=params,
    )

    return result['response']['result']['entry']


def panorama_list_service_groups_command(tag: Optional[str]):
    """
    Get all address groups
    """
    service_groups_arr = panorama_list_service_groups(tag)
    service_groups_output = prettify_service_groups_arr(service_groups_arr)

    return_results({
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
def panorama_get_service_group(service_group_name: str):
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


def panorama_get_service_group_command(service_group_name: str):
    """
    Get an address group
    """

    result = panorama_get_service_group(service_group_name)
    pretty_service_group = prettify_service_group(result)

    return_results({
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


def panorama_create_service_group(service_group_name: str, services: list, tags: list):
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


def panorama_create_service_group_command(args: dict):
    """
    Create a service group
    """
    service_group_name = args['name']
    services = argToList(args['services'])
    tags = argToList(args['tags']) if 'tags' in args else None

    result = panorama_create_service_group(service_group_name, services, tags)

    service_group_output = {
        'Name': service_group_name,
        'Services': services
    }
    if DEVICE_GROUP:
        service_group_output['DeviceGroup'] = DEVICE_GROUP
    if tags:
        service_group_output['Tags'] = tags

    return_results({
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
def panorama_delete_service_group(service_group_name: str):
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


def panorama_delete_service_group_command(service_group_name: str):
    """
    Delete a service group
    """

    service_group = panorama_delete_service_group(service_group_name)
    service_group_output = {'Name': service_group_name}
    if DEVICE_GROUP:
        service_group_output['DeviceGroup'] = DEVICE_GROUP

    return_results({
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
def panorama_edit_service_group(service_group_name: str, services: List[str], tag: List[str]):
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


def panorama_edit_service_group_command(args: dict):
    """
    Edit a service group
    """
    service_group_name = args['name']
    services_to_add = argToList(args['services_to_add']) if 'services_to_add' in args else None
    services_to_remove = argToList(
        args['services_to_remove']) if 'services_to_remove' in args else None
    tag = argToList(args['tag']) if 'tag' in args else None

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

    return_results({
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


def prettify_custom_url_category(custom_url_category: dict):
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
def panorama_get_custom_url_category(name: str):
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


def panorama_get_custom_url_category_command(name: str):
    """
    Get a custom url category
    """

    custom_url_category = panorama_get_custom_url_category(name)
    custom_url_category_output = prettify_custom_url_category(custom_url_category)

    return_results({
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
                                        sites: Optional[list] = None, categories: Optional[list] = None,
                                        description: str = None):
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

    custom_url_category_output: Dict[str, Any] = {'Name': custom_url_category_name}
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


def panorama_create_custom_url_category_command(args: dict):
    """
    Create a custom URL category
    """
    custom_url_category_name = args['name']
    type_ = args['type'] if 'type' in args else None
    sites = argToList(args['sites']) if 'sites' in args else None
    categories = argToList(args['categories']) if 'categories' in args else None
    description = args.get('description')

    custom_url_category, custom_url_category_output = panorama_create_custom_url_category(custom_url_category_name,
                                                                                          type_, sites, categories,
                                                                                          description)
    return_results({
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
def panorama_delete_custom_url_category(custom_url_category_name: str):
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


def panorama_delete_custom_url_category_command(custom_url_category_name: str):
    """
    Delete a custom url category
    """

    result = panorama_delete_custom_url_category(custom_url_category_name)
    custom_url_category_output = {'Name': custom_url_category_name}
    if DEVICE_GROUP:
        custom_url_category_output['DeviceGroup'] = DEVICE_GROUP

    return_results({
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
def panorama_edit_custom_url_category(custom_url_category_name: str, type_: str, items: list,
                                      description: Optional[str] = None):
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

    custom_url_category_output: Dict[str, Any] = {'Name': custom_url_category_name,
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


def panorama_custom_url_category_add_items(custom_url_category_name: str, items: list, type_: str):
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
    return_results({
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


def panorama_custom_url_category_remove_items(custom_url_category_name: str, items: list, type_: str):
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
    return_results({
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


def panorama_edit_custom_url_category_command(args: dict):
    custom_url_category_name = args['name']
    items = argToList(args['sites']) if 'sites' in args else argToList(args['categories'])
    type_ = "URL List" if 'sites' in args else "Category Match"
    if args['action'] == 'remove':
        panorama_custom_url_category_remove_items(custom_url_category_name, items, type_)
    else:
        panorama_custom_url_category_add_items(custom_url_category_name, items, type_)


''' URL Filtering '''


@logger
def panorama_get_url_category(url_cmd: str, url: str):
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
    if 'Failed to query the cloud' in result:
        raise Exception('Failed to query the cloud. Please check your URL Filtering license.')

    if url_cmd == 'url-info-host':
        # The result in this case looks like so: "Ancestors info:\nBM:\nURL.com,1,5,search-engines,, {some more info
        # here...}" - The 4th element is the url category.
        category = result.split(',')[3]
    else:
        result = result.splitlines()[1]
        if url_cmd == 'url':
            category = result.split(' ')[1]
        else:  # url-info-cloud
            category = result.split(',')[3]
    return category


def populate_url_filter_category_from_context(category: str):
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


def calculate_dbot_score(category: str, additional_suspicious: list, additional_malicious: list):
    """translate a category to a dbot score. For more information:
    https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000Cm5hCAC

    Args:
        category: the URL category from URLFiltering

    Returns:
        dbot score.
    """
    predefined_suspicious = ['high-risk', 'medium-risk', 'hacking', 'proxy-avoidance-and-anonymizers', 'grayware',
                             'not-resolved']
    suspicious_categories = list((set(additional_suspicious)).union(set(predefined_suspicious)))

    predefined_malicious = ['phishing', 'command-and-control', 'malware']
    malicious_categories = list((set(additional_malicious)).union(set(predefined_malicious)))

    dbot_score = 1
    if category in malicious_categories:
        dbot_score = 3
    elif category in suspicious_categories:
        dbot_score = 2
    elif category == 'unknown':
        dbot_score = 0

    return dbot_score


def panorama_get_url_category_command(url_cmd: str, url: str, additional_suspicious: list, additional_malicious: list):
    """
    Get the url category from Palo Alto URL Filtering
    """
    urls = argToList(url)

    categories_dict: Dict[str, list] = {}
    categories_dict_hr: Dict[str, list] = {}
    command_results: List[CommandResults] = []
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

        score = calculate_dbot_score(category.lower(), additional_suspicious, additional_malicious)
        dbot_score = Common.DBotScore(
            indicator=url,
            indicator_type=DBotScoreType.URL,
            integration_name='PAN-OS',
            score=score
        )
        url_obj = Common.URL(
            url=url,
            dbot_score=dbot_score,
            category=category
        )
        command_results.append(CommandResults(
            indicator=url_obj,
            readable_output=tableToMarkdown('URL', url_obj.to_context())
        ))

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

    command_results.insert(0, CommandResults(
        outputs_prefix='Panorama.URLFilter',
        outputs_key_field='Category',
        outputs=url_category_output,
        readable_output=human_readable,
        raw_response=categories_dict,
    ))
    return_results(command_results)


''' URL Filter '''


def prettify_get_url_filter(url_filter: dict):
    pretty_url_filter = {'Name': url_filter['@name']}
    if DEVICE_GROUP:
        pretty_url_filter['DeviceGroup'] = DEVICE_GROUP
    if 'description' in url_filter:
        pretty_url_filter['Description'] = url_filter['description']

    pretty_url_filter['Category'] = []
    alert_category_list = []
    block_category_list = []
    allow_category_list = []
    continue_category_list = []
    override_category_list = []

    if 'alert' in url_filter:
        alert_category_list = url_filter['alert']['member']
    if 'block' in url_filter:
        block_category_list = url_filter['block']['member']
    if 'allow' in url_filter:
        allow_category_list = url_filter['allow']['member']
    if 'continue' in url_filter:
        continue_category_list = url_filter['continue']['member']
    if 'override' in url_filter:
        override_category_list = url_filter['override']['member']

    for category in alert_category_list:
        pretty_url_filter['Category'].append({
            'Name': category,
            'Action': 'alert'
        })
    for category in block_category_list:
        pretty_url_filter['Category'].append({
            'Name': category,
            'Action': 'block'
        })
    for category in allow_category_list:
        pretty_url_filter['Category'].append({
            'Name': category,
            'Action': 'block'
        })
    for category in continue_category_list:
        pretty_url_filter['Category'].append({
            'Name': category,
            'Action': 'block'
        })
    for category in override_category_list:
        pretty_url_filter['Category'].append({
            'Name': category,
            'Action': 'block'
        })

    if 'allow-list' in url_filter or 'block-list' in url_filter:
        pretty_url_filter['Overrides'] = []
        if 'allow-list' in url_filter:
            pretty_url_filter['OverrideAllowList'] = url_filter['allow-list']['member']
        else:
            pretty_url_filter['OverrideBlockList'] = url_filter['block-list']['member']
    return pretty_url_filter


@logger
def panorama_get_url_filter(name: str):
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


def panorama_get_url_filter_command(name: str):
    """
    Get a URL Filter
    """

    url_filter = panorama_get_url_filter(name)

    url_filter_output = prettify_get_url_filter(url_filter)

    return_results({
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
        url_filter_name: str, action: str,
        url_category_list: str,
        override_allow_list: Optional[str] = None,
        override_block_list: Optional[str] = None,
        description: Optional[str] = None):
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


def panorama_create_url_filter_command(args: dict):
    """
    Create a URL Filter
    """
    url_filter_name = args['name']
    action = args['action']
    url_category_list = argToList(args['url_category'])
    override_allow_list = argToList(args.get('override_allow_list'))
    override_block_list = argToList(args.get('override_block_list'))
    description = args.get('description')

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

    return_results({
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
def panorama_edit_url_filter(url_filter_name: str, element_to_change: str, element_value: str,
                             add_remove_element: Optional[str] = None):
    url_filter_prev = panorama_get_url_filter(url_filter_name)
    if '@dirtyId' in url_filter_prev:
        LOG(f'Found uncommitted item:\n{url_filter_prev}')
        raise Exception('Please commit the instance prior to editing the URL Filter.')

    url_filter_output: Dict[str, Any] = {'Name': url_filter_name}
    if DEVICE_GROUP:
        url_filter_output['DeviceGroup'] = DEVICE_GROUP
    params = {
        'action': 'edit',
        'type': 'config',
        'key': API_KEY,
    }

    if element_to_change == 'description':
        params['xpath'] = XPATH_OBJECTS + f"profiles/url-filtering/entry[@name='{url_filter_name}']/{element_to_change}"
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


def panorama_edit_url_filter_command(args: dict):
    """
    Edit a URL Filter
    """
    url_filter_name = args['name']
    element_to_change = args['element_to_change']
    add_remove_element = args['add_remove_element']
    element_value = args['element_value']

    result, url_filter_output = panorama_edit_url_filter(url_filter_name, element_to_change, element_value,
                                                         add_remove_element)

    return_results({
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
def panorama_delete_url_filter(url_filter_name: str):
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


def panorama_delete_url_filter_command(url_filter_name: str):
    """
    Delete a custom url category
    """

    result = panorama_delete_url_filter(url_filter_name)

    url_filter_output = {'Name': url_filter_name}
    if DEVICE_GROUP:
        url_filter_output['DeviceGroup'] = DEVICE_GROUP

    return_results({
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


def prettify_rule(rule: dict):
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


def prettify_rules(rules: Union[List[dict], dict]):
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
        params["xpath"] = f'{params["xpath"]}[( tag/member = \'{tag}\')]'

    result = http_request(
        URL,
        'GET',
        params=params,
    )

    return result['response']['result']['entry']


def panorama_list_rules_command(tag: str):
    """
    List security rules
    """
    if DEVICE_GROUP:
        if not PRE_POST:
            raise Exception('Please provide the pre_post argument when listing rules in Panorama instance.')
        else:
            xpath = XPATH_SECURITY_RULES + PRE_POST + '/security/rules/entry'
    else:
        xpath = XPATH_SECURITY_RULES

    rules = panorama_list_rules(xpath, tag)
    pretty_rules = prettify_rules(rules)

    return_results({
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
def panorama_move_rule_command(args: dict):
    """
    Move a security rule
    """
    rulename = args['rulename']
    params = {
        'type': 'config',
        'action': 'move',
        'key': API_KEY,
        'where': args['where'],
    }

    if DEVICE_GROUP:
        if not PRE_POST:
            raise Exception('Please provide the pre_post argument when moving a rule in Panorama instance.')
        else:
            params['xpath'] = XPATH_SECURITY_RULES + PRE_POST + '/security/rules/entry' + '[@name=\'' + rulename + '\']'
    else:
        params['xpath'] = XPATH_SECURITY_RULES + '[@name=\'' + rulename + '\']'

    if 'dst' in args:
        params['dst'] = args['dst']

    result = http_request(URL, 'POST', body=params)
    rule_output = {'Name': rulename}
    if DEVICE_GROUP:
        rule_output['DeviceGroup'] = DEVICE_GROUP

    return_results({
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
def panorama_create_rule_command(args: dict):
    """
    Create a security rule
    """
    rulename = args['rulename'] if 'rulename' in args else ('demisto-' + (str(uuid.uuid4()))[:8])
    source = argToList(args.get('source'))
    destination = argToList(args.get('destination'))
    source_zone = argToList(args.get('source_zone'))
    destination_zone = argToList(args.get('destination_zone'))
    negate_source = args.get('negate_source')
    negate_destination = args.get('negate_destination')
    action = args.get('action')
    service = args.get('service')
    disable = args.get('disable')
    categories = argToList(args.get('category'))
    application = argToList(args.get('application'))
    source_user = args.get('source_user')
    disable_server_response_inspection = args.get('disable_server_response_inspection')
    description = args.get('description')
    target = args.get('target')
    log_forwarding = args.get('log_forwarding', None)
    tags = argToList(args['tags']) if 'tags' in args else None
    profile_setting = args.get('profile_setting')

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
                                          log_forwarding=log_forwarding, tags=tags, category=categories,
                                          from_=source_zone, to=destination_zone, profile_setting=profile_setting)
    result = http_request(
        URL,
        'POST',
        body=params
    )

    rule_output = {SECURITY_RULE_ARGS[key]: value for key, value in args.items() if key in SECURITY_RULE_ARGS}
    rule_output['Name'] = rulename
    if DEVICE_GROUP:
        rule_output['DeviceGroup'] = DEVICE_GROUP

    return_results({
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
        if not PRE_POST:
            raise Exception('please provide the pre_post argument when editing a rule in Panorama instance.')
        else:
            params['xpath'] = XPATH_SECURITY_RULES + PRE_POST + '/security/rules/entry' + '[@name=\'' + rulename + '\']'
    else:
        params['xpath'] = XPATH_SECURITY_RULES + '[@name=\'' + rulename + '\']'
    params["xpath"] = f'{params["xpath"]}/' + element_to_change

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

    return_results({
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
def panorama_edit_rule_command(args: dict):
    """
    Edit a security rule
    """
    rulename = args['rulename']
    element_to_change = args['element_to_change']
    if element_to_change == 'log-forwarding':
        element_to_change = 'log-setting'
    element_value = args['element_value']

    if element_to_change == 'target' and not DEVICE_GROUP:
        raise Exception('The target argument is relevant only for a Palo Alto Panorama instance.')

    behaviour = args.get('behaviour') if 'behaviour' in args else 'replace'
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
        elif element_to_change == 'profile-setting':
            params['element'] = add_argument_profile_setting(element_value, 'profile-setting')
        else:
            params['element'] = add_argument_yes_no(element_value, element_to_change)

        if DEVICE_GROUP:
            if not PRE_POST:
                raise Exception('please provide the pre_post argument when editing a rule in Panorama instance.')
            else:
                params['xpath'] = XPATH_SECURITY_RULES + PRE_POST + f'/security/rules/entry[@name=\'{rulename}\']'
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

        return_results({
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
def panorama_delete_rule_command(rulename: str):
    """
    Delete a security rule
    """
    params = {
        'type': 'config',
        'action': 'delete',
        'key': API_KEY
    }
    if DEVICE_GROUP:
        if not PRE_POST:
            raise Exception('Please provide the pre_post argument when moving a rule in Panorama instance.')
        else:
            params['xpath'] = XPATH_SECURITY_RULES + PRE_POST + '/security/rules/entry' + '[@name=\'' + rulename + '\']'
    else:
        params['xpath'] = XPATH_SECURITY_RULES + '[@name=\'' + rulename + '\']'

    result = http_request(
        URL,
        'POST',
        body=params
    )

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Rule deleted successfully.',
    })


@logger
def panorama_custom_block_rule_command(args: dict):
    """
    Block an object in Panorama
    """
    object_type = args['object_type']
    object_value = argToList(args['object_value'])
    direction = args['direction'] if 'direction' in args else 'both'
    rulename = args['rulename'] if 'rulename' in args else ('demisto-' + (str(uuid.uuid4()))[:8])
    block_destination = False if direction == 'from' else True
    block_source = False if direction == 'to' else True
    target = argToList(args.get('target')) if 'target' in args else None
    log_forwarding = args.get('log_forwarding', None)
    tags = argToList(args['tags']) if 'tags' in args else None

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

    return_results({
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
def panorama_list_pcaps_command(args: dict):
    """
    Get list of pcap files
    """
    if DEVICE_GROUP:
        raise Exception('PCAP listing is only supported on Firewall (not Panorama).')
    pcap_type = args['pcapType']
    params = {
        'type': 'export',
        'key': API_KEY,
        'category': pcap_type
    }

    if 'password' in args:
        params['dlp-password'] = args['password']
    elif args['pcapType'] == 'dlp-pcap':
        raise Exception('can not provide dlp-pcap without password')

    result = http_request(URL, 'GET', params=params, is_pcap=True)
    json_result = json.loads(xml2json(result.text))['response']
    if json_result['@status'] != 'success':
        raise Exception('Request to get list of Pcaps Failed.\nStatus code: ' + str(
            json_result['response']['@code']) + '\nWith message: ' + str(json_result['response']['msg']['line']))

    dir_listing = json_result['result']['dir-listing']
    if 'file' not in dir_listing:
        return_results(f'PAN-OS has no Pcaps of type: {pcap_type}.')
    else:
        pcaps = dir_listing['file']
        pcap_list = [pcap[1:] for pcap in pcaps]
        return_results({
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
def panorama_get_pcap_command(args: dict):
    """
    Get pcap file
    """
    if DEVICE_GROUP:
        raise Exception('Downloading a PCAP file is only supported on a Firewall (not on Panorama).')
    pcap_type = args['pcapType']
    params = {
        'type': 'export',
        'key': API_KEY,
        'category': pcap_type
    }

    password = args.get('password')
    pcap_id = args.get('pcapID')
    search_time = args.get('searchTime')

    if pcap_type == 'dlp-pcap' and not password:
        raise Exception('Can not download dlp-pcap without the password argument.')
    else:
        params['dlp-password'] = password
    if pcap_type == 'threat-pcap' and (not pcap_id or not search_time):
        raise Exception('Can not download threat-pcap without the pcapID and the searchTime arguments.')

    pcap_name = args.get('from')
    local_name = args.get('localName')
    serial_no = args.get('serialNo')
    session_id = args.get('sessionID')
    device_name = args.get('deviceName')

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
    if session_id:
        params['sessionid'] = session_id
    if device_name:
        params['device_name'] = device_name
    if search_time:
        search_time = validate_search_time(search_time)
        params['search-time'] = search_time

    # set file name to the current time if from/to were not specified
    if not file_name:
        file_name = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')

    result = http_request(URL, 'GET', params=params, is_pcap=True)

    # due to pcap file size limitation in the product. For more details, please see the documentation.
    if result.headers['Content-Type'] != 'application/octet-stream':
        raise Exception(
            'PCAP download failed. Most likely cause is the file size limitation.\n'
            'For information on how to download manually, see the documentation for this integration.')

    file = fileResult(file_name + ".pcap", result.content)
    return_results(file)


''' Applications '''


def prettify_applications_arr(applications_arr: Union[List[dict], dict]):
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


def panorama_list_applications_command(predefined: Optional[str] = None):
    """
    List all applications
    """
    predefined = predefined == 'true'
    applications_arr = panorama_list_applications(predefined)
    applications_arr_output = prettify_applications_arr(applications_arr)
    headers = ['Id', 'Name', 'Risk', 'Category', 'SubCategory', 'Technology', 'Description']

    return_results({
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


def prettify_edls_arr(edls_arr: Union[list, dict]):
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

    return_results({
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


def prettify_edl(edl: dict):
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
def panorama_get_edl(edl_name: str):
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


def panorama_get_edl_command(edl_name: str):
    """
    Get an EDL
    """
    edl = panorama_get_edl(edl_name)
    edl_output = prettify_edl(edl)

    return_results({
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
def panorama_create_edl(edl_name: str, url: str, type_: str, recurring: str, certificate_profile: Optional[str],
                        description: Optional[str]):
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


def panorama_create_edl_command(args: Dict[str, str]):
    """
    Create an edl object
    """
    edl_name = args.get('name')
    url = args.get('url', '').replace(' ', '%20')
    type_ = args.get('type')
    recurring = args.get('recurring')
    certificate_profile = args.get('certificate_profile')
    description = args.get('description')

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

    return_results({
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
def panorama_edit_edl(edl_name: str, element_to_change: str, element_value: str):
    edl_prev = panorama_get_edl(edl_name)
    if '@dirtyId' in edl_prev:
        LOG(f'Found uncommitted item:\n{edl_prev}')
        raise Exception('Please commit the instance prior to editing the External Dynamic List')
    edl_type = ''.join(edl_prev['type'].keys())
    edl_output = {'Name': edl_name}
    if DEVICE_GROUP:
        edl_output['DeviceGroup'] = DEVICE_GROUP
    params = {
        'action': 'edit', 'type': 'config', 'key': API_KEY,
        'xpath': f"{XPATH_OBJECTS}external-list/entry[@name='{edl_name}']/type/{edl_type}/{element_to_change}"
    }

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


def panorama_edit_edl_command(args: dict):
    """
    Edit an EDL
    """
    edl_name = args['name']
    element_to_change = args['element_to_change']
    element_value = args['element_value']

    result, edl_output = panorama_edit_edl(edl_name, element_to_change, element_value)

    return_results({
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
def panorama_delete_edl(edl_name: str):
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


def panorama_delete_edl_command(edl_name: str):
    """
    Delete an EDL
    """
    edl = panorama_delete_edl(edl_name)
    edl_output = {'Name': edl_name}
    if DEVICE_GROUP:
        edl_output['DeviceGroup'] = DEVICE_GROUP

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': edl,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'External Dynamic List was deleted successfully',
        'EntryContext': {
            "Panorama.EDL(val.Name == obj.Name)": edl_output
        }
    })


def panorama_refresh_edl(edl_name: str, edl_type: str, location: str, vsys: str):
    params = {
        'type': 'op',
        'key': API_KEY
    }
    # if refreshing an EDL on the FW
    if not edl_type and not location and not vsys:
        edl = panorama_get_edl(edl_name)
        edl_type = ''.join(edl['type'].keys())
    # if refreshing an EDL on the Panorama
    else:
        if not edl_type or not location or not vsys:
            raise Exception('To refresh an EDL from the Firewall on Panorama'
                            ' please use the: edl_type, location and vsys arguments.')

    params['cmd'] = f'<request><system><external-list><refresh><type><{edl_type}><name>{edl_name}' \
                    f'</name></{edl_type}></type></refresh></external-list></system></request>'
    if location:
        params['location'] = location
    if vsys:
        params['vsys'] = vsys

    result = http_request(
        URL,
        'POST',
        body=params,
    )

    return result


def panorama_refresh_edl_command(args: dict):
    """
    Refresh an EDL
    """
    if DEVICE_GROUP:
        raise Exception('EDL refresh is only supported on Firewall (not Panorama).')

    edl_name = args.get('name', '')
    edl_type = args.get('edl_type', '')
    location = args.get('location', '')
    vsys = args.get('vsys', '')

    result = panorama_refresh_edl(edl_name, edl_type, location, vsys)

    return_results({
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


def panorama_register_ip_tag_command(args: dict):
    """
    Register IPs to a Tag
    """
    tag = args['tag']
    ips = argToList(args['IPs'])

    persistent = args['persistent'] if 'persistent' in args else 'true'
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

    return_results({
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


def panorama_unregister_ip_tag_command(args: dict):
    """
    Register IPs to a Tag
    """
    tag = args['tag']
    ips = argToList(args['IPs'])

    result = panorama_unregister_ip_tag(tag, ips)

    return_results({
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


def panorama_register_user_tag_command(args: dict):
    """
    Register Users to a Tag
    """
    major_version = get_pan_os_major_version()
    if major_version <= 8:
        raise Exception('The panorama-register-user-tag command is only available for PAN-OS 9.X and above versions.')
    tag = args['tag']
    users = argToList(args['Users'])

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

    return_results({
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


def panorama_unregister_user_tag_command(args: dict):
    """
    Unregister Users from a Tag
    """
    major_version = get_pan_os_major_version()
    if major_version <= 8:
        raise Exception('The panorama-unregister-user-tag command is only available for PAN-OS 9.X and above versions.')
    tag = args['tag']
    users = argToList(args['Users'])

    result = panorama_unregister_user_tag(tag, users)

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Unregistered user-tag successfully'
    })


''' Traffic Logs '''


def build_traffic_logs_query(source: str, destination: Optional[str], receive_time: Optional[str],
                             application: Optional[str], to_port: Optional[str], action: Optional[str]):
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
def panorama_query_traffic_logs(number_of_logs: str, direction: str, query: str, source: str, destination: str,
                                receive_time: str, application: str, to_port: str, action: str):
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


def panorama_query_traffic_logs_command(args: dict):
    """
    Query the traffic logs
    """
    number_of_logs = args.get('number_of_logs')
    direction = args.get('direction')
    query = args.get('query')
    source = args.get('source')
    destination = args.get('destination')
    receive_time = args.get('receive_time')
    application = args.get('application')
    to_port = args.get('to_port')
    action = args.get('action')

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

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Query Traffic Logs:', query_traffic_output, ['JobID', 'Status'],
                                         removeNull=True),
        'EntryContext': {"Panorama.TrafficLogs(val.JobID == obj.JobID)": query_traffic_output}
    })


@logger
def panorama_get_traffic_logs(job_id: str):
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


def panorama_check_traffic_logs_status_command(job_id: str):
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

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Query Traffic Logs status:', query_traffic_status_output, ['JobID', 'Status'],
                                         removeNull=True),
        'EntryContext': {"Panorama.TrafficLogs(val.JobID == obj.JobID)": query_traffic_status_output}
    })


def prettify_traffic_logs(traffic_logs: List[dict]):
    pretty_traffic_logs_arr = []
    for traffic_log in traffic_logs:
        pretty_traffic_log = {}
        if 'action' in traffic_log:
            pretty_traffic_log['Action'] = traffic_log['action']
        if 'action_source' in traffic_log:
            pretty_traffic_log['ActionSource'] = traffic_log['action_source']
        if 'application' in traffic_log:
            pretty_traffic_log['Application'] = traffic_log['application']
        if 'bytes' in traffic_log:
            pretty_traffic_log['Bytes'] = traffic_log['bytes']
        if 'bytes_received' in traffic_log:
            pretty_traffic_log['BytesReceived'] = traffic_log['bytes_received']
        if 'bytes_sent' in traffic_log:
            pretty_traffic_log['BytesSent'] = traffic_log['bytes_sent']
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


def panorama_get_traffic_logs_command(job_id: str):
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
        return_results({
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
            return_results('No traffic logs matched the query')
        else:
            pretty_traffic_logs = prettify_traffic_logs(logs['entry'])
            query_traffic_logs_output['Logs'] = pretty_traffic_logs
            return_results({
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


def build_array_query(query: str, arg_string: str, string: str, operator: str):
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


def build_logs_query(address_src: Optional[str], address_dst: Optional[str], ip_: Optional[str],
                     zone_src: Optional[str], zone_dst: Optional[str], time_generated: Optional[str],
                     action: Optional[str], port_dst: Optional[str], rule: Optional[str], url: Optional[str],
                     filedigest: Optional[str]):
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
def panorama_query_logs(log_type: str, number_of_logs: str, query: str, address_src: str, address_dst: str, ip_: str,
                        zone_src: str, zone_dst: str, time_generated: str, action: str,
                        port_dst: str, rule: str, url: str, filedigest: str):
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
            raise Exception(
                'The ip argument cannot be used with the address-source or the address-destination arguments.')
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


def panorama_query_logs_command(args: dict):
    """
    Query logs
    """
    log_type = args.get('log-type')
    number_of_logs = args.get('number_of_logs')
    query = args.get('query')
    address_src = args.get('addr-src')
    address_dst = args.get('addr-dst')
    ip_ = args.get('ip')
    zone_src = args.get('zone-src')
    zone_dst = args.get('zone-dst')
    time_generated = args.get('time-generated')
    action = args.get('action')
    port_dst = args.get('port-dst')
    rule = args.get('rule')
    filedigest = args.get('filedigest')
    url = args.get('url')
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

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Query Logs:', query_logs_output, ['JobID', 'Status'], removeNull=True),
        'EntryContext': {"Panorama.Monitor(val.JobID == obj.JobID)": query_logs_output}
    })


def panorama_check_logs_status_command(job_id: str):
    """
    Check query logs status
    """
    job_ids = argToList(job_id)
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

        return_results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': result,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Query Logs status:', query_logs_status_output, ['JobID', 'Status'],
                                             removeNull=True),
            'EntryContext': {"Panorama.Monitor(val.JobID == obj.JobID)": query_logs_status_output}
        })


def prettify_log(log: dict):
    pretty_log = {}

    if 'action' in log:
        pretty_log['Action'] = log['action']
    if 'app' in log:
        pretty_log['Application'] = log['app']
    if 'bytes' in log:
        pretty_log['Bytes'] = log['bytes']
    if 'bytes_received' in log:
        pretty_log['BytesReceived'] = log['bytes_received']
    if 'bytes_sent' in log:
        pretty_log['BytesSent'] = log['bytes_sent']
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
    if 'vsys' in log:
        pretty_log['Vsys'] = log['vsys']

    return pretty_log


def prettify_logs(logs: Union[list, dict]):
    if not isinstance(logs, list):  # handle case of only one log that matched the query
        return prettify_log(logs)
    pretty_logs_arr = []
    for log in logs:
        pretty_log = prettify_log(log)
        pretty_logs_arr.append(pretty_log)
    return pretty_logs_arr


def panorama_get_logs_command(args: dict):
    ignore_auto_extract = args.get('ignore_auto_extract') == 'true'
    job_ids = argToList(args.get('job_id'))
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
            return_results({
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
            if 'response' not in result or 'result' not in result['response'] or 'log' not in result['response'][
                'result'] \
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
            return_results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': result,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': human_readable,
                'IgnoreAutoExtract': ignore_auto_extract,
                'EntryContext': {"Panorama.Monitor(val.JobID == obj.JobID)": query_logs_output}
            })


''' Security Policy Match'''


def build_policy_match_query(application: Optional[str] = None, category: Optional[str] = None, destination: Optional[str] = None,
                             destination_port: Optional[str] = None, from_: Optional[str] = None, to_: Optional[str] = None,
                             protocol: Optional[str] = None, source: Optional[str] = None, source_user: Optional[str] = None):
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


def panorama_security_policy_match(application: Optional[str] = None, category: Optional[str] = None,
                                   destination: Optional[str] = None, destination_port: Optional[str] = None,
                                   from_: Optional[str] = None, to_: Optional[str] = None,
                                   protocol: Optional[str] = None, source: Optional[str] = None,
                                   source_user: Optional[str] = None):
    params = {'type': 'op', 'key': API_KEY,
              'cmd': build_policy_match_query(application, category, destination, destination_port, from_, to_,
                                              protocol, source, source_user)}

    result = http_request(
        URL,
        'GET',
        params=params
    )

    return result['response']['result']


def prettify_matching_rule(matching_rule: dict):
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


def prettify_matching_rules(matching_rules: Union[list, dict]):
    if not isinstance(matching_rules, list):  # handle case of only one log that matched the query
        return prettify_matching_rule(matching_rules)

    pretty_matching_rules_arr = []
    for matching_rule in matching_rules:
        pretty_matching_rule = prettify_matching_rule(matching_rule)
        pretty_matching_rules_arr.append(pretty_matching_rule)

    return pretty_matching_rules_arr


def prettify_query_fields(application: Optional[str] = None, category: Optional[str] = None,
                          destination: Optional[str] = None, destination_port: Optional[str] = None,
                          from_: Optional[str] = None, to_: Optional[str] = None, protocol: Optional[str] = None,
                          source: Optional[str] = None, source_user: Optional[str] = None):
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


def panorama_security_policy_match_command(args: dict):
    if not VSYS:
        raise Exception("The 'panorama-security-policy-match' command is only relevant for a Firewall instance.")

    application = args.get('application')
    category = args.get('category')
    destination = args.get('destination')
    destination_port = args.get('destination-port')
    from_ = args.get('from')
    to_ = args.get('to')
    protocol = args.get('protocol')
    source = args.get('source')
    source_user = args.get('source-user')

    matching_rules = panorama_security_policy_match(application, category, destination, destination_port, from_, to_,
                                                    protocol, source, source_user)
    if not matching_rules:
        return_results('The query did not match a Security policy.')
    else:
        ec_ = {'Rules': prettify_matching_rules(matching_rules['rules']['entry']),
               'QueryFields': prettify_query_fields(application, category, destination, destination_port,
                                                    from_, to_, protocol, source, source_user),
               'Query': build_policy_match_query(application, category, destination, destination_port,
                                                 from_, to_, protocol, source, source_user)}
        return_results({
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


def prettify_static_routes(static_routes: Union[dict, list], virtual_router: str, template: Optional[str] = None):
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


def panorama_list_static_routes_command(args: dict):
    """
    List all static routes of a virtual Router
    """
    template = args.get('template')
    xpath_network, template = set_xpath_network(template)
    virtual_router = args['virtual_router']
    show_uncommitted = args.get('show_uncommitted') == 'true'
    virtual_router_object = panorama_list_static_routes(xpath_network, virtual_router, show_uncommitted)

    if 'static-route' not in virtual_router_object or 'entry' not in virtual_router_object['static-route']:
        human_readable = 'The Virtual Router has does not exist or has no static routes configured.'
        static_routes = virtual_router_object
    else:
        static_routes = prettify_static_routes(virtual_router_object['static-route']['entry'], virtual_router, template)
        table_header = f'Displaying all Static Routes for the Virtual Router: {virtual_router}'
        headers = ['Name', 'Destination', 'NextHop', 'Uncommitted', 'RouteTable', 'Metric', 'BFDprofile']
        human_readable = tableToMarkdown(name=table_header, t=static_routes, headers=headers, removeNull=True)

    return_results({
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


def panorama_get_static_route_command(args: dict):
    """
    Get a static route of a virtual router
    """
    template = args.get('template')
    xpath_network, template = set_xpath_network(template)
    virtual_router = args['virtual_router']
    static_route_name = args['static_route']
    static_route_object = panorama_get_static_route(xpath_network, virtual_router, static_route_name)
    if '@count' in static_route_object and int(static_route_object['@count']) < 1:
        raise Exception('Static route does not exist.')
    static_route = prettify_static_route(static_route_object['entry'], virtual_router, template)
    table_header = f'Static route: {static_route_name}'

    return_results({
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
        params["element"] = f'{params["element"]}<interface>{interface}</interface>'
    if metric:
        params['element'] = f'{params["element"]}<metric>{metric}</metric>'

    result = http_request(URL, 'GET', params=params)
    return result['response']


def panorama_add_static_route_command(args: dict):
    """
    Add a Static Route
    """
    template = args.get('template')
    xpath_network, template = set_xpath_network(template)
    virtual_router = args.get('virtual_router')
    static_route_name = args.get('static_route')
    destination = args.get('destination')
    nexthop_type = args.get('nexthop_type')
    nexthop_value = args.get('nexthop_value')
    interface = args.get('interface', None)
    metric = args.get('metric', None)

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

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': static_route,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {"Panorama.StaticRoutes(val.Name == obj.Name)": static_route}
    })


def panorama_override_vulnerability(threatid: str, vulnerability_profile: str, drop_mode: str):
    xpath = "{}profiles/vulnerability/entry[@name='{}']/threat-exception/entry[@name='{}']/action".format(
        XPATH_OBJECTS,
        vulnerability_profile,
        threatid)
    params = {'action': 'set',
              'type': 'config',
              'xpath': xpath,
              'key': API_KEY,
              'element': "<{0}></{0}>".format(drop_mode)
              }

    return http_request(
        URL,
        'POST',
        body=params,
    )


@logger
def panorama_get_predefined_threats_list(target: str):
    """
    Get the entire list of predefined threats as a file in Demisto
    """
    params = {
        'type': 'op',
        'cmd': '<show><predefined><xpath>/predefined/threats</xpath></predefined></show>',
        'target': target,
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params
    )
    return result


def panorama_get_predefined_threats_list_command(target: Optional[str] = None):
    result = panorama_get_predefined_threats_list(target)
    return_results(fileResult('predefined-threats.json', json.dumps(result['response']['result']).encode('utf-8')))


def panorama_block_vulnerability(args: dict):
    """
    Override vulnerability signature such that it is in block mode
    """
    threatid = args.get('threat_id', '')
    vulnerability_profile = args.get('vulnerability_profile', '')
    drop_mode = args.get('drop_mode', 'drop')

    threat = panorama_override_vulnerability(threatid, vulnerability_profile, drop_mode)
    threat_output = {'ID': threatid, 'NewAction': drop_mode}

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': threat,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Threat with ID {} overridden.'.format(threatid),
        'EntryContext': {
            "Panorama.Vulnerability(val.Name == obj.Name)": threat_output
        }
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


def panorama_delete_static_route_command(args: dict):
    """
    Delete a Static Route
    """
    template = args.get('template')
    xpath_network, template = set_xpath_network(template)
    virtual_router = args['virtual_router']
    route_name = args['route_name']
    deleted_static_route = panorama_delete_static_route(xpath_network, virtual_router, route_name)
    entry_context = {
        'Name': route_name,
        'Deleted': True
    }
    return_results({
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


def panorama_show_device_version_command(target: Optional[str] = None):
    """
    Get device details and show message in war room
    """
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

    return_results({
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


def panorama_download_latest_content_update_command(target: Optional[str] = None):
    """
    Download content and show message in war room
    """
    if DEVICE_GROUP:
        raise Exception('Download latest content is only supported on Firewall (not Panorama).')
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

        return_results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': result,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': human_readable,
            'EntryContext': entry_context
        })
    else:
        # no download took place
        return_results(result['response']['msg'])


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


def panorama_content_update_download_status_command(args: dict):
    """
    Check jobID of content update download status
    """
    if DEVICE_GROUP:
        raise Exception('Content download status is only supported on Firewall (not Panorama).')
    target = str(args['target']) if 'target' in args else None
    job_id = args['job_id']
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

    return_results({
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


def panorama_install_latest_content_update_command(target: Optional[str] = None):
    """
        Check jobID of content content install status
    """
    if DEVICE_GROUP:
        raise Exception('Content download status is only supported on Firewall (not Panorama).')
    result = panorama_install_latest_content_update(target)

    if 'result' in result['response']:
        # installation has been given a jobid
        content_install_info = {
            'JobID': result['response']['result']['job'],
            'Status': 'Pending'
        }
        entry_context = {"Panorama.Content.Install(val.JobID == obj.JobID)": content_install_info}
        human_readable = tableToMarkdown('Result:', content_install_info, ['JobID', 'Status'], removeNull=True)

        return_results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': result,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': human_readable,
            'EntryContext': entry_context
        })
    else:
        # no content install took place
        return_results(result['response']['msg'])


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


def panorama_content_update_install_status_command(args: dict):
    """
    Check jobID of content update install status
    """
    if DEVICE_GROUP:
        raise Exception('Content download status is only supported on Firewall (not Panorama).')
    target = str(args['target']) if 'target' in args else None
    job_id = args['job_id']
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
    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': entry_context
    })


def panorama_check_latest_panos_software_command(target: Optional[str] = None):
    if DEVICE_GROUP:
        raise Exception('Checking latest PAN-OS version is only supported on Firewall (not Panorama).')
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
    return_results(result['response']['result'])


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


def panorama_download_panos_version_command(args: dict):
    """
    Check jobID of pan-os version download
    """
    if DEVICE_GROUP:
        raise Exception('Downloading PAN-OS version is only supported on Firewall (not Panorama).')
    target = str(args['target']) if 'target' in args else None
    target_version = str(args['target_version'])
    result = panorama_download_panos_version(target, target_version)

    if 'result' in result['response']:
        # download has been given a jobid
        panos_version_download = {
            'JobID': result['response']['result']['job']
        }
        entry_context = {"Panorama.PANOS.Download(val.JobID == obj.JobID)": panos_version_download}
        human_readable = tableToMarkdown('Result:', panos_version_download, ['JobID', 'Status'], removeNull=True)

        return_results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': result,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': human_readable,
            'EntryContext': entry_context
        })
    else:
        # no panos download took place
        return_results(result['response']['msg'])


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


def panorama_download_panos_status_command(args: dict):
    """
    Check jobID of panos download status
    """
    if DEVICE_GROUP:
        raise Exception('PAN-OS version download status is only supported on Firewall (not Panorama).')
    target = str(args['target']) if 'target' in args else None
    job_id = args.get('job_id')
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

    return_results({
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


def panorama_install_panos_version_command(args: dict):
    """
    Check jobID of panos install
    """
    if DEVICE_GROUP:
        raise Exception('PAN-OS installation is only supported on Firewall (not Panorama).')
    target = str(args['target']) if 'target' in args else None
    target_version = str(args['target_version'])
    result = panorama_install_panos_version(target, target_version)

    if 'result' in result['response']:
        # panos install has been given a jobid
        panos_install = {
            'JobID': result['response']['result']['job']
        }
        entry_context = {"Panorama.PANOS.Install(val.JobID == obj.JobID)": panos_install}
        human_readable = tableToMarkdown('PAN-OS Installation:', panos_install, ['JobID', 'Status'], removeNull=True)

        return_results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': result,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': human_readable,
            'EntryContext': entry_context
        })
    else:
        # no panos install took place
        return_results(result['response']['msg'])


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


def panorama_install_panos_status_command(args: dict):
    """
    Check jobID of panos install status
    """
    if DEVICE_GROUP:
        raise Exception('PAN-OS installation status status is only supported on Firewall (not Panorama).')
    target = str(args['target']) if 'target' in args else None
    job_id = args['job_id']
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
    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': entry_context
    })


def panorama_device_reboot_command(target: Optional[str] = None):
    if DEVICE_GROUP:
        raise Exception('Device reboot is only supported on Firewall (not Panorama).')
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
    return_results(result['response']['result'])


@logger
def panorama_show_location_ip(ip_address: str):
    params = {
        'type': 'op',
        'cmd': f'<show><location><ip>{ip_address}</ip></location></show>',
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params
    )

    return result


def panorama_show_location_ip_command(ip_address: str):
    """
    Check location of a specified ip address
    """
    result = panorama_show_location_ip(ip_address)

    if 'response' not in result or '@status' not in result['response'] or result['response']['@status'] != 'success':
        raise Exception(f'Failed to successfully show the location of the specified ip: {ip_address}.')

    if 'response' in result and 'result' in result['response'] and 'entry' in result['response']['result']:
        entry = result['response']['result']['entry']
        show_location_output = {
            "ip_address": entry.get('ip'),
            "country_name": entry.get('country'),
            "country_code": entry.get('@cc'),
            "status": 'Found'
        }
    else:
        show_location_output = {
            "ip_address": ip_address,
            "status": 'NotFound'
        }

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(f'IP {ip_address} location:', show_location_output,
                                         ['ip_address', 'country_name', 'country_code', 'result'], removeNull=True),
        'EntryContext': {"Panorama.Location.IP(val.ip_address == obj.ip_address)": show_location_output}
    })


@logger
def panorama_get_license() -> Dict:
    params = {
        'type': 'op',
        'cmd': '<request><license><info/></license></request>',
        'key': API_KEY
    }
    result = http_request(URL, 'GET', params=params)

    return result


def panorama_get_license_command():
    """
    Get information about PAN-OS available licenses and their statuses.
    """
    available_licences = []
    result = panorama_get_license()
    if 'response' not in result or '@status' not in result['response'] or result['response']['@status'] != 'success':
        demisto.debug(str(result))
        raise Exception('Failed to get the information about PAN-OS available licenses and their statuses.')

    entry = result.get('response', {}).get('result', {}).get('licenses', {}).get('entry', [])
    for item in entry:
        available_licences.append({
            'Authcode': item.get('authcode'),
            'Base-license-name': item.get('base-license-name'),
            'Description': item.get('description'),
            'Expired': item.get('expired'),
            'Feature': item.get('feature'),
            'Expires': item.get('expires'),
            'Issued': item.get('issued'),
            'Serial': item.get('serial')
        })

    headers = ['Authcode', 'Base-license-name', 'Description', 'Feature', 'Serial', 'Expired', 'Expires', 'Issued']
    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('PAN-OS Available Licenses', available_licences, headers, removeNull=True),
        'EntryContext': {"Panorama.License(val.Feature == obj.Feature)": available_licences}
    })


def prettify_data_filtering_rule(rule: Dict) -> Dict:
    """
    Prettify the data filtering rule to be compatible to our standard.
    Args:
        rule: The profile rule to prettify

    Returns: rule dictionary compatible to our standards.

    """
    pretty_rule = {
        'Name': rule.get('@name')
    }
    if 'application' in rule and 'member' in rule['application']:
        pretty_rule['Application'] = rule['application']['member']
    if 'file-type' in rule and 'member' in rule['file-type']:
        pretty_rule['File-type'] = rule['file-type']['member']
    if 'direction' in rule:
        pretty_rule['Direction'] = rule['direction']
    if 'alert-threshold' in rule:
        pretty_rule['Alert-threshold'] = rule['alert-threshold']
    if 'block-threshold' in rule:
        pretty_rule['Block-threshold'] = rule['block-threshold']
    if 'data-object' in rule:
        pretty_rule['Data-object'] = rule['data-object']
    if 'log-severity' in rule:
        pretty_rule['Log-severity'] = rule['log-severity']
    if 'description' in rule:
        pretty_rule['Description'] = rule['description']

    return pretty_rule


def prettify_data_filtering_rules(rules: Dict) -> List:
    """

    Args:
        rules: All the rules to prettify

    Returns: A list of all the rules compatible with our standards.

    """
    if not isinstance(rules, list):
        return [prettify_data_filtering_rule(rules)]
    return [prettify_data_filtering_rule(rule) for rule in rules]


@logger
def get_security_profile(xpath: str) -> Dict:
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': xpath,
        'key': API_KEY
    }

    result = http_request(URL, 'GET', params=params)

    return result


def get_security_profiles_command(security_profile: str = None):
    """
    Get information about profiles.
    """
    if security_profile:
        xpath = f'{XPATH_RULEBASE}profiles/{security_profile}'
    else:
        xpath = f'{XPATH_RULEBASE}profiles'

    result = get_security_profile(xpath)
    if security_profile:
        security_profiles = result.get('response', {}).get('result', {})
    else:
        security_profiles = result.get('response', {}).get('result', {}).get('profiles', {})

    if '@dirtyId' in security_profiles:
        demisto.debug(f'Found uncommitted item:\n{security_profiles}')
        raise Exception('Please commit the instance prior to getting the security profiles.')

    human_readable = ''
    context = {}
    if 'spyware' in security_profiles and security_profiles['spyware'] is not None:
        spyware_content = []
        profiles = security_profiles.get('spyware', {}).get('entry', {})
        if isinstance(profiles, list):
            for profile in profiles:
                rules = profile.get('rules', {}).get('entry', [])
                spyware_rules = prettify_profiles_rules(rules)
                spyware_content.append({
                    'Name': profile['@name'],
                    'Rules': spyware_rules
                })
        else:
            rules = profiles.get('rules', {}).get('entry', [])
            spyware_rules = prettify_profiles_rules(rules)
            spyware_content = [{
                'Name': profiles['@name'],
                'Rules': spyware_rules
            }]

        human_readable = tableToMarkdown('Anti Spyware Profiles', spyware_content)
        context.update({"Panorama.Spyware(val.Name == obj.Name)": spyware_content})

    if 'virus' in security_profiles and security_profiles['virus'] is not None:
        virus_content = []
        profiles = security_profiles.get('virus', {}).get('entry', [])
        if isinstance(profiles, list):
            for profile in profiles:
                rules = profile.get('decoder', {}).get('entry', [])
                antivirus_rules = prettify_profiles_rules(rules)
                virus_content.append({
                    'Name': profile['@name'],
                    'Decoder': antivirus_rules
                })
        else:
            rules = profiles.get('decoder', {}).get('entry', [])
            antivirus_rules = prettify_profiles_rules(rules)
            virus_content = [{
                'Name': profiles['@name'],
                'Rules': antivirus_rules
            }]

        human_readable += tableToMarkdown('Antivirus Profiles', virus_content, headers=['Name', 'Decoder'])
        context.update({"Panorama.Antivirus(val.Name == obj.Name)": virus_content})

    if 'file-blocking' in security_profiles and security_profiles['file-blocking'] is not None:
        file_blocking_content = []
        profiles = security_profiles.get('file-blocking', {}).get('entry', {})
        if isinstance(profiles, list):
            for profile in profiles:
                rules = profile.get('rules', {}).get('entry', [])
                file_blocking_rules = prettify_profiles_rules(rules)
                file_blocking_content.append({
                    'Name': profile['@name'],
                    'Rules': file_blocking_rules
                })
        else:
            rules = profiles.get('rules', {}).get('entry', [])
            file_blocking_rules = prettify_profiles_rules(rules)
            file_blocking_content = [{
                'Name': profiles['@name'],
                'Rules': file_blocking_rules
            }]

        human_readable += tableToMarkdown('File Blocking Profiles', file_blocking_content)
        context.update({"Panorama.FileBlocking(val.Name == obj.Name)": file_blocking_content})

    if 'vulnerability' in security_profiles and security_profiles['vulnerability'] is not None:
        vulnerability_content = []
        profiles = security_profiles.get('vulnerability', {}).get('entry', {})
        if isinstance(profiles, list):
            for profile in profiles:
                rules = profile.get('rules', {}).get('entry', [])
                vulnerability_rules = prettify_profiles_rules(rules)
                vulnerability_content.append({
                    'Name': profile['@name'],
                    'Rules': vulnerability_rules
                })
        else:
            rules = profiles.get('rules', {}).get('entry', [])
            vulnerability_rules = prettify_profiles_rules(rules)
            vulnerability_content = [{
                'Name': profiles['@name'],
                'Rules': vulnerability_rules
            }]

        human_readable += tableToMarkdown('Vulnerability Protection Profiles', vulnerability_content)
        context.update({"Panorama.Vulnerability(val.Name == obj.Name)": vulnerability_content})

    if 'data-filtering' in security_profiles and security_profiles['data-filtering'] is not None:
        data_filtering_content = []
        profiles = security_profiles.get('data-filtering', {}).get('entry', {})
        if isinstance(profiles, list):
            for profile in profiles:
                rules = profile.get('rules', {}).get('entry', [])
                data_filtering_rules = prettify_data_filtering_rules(rules)
                data_filtering_content.append({
                    'Name': profile['@name'],
                    'Rules': data_filtering_rules
                })
        else:
            rules = profiles.get('rules', {}).get('entry', [])
            data_filtering_rules = prettify_data_filtering_rules(rules)
            data_filtering_content = [{
                'Name': profiles['@name'],
                'Rules': data_filtering_rules
            }]

        human_readable += tableToMarkdown('Data Filtering Profiles', data_filtering_content)
        context.update({"Panorama.DataFiltering(val.Name == obj.Name)": data_filtering_content})

    if 'url-filtering' in security_profiles and security_profiles['url-filtering'] is not None:
        url_filtering_content = []
        profiles = security_profiles.get('url-filtering', {}).get('entry', {})
        if isinstance(profiles, list):
            for profile in profiles:
                url_filtering_rules = prettify_get_url_filter(profile)
                url_filtering_content.append({
                    'Name': profile['@name'],
                    'Rules': url_filtering_rules
                })
        else:
            url_filtering_rules = prettify_get_url_filter(profiles)
            url_filtering_content = [{
                'Name': profiles['@name'],
                'Rules': url_filtering_rules
            }]

        human_readable += tableToMarkdown('URL Filtering Profiles', url_filtering_content)
        context.update({'Panorama.URLFilter(val.Name == obj.Name)': url_filtering_content})

    if 'wildfire-analysis' in security_profiles and security_profiles['wildfire-analysis'] is not None:
        wildfire_analysis_content = []
        profiles = security_profiles.get('wildfire-analysis', {}).get('entry', [])
        if isinstance(profiles, list):
            for profile in profiles:
                rules = profile.get('rules', {}).get('entry', [])
                wildfire_rules = prettify_wildfire_rules(rules)
                wildfire_analysis_content.append({
                    'Name': profile['@name'],
                    'Rules': wildfire_rules
                })
        else:
            rules = profiles.get('rules', {}).get('entry', [])
            wildfire_rules = prettify_wildfire_rules(rules)
            wildfire_analysis_content = [{
                'Name': profiles['@name'],
                'Rules': wildfire_rules
            }]

        human_readable += tableToMarkdown('WildFire Profiles', wildfire_analysis_content)
        context.update({"Panorama.WildFire(val.Name == obj.Name)": wildfire_analysis_content})

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': context
    })


@logger
def apply_security_profile(xpath: str, profile_name: str) -> Dict:
    params = {
        'action': 'set',
        'type': 'config',
        'xpath': xpath,
        'key': API_KEY,
        'element': f'<member>{profile_name}</member>'
    }
    result = http_request(URL, 'POST', params=params)

    return result


def apply_security_profile_command(profile_name: str, profile_type: str, rule_name: str, pre_post: str = None):

    if DEVICE_GROUP:  # Panorama instance
        if not pre_post:
            raise Exception('Please provide the pre_post argument when applying profiles to rules in '
                            'Panorama instance.')
        panorama_xpath = f"{XPATH_RULEBASE}{pre_post}/security/rules/entry[@name='{rule_name}']/profile-setting/"\
                         f"profiles/{profile_type}",
        apply_security_profile(panorama_xpath, profile_name)
        return_results(f'The profile {profile_name} has been applied to the rule {rule_name}')

    else:  # firewall instance
        firewall_xpath = f"{XPATH_RULEBASE}rulebase/security/rules/entry[@name='{rule_name}']/profile-setting/"\
                         f"profiles/{profile_type}"

        apply_security_profile(firewall_xpath, profile_name)
        return_results(f'The profile {profile_name} has been applied to the rule {rule_name}')


@logger
def get_ssl_decryption_rules(xpath: str) -> Dict:
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': xpath,
        'key': API_KEY
    }
    result = http_request(URL, 'GET', params=params)

    return result


def get_ssl_decryption_rules_command(pre_post: str):

    content = []
    if DEVICE_GROUP:
        if not pre_post:
            raise Exception('Please provide the pre_post argument when getting rules in Panorama instance.')
        else:
            xpath = XPATH_RULEBASE + pre_post + '/decryption/rules'
    else:
        xpath = XPATH_RULEBASE
    result = get_ssl_decryption_rules(xpath)
    ssl_decryption_rules = result.get('response', {}).get('result', {}).get('rules', {}).get('entry')
    if '@dirtyId' in ssl_decryption_rules:
        demisto.debug(f'Found uncommitted item:\n{ssl_decryption_rules}')
        raise Exception('Please commit the instance prior to getting the ssl decryption rules.')
    if isinstance(ssl_decryption_rules, list):
        for item in ssl_decryption_rules:
            content.append({
                'Name': item.get('@name'),
                'UUID': item.get('@uuid'),
                'Target': item.get('target'),
                'Category': item.get('category'),
                'Service': item.get('service', {}).get('member'),
                'Type': item.get('type'),
                'From': item.get('from').get('member'),
                'To': item.get('to').get('member'),
                'Source': item.get('source').get('member'),
                'Destination': item.get('destination', {}).get('member'),
                'Source-user': item.get('source-user', {}).get('member'),
                'Action': item.get('action'),
                'Description': item.get('description')
            })
    else:
        content = [{
            'Name': ssl_decryption_rules.get('@name'),
            'UUID': ssl_decryption_rules.get('@uuid'),
            'Target': ssl_decryption_rules.get('target'),
            'Category': ssl_decryption_rules.get('category'),
            'Service': ssl_decryption_rules.get('service', {}).get('member'),
            'Type': ssl_decryption_rules.get('type'),
            'From': ssl_decryption_rules.get('from').get('member'),
            'To': ssl_decryption_rules.get('to').get('member'),
            'Source': ssl_decryption_rules.get('source').get('member'),
            'Destination': ssl_decryption_rules.get('destination', {}).get('member'),
            'Source-user': ssl_decryption_rules.get('source-user', {}).get('member'),
            'Action': ssl_decryption_rules.get('action'),
            'Description': ssl_decryption_rules.get('description')
        }]

    headers = ['Name', 'UUID', 'Description', 'Target', 'Service', 'Category', 'Type', 'From', 'To', 'Source',
               'Destination', 'Action', 'Source-user']

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('SSL Decryption Rules', content, headers, removeNull=True),
        'EntryContext': {"Panorama.SSLRule(val.UUID == obj.UUID)": content}
    })


def prettify_profile_rule(rule: Dict) -> Dict:
    """
    Args:
        rule: The rule dictionary.

    Returns: Dictionary of the rule compatible with our standards.

    """
    pretty_rule = {
        'Name': rule['@name'],
        'Action': rule['action']
    }
    if 'application' in rule and 'member' in rule['application']:
        pretty_rule['Application'] = rule['application']['member']
    if 'file-type' in rule and 'member' in rule['file-type']:
        pretty_rule['File-type'] = rule['file-type']['member']
    if 'wildfire-action' in rule:
        pretty_rule['WildFire-action'] = rule['wildfire-action']
    if 'category' in rule and 'member' in rule['category']:
        pretty_rule['Category'] = rule['category']['member']
    elif 'category' in rule:
        pretty_rule['Category'] = rule['category']
    if 'severity' in rule and 'member' in rule['severity']:
        pretty_rule['Severity'] = rule['severity']['member']
    if 'threat-name' in rule and 'member' in rule['threat-name']:
        pretty_rule['Threat-name'] = rule['threat-name']['member']
    elif 'threat-name' in rule:
        pretty_rule['Threat-name'] = rule['threat-name']
    if 'packet-capture' in rule:
        pretty_rule['Packet-capture'] = rule['packet-capture']
    if '@maxver' in rule:
        pretty_rule['Max_version'] = rule['@maxver']
    if 'sinkhole' in rule:
        pretty_rule['Sinkhole'] = {}
        if 'ipv4-address' in rule['sinkhole']:
            pretty_rule['Sinkhole']['IPV4'] = rule['sinkhole']['ipv4-address']
        if 'ipv6-address' in rule['sinkhole']:
            pretty_rule['Sinkhole']['IPV6'] = rule['sinkhole']['ipv6-address']
    if 'host' in rule:
        pretty_rule['Host'] = rule['host']
    if 'cve' in rule and 'member' in rule['cve']:
        pretty_rule['CVE'] = rule['cve']['member']
    if 'vendor-id' in rule and 'member' in rule['vendor-id']:
        pretty_rule['Vendor-id'] = rule['vendor-id']['member']
    if 'analysis' in rule:
        pretty_rule['Analysis'] = rule['analysis']
    return pretty_rule


def prettify_profiles_rules(rules: Dict) -> List:
    """
    Args:
        rules: The rules to prettify.

    Returns: List with the rules that are compatible to our standard.

    """
    if not isinstance(rules, list):
        return [prettify_profile_rule(rules)]
    pretty_rules_arr = []
    for rule in rules:
        pretty_rule = prettify_profile_rule(rule)
        pretty_rules_arr.append(pretty_rule)

    return pretty_rules_arr


@logger
def get_anti_spyware_best_practice() -> Dict:
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': '/config/predefined/profiles/spyware',
        'key': API_KEY
    }

    result = http_request(URL, 'GET', params=params)

    return result


def get_anti_spyware_best_practice_command():

    result = get_anti_spyware_best_practice()
    spyware_profile = result.get('response', {}).get('result', {}).get('spyware').get('entry', [])
    strict_profile = next(item for item in spyware_profile if item['@name'] == 'strict')

    botnet_domains = strict_profile.get('botnet-domains', {}).get('lists', {}).get('entry', [])
    pretty_botnet_domains = prettify_profiles_rules(botnet_domains)

    sinkhole = strict_profile.get('botnet-domains', {}).get('sinkhole', {})
    sinkhole_content = []
    if sinkhole:
        sinkhole_content = [
            {'ipv6-address': sinkhole['ipv6-address'], 'ipv4-address': sinkhole['ipv4-address']}
        ]

    botnet_output = pretty_botnet_domains + sinkhole_content

    human_readable = tableToMarkdown('Anti Spyware Botnet-Domains Best Practice', botnet_output,
                                     ['Name', 'Action', 'Packet-capture', 'ipv4-address', 'ipv6-address'],
                                     removeNull=True)

    rules = strict_profile.get('rules', {}).get('entry')
    profile_rules = prettify_profiles_rules(rules)
    human_readable += tableToMarkdown('Anti Spyware Best Practice Rules', profile_rules,
                                      ['Name', 'Severity', 'Action', 'Category', 'Threat-name'], removeNull=True)

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': strict_profile,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'Panorama.Spyware.Rule(val.Name == obj.Name)': profile_rules,
            'Panorama.Spyware.BotentDomain(val.Name == obj.Name)': pretty_botnet_domains,
            'Panorama.Spyware.BotentDomain.Sinkhole(val.ipv4-address == obj.ipv4-address)': sinkhole_content
        }
    })


@logger
def get_file_blocking_best_practice() -> Dict:
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': '/config/predefined/profiles/file-blocking',
        'key': API_KEY
    }

    result = http_request(URL, 'GET', params=params)

    return result


def get_file_blocking_best_practice_command():

    results = get_file_blocking_best_practice()
    file_blocking_profile = results.get('response', {}).get('result', {}).get('file-blocking', {}).get('entry', [])

    strict_profile = next(item for item in file_blocking_profile if item['@name'] == 'strict file blocking')
    file_blocking_rules = strict_profile.get('rules', {}).get('entry', [])

    rules = prettify_profiles_rules(file_blocking_rules)
    human_readable = tableToMarkdown('File Blocking Profile Best Practice', rules,
                                     ['Name', 'Action', 'File-type', 'Application'], removeNull=True)

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': strict_profile,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'Panorama.FileBlocking.Rule(val.Name == obj.Name)': rules,
        }
    })


@logger
def get_antivirus_best_practice() -> Dict:
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': '/config/predefined/profiles/virus',
        'key': API_KEY
    }

    result = http_request(URL, 'GET', params=params)

    return result


def get_antivirus_best_practice_command():

    results = get_antivirus_best_practice()
    antivirus_profile = results.get('response', {}).get('result', {}).get('virus', {})
    strict_profile = antivirus_profile.get('entry', {})
    antivirus_rules = strict_profile.get('decoder', {}).get('entry', [])

    rules = prettify_profiles_rules(antivirus_rules)
    human_readable = tableToMarkdown('Antivirus Best Practice Profile', rules, ['Name', 'Action', 'WildFire-action'],
                                     removeNull=True)

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': strict_profile,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'Panorama.Antivirus.Decoder(val.Name == obj.Name)': rules,
        }
    })


@logger
def get_vulnerability_protection_best_practice() -> Dict:
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': '/config/predefined/profiles/vulnerability',
        'key': API_KEY
    }

    result = http_request(URL, 'GET', params=params)

    return result


def get_vulnerability_protection_best_practice_command():

    results = get_vulnerability_protection_best_practice()
    vulnerability_protection = results.get('response', {}).get('result', {}).get('vulnerability', {}).get('entry', [])
    strict_profile = next(item for item in vulnerability_protection if item['@name'] == 'strict')
    vulnerability_rules = strict_profile.get('rules', {}).get('entry', [])
    rules = prettify_profiles_rules(vulnerability_rules)
    human_readable = tableToMarkdown('vulnerability Protection Best Practice Profile', rules,
                                     ['Name', 'Action', 'Host', 'Severity', 'Category', 'Threat-name', 'CVE',
                                      'Vendor-id'], removeNull=True)

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': strict_profile,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'Panorama.Vulnerability.Rule(val.Name == obj.Name)': rules,
        }
    })


@logger
def get_wildfire_best_practice() -> Dict:
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': '/config/predefined/profiles/wildfire-analysis',
        'key': API_KEY
    }

    result = http_request(URL, 'GET', params=params)

    return result


def prettify_wildfire_rule(rule: Dict) -> Dict:
    """
    Args:
        rule: The profile security rule to prettify.

    Returns: The rule dict compatible with our standard.

    """
    pretty_rule = {
        'Name': rule['@name'],
    }
    if 'application' in rule and 'member' in rule['application']:
        pretty_rule['Application'] = rule['application']['member']
    if 'file-type' in rule and 'member' in rule['file-type']:
        pretty_rule['File-type'] = rule['file-type']['member']
    if 'analysis' in rule:
        pretty_rule['Analysis'] = rule['analysis']

    return pretty_rule


def prettify_wildfire_rules(rules: Dict) -> List:
    """
    Args:
        rules: WildFire rules to prettify.

    Returns: List of the rules that are compatible to our standard.

    """
    if not isinstance(rules, list):
        return [prettify_wildfire_rule(rules)]
    pretty_rules_arr = []
    for rule in rules:
        pretty_rule = prettify_wildfire_rule(rule)
        pretty_rules_arr.append(pretty_rule)

    return pretty_rules_arr


def get_wildfire_best_practice_command():

    result = get_wildfire_best_practice()
    wildfire_profile = result.get('response', {}).get('result', {}).get('wildfire-analysis', {})
    best_practice = wildfire_profile.get('entry', {}).get('rules', {}).get('entry', {})

    rules = prettify_wildfire_rules(best_practice)
    wildfire_schedule = {
        'Recurring': 'every-minute',
        'Action': 'download-and-install'
    }
    ssl_decrypt_settings = {'allow-forward-decrypted-content': 'yes'}
    system_settings = [
        {'Name': 'pe', 'File-size': '10'},
        {'Name': 'apk', 'File-size': '30'},
        {'Name': 'pdf', 'File-size': '1000'},
        {'Name': 'ms-office', 'File-size': '2000'},
        {'Name': 'jar', 'File-size': '5'},
        {'Name': 'flash', 'File-size': '5'},
        {'Name': 'MacOS', 'File-size': '1'},
        {'Name': 'archive', 'File-size': '10'},
        {'Name': 'linux', 'File-size': '2'},
        {'Name': 'script', 'File-size': '20'}
    ]

    human_readable = tableToMarkdown('WildFire Best Practice Profile', rules, ['Name', 'Analysis', 'Application',
                                                                               'File-type'], removeNull=True)
    human_readable += tableToMarkdown('Wildfire Best Practice Schedule', wildfire_schedule)
    human_readable += tableToMarkdown('Wildfire SSL Decrypt Settings', ssl_decrypt_settings)
    human_readable += tableToMarkdown('Wildfire System Settings\n report-grayware-file: yes', system_settings,
                                      ['Name', 'File-size'])

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': wildfire_profile,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'Panorama.WildFire': rules,
            'Panorama.WildFire.File(val.Name == obj.Name)': system_settings,
            'Panorama.WildFire.Schedule': wildfire_schedule,
            'Panorama.WildFire.SSLDecrypt': ssl_decrypt_settings
        }
    })


def set_xpath_wildfire(template: str = None) -> str:
    """
    Setting wildfire xpath relevant to panorama instances.
    """
    if template:
        xpath_wildfire = f"/config/devices/entry[@name='localhost.localdomain']/template/entry[@name=" \
            f"'{template}']/config/devices/entry[@name='localhost.localdomain']/deviceconfig/setting/wildfire"

    else:
        xpath_wildfire = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/setting"
    return xpath_wildfire


@logger
def get_wildfire_system_config(template: str) -> Dict:

    params = {
        'action': 'get',
        'type': 'config',
        'xpath': set_xpath_wildfire(template),
        'key': API_KEY,
    }
    result = http_request(URL, 'GET', params=params)

    return result


@logger
def get_wildfire_update_schedule(template: str) -> Dict:
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': f"/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='{template}']"
        f"/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/update-schedule/wildfire",
        'key': API_KEY
    }
    result = http_request(URL, 'GET', params=params)

    return result


def get_wildfire_configuration_command(template: str):

    file_size = []
    result = get_wildfire_system_config(template)
    system_config = result.get('response', {}).get('result', {}).get('wildfire', {})

    file_size_limit = system_config.get('file-size-limit', {}).get('entry', [])
    for item in file_size_limit:
        file_size.append({
            'Name': item.get('@name'),
            'Size-limit': item.get('size-limit')
        })

    report_grayware_file = system_config.get('report-grayware-file') or 'No'
    human_readable = tableToMarkdown(f'WildFire Configuration\n Report Grayware File: {report_grayware_file}',
                                     file_size, ['Name', 'Size-limit'], removeNull=True)

    result_schedule = get_wildfire_update_schedule(template)

    schedule = result_schedule.get('response', {}).get('result', {}).get('wildfire')
    if '@dirtyId' in schedule:
        demisto.debug(f'Found uncommitted item:\n{schedule}')
        raise Exception('Please commit the instance prior to getting the WildFire configuration.')

    human_readable += tableToMarkdown('The updated schedule for Wildfire', schedule)

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'Panorama.WildFire(val.Name == obj.Name)': file_size,
            'Panorama.WildFire.Schedule': schedule
        }
    })


@logger
def enforce_wildfire_system_config(template: str) -> Dict:
    params = {
        'action': 'set',
        'type': 'config',
        'xpath': f"/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='{template}']/"
        f"config/devices/entry[@name='localhost.localdomain']/deviceconfig/setting",
        'key': API_KEY,
        'element': '<wildfire><file-size-limit><entry name="pe"><size-limit>10</size-limit></entry>'
                   '<entry name="apk"><size-limit>30</size-limit></entry><entry name="pdf">'
                   '<size-limit>1000</size-limit></entry><entry name="ms-office"><size-limit>2000</size-limit></entry>'
                   '<entry name="jar"><size-limit>5</size-limit></entry><entry name="flash">'
                   '<size-limit>5</size-limit></entry><entry name="MacOSX"><size-limit>1</size-limit></entry>'
                   '<entry name="archive"><size-limit>10</size-limit></entry><entry name="linux">'
                   '<size-limit>2</size-limit></entry><entry name="script"><size-limit>20</size-limit></entry>'
                   '</file-size-limit><report-grayware-file>yes</report-grayware-file></wildfire>'
    }
    result = http_request(URL, 'POST', params=params)

    return result


@logger
def enforce_wildfire_schedule(template: str) -> Dict:
    params = {
        'action': 'set',
        'type': 'config',
        'xpath': f"/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='{template}']/config/"
        f"devices/entry[@name='localhost.localdomain']/deviceconfig/system/update-schedule/wildfire",
        'key': API_KEY,
        'element': '<recurring><every-min><action>download-and-install</action></every-min></recurring>'
    }

    result = http_request(URL, 'POST', params=params)

    return result


def enforce_wildfire_best_practice_command(template: str):

    enforce_wildfire_system_config(template)
    enforce_wildfire_schedule(template)

    return_results('The schedule was updated according to the best practice.'
                   '\nRecurring every minute with the action of "download and install"\n'
                   'The file upload for all file types is set to the maximum size.')


@logger
def url_filtering_block_default_categories(profile_name: str) -> Dict:

    params = {
        'action': 'set',
        'type': 'config',
        'xpath': f"{XPATH_RULEBASE}profiles/url-filtering/entry[@name='{profile_name}']/block",
        'key': API_KEY,
        'element': '<member>adult</member><member>hacking</member><member>command-and-control</member><member>'
                   'copyright-infringement</member><member>extremism</member><member>malware</member><member>'
                   'phishing</member><member>proxy-avoidance-and-anonymizers</member><member>parked</member><member>'
                   'unknown</member><member>dynamic-dns</member>'
    }
    result = http_request(URL, 'POST', params=params)

    return result


def url_filtering_block_default_categories_command(profile_name: str):

    url_filtering_block_default_categories(profile_name)
    return_results(f'The default categories to block has been set successfully to {profile_name}')


def get_url_filtering_best_practice_command():

    best_practice = {
        '@name': 'best-practice', 'credential-enforcement': {
            'mode': {'disabled': False},
            'log-severity': 'medium',
            'alert': {
                'member': [
                    'abortion', 'abused-drugs', 'adult', 'alcohol-and-tobacco', 'auctions', 'business-and-economy',
                    'computer-and-internet-info', 'content-delivery-networks', 'cryptocurrency', 'dating',
                    'educational-institutions', 'entertainment-and-arts', 'financial-services', 'gambling', 'games',
                    'government', 'grayware', 'health-and-medicine', 'high-risk', 'home-and-garden',
                    'hunting-and-fishing', 'insufficient-content', 'internet-communications-and-telephony',
                    'internet-portals', 'job-search', 'legal', 'low-risk', 'medium-risk', 'military', 'motor-vehicles',
                    'music', 'newly-registered-domain', 'news', 'not-resolved', 'nudity', 'online-storage-and-backup',
                    'peer-to-peer', 'personal-sites-and-blogs', 'philosophy-and-political-advocacy',
                    'private-ip-addresses', 'questionable', 'real-estate', 'recreation-and-hobbies',
                    'reference-and-research', 'religion', 'search-engines', 'sex-education', 'shareware-and-freeware',
                    'shopping', 'social-networking', 'society', 'sports', 'stock-advice-and-tools', 'streaming-media',
                    'swimsuits-and-intimate-apparel', 'training-and-tools', 'translation', 'travel', 'weapons',
                    'web-advertisements', 'web-based-email', 'web-hosting']},
            'block': {'member': ['command-and-control', 'copyright-infringement', 'dynamic-dns', 'extremism',
                                 'hacking', 'malware', 'parked', 'phishing', 'proxy-avoidance-and-anonymizers',
                                 'unknown']}},
        'alert': {'member': ['abortion', 'abused-drugs', 'adult', 'alcohol-and-tobacco', 'auctions',
                             'business-and-economy', 'computer-and-internet-info', 'content-delivery-networks',
                             'cryptocurrency', 'dating', 'educational-institutions', 'entertainment-and-arts',
                             'financial-services', 'gambling', 'games', 'government', 'grayware', 'health-and-medicine',
                             'high-risk', 'home-and-garden', 'hunting-and-fishing', 'insufficient-content',
                             'internet-communications-and-telephony', 'internet-portals', 'job-search', 'legal',
                             'low-risk', 'medium-risk', 'military', 'motor-vehicles', 'music',
                             'newly-registered-domain', 'news', 'not-resolved', 'nudity', 'online-storage-and-backup',
                             'peer-to-peer', 'personal-sites-and-blogs', 'philosophy-and-political-advocacy',
                             'private-ip-addresses', 'questionable', 'real-estate', 'recreation-and-hobbies',
                             'reference-and-research', 'religion', 'search-engines', 'sex-education',
                             'shareware-and-freeware', 'shopping', 'social-networking', 'society', 'sports',
                             'stock-advice-and-tools', 'streaming-media', 'swimsuits-and-intimate-apparel',
                             'training-and-tools', 'translation', 'travel', 'weapons', 'web-advertisements',
                             'web-based-email', 'web-hosting']},
        'block': {'member': ['command-and-control', 'copyright-infringement', 'dynamic-dns', 'extremism', 'hacking',
                             'malware', 'parked', 'phishing', 'proxy-avoidance-and-anonymizers', 'unknown']}}

    headers_best_practice = {
        'log-http-hdr-xff': 'yes',
        'log-http-hdr-user': 'yes',
        'log-http-hdr-referer': 'yes',
        'log-container-page-only': 'no'
    }
    rules = prettify_get_url_filter(best_practice)
    human_readable = tableToMarkdown('URL Filtering Best Practice Profile Categories', rules)
    human_readable += tableToMarkdown('Best Practice Headers', headers_best_practice)
    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': best_practice,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'Panorama.URLFilter': rules,
            'Panorama.URLFilter.Header': headers_best_practice
        }
    })


@logger
def create_antivirus_best_practice_profile(profile_name: str) -> Dict:
    params = {
        'action': 'set',
        'type': 'config',
        'xpath': f"{XPATH_RULEBASE}profiles/virus/entry[@name='{profile_name}']",
        'key': API_KEY,
        'element': '<decoder><entry name="ftp"><action>reset-both</action><wildfire-action>reset-both</wildfire-action>'
                   '</entry><entry name="http"><action>reset-both</action><wildfire-action>reset-both</wildfire-action>'
                   '</entry><entry name="http2"><action>reset-both</action><wildfire-action>reset-both'
                   '</wildfire-action>'
                   '</entry><entry name="smb"><action>reset-both</action><wildfire-action>reset-both</wildfire-action>'
                   '</entry><entry name="smtp"><action>reset-both</action><wildfire-action>reset-both</wildfire-action>'
                   '</entry><entry name="imap"><action>reset-both</action><wildfire-action>reset-both</wildfire-action>'
                   '</entry><entry name="pop3"><action>reset-both</action><wildfire-action>reset-both</wildfire-action>'
                   '</entry></decoder>'
    }
    result = http_request(URL, 'POST', params=params)

    return result


def create_antivirus_best_practice_profile_command(profile_name: str):
    create_antivirus_best_practice_profile(profile_name)
    return_results(f'The profile {profile_name} was created successfully.')


@logger
def create_anti_spyware_best_practice_profile(profile_name: str) -> Dict:

    params = {
        'action': 'set',
        'type': 'config',
        'xpath': f"{XPATH_RULEBASE}profiles/spyware/entry[@name='{profile_name}']",
        'key': API_KEY,
        'element': """<rules><entry name="simple-critical"><action><reset-both /></action><severity>
        <member>critical</member></severity><threat-name>any</threat-name><category>any</category>
        <packet-capture>disable</packet-capture></entry><entry name="simple-high"><action><reset-both /></action>
        <severity><member>high</member></severity><threat-name>any</threat-name><category>any</category>
        <packet-capture>disable</packet-capture></entry><entry name="simple-medium"><action><reset-both />
        </action><severity><member>medium</member></severity><threat-name>any</threat-name><category>any</category>
        <packet-capture>disable</packet-capture></entry><entry name="simple-informational"><action><default /></action>
        <severity><member>informational</member></severity><threat-name>any</threat-name><category>any</category>
        <packet-capture>disable</packet-capture></entry><entry name="simple-low"><action><default /></action><severity>
        <member>low</member></severity><threat-name>any</threat-name><category>any</category>
        <packet-capture>disable</packet-capture></entry></rules>"""
    }
    result = http_request(URL, 'POST', params=params)

    return result


def create_anti_spyware_best_practice_profile_command(profile_name: str):
    create_anti_spyware_best_practice_profile(profile_name)
    return_results(f'The profile {profile_name} was created successfully.')


@logger
def create_vulnerability_best_practice_profile(profile_name: str) -> Dict:

    params = {
        'action': 'set',
        'type': 'config',
        'xpath': f"{XPATH_RULEBASE}profiles/vulnerability/entry[@name='{profile_name}']",
        'key': API_KEY,
        'element': """<rules><entry name="brute-force"><action><block-ip><duration>300</duration>
        <track-by>source-and-destination</track-by></block-ip></action><vendor-id><member>any</member></vendor-id>
        <severity><member>any</member></severity><cve><member>any</member></cve><threat-name>any</threat-name>
        <host>any</host><category>brute-force</category><packet-capture>disable</packet-capture></entry>
        <entry name="simple-client-critical"><action><reset-both /></action><vendor-id><member>any</member></vendor-id>
        <severity><member>critical</member></severity><cve><member>any</member></cve><threat-name>any</threat-name>
        <host>client</host><category>any</category><packet-capture>disable</packet-capture></entry>
        <entry name="simple-client-high"><action><reset-both /></action><vendor-id><member>any</member></vendor-id>
        <severity><member>high</member></severity><cve><member>any</member></cve><threat-name>any</threat-name>
        <host>client</host><category>any</category><packet-capture>disable</packet-capture></entry>
        <entry name="simple-client-medium"><action><reset-both /></action><vendor-id><member>any</member></vendor-id>
        <severity><member>medium</member></severity><cve><member>any</member></cve><threat-name>any</threat-name>
        <host>client</host><category>any</category><packet-capture>disable</packet-capture></entry>
        <entry name="simple-client-informational"><action><default /></action><vendor-id><member>any</member>
        </vendor-id><severity><member>informational</member></severity><cve><member>any</member></cve>
        <threat-name>any</threat-name><host>client</host><category>any</category>
        <packet-capture>disable</packet-capture></entry><entry name="simple-client-low"><action><default /></action>
        <vendor-id><member>any
        </member></vendor-id><severity><member>low</member></severity><cve><member>any</member></cve><threat-name>any
        </threat-name><host>client</host><category>any</category><packet-capture>disable</packet-capture></entry>
        <entry name="simple-server-critical"><action><reset-both /></action><vendor-id><member>any</member></vendor-id>
        <severity><member>critical</member></severity><cve><member>any</member></cve><threat-name>any</threat-name>
        <host>server</host><category>any</category><packet-capture>disable</packet-capture></entry>
        <entry name="simple-server-high"><action><reset-both /></action><vendor-id><member>any</member></vendor-id>
        <severity><member>high</member></severity><cve><member>any</member></cve><threat-name>any</threat-name>
        <host>server</host><category>any</category><packet-capture>disable</packet-capture></entry>
        <entry name="simple-server-medium"><action><reset-both /></action><vendor-id><member>any</member></vendor-id>
        <severity><member>medium</member></severity><cve><member>any</member></cve><threat-name>any</threat-name>
        <host>server</host><category>any</category><packet-capture>disable</packet-capture></entry>
        <entry name="simple-server-informational"><action><default /></action><vendor-id><member>any</member>
        </vendor-id><severity><member>informational</member></severity><cve><member>any</member></cve><threat-name>any
        </threat-name><host>server</host><category>any</category><packet-capture>disable</packet-capture></entry>
        <entry name="simple-server-low"><action><default /></action><vendor-id><member>any</member></vendor-id>
        <severity><member>low</member></severity><cve><member>any</member></cve><threat-name>any</threat-name>
        <host>server</host><category>any</category><packet-capture>disable</packet-capture></entry></rules>"""
    }
    result = http_request(URL, 'POST', params=params)

    return result


def create_vulnerability_best_practice_profile_command(profile_name: str):
    create_vulnerability_best_practice_profile(profile_name)
    return_results(f'The profile {profile_name} was created successfully.')


@logger
def create_url_filtering_best_practice_profile(profile_name: str) -> Dict:

    params = {
        'action': 'set',
        'type': 'config',
        'xpath': f"{XPATH_RULEBASE}profiles/url-filtering/entry[@name='{profile_name}']",
        'key': API_KEY,
        'element': """<credential-enforcement><mode><disabled /></mode><log-severity>medium</log-severity><alert>
        <member>abortion</member><member>abused-drugs</member><member>alcohol-and-tobacco</member>
        <member>auctions</member><member>business-and-economy</member><member>computer-and-internet-info</member>
        <member>content-delivery-networks</member><member>cryptocurrency</member><member>dating</member>
        <member>educational-institutions</member><member>entertainment-and-arts</member>
        <member>financial-services</member><member>gambling</member><member>games</member><member>government</member>
        <member>grayware</member><member>health-and-medicine</member><member>high-risk</member>
        <member>home-and-garden</member><member>hunting-and-fishing</member><member>insufficient-content</member>
        <member>internet-communications-and-telephony</member><member>internet-portals</member>
        <member>job-search</member><member>legal</member><member>low-risk</member><member>medium-risk</member>
        <member>military</member><member>motor-vehicles</member><member>music</member>
        <member>newly-registered-domain</member><member>news</member><member>not-resolved</member>
        <member>nudity</member>
        <member>online-storage-and-backup</member><member>peer-to-peer</member><member>personal-sites-and-blogs</member>
        <member>philosophy-and-political-advocacy</member><member>private-ip-addresses</member>
        <member>questionable</member><member>real-estate</member><member>recreation-and-hobbies</member>
        <member>reference-and-research</member><member>religion</member><member>search-engines</member>
        <member>sex-education</member><member>shareware-and-freeware</member><member>shopping</member>
        <member>social-networking</member><member>society</member><member>sports</member>
        <member>stock-advice-and-tools</member><member>streaming-media</member>
        <member>swimsuits-and-intimate-apparel</member><member>training-and-tools</member>
        <member>translation</member><member>travel</member>
        <member>weapons</member><member>web-advertisements</member><member>web-based-email</member>
        <member>web-hosting</member></alert><block><member>adult</member><member>command-and-control</member>
        <member>copyright-infringement</member><member>dynamic-dns</member><member>extremism</member>
        <member>hacking</member><member>malware</member><member>parked</member><member>phishing</member>
        <member>proxy-avoidance-and-anonymizers</member><member>unknown</member></block></credential-enforcement>
        <log-http-hdr-xff>yes</log-http-hdr-xff><log-http-hdr-user-agent>yes</log-http-hdr-user-agent>
        <log-http-hdr-referer>yes</log-http-hdr-referer><log-container-page-only>no</log-container-page-only>
        <alert><member>abortion</member><member>abused-drugs</member><member>alcohol-and-tobacco</member>
        <member>auctions</member><member>business-and-economy</member><member>computer-and-internet-info</member>
        <member>content-delivery-networks</member><member>cryptocurrency</member><member>dating</member>
        <member>educational-institutions</member><member>entertainment-and-arts</member>
        <member>financial-services</member><member>gambling</member><member>games</member><member>government</member>
        <member>grayware</member><member>health-and-medicine</member><member>high-risk</member>
        <member>home-and-garden</member><member>hunting-and-fishing</member><member>insufficient-content</member>
        <member>internet-communications-and-telephony</member><member>internet-portals</member>
        <member>job-search</member><member>legal</member><member>low-risk</member>
        <member>medium-risk</member><member>military</member>
        <member>motor-vehicles</member><member>music</member><member>newly-registered-domain</member>
        <member>news</member><member>not-resolved</member><member>nudity</member>
        <member>online-storage-and-backup</member><member>peer-to-peer</member><member>personal-sites-and-blogs</member>
        <member>philosophy-and-political-advocacy</member><member>private-ip-addresses</member>
        <member>questionable</member><member>real-estate</member><member>recreation-and-hobbies</member>
        <member>reference-and-research</member><member>religion</member><member>search-engines</member>
        <member>sex-education</member><member>shareware-and-freeware</member><member>shopping</member>
        <member>social-networking</member><member>society</member><member>sports</member>
        <member>stock-advice-and-tools</member><member>streaming-media</member>
        <member>swimsuits-and-intimate-apparel</member><member>training-and-tools</member>
        <member>translation</member><member>travel</member>
        <member>weapons</member><member>web-advertisements</member><member>web-based-email</member>
        <member>web-hosting</member></alert><block><member>adult</member><member>command-and-control</member>
        <member>copyright-infringement</member><member>dynamic-dns</member><member>extremism</member>
        <member>hacking</member><member>malware</member><member>parked</member><member>phishing</member>
        <member>proxy-avoidance-and-anonymizers</member><member>unknown</member></block>"""
    }
    result = http_request(URL, 'POST', params=params)

    return result


def create_url_filtering_best_practice_profile_command(profile_name: str):
    create_url_filtering_best_practice_profile(profile_name)
    return_results(f'The profile {profile_name} was created successfully.')


@logger
def create_file_blocking_best_practice_profile(profile_name: str) -> Dict:
    params = {
        'action': 'set',
        'type': 'config',
        'xpath': f"{XPATH_RULEBASE}profiles/file-blocking/entry[@name='{profile_name}']",
        'key': API_KEY,
        'element': """<rules><entry name="Block all risky file types"><application><member>any</member></application>
        <file-type><member>7z</member><member>bat</member><member>cab</member><member>chm</member><member>class</member>
        <member>cpl</member><member>dll</member><member>exe</member><member>flash</member><member>hlp</member>
        <member>hta</member><member>jar</member><member>msi</member><member>Multi-Level-Encoding</member>
        <member>ocx</member><member>PE</member><member>pif</member><member>rar</member><member>scr</member>
        <member>tar</member><member>torrent</member><member>vbe</member><member>wsf</member></file-type>
        <direction>both</direction><action>block</action></entry><entry name="Block encrypted files"><application>
        <member>any</member></application><file-type><member>encrypted-rar</member>
        <member>encrypted-zip</member></file-type><direction>both</direction><action>block</action></entry>
        <entry name="Log all other file types"><application><member>any</member></application><file-type>
        <member>any</member></file-type><direction>both</direction><action>alert</action></entry></rules>"""
    }
    result = http_request(URL, 'POST', params=params)

    return result


def create_file_blocking_best_practice_profile_command(profile_name: str):
    create_file_blocking_best_practice_profile(profile_name)
    return_results(f'The profile {profile_name} was created successfully.')


@logger
def create_wildfire_best_practice_profile(profile_name: str) -> Dict:
    params = {
        'action': 'set',
        'type': 'config',
        'xpath': f"{XPATH_RULEBASE}profiles/wildfire-analysis/entry[@name='{profile_name}']",
        'key': API_KEY,
        'element': """<rules><entry name="default"><application><member>any</member></application><file-type>
        <member>any</member></file-type><direction>both</direction><analysis>public-cloud</analysis></entry></rules>"""
    }
    result = http_request(URL, 'POST', params=params)

    return result


def create_wildfire_best_practice_profile_command(profile_name: str):
    create_wildfire_best_practice_profile(profile_name)
    return_results(f'The profile {profile_name} was created successfully.')


def initialize_instance(args: Dict[str, str], params: Dict[str, str]):
    global URL, API_KEY, USE_SSL, USE_URL_FILTERING, VSYS, DEVICE_GROUP, XPATH_SECURITY_RULES, XPATH_OBJECTS, \
        XPATH_RULEBASE, TEMPLATE, PRE_POST
    if not params.get('port'):
        raise DemistoException('Set a port for the instance')

    URL = params.get('server', '').rstrip('/:') + ':' + params.get('port', '') + '/api/'
    API_KEY = str(params.get('key'))
    USE_SSL = not params.get('insecure')
    USE_URL_FILTERING = params.get('use_url_filtering')
    TEMPLATE = params.get('template')

    # determine a vsys or a device-group
    VSYS = params.get('vsys', '')

    if args and args.get('device-group'):
        DEVICE_GROUP = args.get('device-group')  # type: ignore[assignment]
    else:
        DEVICE_GROUP = params.get('device_group', None)  # type: ignore[arg-type]

    PRE_POST = args.get('pre_post', '')

    # configuration check
    if DEVICE_GROUP and VSYS:
        raise DemistoException(
            'Cannot configure both vsys and Device group. Set vsys for firewall, set Device group for Panorama.')
    if not DEVICE_GROUP and not VSYS:
        raise DemistoException('Set vsys for firewall or Device group for Panorama.')

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
        XPATH_OBJECTS = "/config/devices/entry/vsys/entry[@name=\'" + VSYS + "\']/"  # ignore:

    # setting security rulebase xpath relevant to FW or panorama management
    if DEVICE_GROUP:
        device_group_shared = DEVICE_GROUP.lower()
        if DEVICE_GROUP == 'shared':
            XPATH_RULEBASE = "/config/shared/"
            DEVICE_GROUP = device_group_shared
        else:
            XPATH_RULEBASE = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name=\'" + \
                             DEVICE_GROUP + "\']/"
    else:
        XPATH_RULEBASE = f"/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'{VSYS}\']/"


def main():
    try:
        args = demisto.args()
        params = demisto.params()
        additional_malicious = argToList(demisto.params().get('additional_malicious'))
        additional_suspicious = argToList(demisto.params().get('additional_suspicious'))
        initialize_instance(args=args, params=params)
        LOG(f'Command being called is: {demisto.command()}')

        # Remove proxy if not set to true in params
        handle_proxy()

        if demisto.command() == 'test-module':
            panorama_test()

        elif demisto.command() == 'panorama':
            panorama_command(args)

        elif demisto.command() == 'panorama-commit':
            panorama_commit_command()

        elif demisto.command() == 'panorama-commit-status':
            panorama_commit_status_command(args)

        elif demisto.command() == 'panorama-push-to-device-group':
            panorama_push_to_device_group_command()

        elif demisto.command() == 'panorama-push-status':
            panorama_push_status_command(**args)

        # Addresses commands
        elif demisto.command() == 'panorama-list-addresses':
            panorama_list_addresses_command(**args)

        elif demisto.command() == 'panorama-get-address':
            panorama_get_address_command(**args)

        elif demisto.command() == 'panorama-create-address':
            panorama_create_address_command(args)

        elif demisto.command() == 'panorama-delete-address':
            panorama_delete_address_command(**args)

        # Address groups commands
        elif demisto.command() == 'panorama-list-address-groups':
            panorama_list_address_groups_command(**args)

        elif demisto.command() == 'panorama-get-address-group':
            panorama_get_address_group_command(**args)

        elif demisto.command() == 'panorama-create-address-group':
            panorama_create_address_group_command(args)

        elif demisto.command() == 'panorama-delete-address-group':
            panorama_delete_address_group_command(args.get('name'))

        elif demisto.command() == 'panorama-edit-address-group':
            panorama_edit_address_group_command(args)

        # Services commands
        elif demisto.command() == 'panorama-list-services':
            panorama_list_services_command(args.get('tag'))

        elif demisto.command() == 'panorama-get-service':
            panorama_get_service_command(args.get('name'))

        elif demisto.command() == 'panorama-create-service':
            panorama_create_service_command(args)

        elif demisto.command() == 'panorama-delete-service':
            panorama_delete_service_command(args.get('name'))

        # Service groups commands
        elif demisto.command() == 'panorama-list-service-groups':
            panorama_list_service_groups_command(args.get('tags'))

        elif demisto.command() == 'panorama-get-service-group':
            panorama_get_service_group_command(args.get('name'))

        elif demisto.command() == 'panorama-create-service-group':
            panorama_create_service_group_command(args)

        elif demisto.command() == 'panorama-delete-service-group':
            panorama_delete_service_group_command(args.get('name'))

        elif demisto.command() == 'panorama-edit-service-group':
            panorama_edit_service_group_command(args)

        # Custom Url Category commands
        elif demisto.command() == 'panorama-get-custom-url-category':
            panorama_get_custom_url_category_command(args.get('name'))

        elif demisto.command() == 'panorama-create-custom-url-category':
            panorama_create_custom_url_category_command(args)

        elif demisto.command() == 'panorama-delete-custom-url-category':
            panorama_delete_custom_url_category_command(args.get('name'))

        elif demisto.command() == 'panorama-edit-custom-url-category':
            panorama_edit_custom_url_category_command(args)

        # URL Filtering capabilities
        elif demisto.command() == 'url':
            if USE_URL_FILTERING:  # default is false
                panorama_get_url_category_command(url_cmd='url', url=args.get('url'),
                                                  additional_suspicious=additional_suspicious,
                                                  additional_malicious=additional_malicious)
            # do not error out

        elif demisto.command() == 'panorama-get-url-category':
            panorama_get_url_category_command(url_cmd='url', url=args.get('url'),
                                              additional_suspicious=additional_suspicious,
                                              additional_malicious=additional_malicious)

        elif demisto.command() == 'panorama-get-url-category-from-cloud':
            panorama_get_url_category_command(url_cmd='url-info-cloud', url=args.get('url'),
                                              additional_suspicious=additional_suspicious,
                                              additional_malicious=additional_malicious)

        elif demisto.command() == 'panorama-get-url-category-from-host':
            panorama_get_url_category_command(url_cmd='url-info-host', url=args.get('url'),
                                              additional_suspicious=additional_suspicious,
                                              additional_malicious=additional_malicious)

        # URL Filter
        elif demisto.command() == 'panorama-get-url-filter':
            panorama_get_url_filter_command(args.get('name'))

        elif demisto.command() == 'panorama-create-url-filter':
            panorama_create_url_filter_command(args)

        elif demisto.command() == 'panorama-edit-url-filter':
            panorama_edit_url_filter_command(args)

        elif demisto.command() == 'panorama-delete-url-filter':
            panorama_delete_url_filter_command(demisto.args().get('name'))

        # EDL
        elif demisto.command() == 'panorama-list-edls':
            panorama_list_edls_command()

        elif demisto.command() == 'panorama-get-edl':
            panorama_get_edl_command(demisto.args().get('name'))

        elif demisto.command() == 'panorama-create-edl':
            panorama_create_edl_command(args)

        elif demisto.command() == 'panorama-edit-edl':
            panorama_edit_edl_command(args)

        elif demisto.command() == 'panorama-delete-edl':
            panorama_delete_edl_command(demisto.args().get('name'))

        elif demisto.command() == 'panorama-refresh-edl':
            panorama_refresh_edl_command(args)

        # Registered IPs
        elif demisto.command() == 'panorama-register-ip-tag':
            panorama_register_ip_tag_command(args)

        elif demisto.command() == 'panorama-unregister-ip-tag':
            panorama_unregister_ip_tag_command(args)

        # Registered Users
        elif demisto.command() == 'panorama-register-user-tag':
            panorama_register_user_tag_command(args)

        elif demisto.command() == 'panorama-unregister-user-tag':
            panorama_unregister_user_tag_command(args)

        # Security Rules Managing
        elif demisto.command() == 'panorama-list-rules':
            panorama_list_rules_command(args.get('tag'))

        elif demisto.command() == 'panorama-move-rule':
            panorama_move_rule_command(args)

        # Security Rules Configuration
        elif demisto.command() == 'panorama-create-rule':
            panorama_create_rule_command(args)

        elif demisto.command() == 'panorama-custom-block-rule':
            panorama_custom_block_rule_command(args)

        elif demisto.command() == 'panorama-edit-rule':
            panorama_edit_rule_command(args)

        elif demisto.command() == 'panorama-delete-rule':
            panorama_delete_rule_command(args.get('rulename'))

        # Traffic Logs - deprecated
        elif demisto.command() == 'panorama-query-traffic-logs':
            panorama_query_traffic_logs_command(args)

        elif demisto.command() == 'panorama-check-traffic-logs-status':
            panorama_check_traffic_logs_status_command(args.get('job_id'))

        elif demisto.command() == 'panorama-get-traffic-logs':
            panorama_get_traffic_logs_command(args.get('job_id'))

        # Logs
        elif demisto.command() == 'panorama-query-logs':
            panorama_query_logs_command(args)

        elif demisto.command() == 'panorama-check-logs-status':
            panorama_check_logs_status_command(args.get('job_id'))

        elif demisto.command() == 'panorama-get-logs':
            panorama_get_logs_command(args)

        # Pcaps
        elif demisto.command() == 'panorama-list-pcaps':
            panorama_list_pcaps_command(args)

        elif demisto.command() == 'panorama-get-pcap':
            panorama_get_pcap_command(args)

        # Application
        elif demisto.command() == 'panorama-list-applications':
            panorama_list_applications_command(args.get('predefined'))

        # Test security policy match
        elif demisto.command() == 'panorama-security-policy-match':
            panorama_security_policy_match_command(args)

        # Static Routes
        elif demisto.command() == 'panorama-list-static-routes':
            panorama_list_static_routes_command(args)

        elif demisto.command() == 'panorama-get-static-route':
            panorama_get_static_route_command(args)

        elif demisto.command() == 'panorama-add-static-route':
            panorama_add_static_route_command(args)

        elif demisto.command() == 'panorama-delete-static-route':
            panorama_delete_static_route_command(args)

        # Firewall Upgrade
        # Check device software version
        elif demisto.command() == 'panorama-show-device-version':
            panorama_show_device_version_command(args.get('target'))

        # Download the latest content update
        elif demisto.command() == 'panorama-download-latest-content-update':
            panorama_download_latest_content_update_command(args.get('target'))

        # Download the latest content update
        elif demisto.command() == 'panorama-content-update-download-status':
            panorama_content_update_download_status_command(args)

        # Install the latest content update
        elif demisto.command() == 'panorama-install-latest-content-update':
            panorama_install_latest_content_update_command(args.get('target'))

        # Content update install status
        elif demisto.command() == 'panorama-content-update-install-status':
            panorama_content_update_install_status_command(args)

        # Check PAN-OS latest software update
        elif demisto.command() == 'panorama-check-latest-panos-software':
            panorama_check_latest_panos_software_command(args.get('target'))

        # Download target PAN-OS version
        elif demisto.command() == 'panorama-download-panos-version':
            panorama_download_panos_version_command(args)

        # PAN-OS download status
        elif demisto.command() == 'panorama-download-panos-status':
            panorama_download_panos_status_command(args)

        # PAN-OS software install
        elif demisto.command() == 'panorama-install-panos-version':
            panorama_install_panos_version_command(args)

        # PAN-OS install status
        elif demisto.command() == 'panorama-install-panos-status':
            panorama_install_panos_status_command(args)

        # Reboot Panorama Device
        elif demisto.command() == 'panorama-device-reboot':
            panorama_device_reboot_command(args.get('target'))

        # PAN-OS Set vulnerability to drop
        elif demisto.command() == 'panorama-block-vulnerability':
            panorama_block_vulnerability(args)

        # Get pre-defined threats list from the firewall
        elif demisto.command() == 'panorama-get-predefined-threats-list':
            panorama_get_predefined_threats_list_command(args.get('target'))

        elif demisto.command() == 'panorama-show-location-ip':
            panorama_show_location_ip_command(args.get('ip_address'))

        elif demisto.command() == 'panorama-get-licenses':
            panorama_get_license_command()

        elif demisto.command() == 'panorama-get-security-profiles':
            get_security_profiles_command(args.get('security_profile'))

        elif demisto.command() == 'panorama-apply-security-profile':
            apply_security_profile_command(**args)

        elif demisto.command() == 'panorama-get-ssl-decryption-rules':
            get_ssl_decryption_rules_command(**args)

        elif demisto.command() == 'panorama-get-wildfire-configuration':
            get_wildfire_configuration_command(**args)

        elif demisto.command() == 'panorama-get-wildfire-best-practice':
            get_wildfire_best_practice_command()

        elif demisto.command() == 'panorama-enforce-wildfire-best-practice':
            enforce_wildfire_best_practice_command(**args)

        elif demisto.command() == 'panorama-url-filtering-block-default-categories':
            url_filtering_block_default_categories_command(**args)

        elif demisto.command() == 'panorama-get-anti-spyware-best-practice':
            get_anti_spyware_best_practice_command()

        elif demisto.command() == 'panorama-get-file-blocking-best-practice':
            get_file_blocking_best_practice_command()

        elif demisto.command() == 'panorama-get-antivirus-best-practice':
            get_antivirus_best_practice_command()

        elif demisto.command() == 'panorama-get-vulnerability-protection-best-practice':
            get_vulnerability_protection_best_practice_command()

        elif demisto.command() == 'panorama-get-url-filtering-best-practice':
            get_url_filtering_best_practice_command()

        elif demisto.command() == 'panorama-create-antivirus-best-practice-profile':
            create_antivirus_best_practice_profile_command(**args)

        elif demisto.command() == 'panorama-create-anti-spyware-best-practice-profile':
            create_anti_spyware_best_practice_profile_command(**args)

        elif demisto.command() == 'panorama-create-vulnerability-best-practice-profile':
            create_vulnerability_best_practice_profile_command(**args)

        elif demisto.command() == 'panorama-create-url-filtering-best-practice-profile':
            create_url_filtering_best_practice_profile_command(**args)

        elif demisto.command() == 'panorama-create-file-blocking-best-practice-profile':
            create_file_blocking_best_practice_profile_command(**args)

        elif demisto.command() == 'panorama-create-wildfire-best-practice-profile':
            create_wildfire_best_practice_profile_command(**args)

        else:
            raise NotImplementedError(f'Command {demisto.command()} was not implemented.')

    except Exception as err:
        return_error(str(err))

    finally:
        LOG.print_log()


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
