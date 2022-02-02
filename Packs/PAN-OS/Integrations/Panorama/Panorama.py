import enum
from collections import defaultdict
from dataclasses import dataclass, fields
from typing import Generator, Callable, Union

import panos.errors  # type: ignore

# -- This is a way to get around trimming commonserverpython on import
try:
    demisto.args()
except:
    from CommonServerPython import *

from xml.etree.ElementTree import Element
from panos.base import PanDevice, VersionedPanObject, Root, ENTRY, VersionedParamPath  # type: ignore
from panos.panorama import Panorama, DeviceGroup, Template, PanoramaCommitAll  # type: ignore
from panos.firewall import Firewall  # type: ignore
from panos.device import Vsys  # type: ignore
from panos.network import Zone  # type: ignore
from panos.policies import Rulebase, PreRulebase, PostRulebase, SecurityRule  # type: ignore
from panos.objects import (AddressObject, AddressGroup, ServiceObject, ServiceGroup)  # type: ignore
from panos.objects import (LogForwardingProfile, LogForwardingProfileMatchList)  # type: ignore
from panos.objects import (ApplicationObject, SecurityProfileGroup)  # type: ignore
from panos.objects import ApplicationGroup  # type: ignore
from urllib.error import HTTPError

import shutil

''' IMPORTS '''
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union
import uuid
import json
import requests
from urllib.parse import urlparse

# disable insecure warnings
requests.packages.urllib3.disable_warnings()  # type: ignore

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

    # handle raw response that does not contain the response key, e.g configuration export
    if ('response' not in json_result or '@code' not in json_result['response']) and \
            not json_result['response']['@status'] != 'success':
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
                if DEVICE_GROUP:
                    raise Exception('URL filtering commands are only available on Firewall devices.')
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
                if isinstance(json_result['response']['msg']['line']['uid-response']['payload']['register'][
                                  'entry'],
                              list):
                    ips = [o['@ip'] for o in
                           json_result['response']['msg']['line']['uid-response']['payload']['register'][
                               'entry']]
                else:
                    ips = \
                        json_result['response']['msg']['line']['uid-response']['payload']['register'][
                            'entry'][
                            '@ip']
                return_results(
                    'IP ' + str(
                        ips) + ' already exist in the tag. All submitted IPs were not registered to the tag.')
                sys.exit(0)

            # catch timed out log queries and return this as an entry.note
            elif str(json_result['response']['msg']['line']).find('Query timed out') != -1:
                return_results(str(json_result['response']['msg']['line']) + '. Rerun the query.')
                sys.exit(0)

        if '@code' in json_result['response']:
            raise Exception(
                'Request Failed.\nStatus code: ' + str(
                    json_result['response']['@code']) + '\nWith message: ' + str(
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
                'Request Failed.\nStatus code: ' + str(
                    json_result['response']['@code']) + '\nWith message: ' + str(
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
                                 negate_destination: str = None, action: str = None,
                                 service: List[str] = None,
                                 disable: str = None, application: List[str] = None, source_user: str = None,
                                 category: List[str] = None, from_: str = None, to: str = None,
                                 description: str = None,
                                 target: str = None, log_forwarding: str = None,
                                 disable_server_response_inspection: str = None, tags: List[str] = None,
                                 profile_setting: str = None) -> Dict:
    if application is None or len(application) == 0:
        # application always must be specified and the default should be any
        application = ['any']

    # flake8: noqa
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
                   + add_argument_yes_no(disable_server_response_inspection,
                                         'disable-server-response-inspection', True)
                   + add_argument(log_forwarding, 'log-setting', False)
                   + add_argument_list(tags, 'tag', True)
                   + add_argument_profile_setting(profile_setting, 'profile-setting')
    }
    if DEVICE_GROUP:
        if not PRE_POST:
            raise Exception('Please provide the pre_post argument when configuring'
                            ' a security rule in Panorama instance.')
        else:
            params[
                'xpath'] = XPATH_SECURITY_RULES + PRE_POST + '/security/rules/entry' + '[@name=\'' + rulename + '\']'
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
        status_warnings = result.get("response", {}).get('result', {}).get('job', {}).get('warnings', {}).get(
            'line',
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
        raise Exception(
            "The 'panorama-push-to-device-group' command is relevant for a Palo Alto Panorama instance.")

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


def panorama_list_addresses_command(args: dict):
    """
    Get all addresses
    """
    addresses_arr = panorama_list_addresses(args.get('tag'))
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
        'xpath': f'{XPATH_OBJECTS}address/entry[@name=\'{address_name}\']',
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params,
    )

    return result['response']['result']['entry']


def panorama_get_address_command(args: dict):
    """
    Get an address
    """
    address_name = args.get('name')

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


def panorama_delete_address_command(args: dict):
    """
    Delete an address
    """
    address_name = args.get('name')

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


def panorama_list_address_groups_command(args: dict):
    """
    Get all address groups
    """
    address_groups_arr = panorama_list_address_groups(args.get('tag'))
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


def panorama_get_address_group_command(args: dict):
    """
    Get an address group
    """
    address_group_name = args.get('name')

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
                                         ['Name', 'Protocol', 'SourcePort', 'DestinationPort', 'Description',
                                          'Tags'],
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
                                         ['Name', 'Protocol', 'SourcePort', 'DestinationPort', 'Description',
                                          'Tags'],
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

    service = panorama_create_service(service_name, protocol, destination_port, source_port, description,
                                      tags)

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
        'HumanReadable': tableToMarkdown('Service groups:', service_groups_output,
                                         ['Name', 'Services', 'Tags'],
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
        raise Exception(
            'Specify at least one of the following arguments: services_to_add, services_to_remove, tag')

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
                                         ['Name', 'Type', 'Categories', 'Sites', 'Description'],
                                         removeNull=True),
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

    custom_url_category, custom_url_category_output = panorama_create_custom_url_category(
        custom_url_category_name,
        type_, sites, categories,
        description)
    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': custom_url_category,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Created Custom URL Category:', custom_url_category_output,
                                         ['Name', 'Type', 'Categories', 'Sites', 'Description'],
                                         removeNull=True),
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
                                         ['Name', 'Type', 'Categories', 'Sites', 'Description'],
                                         removeNull=True),
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
    predefined_suspicious = ['high-risk', 'medium-risk', 'hacking', 'proxy-avoidance-and-anonymizers',
                             'grayware',
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


def panorama_get_url_category_command(url_cmd: str, url: str, additional_suspicious: list,
                                      additional_malicious: list):
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
    human_readable = tableToMarkdown(f'{title}:', url_category_output_hr, ['URL', 'Category'],
                                     removeNull=True)

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
                                         ['Name', 'Category', 'OverrideAllowList', 'OverrideBlockList',
                                          'Description'],
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
    element = add_argument_list(url_category_list, action, True) + add_argument_list(override_allow_list,
                                                                                     'allow-list',
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
        params[
            'xpath'] = XPATH_OBJECTS + f"profiles/url-filtering/entry[@name='{url_filter_name}']/{element_to_change}"
        params['element'] = add_argument_open(element_value, 'description', False)
        result = http_request(URL, 'POST', body=params)
        url_filter_output['Description'] = element_value

    elif element_to_change == 'override_allow_list':
        prev_override_allow_list = argToList(url_filter_prev['allow-list']['member'])
        if add_remove_element == 'add':
            new_override_allow_list = list((set(prev_override_allow_list)).union(set([element_value])))
        else:
            new_override_allow_list = [url for url in prev_override_allow_list if url != element_value]

        params[
            'xpath'] = XPATH_OBJECTS + "profiles/url-filtering/entry[@name='" + url_filter_name + "']/allow-list"
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

        params[
            'xpath'] = XPATH_OBJECTS + "profiles/url-filtering/entry[@name='" + url_filter_name + "']/block-list"
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
            params[
                'xpath'] = XPATH_SECURITY_RULES + PRE_POST + '/security/rules/entry' + '[@name=\'' + rulename + '\']'
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

    params = prepare_security_rule_params(api_action='set', rulename=rulename, source=source,
                                          destination=destination,
                                          negate_source=negate_source, negate_destination=negate_destination,
                                          action=action, service=service,
                                          disable=disable, application=application, source_user=source_user,
                                          disable_server_response_inspection=disable_server_response_inspection,
                                          description=description, target=target,
                                          log_forwarding=log_forwarding, tags=tags, category=categories,
                                          from_=source_zone, to=destination_zone,
                                          profile_setting=profile_setting)
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
        raise Exception(
            f'Adding objects is only available for the following Objects types:{listable_elements}')
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
            params[
                'xpath'] = XPATH_SECURITY_RULES + PRE_POST + '/security/rules/entry' + '[@name=\'' + rulename + '\']'
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
        elif element_to_change in ['source', 'destination', 'application', 'category', 'source-user',
                                   'service', 'tag']:
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
                raise Exception(
                    'please provide the pre_post argument when editing a rule in Panorama instance.')
            else:
                params[
                    'xpath'] = XPATH_SECURITY_RULES + PRE_POST + f'/security/rules/entry[@name=\'{rulename}\']'
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
            params[
                'xpath'] = XPATH_SECURITY_RULES + PRE_POST + '/security/rules/entry' + '[@name=\'' + rulename + '\']'
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
                                                  destination=['any'], rulename=rulename + '-from',
                                                  target=target,
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
                                                  destination=['any'], rulename=rulename + '-from',
                                                  target=target,
                                                  log_forwarding=log_forwarding, tags=tags)
            result = http_request(URL, 'POST', body=params)
        if block_destination:
            params = prepare_security_rule_params(api_action='set', action='drop', destination=object_value,
                                                  source=['any'], rulename=rulename + '-to', target=target,
                                                  log_forwarding=log_forwarding, tags=tags)
            result = http_request(URL, 'POST', body=params)
        custom_block_output['AddressGroup'] = object_value

    elif object_type == 'url-category':
        params = prepare_security_rule_params(api_action='set', action='drop', source=['any'],
                                              destination=['any'],
                                              category=object_value, rulename=rulename, target=target,
                                              log_forwarding=log_forwarding, tags=tags)
        result = http_request(URL, 'POST', body=params)
        custom_block_output['CustomURLCategory'] = object_value

    elif object_type == 'application':
        params = prepare_security_rule_params(api_action='set', action='drop', source=['any'],
                                              destination=['any'],
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

    serial_number = args.get('serialNumber')
    if VSYS and serial_number:
        raise Exception('The serialNumber argument can only be used in a Panorama instance configuration')
    elif DEVICE_GROUP and not serial_number:
        raise Exception('PCAP listing is only supported on Panorama with the serialNumber argument.')
    elif serial_number:
        params['target'] = serial_number

    result = http_request(URL, 'GET', params=params, is_pcap=True)
    json_result = json.loads(xml2json(result.text))['response']
    if json_result['@status'] != 'success':
        raise Exception('Request to get list of Pcaps Failed.\nStatus code: ' + str(
            json_result['response']['@code']) + '\nWith message: ' + str(
            json_result['response']['msg']['line']))

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
        raise ValueError(
            f"Incorrect data format. searchTime should be of: YYYY/MM/DD HH:MM:SS or YYYY/MM/DD.\n"
            f"Error is: {str(err)}")


@logger
def panorama_get_pcap_command(args: dict):
    """
    Get pcap file
    """
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

    serial_number = args.get('serialNumber')
    if VSYS and serial_number:
        raise Exception('The serialNumber argument can only be used in a Panorama instance configuration')
    elif DEVICE_GROUP and not serial_number:
        raise Exception('PCAP listing is only supported on Panorama with the serialNumber argument.')
    elif serial_number:
        params['target'] = serial_number

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
            raise Exception(
                'Listing predefined applications is only available for PAN-OS 9.X and above versions.')
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
    predefined = predefined == 'true'  # type: ignore
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
                                         ['Name', 'Type', 'URL', 'Recurring', 'CertificateProfile',
                                          'Description'],
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
                                         ['Name', 'Type', 'URL', 'Recurring', 'CertificateProfile',
                                          'Description'],
                                         None, True),
        'EntryContext': {
            "Panorama.EDL(val.Name == obj.Name)": edl_output
        }
    })


@logger
def panorama_create_edl(edl_name: str, url: str, type_: str, recurring: str,
                        certificate_profile: Optional[str],
                        description: Optional[str]):
    params = {
        'action': 'set',
        'type': 'config',
        'xpath': XPATH_OBJECTS + "external-list/entry[@name='" + edl_name + "']/type/" + type_,
        'key': API_KEY
    }

    params['element'] = add_argument(url, 'url',
                                     False) + '<recurring><' + recurring + '/></recurring>' + add_argument(
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
        raise Exception(
            'The panorama-register-user-tag command is only available for PAN-OS 9.X and above versions.')
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
        raise Exception(
            'The panorama-unregister-user-tag command is only available for PAN-OS 9.X and above versions.')
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
def panorama_query_traffic_logs(number_of_logs: str, direction: str, query: str, source: str,
                                destination: str,
                                receive_time: str, application: str, to_port: str, action: str):
    params = {
        'type': 'log',
        'log-type': 'traffic',
        'key': API_KEY
    }

    if query and len(query) > 0:
        params['query'] = query
    else:
        params['query'] = build_traffic_logs_query(source, destination, receive_time, application, to_port,
                                                   action)
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

    if 'response' not in result or 'result' not in result['response'] or 'job' not in result['response'][
        'result']:
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

    if 'response' not in result or 'result' not in result['response'] or 'job' not in result['response'][
        'result'] \
            or 'status' not in result['response']['result']['job']:
        raise Exception('Missing JobID status in response.')
    if result['response']['result']['job']['status'] == 'FIN':
        query_traffic_status_output['Status'] = 'Completed'

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Query Traffic Logs status:', query_traffic_status_output,
                                         ['JobID', 'Status'],
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

    if 'response' not in result or 'result' not in result['response'] or 'job' not in result['response'][
        'result'] \
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
        if 'response' not in result or 'result' not in result['response'] or 'log' not in result['response'][
            'result'] \
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
                                                 ['JobID', 'Source', 'SourcePort', 'Destination',
                                                  'DestinationPort',
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
def panorama_query_logs(log_type: str, number_of_logs: str, query: str, address_src: str, address_dst: str,
                        ip_: str,
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
        raise Exception(
            'Use the free query argument or the fixed search parameters arguments to build your query.')

    result = panorama_query_logs(log_type, number_of_logs, query, address_src, address_dst, ip_,
                                 zone_src, zone_dst, time_generated, action,
                                 port_dst, rule, url, filedigest)

    if result['response']['@status'] == 'error':
        if 'msg' in result['response'] and 'line' in result['response']['msg']:
            message = '. Reason is: ' + result['response']['msg']['line']
            raise Exception('Query logs failed' + message)
        else:
            raise Exception('Query logs failed.')

    if 'response' not in result or 'result' not in result['response'] or 'job' not in result['response'][
        'result']:
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
        'HumanReadable': tableToMarkdown('Query Logs:', query_logs_output, ['JobID', 'Status'],
                                         removeNull=True),
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

        if 'response' not in result or 'result' not in result['response'] or 'job' not in result['response'][
            'result'] \
                or 'status' not in result['response']['result']['job']:
            raise Exception('Missing JobID status in response.')
        if result['response']['result']['job']['status'] == 'FIN':
            query_logs_status_output['Status'] = 'Completed'

        return_results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': result,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Query Logs status:', query_logs_status_output,
                                             ['JobID', 'Status'],
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

        if 'response' not in result or 'result' not in result['response'] or 'job' not in result['response'][
            'result'] \
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
            if 'response' not in result or 'result' not in result['response'] or 'log' not in \
                    result['response'][
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
                                                 ['TimeGenerated', 'SourceAddress', 'DestinationAddress',
                                                  'Application',
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


def build_policy_match_query(application: Optional[str] = None, category: Optional[str] = None,
                             destination: Optional[str] = None,
                             destination_port: Optional[str] = None, from_: Optional[str] = None,
                             to_: Optional[str] = None,
                             protocol: Optional[str] = None, source: Optional[str] = None,
                             source_user: Optional[str] = None):
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
              'cmd': build_policy_match_query(application, category, destination, destination_port, from_,
                                              to_,
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
                          from_: Optional[str] = None, to_: Optional[str] = None,
                          protocol: Optional[str] = None,
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
        raise Exception(
            "The 'panorama-security-policy-match' command is only relevant for a Firewall instance.")

    application = args.get('application')
    category = args.get('category')
    destination = args.get('destination')
    destination_port = args.get('destination-port')
    from_ = args.get('from')
    to_ = args.get('to')
    protocol = args.get('protocol')
    source = args.get('source')
    source_user = args.get('source-user')

    matching_rules = panorama_security_policy_match(application, category, destination, destination_port,
                                                    from_, to_,
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
                                             ['Name', 'Action', 'From', 'To', 'Source', 'Destination',
                                              'Application'],
                                             removeNull=True),
            'EntryContext': {"Panorama.SecurityPolicyMatch(val.Query == obj.Query)": ec_}
        })


''' Static Routes'''


def prettify_static_route(static_route: Dict, virtual_router: str, template: Optional[str] = None) -> Dict[
    str, str]:
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


def prettify_static_routes(static_routes: Union[dict, list], virtual_router: str,
                           template: Optional[str] = None):
    if not isinstance(static_routes, list):  # handle case of only one static route in a virtual router
        return prettify_static_route(static_routes, virtual_router, template)

    pretty_static_route_arr = []
    for static_route in static_routes:
        pretty_static_route = prettify_static_route(static_route, virtual_router, template)
        pretty_static_route_arr.append(pretty_static_route)

    return pretty_static_route_arr


@logger
def panorama_list_static_routes(xpath_network: str, virtual_router: str, show_uncommitted: str) -> Dict[
    str, str]:
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
        static_routes = prettify_static_routes(virtual_router_object['static-route']['entry'], virtual_router,
                                               template)
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
def panorama_get_static_route(xpath_network: str, virtual_router: str, static_route_name: str) -> Dict[
    str, str]:
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
def panorama_add_static_route(xpath_network: str, virtual_router: str, static_route_name: str,
                              destination: str,
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
    return_results(
        fileResult('predefined-threats.json', json.dumps(result['response']['result']).encode('utf-8')))


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
        'EntryContext': {"Panorama.StaticRoutes(val.Name == obj.Name)": entry_context}
        # add key -> deleted: true
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
        human_readable = tableToMarkdown('Result:', content_install_info, ['JobID', 'Status'],
                                         removeNull=True)

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
        human_readable = tableToMarkdown('Result:', panos_version_download, ['JobID', 'Status'],
                                         removeNull=True)

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
        human_readable = tableToMarkdown('PAN-OS Installation:', panos_install, ['JobID', 'Status'],
                                         removeNull=True)

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

    if 'response' not in result or '@status' not in result['response'] or result['response'][
        '@status'] != 'success':
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
                                         ['ip_address', 'country_name', 'country_code', 'result'],
                                         removeNull=True),
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
    if 'response' not in result or '@status' not in result['response'] or result['response'][
        '@status'] != 'success':
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

    headers = ['Authcode', 'Base-license-name', 'Description', 'Feature', 'Serial', 'Expired', 'Expires',
               'Issued']
    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('PAN-OS Available Licenses', available_licences, headers,
                                         removeNull=True),
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

        human_readable += tableToMarkdown('Antivirus Profiles', virus_content,
                                          headers=['Name', 'Decoder', 'Rules'],
                                          removeNull=True)
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


def apply_security_profile_command(profile_name: str, profile_type: str, rule_name: str,
                                   pre_post: str = None):
    if DEVICE_GROUP:  # Panorama instance
        if not pre_post:
            raise Exception('Please provide the pre_post argument when applying profiles to rules in '
                            'Panorama instance.')
        xpath = f"{XPATH_RULEBASE}{pre_post}/security/rules/entry[@name='{rule_name}']/profile-setting/" \
                f"profiles/{profile_type}"

    else:  # firewall instance
        xpath = f"{XPATH_RULEBASE}rulebase/security/rules/entry[@name='{rule_name}']/profile-setting/" \
                f"profiles/{profile_type}"

    apply_security_profile(xpath, profile_name)
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
                                      ['Name', 'Severity', 'Action', 'Category', 'Threat-name'],
                                      removeNull=True)

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
    file_blocking_profile = results.get('response', {}).get('result', {}).get('file-blocking', {}).get(
        'entry', [])

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
    human_readable = tableToMarkdown('Antivirus Best Practice Profile', rules,
                                     ['Name', 'Action', 'WildFire-action'],
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
    vulnerability_protection = results.get('response', {}).get('result', {}).get('vulnerability', {}).get(
        'entry', [])
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

    human_readable = tableToMarkdown('WildFire Best Practice Profile', rules,
                                     ['Name', 'Analysis', 'Application',
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
                    'abortion', 'abused-drugs', 'adult', 'alcohol-and-tobacco', 'auctions',
                    'business-and-economy',
                    'computer-and-internet-info', 'content-delivery-networks', 'cryptocurrency', 'dating',
                    'educational-institutions', 'entertainment-and-arts', 'financial-services', 'gambling',
                    'games',
                    'government', 'grayware', 'health-and-medicine', 'high-risk', 'home-and-garden',
                    'hunting-and-fishing', 'insufficient-content', 'internet-communications-and-telephony',
                    'internet-portals', 'job-search', 'legal', 'low-risk', 'medium-risk', 'military',
                    'motor-vehicles',
                    'music', 'newly-registered-domain', 'news', 'not-resolved', 'nudity',
                    'online-storage-and-backup',
                    'peer-to-peer', 'personal-sites-and-blogs', 'philosophy-and-political-advocacy',
                    'private-ip-addresses', 'questionable', 'real-estate', 'recreation-and-hobbies',
                    'reference-and-research', 'religion', 'search-engines', 'sex-education',
                    'shareware-and-freeware',
                    'shopping', 'social-networking', 'society', 'sports', 'stock-advice-and-tools',
                    'streaming-media',
                    'swimsuits-and-intimate-apparel', 'training-and-tools', 'translation', 'travel',
                    'weapons',
                    'web-advertisements', 'web-based-email', 'web-hosting']},
            'block': {'member': ['command-and-control', 'copyright-infringement', 'dynamic-dns', 'extremism',
                                 'hacking', 'malware', 'parked', 'phishing',
                                 'proxy-avoidance-and-anonymizers',
                                 'unknown']}},
        'alert': {'member': ['abortion', 'abused-drugs', 'adult', 'alcohol-and-tobacco', 'auctions',
                             'business-and-economy', 'computer-and-internet-info',
                             'content-delivery-networks',
                             'cryptocurrency', 'dating', 'educational-institutions', 'entertainment-and-arts',
                             'financial-services', 'gambling', 'games', 'government', 'grayware',
                             'health-and-medicine',
                             'high-risk', 'home-and-garden', 'hunting-and-fishing', 'insufficient-content',
                             'internet-communications-and-telephony', 'internet-portals', 'job-search',
                             'legal',
                             'low-risk', 'medium-risk', 'military', 'motor-vehicles', 'music',
                             'newly-registered-domain', 'news', 'not-resolved', 'nudity',
                             'online-storage-and-backup',
                             'peer-to-peer', 'personal-sites-and-blogs', 'philosophy-and-political-advocacy',
                             'private-ip-addresses', 'questionable', 'real-estate', 'recreation-and-hobbies',
                             'reference-and-research', 'religion', 'search-engines', 'sex-education',
                             'shareware-and-freeware', 'shopping', 'social-networking', 'society', 'sports',
                             'stock-advice-and-tools', 'streaming-media', 'swimsuits-and-intimate-apparel',
                             'training-and-tools', 'translation', 'travel', 'weapons', 'web-advertisements',
                             'web-based-email', 'web-hosting']},
        'block': {
            'member': ['command-and-control', 'copyright-infringement', 'dynamic-dns', 'extremism', 'hacking',
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


def prettify_zones_config(zones_config: Union[List, Dict]) -> Union[List, Dict]:
    pretty_zones_config = []
    if isinstance(zones_config, dict):
        return {
            'Name': zones_config.get('@name'),
            'Network': zones_config.get('network'),
            'ZoneProtectionProfile': zones_config.get('zone-protection-profile'),
            'EnableUserIdentification': zones_config.get('enable-user-identification', 'no'),
            'LogSetting': zones_config.get('log-setting')
        }

    for zone in zones_config:
        pretty_zones_config.append({
            'Name': zone.get('@name'),
            'Network': zone.get('network'),
            'ZoneProtectionProfile': zone.get('zone-protection-profile'),
            'EnableUserIdentification': zone.get('enable-user-identification', 'no'),
            'LogSetting': zone.get('log-setting')
        })

    return pretty_zones_config


def get_interfaces_from_zone_config(zone_config: Dict) -> List:
    """Extract interfaces names from zone configuration"""
    # a zone has several network options as listed bellow, a single zone my only have one network option
    possible_zone_layers = ['layer2', 'layer3', 'tap', 'virtual-wire', 'tunnel']

    for zone_layer in possible_zone_layers:
        zone_network_info = zone_config.get('network', {}).get(zone_layer)

        if zone_network_info:
            interfaces = zone_network_info.get('member')
            if interfaces:
                if isinstance(interfaces, str):
                    return [interfaces]

                else:
                    return interfaces

    return []


def prettify_user_interface_config(zone_config: Union[List, Dict]) -> Union[List, Dict]:
    pretty_interface_config = []
    if isinstance(zone_config, dict):
        interfaces = get_interfaces_from_zone_config(zone_config)

        for interface in interfaces:
            pretty_interface_config.append({
                'Name': interface,
                'Zone': zone_config.get('@name'),
                'EnableUserIdentification': zone_config.get('enable-user-identification', 'no')
            })

    else:
        for zone in zone_config:
            interfaces = get_interfaces_from_zone_config(zone)

            if isinstance(interfaces, str):
                interfaces = [interfaces]

            for interface in interfaces:
                pretty_interface_config.append({
                    'Name': interface,
                    'Zone': zone.get('@name'),
                    'EnableUserIdentification': zone.get('enable-user-identification', 'no')
                })

    return pretty_interface_config


def show_user_id_interface_config_request(args):
    template = args.get('template') if args.get('template') else TEMPLATE
    template_stack = args.get('template_stack')
    vsys = args.get('vsys')

    if VSYS and not vsys:
        vsys = VSYS
    elif not vsys:
        vsys = 'vsys1'

    # firewall instance xpath
    if VSYS:
        xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name=\'" + vsys + "\']/zone"

    # panorama instance xpath
    elif not template_stack:
        xpath = "/config/devices/entry[@name='localhost.localdomain']/" \
                "template/entry[@name=\'" + template + "\']/config/devices/entry[@name='localhost.localdomain']/" \
                                                       "vsys/entry[@name=\'" + vsys + "\']/zone"
    else:
        xpath = "/config/devices/entry[@name='localhost.localdomain']" \
                "/template-stack/entry[@name=\'" + template_stack + \
                "\']/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name=\'" + vsys + "\']/zone"

    params = {
        'action': 'show',
        'type': 'config',
        'xpath': xpath,
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params,
    )

    return dict_safe_get(result, keys=['response', 'result', 'zone', 'entry'])


def show_user_id_interface_config_command(args: dict):
    raw_response = show_user_id_interface_config_request(args)

    if raw_response:
        formatted_results = prettify_user_interface_config(raw_response)
        return_results(
            CommandResults(
                outputs_prefix="Panorama.UserInterfaces",
                outputs_key_field='Name',
                outputs=formatted_results,
                readable_output=tableToMarkdown('User Interface Configuration:', formatted_results,
                                                ['Name', 'Zone', 'EnableUserIdentification'],
                                                removeNull=True),
                raw_response=raw_response
            )
        )

    else:
        return_results("No results found")


def show_zone_config_command(args):
    raw_response = show_user_id_interface_config_request(args)

    if raw_response:
        formatted_results = prettify_zones_config(raw_response)
        return_results(
            CommandResults(
                outputs_prefix="Panorama.Zone",
                outputs_key_field='Name',
                outputs=formatted_results,
                readable_output=tableToMarkdown('Zone Configuration:', formatted_results,
                                                ['Name', 'Network', 'EnableUserIdentification',
                                                 'ZoneProtectionProfile', 'LogSetting'],
                                                removeNull=True),
                raw_response=raw_response
            )
        )

    else:
        return_results("No results found")


def list_configured_user_id_agents_request(args, version):
    template = args.get('template') if args.get('template') else TEMPLATE
    template_stack = args.get('template_stack')
    vsys = args.get('vsys')

    if VSYS and not vsys:
        vsys = VSYS
    elif not vsys:
        vsys = 'vsys1'

    if VSYS:
        if version < 10:
            xpath = "/config/devices/entry[@name='localhost.localdomain']/" \
                    "vsys/entry[@name=\'" + vsys + "\']/user-id-agent"
        else:
            xpath = "/config/devices/entry[@name='localhost.localdomain']" \
                    "/vsys/entry[@name=\'" + vsys + "\']/redistribution-agent"

    elif template_stack:
        if version < 10:
            xpath = "/config/devices/entry[@name='localhost.localdomain']/template-stack" \
                    "/entry[@name=\'" + template_stack + "\']/config/devices/entry[@name='localhost.localdomain']" \
                                                         "/vsys/entry[@name=\'" + vsys + "\']/user-id-agent"
        else:
            xpath = "/config/devices/entry[@name='localhost.localdomain']/template-stack" \
                    "/entry[@name=\'" + template_stack + "\']/config/devices/entry[@name='localhost.localdomain']" \
                                                         "/vsys/entry[@name=\'" + vsys + "\']/redistribution-agent"
    else:
        if version < 10:
            xpath = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name=\'" + template + \
                    "\']/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name=\'" + vsys + \
                    "\']/user-id-agent"
        else:
            xpath = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name=\'" + template + \
                    "\']/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name=\'" + vsys + \
                    "\']/redistribution-agent"

    params = {
        'action': 'show',
        'type': 'config',
        'xpath': xpath,
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params,
    )

    if version < 10:
        return dict_safe_get(result, keys=['response', 'result', 'user-id-agent', 'entry'])

    else:
        return dict_safe_get(result, keys=['response', 'result', 'redistribution-agent', 'entry'])


def prettify_configured_user_id_agents(user_id_agents: Union[List, Dict]) -> Union[List, Dict]:
    pretty_user_id_agents = []
    if isinstance(user_id_agents, dict):
        return {
            'Name': user_id_agents['@name'],
            'Host': dict_safe_get(user_id_agents, keys=['host-port', 'host']),
            'Port': dict_safe_get(user_id_agents, keys=['host-port', 'port']),
            'NtlmAuth': dict_safe_get(user_id_agents, keys=['host-port', 'ntlm-auth'],
                                      default_return_value='no'),
            'LdapProxy': dict_safe_get(user_id_agents, keys=['host-port', 'ldap-proxy'],
                                       default_return_value='no'),
            'CollectorName': dict_safe_get(user_id_agents, keys=['host-port', 'collectorname']),
            'Secret': dict_safe_get(user_id_agents, keys=['host-port', 'secret']),
            'EnableHipCollection': user_id_agents.get('enable-hip-collection', 'no'),
            'IpUserMapping': user_id_agents.get('ip-user-mappings', 'no'),
            'SerialNumber': user_id_agents.get('serial-number'),
            'Disabled': user_id_agents.get('disabled', 'no')
        }

    for agent in user_id_agents:
        pretty_user_id_agents.append({
            'Name': agent['@name'],
            'Host': dict_safe_get(agent, keys=['host-port', 'host']),
            'Port': dict_safe_get(agent, keys=['host-port', 'port']),
            'NtlmAuth': dict_safe_get(agent, keys=['host-port', 'ntlm-auth'], default_return_value='no'),
            'LdapProxy': dict_safe_get(agent, keys=['host-port', 'ldap-proxy'], default_return_value='no'),
            'CollectorName': dict_safe_get(agent, keys=['host-port', 'collectorname']),
            'Secret': dict_safe_get(agent, keys=['host-port', 'secret']),
            'EnableHipCollection': agent.get('enable-hip-collection', 'no'),
            'IpUserMapping': agent.get('ip-user-mappings', 'no'),
            'SerialNumber': agent.get('serial-number'),
            'Disabled': agent.get('disabled', 'no')
        })

    return pretty_user_id_agents


def list_configured_user_id_agents_command(args):
    version = get_pan_os_major_version()
    raw_response = list_configured_user_id_agents_request(args, version)
    if raw_response:
        formatted_results = prettify_configured_user_id_agents(raw_response)
        headers = ['Name', 'Disabled', 'SerialNumber', 'Host', 'Port', 'CollectorName', 'LdapProxy',
                   'NtlmAuth',
                   'IpUserMapping']

        return_results(
            CommandResults(
                outputs_prefix='Panorama.UserIDAgents',
                outputs_key_field='Name',
                outputs=formatted_results,
                readable_output=tableToMarkdown('User ID Agents:', formatted_results,
                                                headers, removeNull=True),
                raw_response=raw_response
            )
        )
    else:
        return_results("No results found")


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


def panorama_upload_content_update_file_command(args: dict):
    category = args.get('category')
    entry_id = args.get('entryID')
    file_path = demisto.getFilePath(entry_id)['path']
    file_name = demisto.getFilePath(entry_id)['name']
    shutil.copy(file_path, file_name)
    with open(file_name, 'rb') as file:
        params = {'type': 'import', 'category': category, 'key': API_KEY}
        response = http_request(uri=URL, method="POST", headers={}, body={}, params=params,
                                files={'file': file})
        human_readble = tableToMarkdown("Results", t=response.get('response'))
        content_upload_info = {
            'Message': response['response']['msg'],
            'Status': response['response']['@status']
        }
        results = CommandResults(raw_response=response,
                                 readable_output=human_readble,
                                 outputs_prefix="Panorama.Content.Upload",
                                 outputs_key_field="Status",
                                 outputs=content_upload_info)

    shutil.rmtree(file_name, ignore_errors=True)
    return results


@logger
def panorama_install_file_content_update(version: str, category: str, validity: str):
    """
    More information about the API endpoint of that request can see here:
    https://docs.paloaltonetworks.com/pan-os/9-1/pan-os-panorama-api/pan-os-xml-api-request-types/run-operational-mode-commands-api.html#idb894d5f5-091f-4e08-b051-4c22cc9c660d
    """
    if category == "content":
        params = {
            'type': 'op',
            'cmd': (
                f'<request><{category}><upgrade><install><skip-content-validity-check>{validity}'
                f'</skip-content-validity-check><file>{version}</file></install></upgrade></{category}></request>'),
            'key': API_KEY
        }
    else:
        params = {
            'type': 'op',
            'cmd': (
                f'<request><{category}><upgrade><install><file>{version}'
                f'</file></install></upgrade></{category}></request>'), 'key': API_KEY
        }
    result = http_request(
        URL,
        'GET',
        params=params
    )
    return result


def panorama_install_file_content_update_command(args: dict):
    version = args.get('version_name')
    category = args.get('category')
    validity = args['skip_validity_check']
    result = panorama_install_file_content_update(version, category, validity)

    if 'result' in result.get('response'):
        # installation has been given a jobid
        content_install_info = {
            'JobID': result['response']['result']['job'],
            'Status': 'Pending'
        }
        entry_context = {"Panorama.Content.Install(val.JobID == obj.JobID)": content_install_info}
        human_readable = tableToMarkdown('Result:', content_install_info, ['JobID', 'Status'],
                                         removeNull=True)

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


"""
PAN-OS Network Operations Integration

Provides additional complex commands for PAN-OS firewalls and ingests configuration issues as incidents.
"""


# Errors
class OpCommandError(Exception):
    pass


# Globals
OUTPUT_PREFIX = "PANOS."
UNICODE_FAIL = u'\U0000274c'
UNICODE_PASS = u'\U00002714\U0000FE0F'


# Best practices
class BestPractices:
    SPYWARE_ALERT_THRESHOLD = ["medium, low"]
    SPYWARE_BLOCK_SEVERITIES = ["critical", "high"]
    VULNERABILITY_ALERT_THRESHOLD = ["medium, low"]
    VULNERABILITY_BLOCK_SEVERITIES = ["critical", "high"]
    URL_BLOCK_CATEGORIES = ["command-and-control", "hacking", "malware", "phishing"]


# pan-os-python new classes
class CustomVersionedPanObject(VersionedPanObject):
    def __init__(self):
        super(CustomVersionedPanObject, self).__init__()

    def _refresh_children(self, running_config=False, xml=None):
        """Override normal refresh method"""
        # Retrieve the xml if we weren't given it
        if xml is None:
            xml = self._refresh_xml(running_config, True)

        if xml is None:
            return

        # Remove all the current child instances first
        self.removeall()

        child = self.CHILDTYPES[0]()
        child.parent = self
        childroot = xml.find(child.XPATH[1:])
        if childroot is not None:
            l = child.refreshall_from_xml(childroot)
            self.extend(l)

        return self.children


class AntiSpywareProfileBotnetDomainList(CustomVersionedPanObject):
    ROOT = Root.VSYS  # pylint: disable=E1101
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/lists")
        params = []

        params.append(
            VersionedParamPath("packet_capture", path="packet-capture")
        )
        params.append(
            VersionedParamPath("is_action_sinkhole", path="action/sinkhole")
        )


class AntiSpywareProfileBotnetDomains(CustomVersionedPanObject):
    ROOT = Root.VSYS  # pylint: disable=E1101
    SUFFIX = ENTRY
    CHILDTYPES = (AntiSpywareProfileBotnetDomainList,)

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/botnet-domains")
        params = []

        self._params = tuple(params)


class AntiSpywareProfileRule(VersionedPanObject):
    ROOT = Root.VSYS  # pylint: disable=E1101
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/rules")
        # params
        params = []
        params.append(
            VersionedParamPath("severity", vartype="member", path="severity")
        )
        params.append(
            VersionedParamPath("is_reset_both", vartype="exist", path="action/reset-both")
        )
        params.append(
            VersionedParamPath("is_reset_client", vartype="exist", path="action/reset-client")
        )
        params.append(
            VersionedParamPath("is_reset_server", vartype="exist", path="action/reset-server")
        )
        params.append(
            VersionedParamPath("is_alert", vartype="exist", path="action/alert")
        )
        params.append(
            VersionedParamPath("is_default", vartype="exist", path="action/default")
        )
        params.append(
            VersionedParamPath("is_allow", vartype="exist", path="action/allow")
        )
        params.append(
            VersionedParamPath("is_drop", vartype="exist", path="action/drop")
        )
        params.append(
            VersionedParamPath("is_block_ip", vartype="exist", path="action/block-ip")
        )
        self._params = tuple(params)


class AntiSpywareProfile(CustomVersionedPanObject):
    """Vulnerability Profile Group Object

    Args:
        name (str): Name of the object

    """

    ROOT = Root.VSYS  # pylint: disable=E1101
    SUFFIX = ENTRY
    CHILDTYPES = (AntiSpywareProfileRule,)

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/profiles/spyware")

        # params
        params = []

        self._params = tuple(params)


class VulnerabilityProfileRule(VersionedPanObject):
    """Vulnerability Profile Rule Object

    Args:
        name (str): Name of the object
        severity (list:str): List of severities matching this rule
    """
    ROOT = Root.VSYS  # pylint: disable=E1101
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/rules")

        # params
        params = []
        params.append(
            VersionedParamPath("severity", vartype="member", path="severity")
        )
        params.append(
            VersionedParamPath("is_reset_both", vartype="exist", path="action/reset-both")
        )
        params.append(
            VersionedParamPath("is_reset_client", vartype="exist", path="action/reset-client")
        )
        params.append(
            VersionedParamPath("is_reset_server", vartype="exist", path="action/reset-server")
        )
        params.append(
            VersionedParamPath("is_alert", vartype="exist", path="action/alert")
        )
        params.append(
            VersionedParamPath("is_default", vartype="exist", path="action/default")
        )
        params.append(
            VersionedParamPath("is_allow", vartype="exist", path="action/allow")
        )
        params.append(
            VersionedParamPath("is_drop", vartype="exist", path="action/drop")
        )
        params.append(
            VersionedParamPath("is_block_ip", vartype="exist", path="action/block-ip")
        )
        self._params = tuple(params)


class VulnerabilityProfile(CustomVersionedPanObject):
    """Vulnerability Profile Group Object

    Args:
        name (str): Name of the object
    """

    ROOT = Root.VSYS  # pylint: disable=E1101
    SUFFIX = ENTRY
    CHILDTYPES = (VulnerabilityProfileRule,)

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/profiles/vulnerability")

        # params
        params = []

        self._params = tuple(params)


class URLFilteringProfile(VersionedPanObject):
    """URL Filtering profile

    :param block: Block URL categories
    :param alert: Alert URL categories
    :param credential_enforce_block: Categories blocking credentials
    :param credential_enforce_alert: Categories alerting on credentials
    """

    ROOT = Root.VSYS  # pylint: disable=E1101
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/profiles/url-filtering")

        # params
        params = []
        params.append(
            VersionedParamPath("block", vartype="member", path="block")
        )

        params.append(
            VersionedParamPath("alert", vartype="member", path="alert")
        )

        params.append(
            VersionedParamPath("credential_enforce_alert", vartype="member",
                               path="credential-enforcement/alert")
        )
        params.append(
            VersionedParamPath("credential_enforce_block", vartype="member",
                               path="credential-enforcement/block")
        )
        self._params = tuple(params)


def run_op_command(device: Union[Panorama, Firewall], cmd: str, **kwargs) -> Element:
    result: Element = device.op(cmd, **kwargs)
    if "status" in result:
        if result.attrib.get("status") != "success":
            raise OpCommandError

    return result


def find_text_in_element(element: Element, tag: str) -> str:
    result = element.find(tag)
    if result is None:
        raise LookupError(f"Tag {tag} not found in element.")

    if not hasattr(result, "text"):
        raise LookupError(f"Tag {tag} has no text.")

    if result.text:
        return result.text
    else:
        return ""


def get_element_attribute(element: Element, attribute: str) -> str:
    if attribute in element.attrib:
        return element.attrib.get(attribute, "")

    else:
        raise AttributeError(f"Element is missing requested attribute {attribute}")


@dataclass
class FrozenTopology(object):
    panorama_objects: list
    firewall_objects: list


class Topology:
    """
    Core topology class; stores references to each object that can be connected to such as Panorama or NGFW
    Endpoints are each `Node`, which can have any number of child `Node` objects to form a tree.

    :param Panorama_objects: Panorama PanDevice object dict
    :param firewall_objects: Firewall PanDevice object dict
    :param ha_pair_serials: Mapping of HA pairs, where the keys are the active members, values are passive.
    """

    def __init__(self):
        self.panorama_objects: dict = {}
        self.firewall_objects: dict = {}
        self.ha_pair_serials: dict = {}
        self.ha_active_devices: dict = {}
        self.username: str = ""
        self.password: str = ""

    def get_peer(self, serial: str):
        """Given a serial, get it's peer, if part of a HA pair."""
        return self.ha_pair_serials.get(serial)

    def get_all_child_firewalls(self, device: Panorama):
        """
        Connect to Panorama and retrieves the full list of managed devices.
        This list will only retrieve devices that are connected to panorama.
        """
        ha_pair_dict = {}
        device_op_command_result: Element = run_op_command(device, "show devices all")
        device_entry: Element
        for device_entry in device_op_command_result.findall("./result/devices/entry"):
            serial_number: str = find_text_in_element(device_entry, "./serial")
            connected: str = find_text_in_element(device_entry, "./connected")
            if connected == "yes":
                new_firewall_object = Firewall(serial=serial_number)
                device.add(new_firewall_object)
                self.add_device_object(new_firewall_object)
                ha_peer_serial_element: Optional[Element] = device_entry.find("./ha/peer/serial")
                ha_peer_serial = None
                if ha_peer_serial_element and hasattr(ha_peer_serial_element, "text"):
                    ha_peer_serial = ha_peer_serial_element.text

                if ha_peer_serial:
                    # The key is always the active device.
                    ha_status: str = find_text_in_element(device_entry, "./ha/state")
                    if ha_status == "active":
                        self.ha_active_devices[serial_number] = ha_peer_serial

                    ha_pair_dict[serial_number] = ha_peer_serial
                else:
                    self.ha_active_devices[serial_number] = "STANDALONE"

        self.ha_pair_serials = ha_pair_dict

    def add_device_object(self, device: Union[PanDevice, Panorama, Firewall]):
        if type(device) is Panorama:
            # Check if HA is active and if so, what the system state is.
            panorama_ha_state_result: Element = run_op_command(device, "show high-availability state")
            enabled = panorama_ha_state_result.find("./result/enabled")

            if enabled == "yes":
                # Only associate Firewalls with the active Panorama instance
                state = find_text_in_element(panorama_ha_state_result, "./result/group/local-info/state")
                if "active" in state:
                    # TODO: Work out how to get the Panorama peer serial..
                    self.ha_active_devices[device.serial] = "peer serial not implemented here.."
                    self.get_all_child_firewalls(device)
                    return
            else:
                self.get_all_child_firewalls(device)

            # This is a bit of a hack - if no ha, treat it as active
            self.ha_active_devices[device.serial] = "STANDALONE"
            self.panorama_objects[device.serial] = device

            return

        elif type(device) is Firewall:
            self.firewall_objects[device.serial] = device
            return

        raise TypeError(f"{type(device)} is not valid as a topology object.")

    def top_level_devices(self) -> Generator[Union[Firewall, Panorama], None, None]:
        """
        Returns a list of the highest level devices. This is normally Panorama, or in a pure NGFW deployment,
        this would be a list of all the `Firewall` instances.
        :return:
        """
        if self.panorama_objects:
            for value in self.panorama_objects.values():
                yield value

            return

        if self.firewall_objects:
            for value in self.firewall_objects.values():
                yield value

    def active_devices(self, filter_str: str = None) -> Generator[Union[Firewall, Panorama], None, None]:
        """
        Yields active devices in the topology
        """
        # If the ha_active_devices dict is not empty, we have gotten HA info from panorama.
        # This means we don't need to refresh the state.
        for device in self.all(filter_str):
            if self.ha_active_devices:
                if device.serial in self.ha_active_devices:
                    yield device
            else:
                status = device.refresh_ha_active()
                if status == "active" or not status:
                    yield device

    def active_top_level_devices(self, device_filter_string: str = None):
        """
        Yields active top level devices
        """
        active_top_level_devices = [x for x in self.top_level_devices() if
                                    x in self.active_devices(device_filter_string)]
        return active_top_level_devices

    @staticmethod
    def filter_devices(devices: dict, filter_str: Optional[str] = None):
        """Filters a list of devices to find matching entries based on the string"""
        # Exact match based on device serial number
        if not filter_str:
            return devices

        if filter_str in devices:
            return {
                filter_str: devices.get(filter_str)
            }

        device: PanDevice
        for serial, device in devices.items():
            if device.hostname == filter_str:
                return {
                    serial: device
                }

    def firewalls(self, filter_string: str = None) -> Generator[Firewall, None, None]:
        """Returns an iterable for each firewall in the topology"""
        firewall_objects = Topology.filter_devices(self.firewall_objects, filter_string)
        if not firewall_objects:
            raise DemistoException("Filter string returned no devices known to this topology.")

        for firewall in firewall_objects.values():
            yield firewall

    def all(self, filter_string: str = None) -> Generator[Union[Firewall, Panorama], None, None]:
        all_devices = {**self.firewall_objects, **self.panorama_objects}
        all_devices = Topology.filter_devices(all_devices, filter_string)
        # Raise if we get an empty dict back
        if not all_devices:
            raise DemistoException("Filter string returned no devices known to this topology.")

        for device in all_devices.values():
            yield device

    def get_by_filter_str(self, filter_string: str = None) -> dict:
        all_devices = {**self.firewall_objects, **self.panorama_objects}
        all_devices = Topology.filter_devices(all_devices, filter_string)
        return all_devices

    @classmethod
    def build_from_string(cls, hostnames: str, username: str, password: str, api_key: str = None):
        """
        Splits a csv list of hostnames and builds the topology based on it.
        :param hostnames: String of hostnames to build
        :param username: Username
        :param password: Password
        """
        topology = cls()
        for hostname in hostnames.split(","):
            try:
                if api_key:
                    device: PanDevice = PanDevice.create_from_device(
                        hostname=hostname,
                        api_key=api_key
                    )
                else:
                    device = PanDevice.create_from_device(
                        hostname=hostname,
                        api_username=username,
                        api_password=password,
                    )
                # Set the timeout
                device.timeout = 120
                topology.add_device_object(device)
            except (panos.errors.PanURLError, panos.errors.PanXapiError, HTTPError) as e:
                demisto.debug(f"Failed to connected to {hostname}, {e}")
                # If a device fails to respond, don't add it to the topology.
                pass

        topology.username = username
        topology.password = password

        return topology

    @classmethod
    def build_from_device(cls, ip: str, username: str, password: str):
        """
        Connects to the given device at `ip`, if it's a single NGFW it adds it directly to nodes, otherwise
        it iterates through it and it's children.
        :param ip: IP address to connect to
        :param username: Login username
        :param password: Login Password
        :return: instance of `Topology`
        """
        device: PanDevice = PanDevice.create_from_device(
            hostname=ip,
            api_username=username,
            api_password=password,
        )
        # Set the timeout
        device.timeout = 120
        topology = cls()
        topology.add_device_object(device)

        topology.username = username
        topology.password = password

        return topology

    def freeze(self) -> dict:
        """
        Serializes the topology information for storage (for example, in the incident context)
        :return: dict of topology information
        """
        frozen_topology = FrozenTopology
        panorama_object: Panorama
        for panorama_object in self.panorama_objects:
            frozen_topology.panorama_objects.append(panorama_object.hostname)
        firewall_object: Firewall
        for firewall_object in self.panorama_objects:
            frozen_topology.firewall_objects.append(firewall_object.hostname)

        return vars(frozen_topology)

    def get_direct_device(self, firewall: Firewall) -> PanDevice:
        """
        Given a firewall object that's proxied via Panorama, create a device that uses a direct API connection
        instead. Used by any command that can't be routed via Panorama.
        :return:
        """
        if firewall.hostname:
            # If it's already a direct connection
            return firewall

        ip_address = firewall.show_system_info().get("system").get("ip-address")

        return PanDevice.create_from_device(
            hostname=ip_address,
            api_username=self.username,
            api_password=self.password
        )

    def get_all_object_containers(
            self,
            device_filter_string: str = None,
            container_name: str = None,
            top_level_devices_only: bool = False,
    ) -> \
            list[tuple[PanDevice, Union[Panorama, Firewall, DeviceGroup, Template, Vsys]]]:
        """
        Given a device, returns all the possible configuration containers that can contain objects -
        vsys and device-groups.
        """
        containers: list[Union[tuple[PanDevice, Callable], tuple[PanDevice, PanDevice]]] = []
        # for device in self.all(device_filter_string):
        # Changed to only refer to active devices, no passives.
        device_retrieval_func = self.active_devices
        if top_level_devices_only:
            device_retrieval_func = self.active_top_level_devices  # type: ignore

        for device in device_retrieval_func(device_filter_string):
            device_groups = DeviceGroup.refreshall(device)
            for device_group in device_groups:
                containers.append((device, device_group))

            templates = Template.refreshall(device)
            for template in templates:
                containers.append((device, template))

            virtual_systems = Vsys.refreshall(device)
            for virtual_system in virtual_systems:
                containers.append((device, virtual_system))

            if type(device) is Panorama:
                # Add the "shared" device if Panorama. Firewalls will always have vsys1
                containers.append((device, device))

        return_containers = []

        if container_name:
            for container in containers:
                if container_name == "shared":
                    if type(container[1]) is Panorama:
                        return_containers.append(container)
                if type(container[1]) not in [Panorama, Firewall]:
                    if container[1].name == container_name:  # type: ignore
                        return_containers.append(container)
        else:
            return_containers = containers

        return return_containers


"""
--- Dataclass Definitions Start Below ---
Dataclasses are split into three types;
 SummaryData: Classes that hold only summary data, and are safe to display in the incident layout
 ResultData: Classes that hold a full representation of the data, used to pass between tasks only
"""


@dataclass
class ResultData:
    hostid: str


@dataclass
class ShowArpCommandResultData(ResultData):
    """
    :param interface: Network interface learnt ARP entry
    :param ip: layer 3 address
    :param mac: Layer 2 address
    :param port: Network interface matching entry
    :param status: ARP Entry status
    :param ttl: Time to Live
    """
    interface: str
    ip: str
    mac: str
    port: str
    status: str
    ttl: str


@dataclass
class ShowArpCommandSummaryData(ResultData):
    """
    :param max: Maximum supported ARP Entries
    :param total: Total current arp entries
    :param timeout: ARP entry timeout
    :param dp: Firewall dataplane associated with Entry
    """
    max: str
    total: str
    timeout: str
    dp: str


@dataclass
class ShowArpCommandResult:
    summary_data: list[ShowArpCommandSummaryData]
    result_data: list[ShowArpCommandResultData]

    _output_prefix = OUTPUT_PREFIX + "ShowArp"
    _title = "PAN-OS ARP Table"

    # The below is required for integration autogen, we can't inspect the original class from the list[]
    _summary_cls = ShowArpCommandSummaryData
    _result_cls = ShowArpCommandResultData


@dataclass
class ShowRoutingCommandSummaryData(ResultData):
    """
    :param total: Total routes
    :param limit: Maximum routes for platform
    :param active: Active routes in routing table
    """
    total: int
    limit: int
    active: int

    def __post_init__(self):
        self.total = int(self.total)
        self.limit = int(self.limit)
        self.active = int(self.active)


@dataclass
class ShowRouteSummaryCommandResult:
    summary_data: list[ShowRoutingCommandSummaryData]
    result_data: list

    _output_prefix = OUTPUT_PREFIX + "ShowRouteSummary"
    _title = "PAN-OS Route Summary"

    _summary_cls = ShowRoutingCommandSummaryData


@dataclass
class ShowRoutingRouteResultData(ResultData):
    """
    :param virtual_router: Virtual router this route belongs to
    :param destination: Network destination of route
    :param nexthop: Next hop to destination
    :param metric: Route metric
    :param flags: Route flags
    :param interface: Next hop interface
    :param route-table: Unicast|multicast route table
    """
    virtual_router: str
    destination: str
    nexthop: str
    metric: str
    flags: str
    age: int
    interface: str
    route_table: str


@dataclass
class ShowRoutingRouteSummaryData(ResultData):
    """
    :param interface: Next hop interface
    :param route_count: Total routes seen on virtual router interface
    """
    interface: str
    route_count: int


@dataclass
class ShowRoutingRouteCommandResult:
    summary_data: list[ShowRoutingRouteSummaryData]
    result_data: list[ShowRoutingRouteResultData]

    _output_prefix = OUTPUT_PREFIX + "ShowRoute"
    _title = "PAN-OS Routes"

    _summary_cls = ShowRoutingRouteSummaryData
    _result_cls = ShowRoutingRouteResultData


@dataclass
class ShowSystemInfoResultData(ResultData):
    """
    :param ip_address: Management IP Address
    :param ipv6_address: Management IPv6 address
    :param netmask: Management Netmask
    :param default_gateway: Management Default Gateway
    :param mac_address: Management MAC address
    :param uptime: Total System uptime
    :param family: Platform family
    :param model: Platform model
    :param sw_version: System software version
    :param av_version: System anti-virus version
    :param app_version: App content version
    :param threat_version: Threat content version
    :param threat_release_date: Release date of threat content
    :param app_release_date: Release date of application content
    :param wildfire_version: Wildfire content version
    :param wildfire_release_date: Wildfire release date
    :param url_filtering_version: URL Filtering content version
    """
    ip_address: str
    netmask: str
    mac_address: str
    uptime: str
    family: str
    model: str
    sw_version: str
    operational_mode: str
    # Nullable fields - when using Panorama these can be null
    ipv6_address: str = ""
    default_gateway: str = ""
    public_ip_address: str = ""
    hostname: str = ""
    av_version: str = ""
    av_release_date: str = ""
    app_version: str = ""
    app_release_date: str = ""
    threat_version: str = ""
    threat_release_date: str = ""
    wildfire_version: str = ""
    wildfire_release_date: str = ""
    url_filtering_version: str = ""


@dataclass
class ShowSystemInfoSummaryData(ResultData):
    """
    :param ip_address: Management IP Address
    :param sw_version: System software version
    :param uptime: Total System uptime
    :param family: Platform family
    :param model: Platform model
    :param hostname: System Hostname
    """
    ip_address: str
    sw_version: str
    family: str
    model: str
    uptime: str
    hostname: str = ""


@dataclass
class ShowSystemInfoCommandResult:
    summary_data: list[ShowSystemInfoSummaryData]
    result_data: list[ShowSystemInfoResultData]

    _output_prefix = OUTPUT_PREFIX + "ShowSystemInfo"
    _title = "PAN-OS System Info"

    _summary_cls = ShowSystemInfoSummaryData
    _result_cls = ShowSystemInfoResultData


@dataclass
class ShowCounterGlobalResultData(ResultData):
    """
    :param category: The counter category
    :param name: Human readable counter name
    :param value: Current counter value
    :param rate: Packets per second rate
    :param aspect: PANOS Aspect
    :param desc: Human readable counter description
    :param counter_id: Counter ID
    :param severity: Counter severity
    :param id: Counter ID
    """
    category: str
    name: str
    value: int
    rate: int
    aspect: str
    desc: str
    id: str
    severity: str

    timestamp = datetime.now()

    def __post_init__(self):
        self.value = int(self.value)
        self.rate = int(self.rate)


@dataclass
class ShowCounterGlobalSummaryData(ResultData):
    """
    :param name: Human readable counter name
    :param value: Current counter value
    :param rate: Packets per second rate
    :param desc: Human readable counter description
    """
    name: str
    value: int
    rate: int
    desc: str

    def __post_init__(self):
        self.value = int(self.value)
        self.rate = int(self.rate)


@dataclass
class ShowCounterGlobalCommmandResult:
    summary_data: list[ShowCounterGlobalSummaryData]
    result_data: list[ShowCounterGlobalResultData]

    _output_prefix = OUTPUT_PREFIX + "ShowCounters"
    _title = "PAN-OS Global Counters"

    _summary_cls = ShowCounterGlobalSummaryData
    _result_cls = ShowCounterGlobalResultData


@dataclass
class ShowRoutingProtocolBGPPeersResultData(ResultData):
    """
    :param peer: Name of BGP peer
    :param vr: Virtual router peer resides in
    :param remote_as: Remote AS (Autonomous System) of Peer
    :param status: Peer connection status
    :param incoming_total: Total incoming routes from peer
    :param incoming_accepted: Total accepted routes from peer
    :param incoming_rejected: Total rejected routes from peer
    :param policy_rejected: Total routes rejected by peer by policy
    :param outgoing_total: Total routes advertised to peer
    :param outgoing_advertised: Count of advertised routes to peer
    :param peer_address: IP address and port of peer
    :param local_address: Local router address and port
    """
    peer: str
    vr: str
    remote_as: str
    status: str
    peer_address: str
    local_address: str
    incoming_total: int = 0
    incoming_accepted: int = 0
    incoming_rejected: int = 0
    policy_rejected: int = 0
    outgoing_total: int = 0
    outgoing_advertised: int = 0

    def __post_init__(self):
        self.incoming_total = int(self.incoming_total)
        self.incoming_accepted = int(self.incoming_accepted)
        self.incoming_rejected = int(self.incoming_rejected)
        self.policy_rejected = int(self.policy_rejected)
        self.outgoing_total = int(self.outgoing_total)
        self.outgoing_advertised = int(self.outgoing_advertised)


@dataclass
class ShowRoutingProtocolBGPPeersSummaryData(ResultData):
    """
    :param peer: Name of BGP peer
    :param status: Peer connection status
    :param incoming_accepted: Total accepted routes from peer
    """
    peer: str
    status: str
    incoming_accepted: int = 0

    def __post_init__(self):
        self.incoming_accepted = int(self.incoming_accepted)


@dataclass
class ShowRoutingProtocolBGPCommandResult:
    summary_data: list[ShowRoutingProtocolBGPPeersSummaryData]
    result_data: list[ShowRoutingProtocolBGPPeersResultData]

    _output_prefix = OUTPUT_PREFIX + "ShowBGPPeers"
    _title = "PAN-OS BGP Peers"

    _summary_cls = ShowRoutingProtocolBGPPeersSummaryData
    _result_cls = ShowRoutingProtocolBGPPeersResultData


@dataclass
class GetDeviceConnectivityResultData(ResultData):
    """
    :param connected: Whether the host is reachable and connected.
    """
    connected: bool


@dataclass
class GetDeviceConnectivityCommandResult:
    summary_data: list[GetDeviceConnectivityResultData]
    result_data: None = None

    _output_prefix = OUTPUT_PREFIX + "DeviceConnectivity"
    _title = "PAN-OS Device Connectivity Status"

    _summary_data = GetDeviceConnectivityResultData


@dataclass
class SoftwareVersion(ResultData):
    """
    :param version: software version in Major.Minor.Maint format
    :param filename: Software version filename
    :param size: Size of software in MB
    :param size_kb: Size of software in KB
    :param release_notes: Link to version release notes on PAN knowledge base
    :param downloaded: True if the software version is present on the system
    :param current: True if this is the currently installed software on the system
    :param latest: True if this is the most recently released software for this platform
    :param uploaded: True if the software version has been uploaded to the system
    """
    version: str
    filename: str
    size: int
    size_kb: int
    release_notes: str
    downloaded: bool
    current: bool
    latest: bool
    uploaded: bool


@dataclass
class SoftwareVersionCommandResult:
    summary_data: list[SoftwareVersion]
    result_data: None = None

    _output_prefix = OUTPUT_PREFIX + "SoftwareVersions"
    _title = "PAN-OS Available Software Versions"

    _summary_cls = SoftwareVersion


@dataclass
class FileInfoResult:
    """
    :param Name: Filename
    :param EntryID: Entry ID
    :param Size: Size of file
    :param Type: Type of file
    :param Info: Basic information of file
    """
    Name: str
    EntryID: str
    Size: int
    Type: str
    Info: str

    _output_prefix = "InfoFile"


@dataclass
class ShowHAState(ResultData):
    """
    :param active: Whether this is the active firewall in a pair or not. True if standalone as well
    :param status: String HA status
    :param peer: HA Peer
    """
    active: bool
    status: str
    peer: str

    _output_prefix = OUTPUT_PREFIX + "HAState"
    _title = "PAN-OS HA State"
    _outputs_key_field = "hostid"


@dataclass
class ShowJobsAllSummaryData(ResultData):
    """
    :param type: Job type
    :param tfin: Time finished
    :param status: Status of job
    :param id: ID of job
    """
    id: int
    type: str
    tfin: str
    status: str
    result: str

    def __post_init__(self):
        self.id = int(self.id)


@dataclass
class ShowJobsAllResultData(ResultData):
    """
    Note; this is only a subset so it supports the
    :param type: Job type
    :param tfin: Time finished
    :param status: Status of job
    :param id: ID of job
    """
    id: int
    type: str
    tfin: str
    status: str
    result: str
    user: str
    tenq: str
    stoppable: str
    description: str
    positionInQ: int
    progress: int

    _output_prefix = OUTPUT_PREFIX + "JobStatus"
    _title = "PAN-OS Job Status"
    _outputs_key_field = "id"

    def __post_init__(self):
        self.id = int(self.id)


@dataclass
class ShowJobsAllCommandResult:
    summary_data: list[ShowJobsAllSummaryData]
    result_data: list[ShowJobsAllResultData]

    _output_prefix = OUTPUT_PREFIX + "JobStatus"
    _title = "PAN-OS Job Status"

    _summary_cls = ShowJobsAllSummaryData
    _result_cls = ShowJobsAllResultData
    _outputs_key_field = "id"


@dataclass
class GenericSoftwareStatus(ResultData):
    """
    :param started: Whether download process has started.
    """
    started: bool


@dataclass
class CommitStatus(ResultData):
    """
    :param job_id: The ID of the commit job. May be empty on first run.,
    :param status: The current status of the commit operation.
    :param device_type: The type of device; can be either "Panorama" or "Firewall"
    :param commit_type: The type of commit operation.
    """
    job_id: str
    commit_type: str
    status: str
    device_type: str

    _output_prefix = OUTPUT_PREFIX + "CommitStatus"
    _title = "PAN-OS Commit Job"
    _outputs_key_field = "job_id"


@dataclass
class PushStatus(ResultData):
    """
    :param job_id: The ID of the push job.
    :param commit_all_status: The current status of the commit all operation on Panorama.
    :param name: The name of the device group or template being pushed.
    :param commit_type: The name of the device group or template being pushed.
    :param device: The device currently being pushed to - None when first initiated.
    :param device_status: The status of the actual commit operation on the device itself
    """
    job_id: str
    commit_type: str
    commit_all_status: str
    device_status: str
    name: str
    device: str

    _output_prefix = OUTPUT_PREFIX + "PushStatus"
    _title = "PAN-OS Push Job"
    _outputs_key_field = "job_id"


@dataclass
class HighAvailabilityStateStatus(ResultData):
    """
    :param state: New HA State
    """
    state: str
    _output_prefix = OUTPUT_PREFIX + "HAStateUpdate"
    _title = "PAN-OS High-Availability Updated State"


@dataclass
class DownloadSoftwareCommandResult:
    summary_data: list[GenericSoftwareStatus]
    result_data: None = None

    _output_prefix = OUTPUT_PREFIX + "DownloadStatus"
    _title = "PAN-OS Software Download request Status"

    _summary_cls = GenericSoftwareStatus


@dataclass
class InstallSoftwareCommandResult:
    summary_data: list[GenericSoftwareStatus]
    result_data: None = None

    _output_prefix = OUTPUT_PREFIX + "InstallStatus"
    _title = "PAN-OS Software Install request Status"

    _summary_cls = GenericSoftwareStatus


@dataclass
class RestartSystemCommandResult:
    summary_data: list[GenericSoftwareStatus]
    result_data: None = None

    _output_prefix = OUTPUT_PREFIX + "RestartStatus"
    _title = "PAN-OS Software Restart request Status"

    _summary_cls = GenericSoftwareStatus


@dataclass
class CheckSystemStatus(ResultData):
    """
    :param up: Whether the host device is up or still unavailable.
    """
    up: bool

    _output_prefix = OUTPUT_PREFIX + "SystemStatus"
    _title = "PAN-OS System Status"
    _outputs_key_field = "hostid"


@dataclass
class DeviceGroupInformation(ResultData):
    """
    :param serial: Serial number of firewall
    :param connected: Whether the firewall is currently connected
    :param hostname: Firewall hostname
    :param last_commit_all_state_sp: Text state of last commit
    :param name: Device group Name
    """
    serial: str
    connected: str
    hostname: str
    last_commit_all_state_sp: str
    name: str = ""

    _output_prefix = OUTPUT_PREFIX + "DeviceGroupOp"
    _title = "PAN-OS Operational Device Group Status"
    _outputs_key_field = "name"


@dataclass
class TemplateStackInformation(ResultData):
    """
    :param serial: Serial number of firewall
    :param connected: Whether the firewall is currently connected
    :param hostname: Firewall hostname
    :param last_commit_all_state_tpl: Text state of last commit
    :param name: Template Stack Name
    """
    serial: str
    connected: str
    hostname: str
    last_commit_all_state_tpl: str
    name: str = ""

    _output_prefix = OUTPUT_PREFIX + "TemplateStackOp"
    _title = "PAN-OS Operational Template Stack status"
    _outputs_key_field = "name"


@dataclass
class ConfigurationHygieneIssue(ResultData):
    """
    :param container_name: What parent container (DG, Template, VSYS) this object belongs to.
    :param issue_code: The shorthand code for the issue
    :param description: Human readable description of issue
    :param name: The affected object name
    """
    container_name: str
    issue_code: str
    description: str
    name: str

    _output_prefix = OUTPUT_PREFIX + "ConfigurationHygiene"
    _title = "PAN-OS Configuration Hygiene Check"


@dataclass
class ConfigurationHygieneCheck:
    """
    :param description: The description of the check
    :param issue_code: The shorthand code for this hygiene check
    :param result: Whether the check passed or failed
    :param issue_count: Total number of matching issues
    """
    description: str
    issue_code: str
    result: str
    issue_count: int = 0


@dataclass
class ConfigurationHygieneCheckResult:
    summary_data: list[ConfigurationHygieneCheck]
    result_data: list[ConfigurationHygieneIssue]

    _output_prefix = OUTPUT_PREFIX + "ConfigurationHygiene"
    _title = "PAN-OS Configuration Hygiene Check"

    _summary_cls = ConfigurationHygieneCheck
    _result_cls = ConfigurationHygieneIssue
    _outputs_key_field = "issue_code"


@dataclass
class ConfigurationHygieneFix(ResultData):
    """
    :param container_name: What parent container (DG, Template, VSYS) this object belongs to.
    :param issue_code: The shorthand code for the issue
    :param description: Human readable description of issue
    :param name: The affected object name
    """
    container_name: str
    issue_code: str
    description: str
    name: str

    _output_prefix = OUTPUT_PREFIX + "ConfigurationHygieneFix"
    _title = "PAN-OS Fixed Configuration Hygiene Issues"


@dataclass
class PanosObjectReference(ResultData):
    """
    :param container_name: What parent container (DG, Template, VSYS) this object belongs to.
    :param name: The PAN-OS object name
    :param object_type: The PAN-OS-Python object type
    """
    container_name: str
    name: str
    object_type: str

    _output_prefix = OUTPUT_PREFIX + "PanosObject"
    _title = "PAN-OS Objects"


def dataclass_from_dict(device: Union[Panorama, Firewall], d: dict, class_type: Callable):
    if device.hostname:
        d["hostid"] = device.hostname
    if device.serial:
        d["hostid"] = device.serial

    r = {}
    for k, v in d.items():
        d_key = k.replace("-", "_")
        dataclass_field = next((x for x in fields(class_type) if x.name == d_key), None)
        if dataclass_field:
            r[d_key] = v

    return class_type(**r)


def flatten_xml_to_dict(element: Element, d: dict, class_type: Callable):
    """Given an XML element, a dictionary, and a class, flattens the XML into the class."""
    for child_element in element:
        tag = child_element.tag
        # Replace hyphens in tags with underscores to match python attributes
        tag = tag.replace("-", "_")
        dataclass_field = next((x for x in fields(class_type) if x.name == tag), None)
        if dataclass_field:
            d[tag] = child_element.text

        if len(child_element) > 0:
            d = {**d, **flatten_xml_to_dict(child_element, d, class_type)}

    return d


def dataclass_from_element(
        device: Union[Panorama, Firewall],
        class_type: Callable,
        element: Optional[Element],
):
    """
    Turns an XML `Element` Object into an instance of the provided dataclass. Dataclass paramaters must match
    child XML tags exactly.
    :param device: PANDevice object
    :param class_type: The dataclass to populate
    :param element: XML `Element`
    """
    d = {}
    if element is None:
        return

    if device.hostname:
        d["hostid"] = device.hostname
    if device.serial:
        d["hostid"] = device.serial

    child_element: Element
    # Handle the XML attributes, if any and if they match dataclass field
    for attr_name, attr_value in element.attrib.items():
        dataclass_field = next((x for x in fields(class_type) if x.name == attr_name), None)
        if dataclass_field:
            d[attr_name] = attr_value

    d = flatten_xml_to_dict(element, d, class_type)

    return class_type(**d)


def resolve_host_id(device: PanDevice):
    host_id: str = ""
    if device.hostname:
        host_id = device.hostname
    if device.serial:
        host_id = device.serial

    return host_id


def resolve_container_name(container: Union[Panorama, Firewall, DeviceGroup, Template, Vsys]):
    if type(container) in [Panorama, Firewall]:
        return "shared"

    return container.name


class HygieneRemediation:
    """Functions that remediate problems generated by HygieneLookups"""

    @staticmethod
    def fix_log_forwarding_profile_enhanced_logging(topology: Topology,
                                                    issues: list[ConfigurationHygieneIssue]) -> list[
        ConfigurationHygieneFix]:
        result = []
        for issue in issues:
            for device, container in topology.get_all_object_containers(
                    issue.hostid,
                    container_name=issue.container_name
            ):
                log_forwarding_profiles: list[LogForwardingProfile] = LogForwardingProfile.refreshall(
                    container)
                for log_forwarding_profile in log_forwarding_profiles:
                    if log_forwarding_profile.name == issue.name:
                        log_forwarding_profile.enhanced_logging = True
                        log_forwarding_profile.apply()
                        result.append(ConfigurationHygieneFix(
                            hostid=resolve_host_id(device),
                            container_name=resolve_container_name(container),
                            description="Enabled Enhanced Application Logging.",
                            name=log_forwarding_profile.name,
                            issue_code=issue.issue_code
                        ))

        return result

    @staticmethod
    def fix_security_zone_no_log_setting(
            topology: Topology,
            issues: list[ConfigurationHygieneIssue],
            log_forwarding_profile: str
    ) -> list[ConfigurationHygieneFix]:
        result = []
        for issue in issues:

            for device, container in topology.get_all_object_containers(
                    issue.hostid,
                    container_name=issue.container_name,
            ):
                security_zones: list[Zone] = Zone.refreshall(container)
                for security_zone in security_zones:
                    if security_zone.name == issue.name:
                        security_zone.log_setting = log_forwarding_profile
                        security_zone.apply()
                        result.append(ConfigurationHygieneFix(
                            hostid=resolve_host_id(device),
                            container_name=resolve_container_name(container),
                            description=f"Set log forwarding profile {log_forwarding_profile}",
                            name=security_zone.name,
                            issue_code=issue.issue_code
                        ))

        return result

    @staticmethod
    def fix_secuity_rule_log_settings(topology: Topology,
                                      issues: list[ConfigurationHygieneIssue],
                                      log_forwarding_profile_name: str,
                                      ) -> list[ConfigurationHygieneFix]:
        result = []
        for issue in issues:
            for device, container in topology.get_all_object_containers(
                    issue.hostid,
                    container_name=issue.container_name
            ):
                firewall_rulebase = Rulebase()
                pre_rulebase = PreRulebase()
                post_rulebase = PostRulebase()
                container.add(pre_rulebase)
                container.add(post_rulebase)
                container.add(firewall_rulebase)
                security_rules: list[SecurityRule] = SecurityRule.refreshall(firewall_rulebase)
                pre_security_rules: list[SecurityRule] = SecurityRule.refreshall(pre_rulebase)
                post_security_rules: list[SecurityRule] = SecurityRule.refreshall(post_rulebase)
                security_rules = security_rules + pre_security_rules + post_security_rules
                for security_rule in security_rules:
                    if security_rule.name == issue.name:
                        security_rule.log_end = True
                        security_rule.log_setting = log_forwarding_profile_name
                        security_rule.apply()
                        result.append(ConfigurationHygieneFix(
                            hostid=resolve_host_id(device),
                            container_name=resolve_container_name(container),
                            description=f"Set log forwarding profile to {log_forwarding_profile_name} and"
                                        f"enabled log at session end.",
                            name=security_rule.name,
                            issue_code=issue.issue_code
                        ))
        return result

    @staticmethod
    def fix_security_rule_security_profile_group(topology: Topology,
                                                 issues: list[ConfigurationHygieneIssue],
                                                 security_profile_group_name: str,
                                                 ) -> list[ConfigurationHygieneFix]:
        result = []
        for issue in issues:
            for device, container in topology.get_all_object_containers(
                    issue.hostid,
                    container_name=issue.container_name
            ):
                firewall_rulebase = Rulebase()
                pre_rulebase = PreRulebase()
                post_rulebase = PostRulebase()
                container.add(pre_rulebase)
                container.add(post_rulebase)
                container.add(firewall_rulebase)
                security_rules: list[SecurityRule] = SecurityRule.refreshall(firewall_rulebase)
                pre_security_rules: list[SecurityRule] = SecurityRule.refreshall(pre_rulebase)
                post_security_rules: list[SecurityRule] = SecurityRule.refreshall(post_rulebase)
                security_rules = security_rules + pre_security_rules + post_security_rules
                for security_rule in security_rules:
                    if security_rule.name == issue.name:
                        security_rule.group = security_profile_group_name
                        security_rule.apply()
                        result.append(ConfigurationHygieneFix(
                            hostid=resolve_host_id(device),
                            container_name=resolve_container_name(container),
                            description=f"Set security profile group {security_profile_group_name}",
                            name=security_rule.name,
                            issue_code=issue.issue_code
                        ))

        return result


class ObjectGetter:
    """Retrieves objects from the PAN-OS configuration"""

    @staticmethod
    def get_object_reference(
            topology: Topology,
            object_type: str,
            device_filter_string: str = None,
            container_filter: str = None,
            object_name: str = None,
            use_regex: str = None
    ) -> list[PanosObjectReference]:
        """Given a string object type, returns all the matching objects by reference."""
        object_class = globals().get(object_type, None)
        if object_class is None:
            raise DemistoException(f"Object type {object_type} is not gettable with this integration.")

        object_references = []
        for device, container in topology.get_all_object_containers(
                device_filter_string,
                container_name=container_filter
        ):
            unfiltered_objects = []
            # If the object class is a security rule we need to handle it specially
            if object_class in ["SecurityRule", "NatRule"]:
                firewall_rulebase = Rulebase()
                pre_rulebase = PreRulebase()
                post_rulebase = PostRulebase()
                container.add(pre_rulebase)
                container.add(post_rulebase)
                container.add(firewall_rulebase)
                unfiltered_objects = object_class.refreshall(firewall_rulebase)
                unfiltered_objects += object_class.refreshall(pre_rulebase)
                unfiltered_objects += object_class.refreshall(post_rulebase)
            else:
                unfiltered_objects = object_class.refreshall(container)

            for panos_object in unfiltered_objects:
                if panos_object.name == object_name or not object_name:
                    object_references.append(
                        PanosObjectReference(
                            object_type=object_type,
                            container_name=resolve_container_name(container),
                            name=panos_object.name,
                            hostid=resolve_host_id(device)
                        )
                    )
                elif use_regex:
                    try:
                        if re.match(object_name, panos_object.name):
                            object_references.append(
                                PanosObjectReference(
                                    object_type=object_type,
                                    container_name=resolve_container_name(container),
                                    name=panos_object.name,
                                    hostid=resolve_host_id(device)
                                )
                            )
                    except re.error:
                        pass

        return object_references


class HygieneCheckRegister:
    """Stores all the hygiene checks this integration is capable of and their assocaited details."""

    def __init__(self, register: dict):
        self.register: dict = register

    def get(self, issue_code) -> ConfigurationHygieneCheck:
        issue_check = self.register.get(issue_code)
        if not issue_check:
            raise DemistoException("Invalid Hygiene check issue name")
        return issue_check

    def values(self):
        return self.register.values()

    @classmethod
    def get_hygiene_check_register(cls, issue_codes: list[str]):
        check_register = {
            "BP-V-1": ConfigurationHygieneCheck(
                issue_code="BP-V-1",
                result=UNICODE_PASS,
                description="Fails if there are no valid log forwarding profiles configured.",
            ),
            "BP-V-2": ConfigurationHygieneCheck(
                issue_code="BP-V-2",
                result=UNICODE_PASS,
                description="Fails if the configured log forwarding profile has no match list.",
            ),
            "BP-V-3": ConfigurationHygieneCheck(
                issue_code="BP-V-3",
                result=UNICODE_PASS,
                description="Fails if enhanced application logging is not configured.",
            ),
            "BP-V-4": ConfigurationHygieneCheck(
                issue_code="BP-V-4",
                result=UNICODE_PASS,
                description="Fails if no vulnerability profile is configured for visibility.",
            ),
            "BP-V-5": ConfigurationHygieneCheck(
                issue_code="BP-V-5",
                result=UNICODE_PASS,
                description="Fails if no spyware profile is configured for visibility."
            ),
            "BP-V-6": ConfigurationHygieneCheck(
                issue_code="BP-V-6",
                result=UNICODE_PASS,
                description="Fails if no spyware profile is configured for url-filtering",
            ),
            "BP-V-7": ConfigurationHygieneCheck(
                issue_code="BP-V-7",
                result=UNICODE_PASS,
                description="Fails when a security zone has no log forwarding setting.",
            ),
            "BP-V-8": ConfigurationHygieneCheck(
                issue_code="BP-V-8",
                result=UNICODE_PASS,
                description="Fails when a security rule is not configured to log at session end.",
            ),
            "BP-V-9": ConfigurationHygieneCheck(
                issue_code="BP-V-9",
                result=UNICODE_PASS,
                description="Fails when a security rule has no log forwarding profile configured.",
            ),
            "BP-V-10": ConfigurationHygieneCheck(
                issue_code="BP-V-10",
                result=UNICODE_PASS,
                description="Fails when a security rule has no configured profiles or profile groups.",
            ),
        }

        return cls({issue_code: check_register[issue_code] for issue_code in issue_codes})


class HygieneLookups:
    """Functions that inspect firewall and panorama configurations for config issues"""

    @staticmethod
    def check_log_forwarding_profiles(
            topology: Topology,
            device_filter_str: str = None,
    ):
        issues = []
        lf_profile_list: list[LogForwardingProfile] = []
        check_register = HygieneCheckRegister.get_hygiene_check_register([
            "BP-V-1",
            "BP-V-2",
            "BP-V-3"
        ])
        for device, container in topology.get_all_object_containers(device_filter_str):
            log_forwarding_profiles: list[LogForwardingProfile] = LogForwardingProfile.refreshall(container)
            lf_profile_list = lf_profile_list + log_forwarding_profiles
            for log_forwarding_profile in log_forwarding_profiles:
                # Enhanced app logging - BP-V-2
                if not log_forwarding_profile.enhanced_logging:
                    issues.append(ConfigurationHygieneIssue(
                        hostid=resolve_host_id(device),
                        container_name=resolve_container_name(container),
                        description="Log forwarding profile is missing enhanced application logging.",
                        name=log_forwarding_profile.name,
                        issue_code="BP-V-3"
                    ))
                    check = check_register.get("BP-V-3")
                    check.result = UNICODE_FAIL
                    check.issue_count += 1

                match_list_list = LogForwardingProfileMatchList.refreshall(log_forwarding_profile)
                if len(match_list_list) == 0:
                    issues.append(ConfigurationHygieneIssue(
                        hostid=resolve_host_id(device),
                        container_name=resolve_container_name(container),
                        description="Log forwarding profile contains no match list.",
                        name=log_forwarding_profile.name,
                        issue_code="BP-V-2"
                    ))
                    check = check_register.get("BP-V-2")
                    check.result = UNICODE_FAIL
                    check.issue_count += 1

                required_log_types = ["traffic", "threat"]
                for log_forwarding_profile_match_list in match_list_list:
                    required_log_types.remove(log_forwarding_profile_match_list.log_type)

                for missing_required_log_type in required_log_types:
                    issues.append(ConfigurationHygieneIssue(
                        hostid=resolve_host_id(device),
                        container_name=resolve_container_name(container),
                        description=f"Log forwarding profile missing log type '{missing_required_log_type}'.",
                        name=log_forwarding_profile.name,
                        issue_code="BP-V-2"
                    ))
                    check = check_register.get("BP-V-2")
                    check.result = UNICODE_FAIL
                    check.issue_count += 1

        # No logging profiles configured in environment - BP-V-1
        if len(lf_profile_list) == 0:
            issues.append(ConfigurationHygieneIssue(
                hostid="PLATFORM",
                container_name="",
                description="No log profiles configured!",
                name="",
                issue_code="BP-V-1"
            ))
            check = check_register.get("BP-V-1")
            check.result = UNICODE_FAIL
            check.issue_count += 1

        return ConfigurationHygieneCheckResult(
            summary_data=[item for item in check_register.values()],
            result_data=issues
        )

    @staticmethod
    def get_conforming_threat_profiles(
            profiles: Union[list[VulnerabilityProfile], list[AntiSpywareProfile]],
            minimum_block_severities: list[str],
            minimum_alert_severities: list[str]
    ) -> Union[list[VulnerabilityProfile], list[AntiSpywareProfile]]:
        """Given a list of threat profiles, return any that conform to best practices."""
        conforming_profiles = []

        for profile in profiles:
            block_severities = minimum_block_severities.copy()
            alert_severities = minimum_alert_severities.copy()

            for rule in profile.children:
                block_actions = [rule.is_reset_both, rule.is_reset_client, rule.is_reset_server,
                                 rule.is_drop, rule.is_block_ip]
                alert_actions = [rule.is_default, rule.is_alert]
                for rule_severity in rule.severity:
                    # If the block severities are blocked
                    if any(block_actions) and rule_severity in block_severities:
                        block_severities.remove(rule_severity)
                        if rule_severity in alert_severities:
                            alert_severities.remove(rule_severity)
                    # If the alert severities are blocked
                    elif any(block_actions) and rule_severity in alert_severities:
                        if rule_severity in alert_severities:
                            alert_severities.remove(rule_severity)
                    # If the alert severities are alert/default
                    elif any(alert_actions) and rule_severity in alert_severities:
                        if rule_severity in alert_severities:
                            alert_severities.remove(rule_severity)

            if not block_severities and not alert_severities:
                conforming_profiles.append(profile)

        return conforming_profiles

    @staticmethod
    def check_vulnerability_profiles(
            topology: Topology,
            device_filter_str: str = None,
            minimum_block_severities: list[str] = None,
            minimum_alert_severities: list[str] = None
    ) -> ConfigurationHygieneCheckResult:

        if not minimum_block_severities:
            minimum_block_severities = BestPractices.VULNERABILITY_BLOCK_SEVERITIES
        if not minimum_alert_severities:
            minimum_alert_severities = BestPractices.VULNERABILITY_ALERT_THRESHOLD

        conforming_profiles: Union[list[VulnerabilityProfile], list[AntiSpywareProfile]] = []
        issues = []

        check_register = HygieneCheckRegister.get_hygiene_check_register([
            "BP-V-4"
        ])

        # BP-V-4 - Check at least one vulnerability profile exists with the correct settings.
        for device, container in topology.get_all_object_containers(device_filter_str):
            vulnerability_profiles: list[VulnerabilityProfile] = VulnerabilityProfile.refreshall(container)
            conforming_profiles = conforming_profiles + HygieneLookups.get_conforming_threat_profiles(
                vulnerability_profiles,
                minimum_block_severities=minimum_block_severities,
                minimum_alert_severities=minimum_alert_severities
            )

        if len(conforming_profiles) == 0:
            issues.append(ConfigurationHygieneIssue(
                hostid="GLOBAL",
                container_name="",
                description="No conforming vulnerability profiles.",
                name="",
                issue_code="BP-V-4"
            ))
            check = check_register.get("BP-V-4")
            check.result = UNICODE_FAIL
            check.issue_count += 1

        return ConfigurationHygieneCheckResult(
            summary_data=[item for item in check_register.values()],
            result_data=issues
        )

    @staticmethod
    def check_spyware_profiles(
            topology: Topology,
            device_filter_str: str = None,
            minimum_block_severities: list[str] = None,
            minimum_alert_severities: list[str] = None
    ) -> ConfigurationHygieneCheckResult:

        if not minimum_block_severities:
            minimum_block_severities = BestPractices.SPYWARE_BLOCK_SEVERITIES
        if not minimum_alert_severities:
            minimum_alert_severities = BestPractices.SPYWARE_ALERT_THRESHOLD

        conforming_profiles: Union[list[VulnerabilityProfile], list[AntiSpywareProfile]] = []
        issues = []
        check_register = HygieneCheckRegister.get_hygiene_check_register([
            "BP-V-5"
        ])
        # BP-V-5 - Check at least one AS profile exists with the correct settings.
        for device, container in topology.get_all_object_containers(device_filter_str):
            spyware_profiles: list[AntiSpywareProfile] = AntiSpywareProfile.refreshall(container)
            conforming_profiles = conforming_profiles + HygieneLookups.get_conforming_threat_profiles(
                spyware_profiles,
                minimum_block_severities=minimum_block_severities,
                minimum_alert_severities=minimum_alert_severities
            )

        if len(conforming_profiles) == 0:
            issues.append(ConfigurationHygieneIssue(
                hostid="GLOBAL",
                container_name="",
                description="No conforming anti-spyware profiles.",
                name="",
                issue_code="BP-V-5"
            ))
            check = check_register.get("BP-V-5")
            check.result = UNICODE_FAIL
            check.issue_count += 1

        return ConfigurationHygieneCheckResult(
            summary_data=[item for item in check_register.values()],
            result_data=issues
        )

    @staticmethod
    def get_conforming_url_filtering_profiles(profiles: list[URLFilteringProfile]) \
            -> list[URLFilteringProfile]:
        conforming_profiles = []
        for profile in profiles:
            if profile.block:
                block_result = all(elem in profile.block for elem in BestPractices.URL_BLOCK_CATEGORIES)
                if block_result:
                    conforming_profiles.append(profile)

        return conforming_profiles

    @staticmethod
    def get_all_conforming_url_filtering_profiles(topology: Topology, device_filter_str: str = None) -> \
            list[PanosObjectReference]:

        result = []
        for device, container in topology.get_all_object_containers(device_filter_str):
            url_filtering_profiles: list[URLFilteringProfile] = URLFilteringProfile.refreshall(container)

            conforming_profiles = HygieneLookups.get_conforming_url_filtering_profiles(
                url_filtering_profiles)

            for profile in conforming_profiles:
                result.append(PanosObjectReference(
                    hostid=resolve_host_id(device),
                    container_name=resolve_container_name(container),
                    name=profile.name,
                    object_type="URLFilteringProfile"
                ))

        return result

    @staticmethod
    def get_all_conforming_spyware_profiles(
            topology: Topology,
            minimum_block_severities: list[str],
            minimum_alert_severities: list[str],
            device_filter_str: str = None,
    ) -> list[PanosObjectReference]:

        result = []
        for device, container in topology.get_all_object_containers(device_filter_str):
            spyware_profiles: list[AntiSpywareProfile] = AntiSpywareProfile.refreshall(container)
            conforming_profiles = HygieneLookups.get_conforming_threat_profiles(
                spyware_profiles,
                minimum_block_severities=minimum_block_severities,
                minimum_alert_severities=minimum_alert_severities
            )

            for profile in conforming_profiles:
                result.append(PanosObjectReference(
                    hostid=resolve_host_id(device),
                    container_name=resolve_container_name(container),
                    name=profile.name,
                    object_type="AntiSpywareProfile"
                ))

        return result

    @staticmethod
    def get_all_conforming_vulnerability_profiles(
            topology: Topology,
            minimum_block_severities: list[str],
            minimum_alert_severities: list[str],
            device_filter_str: str = None,
    ) -> list[PanosObjectReference]:

        result = []
        for device, container in topology.get_all_object_containers(device_filter_str):
            spyware_profiles: list[VulnerabilityProfile] = VulnerabilityProfile.refreshall(container)
            conforming_profiles = HygieneLookups.get_conforming_threat_profiles(
                spyware_profiles,
                minimum_block_severities=minimum_block_severities,
                minimum_alert_severities=minimum_alert_severities
            )

            for profile in conforming_profiles:
                result.append(PanosObjectReference(
                    hostid=resolve_host_id(device),
                    container_name=resolve_container_name(container),
                    name=profile.name,
                    object_type="VulnerabilityProfile"
                ))

        return result

    @staticmethod
    def check_url_filtering_profiles(topology: Topology, device_filter_str: str = None):
        issues: list[ConfigurationHygieneIssue] = []
        conforming_profiles: list[URLFilteringProfile] = []
        check_register = HygieneCheckRegister.get_hygiene_check_register([
            "BP-V-6"
        ])
        # BP-V-6 - Check at least one URL Filtering profile exists with the correct settings.
        for device, container in topology.get_all_object_containers(device_filter_str):
            url_filtering_profiles: list[URLFilteringProfile] = URLFilteringProfile.refreshall(container)
            conforming_profiles = conforming_profiles + HygieneLookups.get_conforming_url_filtering_profiles(
                url_filtering_profiles)

        if len(conforming_profiles) == 0:
            issues.append(ConfigurationHygieneIssue(
                hostid="GLOBAL",
                container_name="",
                description="No conforming url-filtering profiles.",
                name="",
                issue_code="BP-V-6"
            ))
            check = check_register.get("BP-V-6")
            check.result = UNICODE_FAIL
            check.issue_count += 1

        return ConfigurationHygieneCheckResult(
            summary_data=[item for item in check_register.values()],
            result_data=issues
        )

    @staticmethod
    def check_security_zones(topology: Topology, device_filter_str: str = None) \
            -> ConfigurationHygieneCheckResult:
        issues = []
        check_register = HygieneCheckRegister.get_hygiene_check_register([
            "BP-V-7"
        ])
        # This is temporary only look at panorama because PAN-OS-PYTHON doesn't let us tell if a config
        # is template pushed yet
        for device, container in topology.get_all_object_containers(
                device_filter_str,
                top_level_devices_only=True
        ):
            security_zones: list[Zone] = Zone.refreshall(container)
            for security_zone in security_zones:
                if not security_zone.log_setting:
                    issues.append(ConfigurationHygieneIssue(
                        hostid=resolve_host_id(device),
                        container_name=resolve_container_name(container),
                        description="Security zone has no log forwarding setting.",
                        name=security_zone.name,
                        issue_code="BP-V-7"
                    ))
                    check = check_register.get("BP-V-7")
                    check.result = UNICODE_FAIL
                    check.issue_count += 1

        return ConfigurationHygieneCheckResult(
            summary_data=[item for item in check_register.values()],
            result_data=issues
        )

    @staticmethod
    def check_security_rules(topology: Topology, device_filter_str: str = None) \
            -> ConfigurationHygieneCheckResult:
        issues = []

        check_register = HygieneCheckRegister.get_hygiene_check_register([
            "BP-V-8",
            "BP-V-9",
            "BP-V-10",
        ])
        for device, container in topology.get_all_object_containers(device_filter_str):
            firewall_rulebase = Rulebase()
            pre_rulebase = PreRulebase()
            post_rulebase = PostRulebase()
            container.add(pre_rulebase)
            container.add(post_rulebase)
            container.add(firewall_rulebase)
            security_rules: list[SecurityRule] = SecurityRule.refreshall(firewall_rulebase)
            pre_security_rules: list[SecurityRule] = SecurityRule.refreshall(pre_rulebase)
            post_security_rules: list[SecurityRule] = SecurityRule.refreshall(post_rulebase)
            security_rules = security_rules + pre_security_rules + post_security_rules
            for security_rule in security_rules:
                if not security_rule.log_end:
                    issues.append(ConfigurationHygieneIssue(
                        hostid=resolve_host_id(device),
                        container_name=resolve_container_name(container),
                        description="Security rule is not configured to log at session end.",
                        name=security_rule.name,
                        issue_code="BP-V-8"
                    ))
                    check = check_register.get("BP-V-8")
                    check.result = UNICODE_FAIL
                    check.issue_count += 1

                if not security_rule.log_setting:
                    issues.append(ConfigurationHygieneIssue(
                        hostid=resolve_host_id(device),
                        container_name=resolve_container_name(container),
                        description="Security rule has no log forwarding profile.",
                        name=security_rule.name,
                        issue_code="BP-V-9"
                    ))
                    check = check_register.get("BP-V-9")
                    check.result = UNICODE_FAIL
                    check.issue_count += 1

                # BP-V-10 - Check either a group or profile is configured
                if not any([
                    security_rule.group,
                    all(
                        [
                            security_rule.virus,
                            security_rule.spyware,
                            security_rule.vulnerability,
                            security_rule.url_filtering,
                        ]
                    )]
                ):
                    issues.append(ConfigurationHygieneIssue(
                        hostid=resolve_host_id(device),
                        container_name=resolve_container_name(container),
                        description="Security rule has no profile group or configured threat profiles.",
                        name=security_rule.name,
                        issue_code="BP-V-10"
                    ))
                    check = check_register.get("BP-V-10")
                    check.result = UNICODE_FAIL
                    check.issue_count += 1

        return ConfigurationHygieneCheckResult(
            summary_data=[item for item in check_register.values()],
            result_data=issues
        )


class PanoramaCommand:
    GET_DEVICEGROUPS_COMMAND = "show devicegroups"
    GET_TEMPLATE_STACK_COMMAND = "show template-stack"

    @staticmethod
    def get_device_groups(topology: Topology, device_filter_str: str = None) -> list[DeviceGroupInformation]:
        device: Panorama
        result = []
        for device in topology.active_top_level_devices(device_filter_str):
            if type(device) is Panorama:
                response = run_op_command(device, PanoramaCommand.GET_DEVICEGROUPS_COMMAND)
                for device_group_xml in response.findall("./result/devicegroups/entry"):
                    dg_name = get_element_attribute(device_group_xml, "name")
                    for device_xml in device_group_xml.findall("./devices/entry"):
                        r: DeviceGroupInformation = dataclass_from_element(device, DeviceGroupInformation,
                                                                           device_xml)
                        r.name = dg_name
                        result.append(r)

        return result

    @staticmethod
    def get_template_stacks(topology: Topology, device_filter_str: str = None) -> list[
        TemplateStackInformation]:
        device: Panorama
        result = []
        for device in topology.active_top_level_devices(device_filter_str):
            if type(device) is Panorama:
                response = run_op_command(device, PanoramaCommand.GET_TEMPLATE_STACK_COMMAND)
                for template_stack_xml in response.findall("./result/template-stack/entry"):
                    template_name = get_element_attribute(template_stack_xml, "name")
                    for device_xml in template_stack_xml.findall("./devices/entry"):
                        r: TemplateStackInformation = dataclass_from_element(device, TemplateStackInformation,
                                                                             device_xml)
                        r.name = template_name
                        result.append(r)

        return result

    @staticmethod
    def push_all(
            topology: Topology,
            device_filter_str: str = None,
            device_group_filter: list[str] = None,
            template_stack_filter: list[str] = None
    ) -> list[PushStatus]:
        result = []

        for device in topology.active_top_level_devices(device_filter_str):
            # Get the relevent DGs and Templates to push.
            device_groups = PanoramaCommand.get_device_groups(topology, resolve_host_id(device))
            device_group_names = set([x.name for x in device_groups])
            template_stacks = PanoramaCommand.get_template_stacks(topology, resolve_host_id(device))
            template_stack_names = set([x.name for x in template_stacks])

            if device_group_filter:
                device_group_names = set([x for x in device_group_names if x in device_group_filter])

            if template_stack_filter:
                template_stack_names = set([x for x in template_stack_names if x in template_stack_filter])

            for dg_name in device_group_names:
                device_group_commit = PanoramaCommitAll(
                    style="device group",
                    name=dg_name
                )
                result_job_id = device.commit(cmd=device_group_commit)  # type: ignore
                result.append(PushStatus(
                    hostid=resolve_host_id(device),
                    commit_type="devicegroup",
                    name=dg_name,
                    job_id=result_job_id,  # type: ignore
                    commit_all_status="Initiated",
                    device_status="",
                    device=""
                ))

            for template_name in template_stack_names:
                template_stack_commit = PanoramaCommitAll(
                    style="template stack",
                    name=template_name
                )
                result_job_id = device.commit(cmd=template_stack_commit)  # type: ignore
                result.append(PushStatus(
                    hostid=resolve_host_id(device),
                    commit_type="template-stack",
                    name=template_name,
                    job_id=result_job_id,  # type: ignore
                    commit_all_status="Initiated",
                    device_status="",
                    device=""
                ))

        return result

    @staticmethod
    def get_push_status(topology: Topology, match_job_ids: list[str] = None) -> list[PushStatus]:
        result: list[PushStatus] = []
        for device in topology.active_top_level_devices():
            response = run_op_command(device, UniversalCommand.SHOW_JOBS_COMMAND)
            for job in response.findall("./result/job"):
                commit_type = find_text_in_element(job, "./type")
                if commit_type in ["CommitAll"]:
                    commit_all_status = find_text_in_element(job, "./status")
                    job_id = find_text_in_element(job, "./id")
                    commit_type = find_text_in_element(job, "./type")
                    dg_name_xml = job.find("./dgname")
                    tpl_name_xml = job.find("./tplname")
                    name = ""
                    if hasattr(dg_name_xml, "text") and dg_name_xml:
                        name = dg_name_xml.text  # type: ignore

                    if hasattr(tpl_name_xml, "text") and tpl_name_xml:
                        name = tpl_name_xml.text  # type: ignore

                    for device_xml in job.findall("./devices/entry"):
                        serial = find_text_in_element(device_xml, "./serial-no")
                        device_status = find_text_in_element(device_xml, "./result")
                        result.append(PushStatus(
                            hostid=resolve_host_id(device),
                            job_id=job_id,
                            commit_type=commit_type,
                            commit_all_status=commit_all_status,
                            device_status=device_status,
                            name=name,
                            device=serial
                        ))

        if match_job_ids:
            return [x for x in result if x.job_id in match_job_ids]

        return result


class UniversalCommand:
    """Command list for commands that are consistent between PANORAMA and NGFW"""
    SYSTEM_INFO_COMMAND = "show system info"
    SHOW_JOBS_COMMAND = "show jobs all"

    @staticmethod
    def get_system_info(topology: Topology, device_filter_str: str = None) -> ShowSystemInfoCommandResult:
        result_data: list[ShowSystemInfoResultData] = []
        summary_data: list[ShowSystemInfoSummaryData] = []
        for device in topology.all(filter_string=device_filter_str):
            response = run_op_command(device, UniversalCommand.SYSTEM_INFO_COMMAND)
            result_data.append(dataclass_from_element(device, ShowSystemInfoResultData,
                                                      response.find("./result/system")))
            summary_data.append(dataclass_from_element(device, ShowSystemInfoSummaryData,
                                                       response.find("./result/system")))

        return ShowSystemInfoCommandResult(
            result_data=result_data,
            summary_data=summary_data
        )

    @staticmethod
    def get_available_software(topology: Topology,
                               device_filter_str: str = None) -> SoftwareVersionCommandResult:
        summary_data = []
        for device in topology.all(filter_string=device_filter_str):
            device.software.check()
            for version_dict in device.software.versions.values():
                summary_data.append(dataclass_from_dict(device, version_dict, SoftwareVersion))

        return SoftwareVersionCommandResult(
            summary_data=summary_data
        )

    @staticmethod
    def download_software(topology: Topology, version: str,
                          sync: bool = False, device_filter_str=None) -> DownloadSoftwareCommandResult:

        result = []
        for device in topology.all(filter_string=device_filter_str):
            device.software.download(version, sync=sync)
            result.append(GenericSoftwareStatus(
                hostid=resolve_host_id(device),
                started=True
            ))

        return DownloadSoftwareCommandResult(
            summary_data=result
        )

    @staticmethod
    def install_software(topology: Topology, version: str,
                         sync: bool = False, device_filter_str=None) -> InstallSoftwareCommandResult:

        result = []
        for device in topology.all(filter_string=device_filter_str):
            device.software.install(version, sync=sync)
            result.append(GenericSoftwareStatus(
                hostid=resolve_host_id(device),
                started=True
            ))

        return InstallSoftwareCommandResult(
            summary_data=result
        )

    @staticmethod
    def reboot(topology: Topology, hostid: str) -> RestartSystemCommandResult:

        result = []
        for device in topology.all(filter_string=hostid):
            device.restart()
            result.append(GenericSoftwareStatus(
                hostid=resolve_host_id(device),
                started=True
            ))

        return RestartSystemCommandResult(
            summary_data=result
        )

    @staticmethod
    def commit(topology: Topology, device_filter_string: str = None) -> list[CommitStatus]:

        result = []
        for device in topology.active_devices(device_filter_string):
            job_type = "Commit"
            job_id = device.commit()
            if type(device) is Panorama:
                device_type = "Panorama"
            else:
                device_type = "Firewall"

            result.append(CommitStatus(
                hostid=resolve_host_id(device),
                job_id=job_id,
                commit_type=job_type,
                status="started",
                device_type=device_type
            ))

        return result

    @staticmethod
    def get_commit_job_status(topology: Topology, match_job_ids: list[str] = None) -> list[CommitStatus]:
        result: list[CommitStatus] = []
        for device in topology.active_devices():
            response = run_op_command(device, UniversalCommand.SHOW_JOBS_COMMAND)
            for job in response.findall("./result/job"):
                commit_type = find_text_in_element(job, "./type")
                if commit_type in ["Commit", "CommitAll"]:
                    status = find_text_in_element(job, "./status")
                    job_id = find_text_in_element(job, "./id")
                    commit_type = find_text_in_element(job, "./type")
                    if type(device) is Panorama:
                        device_type = "Panorama"
                    else:
                        device_type = "Firewall"
                    result.append(CommitStatus(
                        hostid=resolve_host_id(device),
                        job_id=job_id,
                        commit_type=commit_type,
                        status=status,
                        device_type=device_type
                    ))

        if match_job_ids:
            return [x for x in result if x.job_id in match_job_ids]

        return result

    @staticmethod
    def check_system_availability(topology: Topology, hostid: str) -> CheckSystemStatus:
        devices: dict = topology.get_by_filter_str(hostid)
        # first check if the system exists in the topology; if not, we've failed to connect altogether
        if not devices:
            return CheckSystemStatus(
                hostid=hostid,
                up=False
            )

        show_system_info = UniversalCommand.get_system_info(topology, hostid)
        show_system_info_result = show_system_info.result_data[0]
        if show_system_info_result.operational_mode != "normal":
            return CheckSystemStatus(
                hostid=hostid,
                up=False
            )

        return CheckSystemStatus(
            hostid=hostid,
            up=True
        )

    @staticmethod
    def show_jobs(topology: Topology, device_filter_str: str = None, job_type: str = None,
                  status=None, id: int = None) -> list[ShowJobsAllResultData]:
        result_data = []
        for device in topology.all(filter_string=device_filter_str):
            response = run_op_command(device, UniversalCommand.SHOW_JOBS_COMMAND)
            for job in response.findall("./result/job"):
                result_data_obj: ShowJobsAllResultData = dataclass_from_element(device, ShowJobsAllResultData,
                                                                                job)

                result_data.append(result_data_obj)

                # Filter the result data
                result_data = [x for x in result_data if x.status == status or not status]
                result_data = [x for x in result_data if x.type == job_type or not job_type]
                result_data = [x for x in result_data if x.id == id or not id]

        # The below is very important for XSOAR to de-duplicate the returned key. If there is only one obj
        # being returned, return it as a dict instead of a list.
        if len(result_data) == 1:
            return result_data[0]  # type: ignore

        return result_data


class FirewallCommand:
    """Command List for commands that are relevant only to NGFWs"""
    ARP_COMMAND = "<show><arp><entry name='all'/></arp></show>"
    HA_STATE_COMMAND = "show high-availability state"
    ROUTING_SUMMARY_COMMAND = "show routing summary"
    ROUTING_ROUTE_COMMAND = "show routing route"
    GLOBAL_COUNTER_COMMAND = "show counter global"
    ROUTING_PROTOCOL_BGP_PEER_COMMAND = "show routing protocol bgp peer"
    REQUEST_STATE_PREFIX = "request high-availability state"

    @staticmethod
    def get_arp_table(topology: Topology, device_filter_str: str = None) -> ShowArpCommandResult:
        result_data: list[ShowArpCommandResultData] = []
        summary_data: list[ShowArpCommandSummaryData] = []
        for firewall in topology.firewalls(filter_string=device_filter_str):
            response = run_op_command(firewall, FirewallCommand.ARP_COMMAND, cmd_xml=False)
            summary_data.append(dataclass_from_element(firewall, ShowArpCommandSummaryData,
                                                       response.find("./result")))
            for entry in response.findall("./result/entries/entry"):
                result_data.append(dataclass_from_element(firewall, ShowArpCommandResultData, entry))

        return ShowArpCommandResult(
            result_data=result_data,
            summary_data=summary_data
        )

    @staticmethod
    def get_counter_global(topology: Topology,
                           device_filter_str: str = None) -> ShowCounterGlobalCommmandResult:
        result_data: list[ShowCounterGlobalResultData] = []
        summary_data: list[ShowCounterGlobalSummaryData] = []
        for firewall in topology.firewalls(filter_string=device_filter_str):
            response = run_op_command(firewall, FirewallCommand.GLOBAL_COUNTER_COMMAND)
            for entry in response.findall("./result/global/counters/entry"):
                summary_data.append(dataclass_from_element(firewall, ShowCounterGlobalSummaryData, entry))
                result_data.append(dataclass_from_element(firewall, ShowCounterGlobalResultData, entry))

        return ShowCounterGlobalCommmandResult(
            result_data=result_data,
            summary_data=summary_data
        )

    @staticmethod
    def get_routing_summary(topology: Topology,
                            device_filter_str: str = None) -> ShowRouteSummaryCommandResult:
        summary_data = []
        for firewall in topology.firewalls(filter_string=device_filter_str):
            response = run_op_command(firewall, FirewallCommand.ROUTING_SUMMARY_COMMAND)
            summary_data.append(dataclass_from_element(firewall, ShowRoutingCommandSummaryData,
                                                       response.find("./result/entry/All-Routes")))

        return ShowRouteSummaryCommandResult(
            summary_data=summary_data,
            result_data=[]
        )

    @staticmethod
    def get_bgp_peers(topology: Topology,
                      device_filter_str: str = None) -> ShowRoutingProtocolBGPCommandResult:
        summary_data = []
        result_data = []
        for firewall in topology.firewalls(filter_string=device_filter_str):
            response = run_op_command(firewall, FirewallCommand.ROUTING_PROTOCOL_BGP_PEER_COMMAND)
            summary_data.append(dataclass_from_element(firewall, ShowRoutingProtocolBGPPeersSummaryData,
                                                       response.find("./result/entry")))
            result_data.append(dataclass_from_element(firewall, ShowRoutingProtocolBGPPeersResultData,
                                                      response.find("./result/entry")))

        return ShowRoutingProtocolBGPCommandResult(
            summary_data=summary_data,
            result_data=result_data
        )

    @staticmethod
    def get_device_state(topology: Topology,
                         device_filter_str: str):
        for firewall in topology.firewalls(filter_string=device_filter_str):
            # Connect directly to the firewall
            direct_firewall_connection: Firewall = topology.get_direct_device(firewall)
            direct_firewall_connection.xapi.export(category="device-state")
            return direct_firewall_connection.xapi.export_result.get("content")

    @staticmethod
    def get_ha_status(topology: Topology,
                      device_filter_str: str = None) -> list[ShowHAState]:

        result: list[ShowHAState] = []
        for firewall in topology.all(filter_string=device_filter_str):
            firewall_host_id: str = resolve_host_id(firewall)

            peer_serial: str = topology.get_peer(firewall_host_id)
            if not peer_serial:
                result.append(ShowHAState(
                    hostid=firewall_host_id,
                    status="HA Not enabled.",
                    active=True,
                    peer=""
                ))
            else:
                state_information_element = run_op_command(firewall, FirewallCommand.HA_STATE_COMMAND)
                state = find_text_in_element(state_information_element, "./result/group/local-info/state")

                if state == "active":
                    result.append(ShowHAState(
                        hostid=firewall_host_id,
                        status=state,
                        active=True,
                        peer=peer_serial
                    ))
                else:
                    result.append(ShowHAState(
                        hostid=firewall_host_id,
                        status=state,
                        active=False,
                        peer=peer_serial
                    ))

        if len(result) == 1:
            return result[0]  # type: ignore
        return result

    @staticmethod
    def change_status(topology: Topology, hostid: str, state: str) -> HighAvailabilityStateStatus:
        firewall = list(topology.firewalls(filter_string=hostid))[0]
        run_op_command(firewall, FirewallCommand.REQUEST_STATE_PREFIX + f" {state}")
        return HighAvailabilityStateStatus(
            hostid=resolve_host_id(firewall),
            state=state
        )

    @staticmethod
    def get_routes(topology: Topology,
                   device_filter_str: str = None) -> ShowRoutingRouteCommandResult:
        summary_data = []
        result_data = []
        for firewall in topology.firewalls(filter_string=device_filter_str):
            response = run_op_command(firewall, FirewallCommand.ROUTING_ROUTE_COMMAND)
            for entry in response.findall("./result/entry"):
                result_data.append(
                    dataclass_from_element(firewall, ShowRoutingRouteResultData, entry))

        # Calculate summary as number of routes by network interface and VR
        row: ShowRoutingRouteResultData
        count_data: dict[str, dict] = {}
        for row in result_data:
            if not count_data.get(row.hostid):
                count_data[row.hostid] = defaultdict(int)

            count_data[row.hostid][row.interface] += 1

        for firewall_hostname, interfaces in count_data.items():
            for interface, route_count in interfaces.items():
                summary_data.append(ShowRoutingRouteSummaryData(
                    hostid=firewall_hostname,
                    interface=interface,
                    route_count=route_count
                ))

        return ShowRoutingRouteCommandResult(
            summary_data=summary_data,
            result_data=result_data
        )


"""
-- XSOAR Specific Code Starts below --
"""


class CommandRegister:
    commands: dict[str, Callable] = {}
    file_commands: dict[str, Callable] = {}

    def command(self, command_name: str):
        """
        Register a normal Command for this Integration. Commands always return CommandResults.

        :param command_name: The XSOAR integration command
        """

        def _decorator(func):
            self.commands[command_name] = func

            def _wrapper(topology, demisto_args=None):
                return func(topology, demisto_args)

            return _wrapper

        return _decorator

    def file_command(self, command_name: str):
        """
        Register a file command. file commands always return FileResults.

        :param command_name: The XSOAR integration command
        """

        def _decorator(func):
            self.file_commands[command_name] = func

            def _wrapper(topology, demisto_args=None):
                return func(topology, demisto_args)

            return _wrapper

        return _decorator

    def run_command_result_command(self, command_name: str, func: Callable, topology: Topology,
                                   demisto_args: dict) -> CommandResults:
        result = func(topology, **demisto_args)
        if command_name == "test-module":
            return_results(result)

        if not result:
            command_result = CommandResults(
                readable_output="No results.",
            )
            return_results(command_result)
            return command_result

        # Convert the dataclasses into dicts
        outputs: Union[list, dict] = {}
        summary_list = []
        title = ""
        output_prefix = ""

        if not hasattr(result, "summary_data"):
            # If this isn't a regular summary/result return, but instead, is just one object or a list of flat
            # objects
            if type(result) is list:
                outputs = [vars(x) for x in result]
                summary_list = [vars(x) for x in result]
                # This is a bit controversial
                title = result[0]._title
                output_prefix = result[0]._output_prefix
            else:
                outputs = vars(result)
                summary_list = [vars(result)]
                title = result._title
                output_prefix = result._output_prefix
        else:
            if result.summary_data:
                summary_list = [vars(x) for x in result.summary_data if hasattr(x, "__dict__")]
                outputs = {
                    "Summary": summary_list,
                }

            if result.result_data:
                outputs["Result"] = [vars(x) for x in result.result_data if
                                     hasattr(x, "__dict__")]  # type: ignore

            title = result._title
            output_prefix = result._output_prefix

        extra_args = {}
        if hasattr(result, "_outputs_key_field"):
            extra_args["outputs_key_field"] = getattr(result, "_outputs_key_field")

        readable_output = tableToMarkdown(title, summary_list)
        command_result = CommandResults(
            outputs_prefix=output_prefix,
            outputs=outputs,
            readable_output=readable_output,
            **extra_args
        )
        return_results(command_result)
        return command_result

    def run_file_command(self, func: Callable, topology: Topology,
                         demisto_args: dict) -> dict:

        file_result: dict = func(topology, **demisto_args)
        return_results(file_result)
        return file_result

    def is_command(self, command_name: str) -> bool:
        if command_name in self.commands or command_name in self.file_commands:
            return True

        return False

    def run_command(
            self,
            command_name: str,
            topology: Topology,
            demisto_args: dict
    ) -> Union[CommandResults, dict]:
        """
        Runs the given XSOAR command.
        :param command_name: The name of the decorated XSOAR command.
        :param topology: `Topology` instance
        :param demisto_args: Result of demisto.args()
        """
        if command_name in self.commands:
            func = self.commands.get(command_name)
            return self.run_command_result_command(command_name, func, topology, demisto_args)  # type: ignore

        if command_name in self.file_commands:
            func = self.file_commands.get(command_name)
            return self.run_file_command(func, topology, demisto_args)  # type: ignore

        raise DemistoException("Command not found.")


# This is the store of all the commands available to this integration
COMMANDS = CommandRegister()


@COMMANDS.command("test-module")
def test_module(topology: Topology, device_filter_string: str = None):
    """To get to the test-module command we must connect to the devices, thus no further test is required."""
    if len(topology.firewall_objects) + len(topology.panorama_objects) == 0:
        raise ConnectionError("No firewalls or panorama instances could be connected.")

    return "ok"


@COMMANDS.command("pan-os-platform-get-arp-tables")
def get_arp_tables(topology: Topology, device_filter_string: str = None) -> ShowArpCommandResult:
    """
    Gets all arp tables from all firewalls in the topology.
    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only show specific hostnames or serial numbers.
    """
    result: ShowArpCommandResult = FirewallCommand.get_arp_table(topology, device_filter_string)
    return result


@COMMANDS.command("pan-os-platform-get-route-summary")
def get_route_summaries(topology: Topology,
                        device_filter_string: str = None) -> ShowRouteSummaryCommandResult:
    """
    Pulls all route summary information from the topology
    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only show specific hostnames or serial numbers.
    """
    result: ShowRouteSummaryCommandResult = FirewallCommand.get_routing_summary(topology,
                                                                                device_filter_string)
    return result


@COMMANDS.command("pan-os-platform-get-routes")
def get_routes(topology: Topology,
               device_filter_string: str = None) -> ShowRoutingRouteCommandResult:
    """
    Pulls all route summary information from the topology
    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only show specific hostnames or serial numbers.
    """
    result: ShowRoutingRouteCommandResult = FirewallCommand.get_routes(topology,
                                                                       device_filter_string)
    return result


@COMMANDS.command("pan-os-platform-get-system-info")
def get_system_info(topology: Topology,
                    device_filter_string: str = None) -> ShowSystemInfoCommandResult:
    """
    Gets information from all PAN-OS systems in the topology.
    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only show specific hostnames or serial numbers.
    """
    result: ShowSystemInfoCommandResult = UniversalCommand.get_system_info(topology,
                                                                           device_filter_string)
    return result


@COMMANDS.command("pan-os-platform-get-device-groups")
def get_device_groups(topology: Topology, device_filter_string: str = None) -> list[DeviceGroupInformation]:
    """
    Gets the operational information of the device groups in the topology.
    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only show specific hostnames or serial numbers.
    """
    result: list[DeviceGroupInformation] = PanoramaCommand.get_device_groups(topology, device_filter_string)
    return result


@COMMANDS.command("pan-os-platform-get-template-stacks")
def get_template_stacks(topology: Topology, device_filter_string: str = None) -> list[
    TemplateStackInformation]:
    """
    Gets the operational information of the template-stacks in the topology.
    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only show specific hostnames or serial numbers.
    """
    result: list[TemplateStackInformation] = PanoramaCommand.get_template_stacks(topology,
                                                                                 device_filter_string)
    return result


@COMMANDS.command("pan-os-platform-get-global-counters")
def get_global_counters(topology: Topology,
                        device_filter_string: str = None) -> ShowCounterGlobalCommmandResult:
    """
    Gets global counter information from all the PAN-OS firewalls in the topology
    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only show specific hostnames or serial numbers.
    """
    result: ShowCounterGlobalCommmandResult = FirewallCommand.get_counter_global(topology,
                                                                                 device_filter_string)
    return result


@COMMANDS.command("pan-os-platform-get-bgp-peers")
def get_bgp_peers(topology: Topology,
                  device_filter_string: str = None) -> ShowRoutingProtocolBGPCommandResult:
    """
    Retrieves all BGP peer information from the PAN-OS firewalls in the topology.
    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only show specific hostnames or serial numbers.
    """
    result: ShowRoutingProtocolBGPCommandResult = FirewallCommand.get_bgp_peers(topology,
                                                                                device_filter_string)
    return result


@COMMANDS.command("pan-os-platform-get-device-connectivity")
def get_device_connectivity(topology: Topology, hostid: str) -> GetDeviceConnectivityCommandResult:
    """
    Search the topology for a given hostid. If it's not found, the device is not connected or unreachable.
    :param topology: `Topology` instance !no-auto-argument
    :param hostid: ID (serial or hostname) of host to search for.
    :return:
    """
    if not topology.get_by_filter_str(hostid):
        result = GetDeviceConnectivityResultData(
            hostid=hostid,
            connected=False
        )
        return GetDeviceConnectivityCommandResult(summary_data=[result])
    else:
        result = GetDeviceConnectivityResultData(
            hostid=hostid,
            connected=True
        )
        return GetDeviceConnectivityCommandResult(summary_data=[result])


@COMMANDS.command("pan-os-platform-get-available-software")
def get_available_software(topology: Topology,
                           device_filter_string: str = None) -> SoftwareVersionCommandResult:
    """
    Check the devices for software that is available to be installed.
    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only show specific hostnames or serial numbers.
    """
    result: SoftwareVersionCommandResult = UniversalCommand.get_available_software(topology,
                                                                                   device_filter_string)
    return result


@COMMANDS.file_command("pan-os-platform-get-device-state")
def get_device_state(topology: Topology, hostid: str) -> FileInfoResult:
    """
    Get the device state from the provided device.
    :param topology: `Topology` instance !no-auto-argument
    :param hostid: String to filter to only show specific hostnames or serial numbers.
    """
    result_file_data = FirewallCommand.get_device_state(topology, hostid)
    return fileResult(
        filename=f"{hostid}_device_state.tar.gz",
        data=result_file_data,
        file_type=EntryType.ENTRY_INFO_FILE
    )


@COMMANDS.command("pan-os-platform-get-ha-state")
def get_ha_state(topology: Topology, device_filter_string: str = None) -> list[ShowHAState]:
    """
    Get the HA state and assocaited details from the given device and any other details.
    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only show specific hostnames or serial numbers.
    """
    result: list[ShowHAState] = FirewallCommand.get_ha_status(topology, device_filter_string)
    return result


@COMMANDS.command("pan-os-platform-get-jobs")
def get_jobs(topology: Topology, device_filter_string: str = None, status: str = None, job_type: str = None,
             id: int = None) -> list[ShowJobsAllResultData]:
    """
    Get all the jobs from the devices in the environment, or a single job when ID is specified.

    Jobs are sorted by the most recent queued and are returned in a way that's consumable by Generic Polling.
    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only show specific hostnames or serial numbers.
    :param status: Filter returned jobs by status
    :param job_type: Filter returned jobs by type
    :param id: Filter by ID
    """
    if id:
        id = int(id)

    result: list[ShowJobsAllResultData] = UniversalCommand.show_jobs(
        topology,
        device_filter_string,
        job_type=job_type,
        status=status,
        id=id
    )
    return result


@COMMANDS.command("pan-os-platform-download-software")
def download_software(topology: Topology, version: str,
                      device_filter_string: str = None, sync: bool = False) -> DownloadSoftwareCommandResult:
    """
    Download The provided software version onto the device.
    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only install to sepecific devices or serial numbers
    :param version: software version to upgrade to, ex. 9.1.2
    :param sync: If provided, runs the download synchronously - make sure 'execution-timeout' is increased.
    """
    if sync == "false":
        sync = False

    result: DownloadSoftwareCommandResult = UniversalCommand.download_software(topology, version,
                                                                               device_filter_str=device_filter_string,
                                                                               sync=sync)

    return result


@COMMANDS.command("pan-os-platform-install-software")
def install_software(topology: Topology, version: str,
                     device_filter_string: str = None, sync: bool = False) -> InstallSoftwareCommandResult:
    """
    Install the given software version onto the device. Download the software first with
    pan-os-platform-download-software

    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only install to specific devices or serial numbers
    :param version: software version to upgrade to, ex. 9.1.2
    :param sync: If provided, runs the download synchronously - make sure 'execution-timeout' is increased.
    """
    if sync == "false":
        sync = False
    result: InstallSoftwareCommandResult = UniversalCommand.install_software(topology, version,
                                                                             device_filter_str=device_filter_string,
                                                                             sync=sync)

    return result


@COMMANDS.command("pan-os-platform-reboot")
def reboot(topology: Topology, hostid: str) -> RestartSystemCommandResult:
    """
    Reboot the given host.

    :param topology: `Topology` instance !no-auto-argument
    :param hostid: ID of host (serial or hostname) to reboot
    """
    result: RestartSystemCommandResult = UniversalCommand.reboot(topology, hostid=hostid)

    return result


@COMMANDS.command("pan-os-platform-get-system-status")
def system_status(topology: Topology, hostid: str) -> CheckSystemStatus:
    """
    Checks the status of the given device, checking whether it's up or down and the operational mode normal

    :param topology: `Topology` instance !no-auto-argument
    :param hostid: ID of host (serial or hostname) to check.
    """
    result: CheckSystemStatus = UniversalCommand.check_system_availability(topology, hostid=hostid)

    return result


@COMMANDS.command("pan-os-platform-update-ha-state")
def update_ha_state(topology: Topology, hostid: str, state: str) -> HighAvailabilityStateStatus:
    """
    Checks the status of the given device, checking whether it's up or down and the operational mode normal

    :param topology: `Topology` instance !no-auto-argument
    :param hostid: ID of host (serial or hostname) to update the state.
    :param state: New state.
    """
    result: HighAvailabilityStateStatus = FirewallCommand.change_status(topology, hostid=hostid, state=state)

    return result


"""Hygiene Commands"""


@COMMANDS.command("pan-os-hygiene-check-log-forwarding")
def check_log_forwarding(topology: Topology,
                         device_filter_string: str = None) -> ConfigurationHygieneCheckResult:
    """
    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only check given device
    """
    result: ConfigurationHygieneCheckResult = \
        HygieneLookups.check_log_forwarding_profiles(topology, device_filter_str=device_filter_string)

    return result


@COMMANDS.command("pan-os-hygiene-check-vulnerability-profiles")
def check_vulnerability_profiles(
        topology: Topology,
        device_filter_string: str = None,
        minimum_block_severities: str = "critical,high",
        minimum_alert_severities: str = "medium,low"
) -> ConfigurationHygieneCheckResult:
    """
    Checks the configured Vulnerability profiles to ensure at least one meets best practices.

    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only check given device
    :param minimum_block_severities: csv list of severities that must be in drop/reset/block-ip mode.
    :param minimum_alert_severities: csv list of severities that must be in alert/default or higher mode.
    """
    result: ConfigurationHygieneCheckResult = HygieneLookups.check_vulnerability_profiles(
        topology,
        device_filter_str=device_filter_string,
        minimum_block_severities=minimum_block_severities.split(","),
        minimum_alert_severities=minimum_alert_severities.split(",")
    )

    return result


@COMMANDS.command("pan-os-hygiene-check-spyware-profiles")
def check_spyware_profiles(
        topology: Topology,
        device_filter_string: str = None,
        minimum_block_severities: str = "critical,high",
        minimum_alert_severities: str = "medium,low"
) -> ConfigurationHygieneCheckResult:
    """
    Checks the configured Anti-spyware profiles to ensure at least one meets best practices.

    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only check given device
    :param minimum_block_severities: csv list of severities that must be in drop/reset/block-ip mode.
    :param minimum_alert_severities: csv list of severities that must be in alert/default or higher mode.
    """
    result: ConfigurationHygieneCheckResult = HygieneLookups.check_spyware_profiles(
        topology,
        device_filter_str=device_filter_string,
        minimum_block_severities=minimum_block_severities.split(","),
        minimum_alert_severities=minimum_alert_severities.split(",")
    )

    return result


@COMMANDS.command("pan-os-hygiene-check-url-filtering-profiles")
def check_url_filtering_profiles(
        topology: Topology,
        device_filter_string: str = None
) -> ConfigurationHygieneCheckResult:
    """
    Checks the configured URL Filtering profiles to ensure at least one meets best practices.

    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only check given device
    """
    result: ConfigurationHygieneCheckResult = HygieneLookups.check_url_filtering_profiles(
        topology,
        device_filter_str=device_filter_string,
    )

    return result


@COMMANDS.command("pan-os-hygiene-conforming-url-filtering-profiles")
def get_conforming_url_filtering_profiles(
        topology: Topology,
        device_filter_string: str = None
) -> list[PanosObjectReference]:
    """
    Returns a list of existing PANOS URL filtering objects that conform to best practices.

    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only check given device
    """
    result: list[PanosObjectReference] = HygieneLookups.get_all_conforming_url_filtering_profiles(
        topology,
        device_filter_str=device_filter_string,
    )

    return result


@COMMANDS.command("pan-os-hygiene-conforming-spyware-profiles")
def get_conforming_spyware_profiles(
        topology: Topology,
        device_filter_string: str = None,
        minimum_block_severities: str = "critical,high",
        minimum_alert_severities: str = "medium,low"
) -> list[PanosObjectReference]:
    """
    Returns all Anti-spyware profiles that conform to best practices.

    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only check given device
    :param minimum_block_severities: csv list of severities that must be in drop/reset/block-ip mode.
    :param minimum_alert_severities: csv list of severities that must be in alert/default or higher mode.
    """
    result: list[PanosObjectReference] = HygieneLookups.get_all_conforming_spyware_profiles(
        topology,
        device_filter_str=device_filter_string,
        minimum_block_severities=minimum_block_severities.split(","),
        minimum_alert_severities=minimum_alert_severities.split(",")
    )

    return result


@COMMANDS.command("pan-os-hygiene-conforming-vulnerability-profiles")
def get_conforming_vulnerability_profiles(
        topology: Topology,
        device_filter_string: str = None,
        minimum_block_severities: str = "critical,high",
        minimum_alert_severities: str = "medium,low"
) -> list[PanosObjectReference]:
    """
    Returns all Vulnerability profiles that conform to best practices.

    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only check given device
    :param minimum_block_severities: csv list of severities that must be in drop/reset/block-ip mode.
    :param minimum_alert_severities: csv list of severities that must be in alert/default or higher mode.
    """
    result: list[PanosObjectReference] = HygieneLookups.get_all_conforming_vulnerability_profiles(
        topology,
        device_filter_str=device_filter_string,
        minimum_block_severities=minimum_block_severities.split(","),
        minimum_alert_severities=minimum_alert_severities.split(",")
    )

    return result


@COMMANDS.command("pan-os-hygiene-check-security-zones")
def check_security_zones(topology: Topology,
                         device_filter_string: str = None) -> ConfigurationHygieneCheckResult:
    """
    Check configured security zones have correct settings.

    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only check given device
    """
    result: ConfigurationHygieneCheckResult = \
        HygieneLookups.check_security_zones(topology, device_filter_str=device_filter_string)

    return result


@COMMANDS.command("pan-os-hygiene-check-security-rules")
def check_security_rules(topology: Topology,
                         device_filter_string: str = None) -> ConfigurationHygieneCheckResult:
    """
    Check security rules are configured correctly.

    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only check given device
    """
    result: ConfigurationHygieneCheckResult = \
        HygieneLookups.check_security_rules(topology, device_filter_str=device_filter_string)

    return result


def hygiene_issue_dict_to_object(issue_dicts: Union[list[dict], dict]) -> list[ConfigurationHygieneIssue]:
    if type(issue_dicts) is not list:
        issue_dicts = [issue_dicts]  # type: ignore

    issues: list[ConfigurationHygieneIssue] = []
    for issue_dict in issue_dicts:
        issue_dict["container_name"] = issue_dict["containername"]
        issue_dict["issue_code"] = issue_dict["issuecode"]
        del (issue_dict["containername"])
        del (issue_dict["issuecode"])
        issues.append(
            ConfigurationHygieneIssue(**issue_dict)
        )
    return issues


@COMMANDS.command("pan-os-hygiene-fix-log-forwarding")
def fix_log_forwarding(
        topology: Topology,
        issue: list,
) -> list[ConfigurationHygieneFix]:
    """
    :param topology: `Topology` instance !no-auto-argument
    :param issue: Dictionary of Hygiene issue, from a hygiene check command. Can be a list.
    """
    issue_objects = hygiene_issue_dict_to_object(issue)
    result: list[ConfigurationHygieneFix] = \
        HygieneRemediation.fix_log_forwarding_profile_enhanced_logging(topology, issues=issue_objects)

    return result


@COMMANDS.command("pan-os-hygiene-fix-security-zone-log-settings")
def fix_security_zone_log_setting(
        topology: Topology,
        issue: list,
        log_forwarding_profile_name: str
) -> list[ConfigurationHygieneFix]:
    """
    Fixes security zones that are configured without a valid log forwarding profile.
    :param topology: `Topology` instance !no-auto-argument
    :param issue: Dictionary of Hygiene issue, from a hygiene check command. Can be a list.
    :param log_forwarding_profile_name: Name of log forwarding profile to set.
    """
    issue_objects = hygiene_issue_dict_to_object(issue)
    result: list[ConfigurationHygieneFix] = HygieneRemediation.fix_security_zone_no_log_setting(
        topology,
        log_forwarding_profile=log_forwarding_profile_name,
        issues=issue_objects
    )

    return result


@COMMANDS.command("pan-os-hygiene-fix-security-rule-log-settings")
def fix_security_rule_log_setting(
        topology: Topology,
        issue: list,
        log_forwarding_profile_name: str
) -> list[ConfigurationHygieneFix]:
    """
    Fixed security rules that have incorrect log settings by adding a log forwarding profile and setting
    log at session end.
    :param topology: `Topology` instance !no-auto-argument
    :param issue: Dictionary of Hygiene issue, from a hygiene check command. Can be list.
    :param log_forwarding_profile_name: Name of log forwarding profile to use as log setting.
    """
    issue_objects = hygiene_issue_dict_to_object(issue)
    result: list[ConfigurationHygieneFix] = HygieneRemediation.fix_secuity_rule_log_settings(
        topology,
        log_forwarding_profile_name=log_forwarding_profile_name,
        issues=issue_objects
    )

    return result


@COMMANDS.command("pan-os-hygiene-fix-security-rule-profile-settings")
def fix_security_rule_security_profile_group(
        topology: Topology,
        issue: list,
        security_profile_group_name: str
) -> list[ConfigurationHygieneFix]:
    """
    Fixed security rules that have incorrect log settings by adding a log forwarding profile and setting
    log at session end.
    :param topology: `Topology` instance !no-auto-argument
    :param issue: Dictionary of Hygiene issue, from a hygiene check command
    :param security_profile_group_name: Name of Security profile group to use as log setting.
    """
    issue_objects = hygiene_issue_dict_to_object(issue)
    result: list[ConfigurationHygieneFix] = HygieneRemediation.fix_security_rule_security_profile_group(
        topology,
        security_profile_group_name=security_profile_group_name,
        issues=issue_objects
    )

    return result


class ObjectTypeEnum(enum.Enum):
    ADDRESS = "AddressObject"
    ADDRESS_GROUP = "AddressGroup"
    SERVICE_GROUP = "ServiceGroup"
    SERVICE = "ServiceObject"
    APPLICATION = "ApplicationObject"
    APPLICATION_GROUP = "ApplicationGroup"
    LOG_FORWARDING_PROFILE = "LogForwardingProfile"
    SECURITY_PROFILE_GROUP = "SecurityProfileGroup"


# Configuration Commands begin here
@COMMANDS.command("pan-os-config-commit")
def commit(topology: Topology, device_filter_string: str = None) -> list[CommitStatus]:
    """
    Commit the configuration for the entire topology. Note this only commits the configuration - it does
    not push the configuration in the case of Panorama.

    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only check given device
    """
    result: list[CommitStatus] = UniversalCommand.commit(topology, device_filter_string)

    return result


@COMMANDS.command("pan-os-config-push-all")
def push_all(
        topology: Topology,
        device_filter_string: str = None,
        device_group_filter: list[str] = None,
        template_stack_filter: list[str] = None
) -> list[PushStatus]:
    """
    Push the configuration to all the device groups and template-stacks in the environment.

    :param device_filter_string: String to filter to only check given device
    :param topology: `Topology` instance !no-auto-argument
    :param device_group_filter: List of device group names to push configuration to.
    :param template_stack_filter: List of template stack names to pushconfiguration to.
    """
    result: list[PushStatus] = PanoramaCommand.push_all(
        topology,
        device_filter_string,
        device_group_filter=device_group_filter,
        template_stack_filter=template_stack_filter
    )

    return result


@COMMANDS.command("pan-os-config-get-commit-status")
def get_commit_status(topology: Topology, match_job_id: list[str] = None) -> list[CommitStatus]:
    """
    Returns the status of the commit operation on all devices. If an ID is given, only that id will be returned.

    :param topology: `Topology` instance !no-auto-argument
    :param match_job_id: job ID or list of Job IDs to return.
    """
    result: list[CommitStatus] = UniversalCommand.get_commit_job_status(topology, match_job_id)

    return result


@COMMANDS.command("pan-os-config-get-push-status")
def get_push_status(
        topology: Topology,
        match_job_id: list[str] = None,

) -> list[PushStatus]:
    """
    Returns the status of the push (commit-all) jobs from Panorama.

    :param topology: `Topology` instance !no-auto-argument
    :param match_job_id: job ID or list of Job IDs to return.
    """
    result: list[PushStatus] = PanoramaCommand.get_push_status(topology, match_job_id)

    return result


@COMMANDS.command("pan-os-config-get-object")
def get_object(
        topology: Topology,
        object_type: ObjectTypeEnum,
        device_filter_string: str = None,
        object_name: str = None,
        parent: str = None,
        use_regex: str = None
) -> list[PanosObjectReference]:
    """Searches and returns a reference for the given object type and name. If no name is provided, all
    objects of the given type are returned. Note this only returns a reference, and not the complete object
    information.
    :param topology: `Topology` instance !no-auto-argument
    :param object_name: The name of the object refernce to return if looking for a specific object. Supports regex if "use_regex" is set.
    :param object_type: The type of object to search; see https://pandevice.readthedocs.io/en/latest/module-objects.html
    :param device_filter_string: If provided, only objects from the given device are returned.
    :param parent: The parent vsys or device group to search. if not provided, all will be returned.
    :param use_regex: Enables regex matching on object name.
    """
    result: list[PanosObjectReference] = ObjectGetter.get_object_reference(
        topology=topology,
        device_filter_string=device_filter_string,
        object_name=object_name,
        # Fixing the ignore below would rfequire adding union handling to code generation script.
        object_type=object_type,  # type: ignore
        container_filter=parent,
        use_regex=use_regex
    )
    return result


@dataclass
class DemistoParameters:
    """
    Demisto Parameters
    :param str hostnames: PAN-OS Hostnames (csv)
    """
    hostnames: str
    credentials: dict
    api_key: str = ""


def convert_params_to_object(params: dict) -> DemistoParameters:
    """Converts demisto params to the class used by NetOps code."""
    server_url = params.get('server')
    parsed_url = urlparse(server_url)
    hostname = parsed_url.hostname
    api_key = params.get('key', '')

    return DemistoParameters(
        hostnames=hostname,  # type: ignore
        api_key=api_key,
        credentials={}
    )


def main():
    # If it's an Network Operations command;
    if COMMANDS.is_command(demisto.command()):
        try:
            demisto_params = convert_params_to_object(demisto.params())
            topology = Topology.build_from_string(
                demisto_params.hostnames,
                demisto_params.credentials.get("identifier"),
                demisto_params.credentials.get("password"),
                api_key=demisto_params.api_key
            )
            return COMMANDS.run_command(demisto.command(), topology, demisto.args())
        except Exception as e:
            return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')

    else:
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
                panorama_list_addresses_command(args)

            elif demisto.command() == 'panorama-get-address':
                panorama_get_address_command(args)

            elif demisto.command() == 'panorama-create-address':
                panorama_create_address_command(args)

            elif demisto.command() == 'panorama-delete-address':
                panorama_delete_address_command(args)

            # Address groups commands
            elif demisto.command() == 'panorama-list-address-groups':
                panorama_list_address_groups_command(args)

            elif demisto.command() == 'panorama-get-address-group':
                panorama_get_address_group_command(args)

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

            elif demisto.command() == 'panorama-show-user-id-interfaces-config':
                show_user_id_interface_config_command(args)

            elif demisto.command() == 'panorama-show-zones-config':
                show_zone_config_command(args)

            elif demisto.command() == 'panorama-list-configured-user-id-agents':
                list_configured_user_id_agents_command(args)

            elif demisto.command() == 'panorama-upload-content-update-file':
                return_results(panorama_upload_content_update_file_command(args))

            elif demisto.command() == 'panorama-install-file-content-update':
                panorama_install_file_content_update_command(args)

            # The following code exists PURELY to supress XSOAR linter errors. This code is
            # unreachable.
            elif demisto.command() == 'pan-os-platform-get-arp-tables':
                pass
            elif demisto.command() == 'pan-os-platform-get-route-summary':
                pass
            elif demisto.command() == 'pan-os-platform-get-routes':
                pass
            elif demisto.command() == 'pan-os-platform-get-system-info':
                pass

            else:
                raise NotImplementedError(f'Command {demisto.command()} was not implemented.')

        except Exception as err:
            return_error(str(err))

        finally:
            LOG.print_log()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
