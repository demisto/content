import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from collections import defaultdict
from dataclasses import dataclass, fields
from types import SimpleNamespace
from functools import partial
import enum
import html

import panos.errors

from panos.base import PanDevice, VersionedPanObject, Root, ENTRY, VersionedParamPath  # type: ignore
from panos.panorama import Panorama, DeviceGroup, Template, PanoramaCommitAll
from panos.policies import Rulebase, PreRulebase, PostRulebase, SecurityRule, NatRule
from panos.objects import (
    LogForwardingProfile, LogForwardingProfileMatchList, AddressObject, AddressGroup, ServiceObject, ServiceGroup,
    ApplicationObject, ApplicationGroup, SecurityProfileGroup
)
from panos.firewall import Firewall
from panos.device import Vsys
from panos.network import Zone
from urllib.error import HTTPError

import shutil

''' IMPORTS '''
import uuid
from typing import Tuple, Callable, ValuesView, Iterator, Literal, TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from typing import TypedDict, NotRequired  # type: ignore[attr-defined]
else:
    TypedDict = type('TypedDict', (), {'__new__': lambda cls, **kw: kw})
    NotRequired = Optional

''' GLOBALS '''
URL = ''
API_KEY = None
USE_SSL = None
USE_URL_FILTERING = None
TEMPLATE = None
VSYS = ''
PRE_POST = ''
OUTPUT_PREFIX = "PANOS."
UNICODE_FAIL = u'\U0000274c'
UNICODE_PASS = u'\U00002714\U0000FE0F'

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
QUERY_DATE_FORMAT = '%Y/%m/%d %H:%M:%S'
FETCH_INCIDENTS_LOG_TYPES = ['Traffic', 'Threat', 'Url', 'Data', 'Correlation', 'System', 'Wildfire', 'Decryption']
LOG_TYPE_TO_REQUEST = {
    'Traffic': 'traffic',
    'Threat': 'threat',
    'Url': 'url',
    'Data': 'data',
    'Correlation': 'corr',
    'System': 'system',
    'Wildfire': 'wildfire',
    'Decryption': 'decryption'}
FETCH_RANGE = range(1, 5001)

XPATH_SECURITY_RULES = ''
DEVICE_GROUP = ''
DEVICE_GROUP_PARAM_NAME = 'device_group'
DEVICE_GROUP_ARG_NAME = 'device-group'

XPATH_OBJECTS = ''

XPATH_RULEBASE = ''

# pan-os-python device timeout value, in seconds
DEVICE_TIMEOUT = 120
DEFAULT_LIMIT_PAGE_SIZE = 50

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
    'disabled': 'Disabled',
    'application': 'Application',
    'source_user': 'SourceUser',
    'disable_server_response_inspection': 'DisableServerResponseInspection',
    'description': 'Description',
    'target': 'Target',
    'log_forwarding': 'LogForwarding',
    'log-setting': 'LogForwarding',
    'tag': 'Tags',
    'profile-setting': 'ProfileSetting',
    'audit-comment': 'AuditComment'
}
ELEM_TO_CONTEXT = {
    'source': 'Source',
    'destination': 'Destination',
    'application': 'Application',
    'action': 'Action',
    'category': 'Category',
    'description': 'Description',
    'disabled': 'Disabled',
    'target': 'Target',
    'log-forwarding': 'LogForwarding',
    'log-setting': 'LogForwarding',
    'tag': 'Tags',
    'profile-setting': 'ProfileSetting',
    'source-user': 'SourceUser',
    'service': 'Service',
    'audit-comment': 'AuditComment'
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
OBJ_NOT_FOUND_ERR = 'Object was not found'
# was taken from here: https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000Cm5hCAC
PAN_DB_URL_FILTERING_CATEGORIES = {
    'abortion',
    'abused-drugs',
    'adult',
    'alcohol-and-tobacco',
    'auctions',
    'business-and-economy',
    'command-and-control',
    'computer-and-internet-info',
    'content-delivery-networks',
    'copyright-infringement',
    'cryptocurrency',
    'dating',
    'dynamic-dns',
    'educational-institutions',
    'entertainment-and-arts',
    'extremism',
    'financial-services',
    'gambling',
    'games',
    'government',
    'grayware',
    'hacking',
    'health-and-medicine',
    'home-and-garden',
    'hunting-and-fishing',
    'insufficient-content',
    'internet-Communications-and-telephony',
    'internet-portals',
    'job-search',
    'legal',
    'malware',
    'military',
    'motor-vehicles',
    'music',
    'newly-registered-domain',
    'news',
    'nudity',
    'online-storage-and-backup',
    'parked',
    'peer-to-peer',
    'personal-sites-and-blogs',
    'philosophy-and-political-advocacy',
    'phishing',
    'private-ip-addresses',
    'proxy-avoidance-and-anonymizers',
    'questionable',
    'real-estate',
    'recreation-and-hobbies',
    'reference-and-research',
    'religion',
    'search-engines',
    'sex-education',
    'shareware-and-freeware',
    'shopping',
    'social-networking',
    'society',
    'sports',
    'stock-advice-and-tools',
    'streaming-media',
    'swimsuits-and-intimate-apparel',
    'training-and-tools',
    'translation',
    'travel',
    'unknown',
    'weapons',
    'web-advertisements',
    'web-hosting',
    'web-based-email',
    'high-risk',
    'medium-risk',
    'low-risk',
    'real-time-detection',
    'ransomware'
}

RULE_FILTERS = ('nat-type', 'action')
APPILICATION_FILTERS = ('risk', 'category', 'subcategory', 'technology')
CHARACTERISTICS_LIST = ('virus-ident',
                        'file-type-ident',
                        'evasive-behavior',
                        'consume-big-bandwidth',
                        'used-by-malware',
                        'able-to-transfer-file',
                        'has-known-vulnerability',
                        'tunnel-other-application',
                        'prone-to-misuse',
                        'pervasive-use',
                        'data-ident',
                        'file-forward',
                        'is-saas')

RULE_TYPES_MAP = {
    "Security Rule": "security",
    "NAT Rule": "nat",
    "PBF Rule": "pbf"
}


class ExceptionCommandType(enum.Enum):
    ADD = 'set'
    EDIT = 'edit'
    DELETE = 'delete'
    LIST = 'get'


class QueryMap(TypedDict):
    '''dict[str, str]
    Contains the log types mapped to the query
    used to fetch them from PAN-OS.
    '''
    Traffic: NotRequired[str]
    Threat: NotRequired[str]
    Url: NotRequired[str]
    Data: NotRequired[str]
    Correlation: NotRequired[str]
    System: NotRequired[str]
    Wildfire: NotRequired[str]
    Decryption: NotRequired[str]


class LastFetchTimes(QueryMap):
    '''dict[str, str]
    Maps log types to the latest log already fetched.
    '''


class LastIDs(TypedDict):
    '''dict[str, dict[str, str] | int]
    Maps devices to the "seqno" of the last log
    associated with the device.
    For correlation logs holds the last "@logid".
    '''
    Traffic: NotRequired[dict[str, str]]
    Threat: NotRequired[dict[str, str]]
    Url: NotRequired[dict[str, str]]
    Data: NotRequired[dict[str, str]]
    Correlation: NotRequired[int]  # contains the last "@logid"
    System: NotRequired[dict[str, str]]
    Wildfire: NotRequired[dict[str, str]]
    Decryption: NotRequired[dict[str, str]]


class MaxFetch(TypedDict):
    '''dict[str, int]
    Contains the log types mapped to the max fetch.
    '''
    Traffic: NotRequired[int]
    Threat: NotRequired[int]
    Url: NotRequired[int]
    Data: NotRequired[int]
    Correlation: NotRequired[int]
    System: NotRequired[int]
    Wildfire: NotRequired[int]
    Decryption: NotRequired[int]


class Offset(TypedDict):
    '''dict[str, int]
    Contains the log types mapped to the offset needed.
    '''
    Traffic: NotRequired[int]
    Threat: NotRequired[int]
    Url: NotRequired[int]
    Data: NotRequired[int]
    Correlation: NotRequired[int]
    System: NotRequired[int]
    Wildfire: NotRequired[int]
    Decryption: NotRequired[int]


class LastRun(TypedDict):
    last_fetch_dict: LastFetchTimes
    last_id_dict: LastIDs
    offset_dict: Offset


class PAN_OS_Not_Found(Exception):
    """ PAN-OS Error. """

    def __init__(self, *args):  # real signature unknown
        pass


class InvalidUrlLengthException(Exception):
    pass


class PanosResponse():
    class PanosNamespace(SimpleNamespace):
        """
        Namespace class for the PanosResponse
        """

        def __init__(self, ignored_keys: set | None = None, **kwargs):
            if not ignored_keys:
                ignored_keys = set()
            super().__init__(**{k: v for k, v in kwargs.items() if k not in ignored_keys})

        def __getattr__(self, attr):
            """
            If an AttributeError is raised, this method is called, if the attr was not found, Returns None.
            """
            return [] if attr == 'entry' else None

    def __init__(self, response: dict, ignored_keys: set | None = None, illegal_chars: set | None = None):
        self.raw = response
        self.ns = self.to_class(response, ignored_keys=ignored_keys, illegal_chars=illegal_chars)

    def get_nested_key(self, items: str):
        """
        Arguments:
        -------
        items: string of dotted notation to retrieve

        Returns:
        -------
        Dicitonary value of the requested items
        """
        return_response = self.raw
        for item in items.split("."):
            return_response = return_response.get(item, {})
        return return_response

    def handle_illegal_chars(self, dictionary: dict, illegal_chars: set | None = None):
        if not illegal_chars:
            return dictionary
        return {
            key.replace(char, ''): val for key, val in dictionary.items() for char in illegal_chars
        }

    def to_class(self, response, ignored_keys: set | None = None, illegal_chars: set | None = None) -> PanosNamespace:
        if not ignored_keys:
            ignored_keys = set()
        if not illegal_chars:
            illegal_chars = set()
        json_dump = json.dumps(response)
        return json.loads(
            json_dump,
            object_hook=lambda d: self.PanosNamespace(
                **self.handle_illegal_chars(d, illegal_chars=illegal_chars),
                ignored_keys=ignored_keys
            )
        )


def http_request(uri: str, method: str, headers: dict = {},
                 body: dict = {}, params: dict = {}, files: dict | None = None, is_file: bool = False,
                 is_xml: bool = False) -> Any:
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
    if is_file:
        return result
    if is_xml:
        return result.text

    json_result = json.loads(xml2json(result.text))

    # handle raw response that does not contain the response key, e.g configuration export
    if ('response' not in json_result or '@code' not in json_result['response']) and \
            not json_result['response']['@status'] != 'success':
        return json_result

    # handle non success
    if json_result['response']['@status'] != 'success':
        if 'msg' in json_result['response'] and 'line' in json_result['response']['msg']:
            response_msg = json_result['response']['msg']['line']
            # catch non existing object error and display a meaningful message
            if response_msg == 'No such node':
                raise Exception(
                    'Object was not found, verify that the name is correct and that the instance was committed.')

            #  catch urlfiltering error and display a meaningful message
            elif str(response_msg).find('test -> url') != -1:
                if DEVICE_GROUP:
                    raise Exception('URL filtering commands are only available on Firewall devices.')
                if 'Node can be at most 1278 characters' in response_msg:
                    raise InvalidUrlLengthException('URL Node can be at most 1278 characters.')
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
            xpath = params.get('xpath') or body.get('xpath')
            demisto.debug(f'Object with {xpath=} was not found')
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


def parse_pan_os_un_committed_data(dictionary, keys_to_remove):
    """
    When retrieving an un-committed object from panorama, a lot of un-relevant data is returned by the api.
    This function takes any api response of pan-os with data that was not committed and removes the un-relevant data
    from the response recursively so the response would be just like an object that was already committed.
    This must be done to keep the context aligned with both committed and un-committed objects.

    Args:
        dictionary (dict): The entry that the pan-os objects is in.
        keys_to_remove (list): keys which should be removed from the pan-os api response
    """
    if not dictionary:
        return
    for key in keys_to_remove:
        if key in dictionary:
            del dictionary[key]

    for key in dictionary:
        if isinstance(dictionary[key], dict) and '#text' in dictionary[key]:
            dictionary[key] = dictionary[key]['#text']
        elif isinstance(dictionary[key], list) and isinstance(dictionary[key][0], dict) \
                and dictionary[key][0].get('#text'):
            temp_list = []
            for text in dictionary[key]:
                if isinstance(text, dict):
                    temp_list.append(text.get('#text'))
                elif isinstance(text, str):
                    temp_list.append(text)
            dictionary[key] = temp_list

    for value in dictionary.values():
        if isinstance(value, dict):
            parse_pan_os_un_committed_data(value, keys_to_remove)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    parse_pan_os_un_committed_data(item, keys_to_remove)


def do_pagination(
    entries: list,
    page: Optional[int] = None,
    page_size: int = DEFAULT_LIMIT_PAGE_SIZE,
    limit: int = DEFAULT_LIMIT_PAGE_SIZE
):
    if isinstance(entries, list) and page is not None:
        if page <= 0:
            raise DemistoException(f'page {page} must be a positive number')
        entries = entries[(page - 1) * page_size:page_size * page]  # do pagination
    elif isinstance(entries, list):
        entries = entries[:limit]

    return entries


def extract_objects_info_by_key(_entry, _key):
    if isinstance(_entry, dict):
        key_info = _entry.get(_key)
        if not key_info:  # api could not return the key
            return None

        if isinstance(key_info, dict) and (_member := key_info.get('member')):
            return _member
        elif isinstance(key_info, str):
            return key_info
    elif isinstance(_entry, list):
        return [item.get(_key) for item in _entry]
    return None


def build_body_request_to_edit_pan_os_object(
    behavior,
    object_name,
    element_value,
    is_listable,
    xpath='',
    should_contain_entries=True,
    is_entry=False,
    is_empty_tag=False,
    is_commit_required=True
):
    """
    This function builds up a general body-request (element) to add/remove/replace an existing pan-os object by
    the requested behavior and a full xpath to the object.

    Args:
        behavior (str): must be one of add/remove/replace.
        object_name (str): the name of the object that needs to be updated.
        element_value (str): the value of the new element.
        is_listable (bool): whether the object is listable or not, not relevant when behavior == 'replace'.
        xpath (str): the full xpath to the object that should be edit. not required if behavior == 'replace'
        should_contain_entries (bool): whether an object should contain at least one entry. True if yes, False if not.
        is_entry (bool): whether the element should be of the following form:
            <entry name="{entry_name}"/>
        is_empty_tag (bool): whether tag should be created completely empty, for example <action/>
        is_commit_required (bool): whether a commit is required when trying to add pan-os-object.

    Returns:
        dict: a body request for the new object to update it.
    """

    if behavior not in {'replace', 'remove', 'add'}:
        raise ValueError(f'behavior argument must be one of replace/remove/add values')

    if behavior == 'replace':
        element = prepare_pan_os_objects_body_request(
            object_name, element_value, is_list=is_listable, is_entry=is_entry, is_empty_tag=is_empty_tag
        )
    else:  # add or remove is only for listable objects.
        current_objects_items = panorama_get_current_element(
            element_to_change=object_name, xpath=xpath, is_commit_required=is_commit_required
        )
        if behavior == 'add':
            updated_object_items = list((set(current_objects_items)).union(set(argToList(element_value))))
        else:  # remove
            updated_object_items = [item for item in current_objects_items if item not in argToList(element_value)]
            if not updated_object_items and should_contain_entries:
                raise DemistoException(f'The object: {object_name} must have at least one item.')

        element = prepare_pan_os_objects_body_request(
            object_name, updated_object_items, is_list=True, is_entry=is_entry, is_empty_tag=is_empty_tag
        )

    return element


def prepare_pan_os_objects_body_request(key, value, is_list=True, is_entry=False, is_empty_tag=False):
    if is_entry:
        return {key: ''.join([f'<entry name="{entry}"/>' for entry in argToList(value)])}
    if is_empty_tag:
        return {key: f'<{value}/>'}
    return {key: {'member': argToList(value)}} if is_list else {key: value}


def dict_to_xml(_dictionary, contains_xml_chars=False):
    """
    Transforms a dict object to an XML string.

    Args:
        _dictionary (dict): the dict to parse into XML
        contains_xml_chars (bool): whether dict contains any XML special chars such as < or >

    Returns:
        str: the dict representation in XML.
    """
    xml = re.sub('<\/*xml2json>', '', json2xml({'xml2json': _dictionary}).decode('utf-8'))
    if contains_xml_chars:
        return xml.replace('&gt;', '>').replace('&lt;', '<')
    return xml


def add_argument_list(arg: Any, field_name: str, member: Optional[bool], any_: Optional[bool] = False) -> str:
    member_stringify_list = ''
    if arg:
        if isinstance(arg, str):
            arg = [arg]

        for item in arg:
            member_stringify_list += f'<member>{item}</member>'
        if field_name == 'member':
            return member_stringify_list
        elif member:
            return f'<{field_name}>{member_stringify_list}</{field_name}>'
        else:
            return f'<{field_name}>{arg}</{field_name}>'

    if any_:
        if member:
            return f'<{field_name}><member>any</member></{field_name}>'
        else:
            return f'<{field_name}>any</{field_name}>'
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
    if arg and arg.lower() == 'no':
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


def set_xpath_network(template: str | None = None) -> Tuple[str, Optional[str]]:
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
                                 disable: str = None, application: List[str] = None, source_user: List[str] = None,
                                 category: List[str] = None, from_: str = None, to: str = None, description: str = None,
                                 target: str = None, log_forwarding: str = None,
                                 disable_server_response_inspection: str = None, tags: List[str] = None,
                                 profile_setting: str = None, where: str = 'bottom', dst: str = None) -> Dict:
    if application is None or len(application) == 0:
        # application always must be specified and the default should be any
        application = ['any']

    # flake8: noqa
    rulename = rulename if rulename else f'demisto-{str(uuid.uuid4())[:8]}'
    params = {
        'type': 'config',
        'action': api_action,
        'key': API_KEY,
        'where': where,  # default where will be bottom for BC purposes
        'element': add_argument_open(action, 'action', False)
        + add_argument_target(target, 'target')
        + add_argument_open(description, 'description', False)
        + add_argument_list(source, 'source', True, True)
        + add_argument_list(destination, 'destination', True, True)
        + add_argument_list(application, 'application', True)
        + add_argument_list(category, 'category', True)
        + add_argument_list(source_user, 'source-user', True)
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
    if dst:
        if where not in ('before', 'after'):
            raise DemistoException('Please provide a dst rule only when the where argument is before or after.')
        else:
            params['dst'] = dst

    if DEVICE_GROUP:
        if not PRE_POST:
            raise Exception('Please provide the pre_post argument when configuring '
                            'a security rule in Panorama instance.')
        else:
            params['xpath'] = f"{XPATH_RULEBASE}{PRE_POST}/security/rules/entry[@name='{rulename}']"
    else:
        params['xpath'] = f"{XPATH_RULEBASE}rulebase/security/rules/entry[@name='{rulename}']"

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


def build_xpath_filter(name_match: str | None = None, name_contains: str | None = None, filters: dict | None = None) -> str:
    xpath_prefix = ''
    if name_match:
        xpath_prefix = f"@name='{name_match}'"
    if name_contains:
        xpath_prefix = f"contains(@name,'{name_contains}')"
    if filters:
        for key, value in filters.items():
            if key in RULE_FILTERS or key in APPILICATION_FILTERS:
                if xpath_prefix:
                    xpath_prefix += 'and'
                xpath_prefix += f"({key}='{value}')"
            if key == 'tags':
                for tag in value:
                    if xpath_prefix:
                        xpath_prefix += 'and'
                    xpath_prefix += f"(tag/member='{tag}')"
            if key == 'characteristics':
                for characteristic in value:
                    if xpath_prefix:
                        xpath_prefix += 'and'
                    xpath_prefix += f"({characteristic}='yes')"
    return xpath_prefix


def filter_rules_by_status(disabled: str, rules: list) -> list:
    for rule in rules:
        parse_pan_os_un_committed_data(rule, ['@admin', '@dirtyId', '@time'])

    if disabled.lower() == 'yes':
        return list(filter(lambda x: x.get('disabled', '').lower() == 'yes', rules))
    else:
        return list(filter(lambda x: x.get('disabled', '').lower() != 'yes', rules))


''' FUNCTIONS'''


def panorama_test(fetch_params):
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

    try:
        # Test the topology functionality
        topology = get_topology()
        test_topology_connectivity(topology)

        # Test fetch incidents parameters
        if fetch_params.get('isFetch'):
            test_fetch_incidents_parameters(fetch_params)

    except DemistoException as e:
        raise e
    except Exception as exception_text:
        demisto.debug(f"Failed to create topology; topology commands will not work. {exception_text}")

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


def list_device_groups_names():
    """
    Get device group names in the Panorama
    """
    device_group_names = get_device_groups_names()

    return CommandResults(
        outputs_prefix='Panorama.DeviceGroupNames',
        outputs=device_group_names,
        readable_output=tableToMarkdown('Device Group Names:', device_group_names, ['Group Name']),
    )


def start_tsf_export():
    """
    Start export of tech support file (TSF) from PAN-OS:
    https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-panorama-api/pan-os-xml-api-request-types/export-files-api/export-technical-support-data
    """
    params = {
        'type': 'export',
        'category': 'tech-support',
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params
    )
    return result


def get_tsf_export_status(job_id: str):
    """
    Get status of TSF export.
    """
    params = {
        'type': 'export',
        'category': 'tech-support',
        'action': 'status',
        'job-id': job_id,
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params
    )
    return result


def download_tsf(job_id: str):
    """
    Download an exported TSF.
    """
    params = {
        'type': 'export',
        'category': 'tech-support',
        'action': 'get',
        'job-id': job_id,
        'key': API_KEY
    }
    result = http_request(
        URL,
        'GET',
        params=params,
        is_file=True
    )
    return fileResult("tech_support_file.tar.gz", result.content)


@polling_function(
    name=demisto.command(),
    interval=arg_to_number(demisto.args().get('interval_in_seconds', 30)),
    timeout=arg_to_number(demisto.args().get('timeout', 1200)),
    requires_polling_arg=False
)
def export_tsf_command(args: dict):
    """
    Export a TSF from PAN-OS.
    """
    if job_id := args.get('job_id'):
        job_status = dict_safe_get(
            get_tsf_export_status(job_id),
            ['response', 'result', 'job', 'status']
        )
        return PollResult(
            response=download_tsf(job_id),
            continue_to_poll=job_status != 'FIN',  # continue polling if job isn't done
        )
    else:  # either no polling is required or this is the first run
        result = start_tsf_export()
        job_id = dict_safe_get(result, ['response', 'result', 'job'])

        if not job_id:
            raise DemistoException("Failed to start tech support file export.")

        return PollResult(
            response=download_tsf(job_id),
            continue_to_poll=True,
            args_for_next_run={
                'job_id': job_id,
                'interval_in_seconds': arg_to_number(args.get('interval_in_seconds')),
                'timeout': arg_to_number(args.get('timeout'))
            },
            partial_result=CommandResults(
                readable_output=f'Waiting for tech support file export with job ID {job_id} to finish...'
            )
        )


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

    for arg in args:
        params[arg] = args[arg]

    is_xml = argToBoolean(params.get("is_xml", "false"))
    params['key'] = API_KEY

    result = http_request(
        URL,
        'POST',
        body=params,
        is_xml=is_xml
    )

    return_results(CommandResults(
        outputs_prefix='Panorama.Command',
        outputs=result,
        readable_output='Command was executed successfully.'
    ))


@logger
def panorama_commit(args):
    command: str = ''
    partial_command: str = ''
    is_partial = False
    if device_group := args.get('device-group'):
        command += f'<device-group><entry name="{device_group}"/></device-group>'

    admin_name = args.get('admin_name')
    if admin_name:
        is_partial = True
        partial_command += f'<admin><member>{admin_name}</member></admin>'

    force_commit = argToBoolean(args.get('force_commit')) if args.get('force_commit') else None
    if force_commit:
        command += '<force></force>'

    description = args.get('description')
    if description:
        command += f'<description>{description}</description>'

    exclude_device_network = args.get('exclude_device_network_configuration')
    exclude_device_network_configuration = argToBoolean(exclude_device_network) if exclude_device_network else None
    if exclude_device_network_configuration:
        is_partial = True
        partial_command += '<device-and-network>excluded</device-and-network>'

    exclude_shared_objects_str = args.get('exclude_shared_objects')
    exclude_shared_objects = argToBoolean(exclude_shared_objects_str) if exclude_shared_objects_str else None
    if exclude_shared_objects:
        is_partial = True
        partial_command += '<shared-object>excluded</shared-object>'

    if is_partial:
        command = f'{command}<partial>{partial_command}</partial>'

    params = {
        'type': 'commit',
        'cmd': f'<commit>{command}</commit>',
        'key': API_KEY
    }
    if is_partial:
        params['action'] = 'partial'

    result = http_request(
        URL,
        'POST',
        body=params
    )

    return result


@polling_function(
    name=demisto.command(),  # should fit to both pan-os-commit and panorama-commit (deprecated)
    interval=arg_to_number(demisto.args().get('interval_in_seconds', 10)),
    timeout=arg_to_number(demisto.args().get('timeout', 120))
)
def panorama_commit_command(args: dict):
    """
    Commit any configuration in PAN-OS
    This function implements the 'pan-os-commit' command.
    Supports polling as well.
    """
    commit_description = args.get('description', '')

    if job_id := args.get('commit_job_id'):
        commit_status = panorama_commit_status({'job_id': job_id}).get('response', {}).get('result', {})
        job_result = commit_status.get('job', {}).get('result')
        commit_output = {
            'JobID': job_id,
            'Description': commit_description,
            'Status': 'Success' if job_result == 'OK' else 'Failure'
        }
        return PollResult(
            response=CommandResults(  # this is what the response will be in case job has finished
                outputs_prefix='Panorama.Commit',
                outputs_key_field='JobID',
                outputs=commit_output,
                readable_output=tableToMarkdown('Commit Status:', commit_output, removeNull=True)
            ),
            continue_to_poll=commit_status.get('job', {}).get('status') != 'FIN',  # continue polling if job isn't done
        )
    else:  # either no polling is required or this is the first run
        result = panorama_commit(args)
        job_id = result.get('response', {}).get('result', {}).get('job', '')
        if job_id:
            context_output = {
                'JobID': job_id,
                'Description': commit_description,
                'Status': 'Pending'
            }
            continue_to_poll = True
            commit_output = CommandResults(  # type: ignore[assignment]
                outputs_prefix='Panorama.Commit',
                outputs_key_field='JobID',
                outputs=context_output,
                readable_output=tableToMarkdown('Commit Status:', context_output, removeNull=True)
            )
        else:  # nothing to commit in pan-os, hence even if polling=true, no reason to poll anymore.
            commit_output = result.get('response', {}).get('msg') or 'There are no changes to commit.'  # type: ignore[assignment]
            continue_to_poll = False

        return PollResult(
            response=commit_output,
            continue_to_poll=continue_to_poll,
            args_for_next_run={
                'commit_job_id': job_id,
                'description': commit_description,
                'polling': argToBoolean(args.get('polling')),
                'interval_in_seconds': arg_to_number(args.get('interval_in_seconds')),
                'timeout': arg_to_number(args.get('timeout'))
            },
            partial_result=CommandResults(
                readable_output=f'Waiting for commit "{commit_description}" with job ID {job_id} to finish...'
                if commit_description else f'Waiting for commit job ID {job_id} to finish...'
            )
        )


@logger
def panorama_commit_status(args: dict):
    params = {
        'type': 'op',
        'cmd': f'<show><jobs><id>{args.get("job_id")}</id></jobs></show>',
        'key': API_KEY
    }

    if target := args.get('target'):
        params['target'] = target

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
def panorama_push_to_device_group(args: dict):
    command: str = ''
    command += f'<device-group><entry name="{DEVICE_GROUP}"/></device-group>'

    serial_number = args.get('serial_number')
    if serial_number:
        command = f'<device-group><entry name="{DEVICE_GROUP}"><devices><entry name="{serial_number}"/>' \
                  f'</devices></entry></device-group>'

    if argToBoolean(args.get('validate-only', 'false')):
        command += '<validate-only>yes</validate-only>'
    if not argToBoolean(args.get('include-template', 'true')):
        command += '<include-template>no</include-template>'
    if description := args.get('description'):
        command += f'<description>{description}</description>'

    params = {
        'type': 'commit',
        'action': 'all',
        'cmd': f'<commit-all><shared-policy>{command}</shared-policy></commit-all>',
        'key': API_KEY
    }

    result = http_request(
        URL,
        'POST',
        body=params
    )

    return result


@logger
def panorama_push_to_template(args: dict):
    """
    Push a single template.
    """
    command: str = ''
    command += f'<name>{TEMPLATE}</name>'

    if serial_number := args.get('serial_number'):
        command = f'<name>{TEMPLATE}</name><device><member>{serial_number}</member></device>'

    if argToBoolean(args.get('validate-only', 'false')):
        command += '<validate-only>yes</validate-only>'
    if description := args.get('description'):
        command += f'<description>{description}</description>'

    params = {
        'type': 'commit',
        'action': 'all',
        'cmd': f'<commit-all><template>{command}</template></commit-all>',
        'key': API_KEY
    }

    result = http_request(
        URL,
        'POST',
        body=params
    )

    return result


@logger
def panorama_push_to_template_stack(args: dict):
    """
    Push a single template-stack
    """
    template_stack = args.get("template-stack")
    command: str = ''
    command += f'<name>{template_stack}</name>'

    if serial_number := args.get('serial_number'):
        command = f'<name>{template_stack}</name><device><member>{serial_number}</member></device>'

    if argToBoolean(args.get('validate-only', 'false')):
        command += '<validate-only>yes</validate-only>'
    if description := args.get('description'):
        command += f'<description>{description}</description>'

    params = {
        'type': 'commit',
        'action': 'all',
        'cmd': f'<commit-all><template-stack>{command}</template-stack></commit-all>',
        'key': API_KEY
    }

    result = http_request(
        URL,
        'POST',
        body=params
    )

    return result


@polling_function(
    name='pan-os-push-to-device-group',
    interval=arg_to_number(demisto.args().get('interval_in_seconds', 10)),
    timeout=arg_to_number(demisto.args().get('timeout', 120))
)
def panorama_push_to_device_group_command(args: dict):
    """
    Push Panorama configuration and show message in war-room
    """
    if not DEVICE_GROUP:
        raise Exception("The 'panorama-push-to-device-group' command is relevant for a Palo Alto Panorama instance.")

    description = args.get('description')

    if push_job_id := args.get('push_job_id'):
        result = panorama_push_status(job_id=push_job_id)

        push_status = result.get('response', {}).get('result', {})

        push_output = parse_push_status_response(result)
        push_output['DeviceGroup'] = DEVICE_GROUP
        if description:
            push_output['Description'] = description

        return PollResult(
            response=CommandResults(
                outputs_prefix='Panorama.Push',
                outputs_key_field='JobID',
                outputs=push_output,
                readable_output=tableToMarkdown('Push to Device Group:', push_output, removeNull=True)
            ),
            continue_to_poll=push_status.get('job', {}).get('status') != 'FIN'  # continue polling if job isn't done
        )
    else:
        result = panorama_push_to_device_group(args)
        job_id = result.get('response', {}).get('result', {}).get('job', '')
        if job_id:
            context_output = {
                'DeviceGroup': DEVICE_GROUP,
                'JobID': job_id,
                'Status': 'Pending'
            }
            if description:
                context_output['Description'] = description
            continue_to_poll = True
            push_output = CommandResults(  # type: ignore[assignment]
                outputs_prefix='Panorama.Push',
                outputs_key_field='JobID',
                outputs=context_output,
                readable_output=tableToMarkdown('Push to Device Group:', context_output, removeNull=True)
            )
        else:
            push_output = CommandResults(
                readable_output=result.get('response', {}).get('msg') or 'There are no changes to push.'
            )
            continue_to_poll = False

        args_for_next_run = {
            'push_job_id': job_id,
            'polling': argToBoolean(args.get('polling', False)),
            'interval_in_seconds': arg_to_number(args.get('interval_in_seconds', 10)),
            'description': description,
            'device-group': DEVICE_GROUP
        }

        return PollResult(
            response=push_output,
            continue_to_poll=continue_to_poll,
            args_for_next_run=args_for_next_run,
            partial_result=CommandResults(
                readable_output=f'Waiting for Job-ID {job_id} to finish push changes to device-group {DEVICE_GROUP}...'
            )
        )


def panorama_push_to_template_command(args: dict):
    """
    Push Panorama Template to it's associated firewalls
    """

    if not TEMPLATE:
        raise Exception("The 'panorama-push-to-template' command is relevant for a Palo Alto Panorama instance.")

    result = panorama_push_to_template(args)
    if 'result' in result['response']:
        # commit has been given a jobid
        push_output = {
            'Template': TEMPLATE,
            'JobID': result['response']['result']['job'],
            'Status': 'Pending'
        }
        return_results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': result,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Push to Template:', push_output, ['JobID', 'Status'],
                                             removeNull=True),
            'EntryContext': {
                "Panorama.Push(val.JobID == obj.JobID)": push_output
            }
        })
    else:
        # no changes to commit
        return_results(result['response']['msg']['line'])


def panorama_push_to_template_stack_command(args: dict):
    """
    Push Panorama Template to it's associated firewalls
    """
    template_stack = args.get("template-stack")
    result = panorama_push_to_template_stack(args)
    if 'result' in result['response']:
        # commit has been given a jobid
        push_output = {
            'TemplateStack': template_stack,
            'JobID': result['response']['result']['job'],
            'Status': 'Pending'
        }
        return_results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': result,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Push to Template:', push_output, ['JobID', 'Status'],
                                             removeNull=True),
            'EntryContext': {
                "Panorama.Push(val.JobID == obj.JobID)": push_output
            }
        })
    else:
        # no changes to commit
        return_results(result['response']['msg']['line'])


@logger
def panorama_push_status(job_id: str, target: Optional[str] = None):
    params = {
        'type': 'op',
        'cmd': f'<show><jobs><id>{job_id}</id></jobs></show>',
        'key': API_KEY
    }
    if target:
        params['target'] = target

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


def parse_push_status_response(result: dict):
    job = result.get('response', {}).get('result', {}).get('job', {})
    if job.get('type', '') not in ('CommitAll', 'ValidateAll'):
        raise Exception('JobID given is not of a Push neither of a validate.')

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
    status_errors = []  # type: ignore
    devices = safeget(result, ["response", "result", "job", "devices", "entry"])
    if devices:
        for device in devices:
            device_warnings = safeget(device, ["details", "msg", "warnings", "line"])
            status_warnings.extend([] if not device_warnings else device_warnings)
            device_errors = safeget(device, ["details", "msg", "errors", "line"])
            if isinstance(device_errors, str) and device_errors:
                status_errors.append(device_errors)
            else:
                status_errors.extend([] if not device_errors else device_errors)
    push_status_output["Warnings"] = status_warnings
    push_status_output["Errors"] = status_errors

    return push_status_output


def panorama_push_status_command(args: dict):
    """
    Check jobID of push status
    """
    job_id = args.get('job_id')
    target = args.get('target')
    result = panorama_push_status(job_id, target)

    push_status_output = parse_push_status_response(result)

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Push to Device Group status:', push_status_output,
                                         ['JobID', 'Status', 'Details', 'Errors', 'Warnings'], removeNull=True),
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
        if 'ip-wildcard' in address:
            pretty_address['IP_Wildcard'] = address['ip-wildcard']
        if 'fqdn' in address:
            pretty_address['FQDN'] = address['fqdn']
        if 'tag' in address and address['tag'] is not None and 'member' in address['tag']:
            # handling edge cases in which the Tag value is None, e.g:
            # {'@name': 'test', 'ip-netmask': '1.1.1.1', 'tag': None}
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
                                         ['Name', 'IP_Netmask', 'IP_Range', 'IP_Wildcard', 'FQDN', 'Tags'],
                                         removeNull=True),
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

    if 'tag' in address and address['tag'] is not None and 'member' in address['tag']:
        # handling edge cases in which the Tag value is None, e.g:
        # {'@name': 'test', 'ip-netmask': '1.1.1.1', 'tag': None}
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

    try:
        result = http_request(
            URL,
            'GET',
            params=params,
        )
    except Exception as err:
        if OBJ_NOT_FOUND_ERR in str(err):
            return {}
        raise

    return result['response']['result']['entry']


def panorama_get_address_command(args: dict):
    """
    Get an address
    """
    address_name = args.get('name')

    if not (address := panorama_get_address(address_name)):
        return_results(f'Address name {address_name} was not found')
        return
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
def panorama_create_address(address_name: str, fqdn: str | None = None, ip_netmask: str | None = None,
                            ip_range: str | None = None,
                            description: str | None = None, tags: list | None = None, ip_wildcard: str | None = None):
    params = {'action': 'set',
              'type': 'config',
              'xpath': XPATH_OBJECTS + "address/entry[@name='" + address_name + "']",
              'key': API_KEY,
              'element': (add_argument(fqdn, 'fqdn', False)
                          + add_argument(ip_netmask, 'ip-netmask', False)
                          + add_argument(ip_range, 'ip-range', False)
                          + add_argument(ip_wildcard, 'ip-wildcard', False)
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

    if tags := set(argToList(args.get('tag', []))):
        result = http_request(URL, 'GET', params={'type': 'config', 'action': 'get',
                                                  'key': API_KEY, 'xpath': f'{XPATH_OBJECTS}tag'})
        entries = result.get('response', {}).get('result', {}).get('tag', {}).get('entry', [])
        if isinstance(entries, dict):  # In case there is only one tag.
            entries = [entries]
        existing_tags = set([entry.get('@name') for entry in entries])
        if non_existent_tags := tags - existing_tags:
            if argToBoolean(args.get('create_tag', False)):
                for tag in non_existent_tags:
                    http_request(URL, 'POST', body={'type': 'config', 'action': 'set', 'key': API_KEY,
                                                    'xpath': f"{XPATH_OBJECTS}tag/entry[@name='{tag}']",
                                                    'element': '<comments>created via API</comments>'})
            else:
                raise DemistoException(
                    f'Failed to create the address object since the tags `{non_existent_tags}` does not exist. '
                    f'You can use the `create_tag` argument to create the tag.'
                )

    fqdn = args.get('fqdn')
    ip_netmask = args.get('ip_netmask')
    ip_range = args.get('ip_range')
    ip_wildcard = args.get('ip_wildcard')

    # make sure only one of fqdn/ip_netmask/ip_range/ip_wildcard was provided.

    if sum(
        map(bool, [(fqdn is not None), (ip_netmask is not None), (ip_range is not None), (ip_wildcard is not None)])
    ) != 1:
        raise DemistoException(
            f'Please specify exactly one of the following arguments: fqdn, ip_netmask, ip_range, ip_wildcard.'
        )

    address = panorama_create_address(address_name, fqdn, ip_netmask, ip_range, description, tags, ip_wildcard)

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
        address_output['Tags'] = list(tags)

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


def pan_os_edit_address(name, element_value, element_to_change, is_listable):
    params = {
        'xpath': f'{XPATH_OBJECTS}address/entry[@name="{name}"]/{element_to_change}',
        'element': dict_to_xml(build_body_request_to_edit_pan_os_object(
            behavior='replace',
            object_name=element_to_change,
            element_value=element_value,
            is_listable=is_listable,
        ),
        ),
        'action': 'edit',
        'type': 'config',
        'key': API_KEY
    }

    return http_request(URL, 'POST', params=params)


def pan_os_edit_address_command(args):
    address_name = args.get('name')
    element_value, element_to_change = args.get('element_value'), args.get('element_to_change')

    raw_response = pan_os_edit_address(
        name=address_name,
        element_to_change=element_to_change.replace('_', '-'),
        element_value=element_value,
        is_listable=element_to_change == 'tag',
    )

    return CommandResults(
        raw_response=raw_response,
        readable_output=f'Address {address_name} was edited successfully.'
    )


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
        if 'tag' in address_group and address_group['tag'] is not None and 'member' in address_group['tag']:
            # handling edge cases in which the Tag value is None, e.g:
            # {'@name': 'test', 'static': {'member': 'test_address'}, 'tag': None}
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
def panorama_list_address_groups(tag: str | None = None):
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
    if 'tag' in address_group and address_group['tag'] is not None and 'member' in address_group['tag']:
        # handling edge cases in which the Tag value is None, e.g:
        # {'@name': 'test', 'static': {'member': 'test_address'}, 'tag': None}
        pretty_address_group['Tags'] = address_group['tag']['member']

    if pretty_address_group['Type'] == 'static':
        pretty_address_group['Addresses'] = address_group['static']['member']
    else:
        pretty_address_group['Match'] = address_group['dynamic']['filter']

    return pretty_address_group


@logger
def panorama_get_address_group(address_group_name: str):
    params = {
        'action': 'get',
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
                                         description: str | None = None, tags: list | None = None):
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
                                          description: str | None = None, tags: list | None = None):
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
    address_group_name = args.get('name', '')
    type_ = args.get('type', '').lower()
    match = args.get('match')
    element_to_add = argToList(args['element_to_add']) if 'element_to_add' in args else None
    element_to_remove = argToList(
        args['element_to_remove']) if 'element_to_remove' in args else None

    match_path: str
    match_param: str
    addresses_param: str
    addresses_path: str
    result: Any
    addresses = []
    if type_ == 'dynamic':
        if not match:
            raise Exception('To edit a Dynamic Address group, Please provide a match.')
        match_param = add_argument_open(match, 'filter', False)
        match_path = f"{XPATH_OBJECTS}address-group/entry[@name=\'{address_group_name}\']/dynamic/filter"
    else:
        match_param = ""
        match_path = ""
        demisto.debug(f"{type_=} -> {match_param=} {match_path=}")

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
            addresses = [item for item in address_group_list if item not in element_to_remove]  # type: ignore[operator]
            if not addresses:
                raise DemistoException(
                    f'cannot remove {address_group_list} addresses from address group {address_group_name}, '
                    f'address-group {address_group_name} must have at least one address in its configuration'
                )
        addresses_param = add_argument_list(addresses, 'member', False)
        addresses_path = f"{XPATH_OBJECTS}address-group/entry[@name=\'{address_group_name}\']/static"
    else:
        addresses_param = ""
        addresses_path = ""
        demisto.debug(f"{type_=} -> {addresses_param=} {addresses_path=}")

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

    result = None
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
        description_path = f"{XPATH_OBJECTS}address-group/entry[@name=\'{address_group_name}\']/description"
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
        tag_path = f"{XPATH_OBJECTS}address-group/entry[@name=\'{address_group_name}\']/tag"
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
        'HumanReadable': f'Address Group {address_group_name} was edited successfully.',
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
        if 'tag' in service and service['tag'] is not None and 'member' in service['tag']:
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
def panorama_list_services(tag: str | None = None):
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
    if 'tag' in service and service['tag'] is not None and 'member' in service['tag']:
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
                            source_port: str | None = None, description: str | None = None, tags: list | None = None):
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
        if 'tag' in service_group and service_group['tag'] is not None and 'member' in service_group['tag']:
            # handling edge cases in which the Tag value is None, e.g:
            # {'@name': 'sg_group', 'members': {'member': 'test_sg'}, 'tag': None}
            pretty_service_group['Tags'] = service_group['tag']['member']

        pretty_service_groups_arr.append(pretty_service_group)

    return pretty_service_groups_arr


@logger
def panorama_list_service_groups(tag: str | None = None):
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
    if 'tag' in service_group and service_group['tag'] is not None and 'member' in service_group['tag']:
        # handling edge cases in which the Tag value is None, e.g:
        # {'@name': 'sg_group', 'members': {'member': 'test_sg'}, 'tag': None}
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

    result = panorama_create_service_group(service_group_name, services, tags)  # type: ignore[arg-type]

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
    result: Any
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
            services = [item for item in service_group_list if item not in services_to_remove]  # type: ignore[operator]

        if len(services) == 0:
            raise Exception('A Service group must have at least one service.')

    result = panorama_edit_service_group(service_group_name, services, tag)  # type: ignore[arg-type]

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
def panorama_create_custom_url_category(custom_url_category_name: str, type_: Any | None = None,
                                        sites: Optional[list] = None, categories: Optional[list] = None,
                                        description: str | None = None):
    #  In PAN-OS 9.X changes to the default behavior were introduced regarding custom url categories.
    major_version = get_pan_os_major_version()
    element = add_argument(description, 'description', False)
    if major_version <= 8:
        if type_ or categories:
            raise DemistoException('The type and categories arguments are only relevant for PAN-OS 9.x versions.')
        element += add_argument_list(sites, 'list', True)
    else:  # major is 9.x
        if not type_:
            raise DemistoException('The type argument is mandatory for PAN-OS 9.x versions.')
        if (not sites and not categories) or (sites and categories):
            raise DemistoException('Exactly one of the sites and categories arguments should be defined.')
        if (type_ == 'URL List' and categories) or (type_ == 'Category Match' and sites):
            raise DemistoException('URL List type is only for sites, Category Match is only for categories.')

        if type_ == 'URL List':
            element += add_argument_list(sites, 'list', True)
        else:
            element += add_argument_list(categories, 'list', True)
        element += add_argument(type_, 'type', False)

    params = {
        'action': 'set',
        'type': 'config',
        'xpath': f'{XPATH_OBJECTS}profiles/custom-url-category/entry[@name=\'{custom_url_category_name}\']',
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

    # escape URLs with HTML escaping
    sites = [html.escape(site) for site in merged_items]

    result, custom_url_category_output = panorama_edit_custom_url_category(custom_url_category_name, type_,
                                                                           sites, description)
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

    custom_url_category_items = None
    if 'list' in custom_url_category:
        if 'member' in custom_url_category['list']:
            custom_url_category_items = argToList(custom_url_category['list']['member'])
    if not custom_url_category_items:
        raise Exception('Custom url category does not contain sites or categories.')

    subtracted_items = [item for item in custom_url_category_items if item not in items]

    # escape URLs with HTML escaping
    sites = [html.escape(site) for site in subtracted_items]

    result, custom_url_category_output = panorama_edit_custom_url_category(custom_url_category_name, type_,
                                                                           sites, description)
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
def panorama_get_url_category(url_cmd: str, url: str, target: Optional[str] = None) -> List[str]:
    params = {
        'action': 'show',
        'type': 'op',
        'key': API_KEY,
        'cmd': f'<test><{url_cmd}>{url}</{url_cmd}></test>'
    }

    if target:
        params['target'] = target

    raw_result = http_request(
        URL,
        'POST',
        body=params,
    )
    result = raw_result['response']['result']
    if 'Failed to query the cloud' in result:
        raise Exception('Failed to query the cloud. Please check your URL Filtering license.')
    # result structur example: 'https://someURL.com not-resolved (Base db) expires in 4 seconds
    # https://someURL.com shareware-and-freeware online-storage-and-backup low-risk (Cloud db)'
    return [url_category for url_category in PAN_DB_URL_FILTERING_CATEGORIES if url_category in result]


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

    predefined_malicious = ['phishing', 'command-and-control', 'malware', 'ransomware']
    malicious_categories = list((set(additional_malicious)).union(set(predefined_malicious)))

    dbot_score = 1
    if category in malicious_categories:
        dbot_score = 3
    elif category in suspicious_categories:
        dbot_score = 2
    elif category == 'unknown':
        dbot_score = 0

    return dbot_score


def panorama_get_url_category_command(
    url_cmd: str,
    url: str,
    additional_suspicious: list,
    additional_malicious: list,
    reliability: str,
    target: Optional[str] = None
):
    """
    Get the url category from Palo Alto URL Filtering
    """
    urls = argToList(url)

    categories_dict: Dict[str, list] = {}
    categories_dict_hr: Dict[str, list] = {}
    command_results: List[CommandResults] = []
    for url in urls:
        err_readable_output = None
        try:
            categories = panorama_get_url_category(url_cmd, url, target)
            max_url_dbot_score = 0
            url_dbot_score_category = ''
            for category in categories:
                if category in categories_dict:
                    categories_dict[category].append(url)
                    categories_dict_hr[category].append(url)
                else:
                    categories_dict[category] = [url]
                    categories_dict_hr[category] = [url]
                context_urls = populate_url_filter_category_from_context(category)
                categories_dict[category] = list((set(categories_dict[category])).union(set(context_urls)))

                current_dbot_score = calculate_dbot_score(
                    category.lower(), additional_suspicious, additional_malicious
                )
                if current_dbot_score > max_url_dbot_score:
                    max_url_dbot_score = current_dbot_score
                    url_dbot_score_category = category

            dbot_score = Common.DBotScore(
                indicator=url,
                indicator_type=DBotScoreType.URL,
                integration_name='PAN-OS',
                score=max_url_dbot_score,
                reliability=reliability
            )
            url_obj = Common.URL(
                url=url,
                dbot_score=dbot_score,
                category=url_dbot_score_category
            )
            readable_output = err_readable_output or tableToMarkdown(
                'URL', url_obj.to_context(),
                headerTransform=lambda x: x.partition('(')[0]
            )
            command_results.append(CommandResults(
                indicator=url_obj,
                readable_output=readable_output
            ))
        except InvalidUrlLengthException as e:
            score = 0
            category = None
            err_readable_output = str(e)
            dbot_score = Common.DBotScore(
                indicator=url,
                indicator_type=DBotScoreType.URL,
                integration_name='PAN-OS',
                score=score,
                reliability=reliability
            )
            url_obj = Common.URL(
                url=url,
                dbot_score=dbot_score,
                category=category
            )
            readable_output = err_readable_output
            command_results.append(CommandResults(
                indicator=url_obj,
                readable_output=readable_output
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

    alert_category_list = argToList(alert_category_list)
    for category in alert_category_list:
        pretty_url_filter['Category'].append({
            'Name': category,
            'Action': 'alert'
        })
    block_category_list = argToList(block_category_list)
    for category in block_category_list:
        pretty_url_filter['Category'].append({
            'Name': category,
            'Action': 'block'
        })
    allow_category_list = argToList(allow_category_list)
    for category in allow_category_list:
        pretty_url_filter['Category'].append({
            'Name': category,
            'Action': 'block'
        })
    continue_category_list = argToList(continue_category_list)
    for category in continue_category_list:
        pretty_url_filter['Category'].append({
            'Name': category,
            'Action': 'block'
        })
    override_category_list = argToList(override_category_list)
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
        'xpath': f'{XPATH_OBJECTS}profiles/url-filtering/entry[@name=\"{name}\"]',
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
def create_url_filter_params(
        url_filter_name: str, action: str,
        url_category_list: str,
        override_allow_list: Optional[str] = None,
        override_block_list: Optional[str] = None,
        description: Optional[str] = None):
    element = add_argument_list(url_category_list, action, True) + \
        add_argument_list(override_allow_list, 'allow-list', True) + \
        add_argument_list(override_block_list, 'block-list', True) + \
        add_argument(description, 'description', False)
    major_version = get_pan_os_major_version()
    if major_version <= 8:  # up to version 8.X included, the action xml tag needs to be added
        element += "<action>block</action>"
    url_filter_params = {
        'action': 'set',
        'type': 'config',
        'xpath': f'{XPATH_OBJECTS}profiles/url-filtering/entry[@name=\'{url_filter_name}\']',
        'element': element,
        'key': API_KEY
    }
    return url_filter_params


@logger
def panorama_create_url_filter(
        url_filter_name: str, action: str,
        url_category_list: str,
        override_allow_list: Optional[str] = None,
        override_block_list: Optional[str] = None,
        description: Optional[str] = None):
    params = create_url_filter_params(url_filter_name, action, url_category_list, override_allow_list,
                                      override_block_list, description)

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
    url_filter_name = str(args.get('name', ''))
    action = str(args.get('action', ''))
    url_category_list = argToList(args.get('url_category'))
    override_allow_list = argToList(args.get('override_allow_list'))
    override_block_list = argToList(args.get('override_block_list'))
    description = args.get('description', '')

    result = panorama_create_url_filter(url_filter_name, action, url_category_list, override_allow_list,
                                        override_block_list, description)

    url_filter_output: Dict[str, Any] = {'Name': url_filter_name}
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
def verify_edit_url_filter_args(major_version: int, element_to_change: str) -> None:
    if major_version >= 9:  # only url categories are allowed, e.g gambling, abortion
        if element_to_change not in ('allow_categories', 'block_categories', 'description'):
            raise DemistoException('Only the allow_categories, block_categories, description properties can be changed'
                                   ' in PAN-OS 9.x or later versions.')
    else:  # major_version 8.x or lower. only url lists are allowed, e.g www.test.com
        if element_to_change not in ('override_allow_list', 'override_block_list', 'description'):
            raise DemistoException('Only the override_allow_list, override_block_list, description properties can be'
                                   ' changed in PAN-OS 8.x or earlier versions.')


@logger
def set_edit_url_filter_xpaths(major_version: int) -> Tuple[str, str]:
    if major_version >= 9:
        return 'allow', 'block'
    return 'allow-list', 'block-list'


@logger
def panorama_edit_url_filter(url_filter_name: str, element_to_change: str, element_value: str,
                             add_remove_element: Optional[str] = None):
    url_filter_prev = panorama_get_url_filter(url_filter_name)
    if '@dirtyId' in url_filter_prev:
        LOG(f'Found uncommitted item:\n{url_filter_prev}')
        raise DemistoException('Please commit the instance prior to editing the URL Filter.')

    url_filter_output: Dict[str, Any] = {'Name': url_filter_name}
    if DEVICE_GROUP:
        url_filter_output['DeviceGroup'] = DEVICE_GROUP
    params = {
        'action': 'edit',
        'type': 'config',
        'key': API_KEY,
    }

    major_version = get_pan_os_major_version()
    # it seems that in major 9.x pan-os changed the terminology from allow-list/block-list to allow/block
    # with regards to url filter xpaths
    verify_edit_url_filter_args(major_version, element_to_change)
    allow_name, block_name = set_edit_url_filter_xpaths(major_version)

    if element_to_change == 'description':
        params['xpath'] = f"{XPATH_OBJECTS}profiles/url-filtering/entry[@name=\'{url_filter_name}\']/{element_to_change}"
        params['element'] = add_argument_open(element_value, 'description', False)
        result = http_request(URL, 'POST', body=params)
        url_filter_output['Description'] = element_value

    elif element_to_change in ('override_allow_list', 'allow_categories'):
        previous_allow = argToList(url_filter_prev.get(allow_name, {}).get('member', []))
        if add_remove_element == 'add':
            new_allow = list((set(previous_allow)).union(set([element_value])))
        else:
            if element_value not in previous_allow:
                raise DemistoException(f'The element {element_value} is not present in {url_filter_name}')
            new_allow = [url for url in previous_allow if url != element_value]

        params['xpath'] = f"{XPATH_OBJECTS}profiles/url-filtering/entry[@name=\'{url_filter_name}\']/{allow_name}"
        params['element'] = add_argument_list(new_allow, allow_name, True)
        result = http_request(URL, 'POST', body=params)
        url_filter_output[element_to_change] = new_allow

    # element_to_change in ('override_block_list', 'block_categories')
    else:
        previous_block = argToList(url_filter_prev.get(block_name, {}).get('member', []))
        if add_remove_element == 'add':
            new_block = list((set(previous_block)).union(set([element_value])))
        else:
            if element_value not in previous_block:
                raise DemistoException(f'The element {element_value} is not present in {url_filter_name}')
            new_block = [url for url in previous_block if url != element_value]

        params['xpath'] = f"{XPATH_OBJECTS}profiles/url-filtering/entry[@name=\'{url_filter_name}\']/{block_name}"
        params['element'] = add_argument_list(new_block, block_name, True)
        result = http_request(URL, 'POST', body=params)
        url_filter_output[element_to_change] = new_block

    return result, url_filter_output


def panorama_edit_url_filter_command(args: dict):
    """
    Edit a URL Filter
    """
    url_filter_name = str(args.get('name'))
    element_to_change = str(args.get('element_to_change'))
    add_remove_element = str(args.get('add_remove_element'))
    element_value = str(args.get('element_value'))

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
    parse_pan_os_un_committed_data(rule, ['@admin', '@dirtyId', '@time'])

    rule_get = partial(dict_safe_get, rule, default_return_value='', return_type=(str, list), raise_return_type=False)

    # get rule devices:
    entries = rule_get(['target', 'devices', 'entry'])
    if not isinstance(entries, list):
        entries = [entries]
    rule_devices = [
        entry.get('@name') for entry in entries if isinstance(entry, dict)
    ]

    # get rule profiles:
    profile_keys = (
        'url-filtering',
        'data-filtering',
        'file-blocking',
        'virus',
        'spyware',
        'vulnerability',
        'wildfire-analysis',
    )
    profiles = rule_get(  # pylint: disable=E1124
        ['profile-setting', 'profiles'], return_type=dict, default_return_value={})
    rule_profiles = {
        key: dict_safe_get(profiles, [key, 'member'], '')
        for key in profile_keys
    }

    pretty_rule: Dict[str, Any] = {

        'DeviceGroup': DEVICE_GROUP,
        'Location': rule.get('@loc', ''),
        'UUID': rule.get('@uuid', ''),
        'NegateDestination': rule.get('negate-destination', ''),
        'Disabled': rule.get('disabled', ''),
        'ICMPUnreachable': rule.get('icmp-unreachable', ''),
        'Description': rule.get('description', ''),
        'GroupTag': rule.get('group-tag', ''),
        'LogForwardingProfile': rule.get('log-setting', ''),
        'NegateSource': rule.get('negate-source', ''),
        'SecurityProfileGroup': rule_get(['profile-setting', 'group', 'member']),
        'SecurityProfile': rule_profiles,
        'Target': {
            'devices': rule_devices,
            'negate': rule_get(['target', 'negate']),
        },
        'Name': rule.get('@name', ''),
        'Type': rule.get('rule-type', ''),
        'From': rule_get(['from', 'member']),
        'DestinationDevice': rule_get(['destination-hip', 'member']),
        'Action': rule.get('action', ''),
        'SourceDevice': rule_get(['source-hip', 'member']),
        'Tags': rule_get(['tag', 'member']),
        'SourceUser': rule_get(['source-user', 'member']),
        'Application': rule_get(['application', 'member']),
        'Service': rule_get(['service', 'member']),
        'To': rule_get(['to', 'member']),
        'Source': rule_get(['source', 'member']),
        'CustomUrlCategory': rule_get(['category', 'member']),
        'Destination': rule_get(['destination', 'member']),
        'Options': {
            'LogAtSessionStart': rule.get('log-start', ''),
            'LogForwarding': rule.get('log-setting', ''),
            'Schedule': rule.get('schedule', ''),
            'QoSMarking': next(iter(rule_get(['qos', 'marking'], return_type=dict, default_return_value={})), None),  # pylint: disable=E1124
            'DisableServerResponseInspection': rule_get(['option', 'disable-server-response-inspection']),
        }
    }

    return pretty_rule


def prettify_rules(rules: Union[List[dict], dict], target: Optional[str] = None):
    if not isinstance(rules, list):
        rules = [rules]
    pretty_rules_arr = []
    for rule in rules:
        if target and not target_filter(rule, target):
            continue
        pretty_rules_arr.append(prettify_rule(rule))

    return pretty_rules_arr


def target_filter(rule: dict, target: str) -> bool:
    """
    Args:
        rule (dict): A rule from the panorama instance.
        target (str): A serial number to filter the rule on

    Returns:
        True if the rule contains the firewall serial number (target), False if not.
    """
    firewalls_the_rule_applies_to = rule.get('target', {}).get('devices', {}).get('entry')
    if not isinstance(firewalls_the_rule_applies_to, list):
        firewalls_the_rule_applies_to = [firewalls_the_rule_applies_to]
    for entry in firewalls_the_rule_applies_to:
        if entry and entry.get('@name', None) == target:
            return True

    return False


@logger
def panorama_list_rules(xpath: str, name: str | None = None, filters: dict | None = None, query: str | None = None):
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': xpath,
        'key': API_KEY
    }

    if query:
        params["xpath"] = f'{params["xpath"]}[{query.replace(" eq ", " = ")}]'
    elif xpath_filter := build_xpath_filter(name_match=name, filters=filters):
        params["xpath"] = f'{params["xpath"]}[{xpath_filter}]'

    result = http_request(
        URL,
        'GET',
        params=params,
    )

    return result['response']['result']['entry']


def panorama_list_rules_command(args: dict):
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

    filters = assign_params(
        tags=argToList(args.get('tags')),
        action=args.get('action')
    )
    name = args.get('rulename')
    query = args.get('query')
    target = args.get('target')

    rules = panorama_list_rules(xpath, name, filters, query)
    if disabled := args.get('disabled'):
        rules = filter_rules_by_status(disabled, rules)

    pretty_rules = prettify_rules(rules, target)

    to_human_readable = {
        'SecurityProfileGroup': 'Profile Group',
        'SecurityProfile': 'Profiles',
        'From': 'Source Zone',
        'DestinationDevice': 'Destination Device',
        'SourceDevice': 'Source Device',
        'SourceUser': 'Source User',
        'To': 'Destination Zone',
        'Source': 'Source Address',
        'CustomUrlCategory': 'Url Category',
        'Destination': 'Destination Address',
    }

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': rules,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Security Rules:', pretty_rules,
                                         ['Name', 'Location', 'Tags', 'Type',
                                          'From', 'Source', 'SourceUser',
                                          'SourceDevice', 'To', 'Destination',
                                          'DestinationDevice', 'Application',
                                          'Service', 'CustomUrlCategory', 'Action',
                                          'SecurityProfile', 'SecurityProfileGroup',
                                          'Options', 'Target'],
                                         headerTransform=lambda x: to_human_readable.get(x, x),
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
    result = panorama_move_rule(args)
    rulename = args['rulename']
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


def panorama_move_rule(args):
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
    return result


''' Security Rule Configuration '''


@logger
def panorama_create_rule_command(args: dict):
    """
    Create a security rule
    """
    rulename = args['rulename'] = args['rulename'] if 'rulename' in args else ('demisto-' + (str(uuid.uuid4()))[:8])
    source = argToList(args.get('source'))
    destination = argToList(args.get('destination'))
    source_zone = argToList(args.get('source_zone'))
    destination_zone = argToList(args.get('destination_zone'))
    negate_source = args.get('negate_source')
    negate_destination = args.get('negate_destination')
    action = args.get('action')
    service = argToList(args.get('service'))
    disable = args.get('disable')
    categories = argToList(args.get('category'))
    application = argToList(args.get('application'))
    source_user = argToList(args.get('source_user'))
    disable_server_response_inspection = args.get('disable_server_response_inspection')
    description = args.get('description')
    target = args.get('target')
    log_forwarding = args.get('log_forwarding', None)
    tags = argToList(args['tags']) if 'tags' in args else None
    profile_setting = args.get('profile_setting')
    where = args.get('where', 'bottom')
    dst = args.get('dst')

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
                                          from_=source_zone, to=destination_zone, profile_setting=profile_setting,
                                          where=where, dst=dst)

    if args.get('audit_comment'):
        params['audit-comment'] = args.get('audit_comment')

    result = http_request(
        URL,
        'POST',
        body=params
    )

    rule_output = {SECURITY_RULE_ARGS[key]: value for key, value in args.items() if key in SECURITY_RULE_ARGS}
    rule_output['Name'] = rulename
    if DEVICE_GROUP:
        rule_output['DeviceGroup'] = DEVICE_GROUP

    if where:
        try:
            panorama_move_rule(args)
        except Exception as e:
            demisto.error(f'Unable to move rule. {e}')

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
def panorama_get_current_element(element_to_change: str, xpath: str, is_commit_required: bool = True) -> list:
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
    current_object = result.get(element_to_change, {}) or {}
    if is_commit_required:
        if '@dirtyId' in result or '@dirtyId' in current_object:
            LOG(f'Found uncommitted item:\n{result}')
            raise DemistoException('Please commit the instance prior to editing the rule.')
    else:
        # remove un-relevant committed data
        parse_pan_os_un_committed_data(result, ['@admin', '@dirtyId', '@time'])

    current_objects_items = []

    if 'list' in current_object:
        current_objects_items = argToList(current_object['list']['member'])
    elif 'member' in current_object:
        current_objects_items = argToList(current_object.get('member'))
    elif 'entry' in current_object:
        entries = current_object['entry']
        if not isinstance(entries, list):
            entries = [entries]
        current_objects_items = [entry.get('@name') for entry in entries]

    return current_objects_items


@logger
def panorama_edit_rule_items(rulename: str, element_to_change: str, element_value: List[str], behaviour: str):
    listable_elements = ['source', 'destination', 'application', 'category', 'source-user', 'service', 'tag', 'profile-setting']
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

    # in this case, we want to remove the profile-setting group
    if element_to_change == 'profile-setting':
        params['action'] = 'set'
        params['element'] = '<profile-setting><group/></profile-setting>'
        values = [element_value]
        result = http_request(URL, 'POST', body=params)

    else:
        params["xpath"] = f'{params["xpath"]}/{element_to_change}'

        current_objects_items = panorama_get_current_element(element_to_change, params['xpath'],
                                                             is_commit_required=False)
        if behaviour == 'add':
            values = list((set(current_objects_items)).union(set(element_value)))  # type: ignore[arg-type]
        else:  # remove
            if not_existing_values := [item for item in element_value if item not in current_objects_items]:
                return_warning(f'The following {element_to_change}s do not exist: {", ".join(not_existing_values)}',
                               exit=len(not_existing_values) == len(element_value))
            values = [item for item in current_objects_items if item not in element_value]
            if not values:
                if element_to_change == 'tag':
                    params['element'] = '<tag></tag>'
                else:
                    raise Exception(f'The object: {element_to_change} must have at least one item.')

        params['element'] = add_argument_list(values, element_to_change, True) if 'element' not in params else params['element']
        result = http_request(URL, 'POST', body=params)

    rule_output = {
        'Name': rulename,
        ELEM_TO_CONTEXT[element_to_change]: values
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


def build_audit_comment_params(
    name: str, pre_post: str, audit_comment: str = '', policy_type='security', xml_type='set'
) -> dict:
    """
    Builds up the params needed to update the audit comment of a policy rule.
    """
    _xpath = f"{XPATH_RULEBASE}{pre_post}/{policy_type}/rules/entry[@name='{name}']"
    return {
        'type': 'op',
        'cmd': build_audit_comment_cmd(_xpath, audit_comment, xml_type),
        'key': API_KEY
    }


def build_audit_comment_cmd(xpath, audit_comment, xml_type='set') -> str:
    """
    Builds up the needed `cmd` param to get or update the audit comment of a policy rule.
    """
    if xml_type == 'set':
        return f"<set><audit-comment><xpath>{xpath}</xpath><comment>{audit_comment}</comment></audit-comment></set>"
    elif xml_type == 'show':
        return f"<show><config><list><audit-comments><xpath>{xpath}</xpath></audit-comments></list></config></show>"
    return ""


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

    behaviour = args.get('behaviour', 'replace')
    # in this case of profile-setting add is the same as replace
    behaviour = 'replace' if element_to_change == 'profile-setting' and behaviour == 'add' else behaviour
    if behaviour != 'replace':
        panorama_edit_rule_items(rulename, element_to_change, argToList(element_value), behaviour)
    else:
        pre_post = args.get('pre_post') or ''
        if DEVICE_GROUP and not pre_post:  # panorama instances must have the pre_post argument!
            raise Exception('please provide the pre_post argument when editing a rule in Panorama instance.')

        if args.get('element_to_change') == 'audit-comment':
            new_audit_comment = args.get('element_value') or ''
            # to update audit-comment of a security rule, it is required to build a 'cmd' parameter
            params = build_audit_comment_params(
                rulename, pre_post='rulebase' if VSYS else pre_post, audit_comment=new_audit_comment
            )
        else:
            params = {
                'type': 'config',
                'action': 'edit',
                'key': API_KEY,
            }

            if element_to_change in ['action', 'description', 'log-setting']:
                params['element'] = add_argument_open(element_value, element_to_change, False)
            elif element_to_change in [
                'source', 'destination', 'application', 'category', 'source-user', 'service', 'tag'
            ]:
                element_value = argToList(element_value)
                params['element'] = add_argument_list(element_value, element_to_change, True)
            elif element_to_change == 'target':
                params['element'] = add_argument_target(element_value, 'target')
            elif element_to_change == 'profile-setting':
                params['element'] = add_argument_profile_setting(element_value, 'profile-setting')
            else:
                params['element'] = add_argument_yes_no(element_value, element_to_change)

            if DEVICE_GROUP:
                params['xpath'] = XPATH_SECURITY_RULES + PRE_POST + f'/security/rules/entry[@name=\'{rulename}\']'
            else:
                params['xpath'] = XPATH_SECURITY_RULES + '[@name=\'' + rulename + '\']'
            params['xpath'] += '/' + element_to_change

        result = http_request(URL, 'POST', body=params)

        rule_output = {
            'Name': rulename,
            ELEM_TO_CONTEXT[element_to_change]: element_value
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
    where = args.get('where', 'bottom')
    dst = args.get('dst')
    result: Any
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
                                                  log_forwarding=log_forwarding, tags=tags, where=where, dst=dst)
            result = http_request(URL, 'POST', body=params)
        if block_destination:
            params = prepare_security_rule_params(api_action='set', action='drop', destination=object_value,
                                                  source=['any'], rulename=rulename + '-to', target=target,
                                                  log_forwarding=log_forwarding, tags=tags, where=where, dst=dst)
            result = http_request(URL, 'POST', body=params)
        custom_block_output['IP'] = object_value

    elif object_type in ['address-group', 'edl']:
        if block_source:
            params = prepare_security_rule_params(api_action='set', action='drop', source=object_value,
                                                  destination=['any'], rulename=rulename + '-from', target=target,
                                                  log_forwarding=log_forwarding, tags=tags, where=where, dst=dst)
            result = http_request(URL, 'POST', body=params)
        if block_destination:
            params = prepare_security_rule_params(api_action='set', action='drop', destination=object_value,
                                                  source=['any'], rulename=rulename + '-to', target=target,
                                                  log_forwarding=log_forwarding, tags=tags, where=where, dst=dst)
            result = http_request(URL, 'POST', body=params)
        custom_block_output['AddressGroup'] = object_value

    elif object_type == 'url-category':
        params = prepare_security_rule_params(api_action='set', action='drop', source=['any'], destination=['any'],
                                              category=object_value, rulename=rulename, target=target,
                                              log_forwarding=log_forwarding, tags=tags, where=where, dst=dst)
        result = http_request(URL, 'POST', body=params)
        custom_block_output['CustomURLCategory'] = object_value

    elif object_type == 'application':
        params = prepare_security_rule_params(api_action='set', action='drop', source=['any'], destination=['any'],
                                              application=object_value, rulename=rulename, target=target,
                                              log_forwarding=log_forwarding, tags=tags, where=where, dst=dst)
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

    result = http_request(URL, 'GET', params=params, is_file=True)
    json_result = json.loads(xml2json(result.text))['response']
    if json_result['@status'] != 'success':
        raise Exception('Request to get list of Pcaps Failed.\nStatus code: ' + str(
            json_result['response']['@code']) + '\nWith message: ' + str(json_result['response']['msg']['line']))

    dir_listing = (json_result.get('result') or {}).get('dir-listing') or {}
    if 'file' not in dir_listing:
        return_results(f'PAN-OS has no Pcaps of type: {pcap_type}.')
    else:
        pcaps = dir_listing['file']
        if isinstance(pcaps, str):
            # means we have only 1 pcap in the firewall, the api returns string if only 1 pcap is available
            pcaps = [pcaps]
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
    pcap_type = args['pcapType']
    params = {
        'type': 'export',
        'key': API_KEY,
        'category': pcap_type
    }

    password = args.get('password')
    pcap_id = args.get('pcapID')
    search_time = args.get('searchTime')
    pcap_name = args.get('from')

    if pcap_type == 'filter-pcap' and not pcap_name:
        raise Exception('cannot download filter-pcap without the from argument')

    if pcap_type == 'dlp-pcap' and not password:
        raise Exception('Can not download dlp-pcap without the password argument.')
    else:
        params['dlp-password'] = password
    if pcap_type == 'threat-pcap' and (not pcap_id or not search_time):
        raise Exception('Can not download threat-pcap without the pcapID and the searchTime arguments.')

    local_name = args.get('localName')
    serial_no = args.get('serialNo')
    session_id = args.get('sessionID')
    device_name = args.get('deviceName')

    serial_number = args.get('serialNumber')
    if VSYS and serial_number:
        raise Exception('The serialNumber argument can only be used in a Panorama instance configuration')
    elif DEVICE_GROUP and not serial_number and pcap_type != 'threat-pcap':
        raise Exception('PCAP listing is only supported on Panorama with the serialNumber argument.')
    elif serial_number and pcap_type != 'threat-pcap':
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

    result = http_request(URL, 'GET', params=params, is_file=True)

    # due to pcap file size limitation in the product. For more details, please see the documentation.
    if result.headers['Content-Type'] != 'application/octet-stream':
        json_result = json.loads(xml2json(result.text)).get('response', {})
        if (json_result.get('@status') or '') == 'error':
            errors = '\n'.join(
                [f'{error_key}: {error_val}' for error_key, error_val in (json_result.get('msg') or {}).items()]
            )
            raise Exception(errors)
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
        application_characteristics_list = []
        for characteristics_name, value in application.items():
            if characteristics_name in CHARACTERISTICS_LIST and value == 'yes':
                application_characteristics_list.append(str(characteristics_name))
        pretty_application_arr.append({
            'Category': application.get('category'),
            'SubCategory': application.get('subcategory'),
            'Risk': application.get('risk'),
            'Technology': application.get('technology'),
            'Name': application.get('@name'),
            'Description': application.get('description'),
            'Characteristics': application_characteristics_list,
            'Id': application.get('@id'),
        })
    return pretty_application_arr


@logger
def panorama_list_applications(args: Dict[str, str], predefined: bool) -> Union[List[dict], dict]:
    major_version = get_pan_os_major_version()
    params = {
        'type': 'config',
        'action': 'get',
        'key': API_KEY
    }
    filters = assign_params(
        risk=args.get('risk'),
        category=args.get('category'),
        subcategory=args.get('sub_category'),
        technology=args.get('technology'),
        characteristics=argToList(args.get('characteristics')),
    )
    name_match = args.get('name_match')
    demisto.debug('name_match', name_match)
    name_contain = args.get('name_contain')
    if name_match and name_contain:
        raise Exception('Please specify only one of name_match/name_contain')
    xpath_filter = build_xpath_filter(name_match, name_contain, filters)
    demisto.debug("xpath_filter", xpath_filter)
    if predefined:  # if predefined = true, no need for device group.
        if major_version < 9:
            raise Exception('Listing predefined applications is only available for PAN-OS 9.X and above versions.')
        else:
            if xpath_filter:
                params['xpath'] = f'/config/predefined/application/entry[{xpath_filter}]'
            else:
                params['xpath'] = '/config/predefined/application'
    else:
        # if device-group was provided it will be set in initialize_instance function.
        if xpath_filter:
            params['xpath'] = XPATH_OBJECTS + f"application/entry[{xpath_filter}]"
        else:
            params['xpath'] = XPATH_OBJECTS + "application/entry"
    demisto.debug(params['xpath'])
    result = http_request(
        URL,
        'POST',
        body=params
    )
    applications_api_response = result['response']['result']
    if filters or name_match or name_contain:
        applications = applications_api_response.get('entry') or []
    elif predefined:
        applications = applications_api_response.get('application', {}).get('entry') or []
    else:
        applications = applications_api_response.get('entry') or []
        if not applications and major_version >= 9:
            applications = applications_api_response.get('application') or []

    return applications


def panorama_list_applications_command(args: Dict[str, str]):
    """
    List all applications
    """
    predefined = args.get('predefined') == 'true'
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size')) or DEFAULT_LIMIT_PAGE_SIZE
    limit = arg_to_number(args.get('limit')) or DEFAULT_LIMIT_PAGE_SIZE
    applications_arr = panorama_list_applications(args, predefined)
    entries = do_pagination(applications_arr, page=page, page_size=page_size, limit=limit)
    applications_arr_output = prettify_applications_arr(entries)
    headers = ['Id', 'Name', 'Risk', 'Category', 'SubCategory', 'Technology', 'Description', 'Characteristics']

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': applications_arr,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Applications', t=applications_arr_output, headers=headers, removeNull=True),
        'EntryContext': {
            "Panorama.Applications(val.Name == obj.Name)": applications_arr_output
        }
    })


''' External Dynamic Lists Commands '''


def prettify_edls_arr(edls_arr: Union[list, dict]):
    if isinstance(edls_arr, dict):  # handle case of only one edl in the instance
        parse_pan_os_un_committed_data(edls_arr, ['@admin', '@dirtyId', '@time'])
        return prettify_edl(edls_arr)

    for edl in edls_arr:
        parse_pan_os_un_committed_data(edl, ['@admin', '@dirtyId', '@time'])

    pretty_edls_arr = []

    for edl in edls_arr:
        pretty_edl = {
            'Name': edl['@name'],
            'Type': ''.join(edl['type'])
        }
        edl_type = pretty_edl['Type']

        if edl['type'][edl_type]:
            if 'url' in edl['type'][edl_type]:
                pretty_edl['URL'] = edl['type'][edl_type]['url']
            if 'certificate-profile' in edl['type'][edl_type]:
                pretty_edl['CertificateProfile'] = edl['type'][edl_type]['certificate-profile']
            if 'recurring' in edl['type'][edl_type]:
                pretty_edl['Recurring'] = ''.join(edl['type'][edl_type]['recurring'])
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
        'Type': ''.join(edl['type'])
    }
    edl_type = pretty_edl['Type']

    if edl['type'][edl_type]:
        if 'url' in edl['type'][edl_type]:
            pretty_edl['URL'] = edl['type'][edl_type]['url']
        if 'certificate-profile' in edl['type'][edl_type]:
            pretty_edl['CertificateProfile'] = edl['type'][edl_type]['certificate-profile']
        if 'recurring' in edl['type'][edl_type]:
            pretty_edl['Recurring'] = ''.join(edl['type'][edl_type]['recurring'])
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
    edl_type = ''.join(edl_prev['type'])
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
        edl_type = ''.join(edl['type'])
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
def panorama_register_ip_tag(tag: str, ips: List, persistent: str, timeout: int):
    entry: str = ''
    for ip in ips:
        if timeout:
            entry += f'<entry ip=\"{ip}\" persistent=\"{persistent}\"><tag><member timeout="{timeout}">{tag}' \
                     f'</member></tag></entry>'
        else:
            entry += f'<entry ip=\"{ip}\" persistent=\"{persistent}\"><tag><member>{tag}</member></tag></entry>'

    params = {
        'type': 'user-id',
        'cmd': f'<uid-message><version>2.0</version><type>update</type><payload><register>{entry}'
               f'</register></payload></uid-message>',
        'key': API_KEY,
    }
    if VSYS:
        params['vsys'] = VSYS

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
    tag: str = args.get('tag', '')
    ips: list = argToList(args.get('IPs'))
    persistent = args.get('persistent', 'true')
    persistent = '1' if persistent == 'true' else '0'
    # if not given, timeout will be 0 and persistent will be used
    timeout = arg_to_number(args.get('timeout', '0'))

    major_version = get_pan_os_major_version()

    if major_version <= 8 and timeout:
        raise DemistoException('The timeout argument is only applicable on 9.x PAN-OS versions or higher.')

    result = panorama_register_ip_tag(tag, ips, persistent, timeout)

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
        'key': API_KEY,
    }
    if VSYS:
        params['vsys'] = VSYS

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
def panorama_register_user_tag(tag: str, users: List, timeout: Optional[int]):
    entry: str = ''
    for user in users:
        if timeout:
            entry += f'<entry user=\"{user}\"><tag><member timeout="{timeout}">{tag}</member></tag></entry>'
        else:
            entry += f'<entry user=\"{user}\"><tag><member>{tag}</member></tag></entry>'

    params = {
        'type': 'user-id',
        'cmd': f'<uid-message><version>2.0</version><type>update</type><payload><register-user>{entry}'
               f'</register-user></payload></uid-message>',
        'key': API_KEY,
    }
    if VSYS:
        params['vsys'] = VSYS

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
    # if not given, timeout will be 0 (never expires)
    timeout = arg_to_number(args.get('timeout', '0'))

    result = panorama_register_user_tag(tag, users, timeout)

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
        'key': API_KEY,
    }
    if VSYS:
        params['vsys'] = VSYS

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
        query += '(addr.dst in ' + destination + ')'
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
                     filedigest: Optional[str], time_generated_after: Optional[str],):
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
        date = dateparser.parse(time_generated)
        if len(query) > 0 and query[-1] == ')':
            query += ' and '
        query += '(time_generated leq \'' + date.strftime("%Y/%m/%d %H:%M:%S") + '\')'  # type: ignore
    if time_generated_after:
        date = dateparser.parse(time_generated_after)
        if len(query) > 0 and query[-1] == ')':
            query += ' and '
        query += '(time_generated geq \'' + date.strftime("%Y/%m/%d %H:%M:%S") + '\')'  # type: ignore
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
                        zone_src: str, zone_dst: str, time_generated: str, time_generated_after: str, action: str,
                        port_dst: str, rule: str, url: str, filedigest: str, show_detail: str = 'no'):
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
                                           port_dst, rule, url, filedigest, time_generated_after)
    if number_of_logs:
        params['nlogs'] = number_of_logs

    if show_detail:
        params['show-detail'] = show_detail

    result = http_request(
        URL,
        'GET',
        params=params,
    )

    return result


@polling_function(
    name=demisto.command(),
    interval=arg_to_number(demisto.args().get('interval_in_seconds', 10)),
    timeout=arg_to_number(demisto.args().get('timeout', 600))
)
def panorama_query_logs_command(args: dict):
    """
    Query logs
    """
    log_type = args.get('log-type')
    number_of_logs = arg_to_number(args.get('number_of_logs', 100))
    query = args.get('query')
    address_src = args.get('addr-src')
    address_dst = args.get('addr-dst')
    ip_ = args.get('ip')
    zone_src = args.get('zone-src')
    zone_dst = args.get('zone-dst')
    time_generated = args.get('time-generated')
    time_generated_after = args.get('time-generated-after')
    action = args.get('action')
    port_dst = args.get('port-dst')
    rule = args.get('rule')
    filedigest = args.get('filedigest')
    url = args.get('url')
    job_id = args.get('query_log_job_id')
    illegal_chars = {'@', '#'}
    ignored_keys = {'entry'}
    # The API refers to any value other than 'yes' as 'no'.
    show_detail = args.get('show-detail', 'no') or 'no'

    if not job_id:
        if query and (address_src or address_dst or zone_src or zone_dst
                      or time_generated or time_generated_after or action or port_dst or rule or url or filedigest):
            raise Exception('Use the free query argument or the fixed search parameters arguments to build your query.')

        result: PanosResponse = PanosResponse(
            panorama_query_logs(
                log_type, number_of_logs, query, address_src, address_dst, ip_,
                zone_src, zone_dst, time_generated, time_generated_after, action,
                port_dst, rule, url, filedigest, show_detail
            ),
            illegal_chars=illegal_chars,
            ignored_keys=ignored_keys
        )
        if result.ns.response.status == 'error':
            if result.ns.response.result.msg.line:
                raise Exception(f"Query logs failed. Reason is: {result.ns.response.result.msg.line}")
            else:
                raise Exception('Query logs failed.')
        if not result.ns.response.result.job:
            raise Exception('Missing JobID in response.')
        query_logs_output = {
            'JobID': result.ns.response.result.job,
            'Status': 'Pending',
            'LogType': log_type,
            'Message': result.ns.response.result.msg.line
        }

        command_results = CommandResults(
            raw_response=result.raw,
            outputs_prefix='Panorama.Monitor',
            outputs_key_field='JobID',
            outputs=query_logs_output,
            readable_output=tableToMarkdown('Query Logs:', query_logs_output, ['JobID', 'Status'], removeNull=True)
        )

        poll_result = PollResult(
            response=command_results,
            continue_to_poll=True,
            args_for_next_run={
                'query_log_job_id': result.ns.response.result.job,
                'log-type': log_type,
                'polling': argToBoolean(args.get('polling', 'false')),
                'interval_in_seconds': arg_to_number(args.get('interval_in_seconds', 10)),
                'timeout': arg_to_number(args.get('timeout', 120))
            },
            partial_result=CommandResults(
                readable_output=f"Fetching {log_type} logs for job ID {result.ns.response.result.job}...",
                raw_response=result.raw
            )
        )

    else:
        # Only used in subsequent polling executions

        parsed: PanosResponse = PanosResponse(
            panorama_get_traffic_logs(job_id),
            illegal_chars=illegal_chars,
            ignored_keys=ignored_keys
        )
        if parsed.ns.response.status == 'error':
            if parsed.ns.response.result.msg.line:
                raise Exception(
                    f'Query logs failed. Reason is: {parsed.ns.response.result.msg.line}'
                )
            else:
                raise Exception(
                    f'Query logs failed.'
                )

        if not parsed.ns.response.result.job.id:
            raise Exception('Missing JobID status in response.')

        query_logs_output = {
            'JobID': job_id,
            'LogType': log_type
        }
        readable_output = None
        if parsed.ns.response.result.job.status.upper() == 'FIN':
            query_logs_output['Status'] = 'Completed'
            if parsed.ns.response.result.log.logs.count == '0':
                readable_output = f'No {log_type} logs matched the query.'
                query_logs_output['Logs'] = []
            else:
                pretty_logs = prettify_logs(parsed.get_nested_key('response.result.log.logs.entry'))
                query_logs_output['Logs'] = pretty_logs
                readable_output = tableToMarkdown(
                    f'Query {log_type} Logs:',
                    pretty_logs,
                    ['TimeGenerated', 'SourceAddress', 'DestinationAddress', 'Application', 'Action', 'Rule', 'URLOrFilename'],
                    removeNull=True
                )

        poll_result = PollResult(
            response=CommandResults(
                outputs_prefix='Panorama.Monitor',
                outputs_key_field='JobID',
                outputs=query_logs_output,
                readable_output=readable_output,
                raw_response=parsed.raw
            ),
            continue_to_poll=parsed.ns.response.result.job.status != 'FIN'
        )

    return poll_result


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
                                   source_user: Optional[str] = None, target: Optional[str] = None,
                                   vsys: Optional[str] = None):
    params = {'type': 'op', 'key': API_KEY, 'target': target, 'vsys': vsys,
              'cmd': build_policy_match_query(application, category, destination, destination_port, from_, to_,
                                              protocol, source, source_user)}

    result = http_request(
        URL,
        'GET',
        params=params
    )

    return result['response']['result']


def prettify_matching_rule(matching_rule: dict, device: dict = {}):
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

    for key, val in device.items():
        pretty_matching_rule[f'Device{key}'] = val

    return pretty_matching_rule


def prettify_matching_rules(matching_rules: Union[list, dict], device):
    if not isinstance(matching_rules, list):  # handle case of only one log that matched the query
        return prettify_matching_rule(matching_rules, device)

    pretty_matching_rules_arr = []
    for matching_rule in matching_rules:
        pretty_matching_rule = prettify_matching_rule(matching_rule, device)
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


def devices(targets=None, vsys_s=None):
    """
    This method is used to determine the target and vsys that should be used,
    or iterate over all the connected target and vsys.
    e.g. none of then in case of an FW instance.
    Args:
        targets(str): A list of all the serial number for the FW targets
        vsys_s(str): A list of all the vsys names for the targets.

    Yields:
        target, vsys
    """
    if VSYS:  # for FW intstances
        yield None, None
    elif targets and vsys_s:
        for target in targets:
            for vsys in vsys_s:
                yield target, vsys
    else:
        res = http_request(URL, 'GET', params={'key': API_KEY, 'type': 'op',
                                               'cmd': '<show><devices><all></all></devices></show>'})
        devices_entry = dict_safe_get(res, ['response', 'result', 'devices', 'entry'])
        devices_entry = devices_entry if isinstance(devices_entry, list) else [devices_entry]
        devices_entry = filter(lambda x: x['serial'] in targets, devices_entry) if targets else devices_entry
        for device in devices_entry:
            if not vsys_s:
                if device.get('multi-vsys', 'no') == 'yes':
                    vsys_s_entry = dict_safe_get(device, ['vsys', 'entry'])
                    vsys_s_entry = vsys_s_entry if isinstance(vsys_s_entry, list) else [vsys_s_entry]
                    final_vsys_s = map(lambda x: x['@name'], vsys_s_entry)
                else:
                    final_vsys_s = iter([None])  # type: ignore
            else:
                final_vsys_s = vsys_s
            for vsys in final_vsys_s:
                yield device['serial'], vsys


def format_readable_security_policy_match_headers(hedear_name):
    formated_headers = {
        'From': 'From zone',
        'To': 'To zone',
    }
    return formated_headers.get(hedear_name, hedear_name)


def readable_security_policy_match_outputs(context_list):
    readable_list = []
    for context in context_list:
        vsys = dict_safe_get(context, ['Device', 'Vsys'])
        target = dict_safe_get(context, ['Device', 'Serial'])
        if vsys and target:
            table_name = f'Matching Security Policies in `{target}/{vsys}` FW:'
        elif target:
            table_name = f'Matching Security Policies in `{target}` FW:'
        else:
            table_name = 'Matching Security Policies:'

        readable_list.append(tableToMarkdown(table_name, context['Rules'], removeNull=True,
                                             headers=['Name', 'Action', 'From', 'Source', 'To', 'Destination', 'Application'],
                                             headerTransform=format_readable_security_policy_match_headers))

    return '\n'.join(readable_list)


def panorama_security_policy_match_command(args: dict):
    application = args.get('application')
    category = args.get('category')
    destination = args.get('destination')
    destination_port = args.get('destination-port')
    from_ = args.get('from')
    to_ = args.get('to')
    protocol = args.get('protocol')
    source = args.get('source')
    source_user = args.get('source-user')

    context_list = []
    raw_list = []
    for target, vsys in devices(targets=argToList(args.get('target')), vsys_s=argToList(args.get('vsys'))):
        matching_rules = panorama_security_policy_match(application, category, destination, destination_port, from_, to_,
                                                        protocol, source, source_user, target, vsys)
        if matching_rules:

            device = {key: val for key, val in zip(['Serial', 'Vsys'], [target, vsys]) if val} if target or vsys else {}
            context = {
                'Rules': prettify_matching_rules(matching_rules['rules']['entry'], device),
                'QueryFields': prettify_query_fields(application, category, destination, destination_port, from_,
                                                     to_, protocol, source, source_user),
                'Query': build_policy_match_query(application, category, destination, destination_port, from_,
                                                  to_, protocol, source, source_user)
            }
            if device:
                context['Device'] = device
            context_list.append(context)
            raw_list.extend(matching_rules) if isinstance(matching_rules, list) else raw_list.append(matching_rules)
    if not context_list:
        return_results('The query did not match a Security policy.')
    else:
        readable_output = readable_security_policy_match_outputs(context_list)

        return_results(CommandResults(
            outputs_prefix='Panorama.SecurityPolicyMatch(val.Query == obj.Query && val.Device == obj.Device)',
            raw_response=raw_list, outputs=context_list, readable_output=readable_output))


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
                              nexthop_type: str, nexthop_value: str, interface: str | None = None,
                              metric: str | None = None) -> Dict[str, str]:
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


def panorama_get_predefined_threats_list(target: Optional[str] = None):
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


def panorama_show_device_version(target: str | None = None):
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
def panorama_download_latest_content_update_content(target: Optional[str] = None):
    params = {
        'type': 'op',
        'cmd': '<request><content><upgrade><download><latest/></download></upgrade></content></request>',
        'key': API_KEY
    }
    if target:
        params['target'] = target

    result = http_request(
        URL,
        'POST',
        body=params
    )

    return result


def panorama_download_latest_content_update_command(args: dict):
    """
    Download content and show message in war room
    """
    target = args.get('target', None)
    if DEVICE_GROUP and not target:
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
        'key': API_KEY
    }
    if target:
        params['target'] = target

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
    target = str(args['target']) if 'target' in args else None
    if DEVICE_GROUP and not target:
        raise Exception('Content download status is only supported on Firewall (not Panorama).')
    job_id = args['job_id']
    result = panorama_content_update_download_status(target, job_id)

    content_download_status = {
        'JobID': result['response']['result']['job']['id']
    }
    if result['response']['result']['job']['status'] in ['FIN', 'ACT', 'FAIL']:
        status_res = result['response']['result']['job']['result']
        if status_res == 'OK':
            content_download_status['Status'] = 'Completed'
        elif status_res == 'FAIL':
            content_download_status['Status'] = 'Failed'
        elif status_res == 'PEND':
            content_download_status['Status'] = 'Pending'
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
        'key': API_KEY
    }
    if target:
        params['target'] = target
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
        'key': API_KEY
    }
    if target:
        params['target'] = target
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

    if result['response']['result']['job']['status'] in ['FIN', 'ACT', 'FAIL']:
        status_res = result['response']['result']['job']['result']
        if status_res == 'OK':
            content_install_status['Status'] = 'Completed'
        elif status_res == 'FAIL':
            content_install_status['Status'] = 'Failed'
        elif status_res == 'PEND':
            content_install_status['Status'] = 'Pending'
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
    to_context = result.get('response', {}).get('result', {})
    versions = to_context.get('sw-updates', {}).get('versions').get('entry', [])
    if len(versions) > 5:
        versions = versions[:5]
    human_readable = tableToMarkdown('5 latest pan-os software releases', versions,
                                     ['version', 'filename', 'size', 'released-on', 'downloaded', 'current', 'latest',
                                      'uploaded'], removeNull=True)
    return CommandResults(readable_output=human_readable,
                          outputs=to_context,
                          raw_response=result,
                          outputs_prefix='Panorama.LatestVersions'
                          )


@logger
def panorama_download_panos_version(target: str, target_version: str):
    params = {
        'type': 'op',
        'cmd': f'<request><system><software><download><version>{target_version}'
               f'</version></download></software></system></request>',
        'key': API_KEY
    }
    if target:
        params['target'] = target
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
        'key': API_KEY
    }
    if target:
        params['target'] = target
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
    target = str(args['target']) if 'target' in args else None
    job_id = args.get('job_id')
    result = panorama_download_panos_status(target, job_id)
    panos_download_status = {
        'JobID': result['response']['result']['job']['id']
    }
    if result['response']['result']['job']['status'] in ['FIN', 'ACT', 'FAIL']:
        status_res = result['response']['result']['job']['result']
        if status_res == 'OK':
            panos_download_status['Status'] = 'Completed'
        elif status_res == 'FAIL':
            panos_download_status['Status'] = 'Failed'
        elif status_res == 'PEND':
            panos_download_status['Status'] = 'Pending'
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
        'key': API_KEY
    }
    if target:
        params['target'] = target

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
    target = str(args['target']) if 'target' in args else None
    if DEVICE_GROUP and not target:
        raise Exception('PAN-OS installation is only supported on Firewall (not Panorama).')
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
        'key': API_KEY
    }
    if target:
        params['target'] = target
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


def panorama_device_reboot_command(args: dict):
    params = {
        'type': 'op',
        'cmd': '<request><restart><system></system></restart></request>',
        'key': API_KEY
    }
    if target := args.get('target', None):
        params['target'] = target
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
    if isinstance(rule.get('application'), dict) and 'member' in rule['application']:
        pretty_rule['Application'] = rule['application']['member']
    if isinstance(rule.get('file-type'), dict) and 'member' in rule['file-type']:
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


def get_security_profiles_command(security_profile: str | None = None):
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

        human_readable += tableToMarkdown('Antivirus Profiles', virus_content, headers=['Name', 'Decoder', 'Rules'],
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
def apply_security_profile(xpath: str, profile_name: str, profile_type: str) -> Dict:
    # get the rule state
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': xpath,
        'key': API_KEY,
    }
    result = http_request(URL, 'GET', params=params)

    # Get all profile types already existing, so we don't override them when updating
    profile_types_result = dict_safe_get(result, ['response', 'result', 'entry', 'profile-setting', 'profiles'],
                                         default_return_value={})

    # align the response for both committed and un-committed profiles
    parse_pan_os_un_committed_data(profile_types_result, ['@admin', '@dirtyId', '@time'])

    # remove from the types the given profile type, since we update it anyway
    profile_types = {'data-filtering', 'file-blocking', 'spyware', 'url-filtering',
                     'virus', 'vulnerability', 'wildfire-analysis'} - {profile_type}

    rule_profiles = ''

    if profile_name:  # if profile_name was not provided, we remove the profile type from the rule.
        # first we update the given profile type with the given profile name
        rule_profiles += f"<{profile_type}><member>{profile_name}</member></{profile_type}>"

    # Keeping the existing profile types
    for p_type in profile_types:
        if profile_types_result and p_type in profile_types_result:
            p_name = profile_types_result.get(p_type, {}).get('member')
            rule_profiles += f"<{p_type}><member>{p_name}</member></{p_type}>"

    params = {
        'action': 'set',
        'type': 'config',
        'xpath': xpath,
        'key': API_KEY,
        'element': f'<profile-setting><profiles>{rule_profiles}</profiles></profile-setting>'
    }

    result = http_request(URL, 'POST', params=params)

    return result


def apply_security_profile_command(args):
    profile_name = args.get('profile_name', '')  # when removing a profile, no need to a pass a profile_name
    profile_type = args.get('profile_type')
    rule_name = args.get('rule_name')
    pre_post = args.get('pre_post')

    if DEVICE_GROUP:  # Panorama instance
        if not pre_post:
            raise Exception('Please provide the pre_post argument when applying profiles to rules in '
                            'Panorama instance.')
        xpath = f"{XPATH_RULEBASE}{pre_post}/security/rules/entry[@name='{rule_name}']"

    else:  # firewall instance
        xpath = f"{XPATH_RULEBASE}rulebase/security/rules/entry[@name='{rule_name}']"

    apply_security_profile(xpath, profile_name, profile_type)
    if profile_name:
        return_results(f'The profile {profile_type} = {profile_name} has been applied to the rule {rule_name}')
    else:
        return_results(f'The profile {profile_type} has been removed from the rule {rule_name}')


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
    if isinstance(rule.get('application'), dict) and 'member' in rule['application']:
        pretty_rule['Application'] = rule['application']['member']
    if isinstance(rule.get('file-type'), dict) and 'member' in rule['file-type']:
        pretty_rule['File-type'] = rule['file-type']['member']
    if 'wildfire-action' in rule:
        pretty_rule['WildFire-action'] = rule['wildfire-action']
    if isinstance(rule.get('category'), dict) and 'member' in rule['category']:
        pretty_rule['Category'] = rule['category']['member']
    elif 'category' in rule:
        pretty_rule['Category'] = rule['category']
    if isinstance(rule.get('severity'), dict) and 'member' in rule['severity']:
        pretty_rule['Severity'] = rule['severity']['member']
    if isinstance(rule.get('threat-name'), dict) and 'member' in rule['threat-name']:
        pretty_rule['Threat-name'] = rule['threat-name']['member']
    elif 'threat-name' in rule:
        pretty_rule['Threat-name'] = rule['threat-name']
    if 'packet-capture' in rule:
        pretty_rule['Packet-capture'] = rule['packet-capture']
    if '@maxver' in rule:
        pretty_rule['Max_version'] = rule['@maxver']
    if isinstance(rule.get('sinkhole'), dict):
        pretty_rule['Sinkhole'] = {}
        if 'ipv4-address' in rule['sinkhole']:
            pretty_rule['Sinkhole']['IPV4'] = rule['sinkhole']['ipv4-address']
        if 'ipv6-address' in rule['sinkhole']:
            pretty_rule['Sinkhole']['IPV6'] = rule['sinkhole']['ipv6-address']
    if 'host' in rule:
        pretty_rule['Host'] = rule['host']
    if isinstance(rule.get('cve'), dict) and 'member' in rule['cve']:
        pretty_rule['CVE'] = rule['cve']['member']
    if isinstance(rule.get('vendor-id'), dict) and 'member' in rule['vendor-id']:
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


def apply_dns_signature_policy_command(args: dict) -> CommandResults:
    """
        Args:
            - the args passed by the user

        Returns:
            - A CommandResult object
    """
    anti_spy_ware_name = args.get('anti_spyware_profile_name')
    edl = args.get('dns_signature_source')
    action = args.get('action')
    ipv4_address = args.get('ipv4', 'pan-sinkhole-default-ip')
    ipv6_adderss = args.get('ipv6', '::1')
    packet_capture = args.get('packet_capture', 'disable')

    # for Panorama instance
    params = {
        'action': 'set',
        'type': 'config',
        'xpath': f"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{DEVICE_GROUP}']"
                 f"/profiles/spyware/entry[@name='{anti_spy_ware_name}']",
        'key': API_KEY,
        'element': f'<botnet-domains>'
                   f'<lists>'
                   f'<entry name="{edl}"><packet-capture>{packet_capture}</packet-capture>'
                   f'<action><{action}/></action></entry>'
                   f'</lists>'
                   f'<sinkhole><ipv4-address>{ipv4_address}</ipv4-address><ipv6-address>{ipv6_adderss}</ipv6-address></sinkhole>'
                   f'</botnet-domains>'
    }
    if VSYS:  # if it's a firewall instance, modify the xpath param
        params['xpath'] = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{VSYS}']" \
                          f"/profiles/spyware/entry[@name='{anti_spy_ware_name}']"

    result = http_request(
        URL,
        'POST',
        params=params,
    )
    res_status = result.get('response', {}).get('@status')
    if res_status == 'error':
        err_msg = result.get('response', {}).get('msg', {}).get('line')
        raise DemistoException(f'Error: {err_msg}')

    return CommandResults(
        readable_output=f'**{res_status}**',
        raw_response=result,
    )


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
    if isinstance(rule.get('application'), dict) and 'member' in rule['application']:
        pretty_rule['Application'] = rule['application']['member']
    if isinstance(rule.get('file-type'), dict) and 'member' in rule['file-type']:
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


def set_xpath_wildfire(template: str | None = None) -> str:
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


def show_user_id_interface_config_request(args: dict):
    # template argument is managed in hte initialize_instance method
    template_stack = str(args.get('template_stack', ''))

    vsys = args.get('vsys')
    if VSYS and not vsys:
        vsys = VSYS
    elif not vsys:
        vsys = 'vsys1'

    if not VSYS and not TEMPLATE and not template_stack:
        raise DemistoException('In order to show the User Interface configuration in your Panorama, '
                               'supply either the template or the template_stack arguments.')

    if VSYS:  # firewall instance xpath
        xpath = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name=\'{vsys}\']/zone"
    elif not template_stack:  # panorama instance xpath with template
        template_test(str(TEMPLATE))  # verify that the template exists
        xpath = f"/config/devices/entry[@name='localhost.localdomain']/template/entry[@name=\'{TEMPLATE}\']/config" \
                f"/devices/entry[@name='localhost.localdomain']/vsys/entry[@name=\'{vsys}\']/zone"
    else:  # panorama instance xpath with template_stack
        xpath = "/config/devices/entry[@name='localhost.localdomain']/template-stack/" \
                f"entry[@name=\'{template_stack}\']/config/devices/entry[@name='localhost.localdomain']/vsys/" \
                f"entry[@name=\'{vsys}\']/zone"

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


def list_configured_user_id_agents_request(args: dict, version):
    # template argument is managed in hte initialize_instance method
    template_stack = str(args.get('template_stack', ''))

    vsys = args.get('vsys')
    if VSYS and not vsys:
        vsys = VSYS
    elif not vsys:
        vsys = 'vsys1'

    if not VSYS and not TEMPLATE and not template_stack:
        raise DemistoException('In order to show the the User ID Agents in your Panorama, '
                               'supply either the template or the template_stack arguments.')

    if VSYS:
        if version < 10:
            xpath = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name=\'{vsys}\']/user-id-agent"
        else:
            xpath = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name=\'{vsys}\']/" \
                    "redistribution-agent"

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
        template_test(str(TEMPLATE))  # verify that the template exists
        if version < 10:
            xpath = f"/config/devices/entry[@name='localhost.localdomain']/template/entry[@name=\'{TEMPLATE}\']" \
                    f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name=\'{vsys}\']/user-id-agent"
        else:
            xpath = f"/config/devices/entry[@name='localhost.localdomain']/template/entry[@name=\'{TEMPLATE}\']/" \
                    f"config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name=\'{vsys}\']/" \
                    "redistribution-agent"

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
            'NtlmAuth': dict_safe_get(user_id_agents, keys=['host-port', 'ntlm-auth'], default_return_value='no'),
            'LdapProxy': dict_safe_get(user_id_agents, keys=['host-port', 'ldap-proxy'], default_return_value='no'),
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


def list_configured_user_id_agents_command(args: dict):
    version = get_pan_os_major_version()
    raw_response = list_configured_user_id_agents_request(args, version)
    if raw_response:
        formatted_results = prettify_configured_user_id_agents(raw_response)
        headers = ['Name', 'Disabled', 'SerialNumber', 'Host', 'Port', 'CollectorName', 'LdapProxy', 'NtlmAuth',
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
    API_KEY = str(params.get('key')) or str((params.get('credentials') or {}).get('password', ''))  # type: ignore
    if not API_KEY:
        raise Exception('API Key must be provided.')
    USE_SSL = not params.get('insecure')
    USE_URL_FILTERING = params.get('use_url_filtering')

    # determine a vsys or a device-group
    VSYS = params.get('vsys', '')

    DEVICE_GROUP = args.get(DEVICE_GROUP_ARG_NAME) or params.get(DEVICE_GROUP_PARAM_NAME)  # type: ignore[assignment]

    if args and args.get('template'):
        TEMPLATE = args.get('template')  # type: ignore[assignment]
    else:
        TEMPLATE = params.get('template', None)  # type: ignore[arg-type]

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
        response = http_request(uri=URL, method="POST", headers={}, body={}, params=params, files={'file': file})
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


"""
PAN-OS Network Operations Integration
Provides additional complex commands for PAN-OS firewalls and ingests configuration issues as incidents.
"""


# Errors
class OpCommandError(Exception):
    pass


# Best practices
class BestPractices:
    SPYWARE_ALERT_THRESHOLD = ["medium", "low"]
    SPYWARE_BLOCK_SEVERITIES = ["critical", "high"]
    VULNERABILITY_ALERT_THRESHOLD = ["medium", "low"]
    VULNERABILITY_BLOCK_SEVERITIES = ["critical", "high"]
    URL_BLOCK_CATEGORIES = ["command-and-control", "hacking", "malware", "phishing"]


# pan-os-python new classes
class CustomVersionedPanObject(VersionedPanObject):
    """This is a patch for functionality in pan-os-python that doesn't easily enable us to retrieve these specific types of
    objects. This allows us to still use VersionedPanObjects to keep the code consistent."""

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
            child_xml_elements = child.refreshall_from_xml(childroot)
            self.extend(child_xml_elements)

        return self.children


class AntiSpywareProfileBotnetDomainList(CustomVersionedPanObject):
    ROOT = Root.VSYS  # pylint: disable=E1101
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/lists")
        self._params = (
            VersionedParamPath("packet_capture", path="packet-capture"),
            VersionedParamPath("is_action_sinkhole", path="action/sinkhole")
        )


class AntiSpywareProfileBotnetDomains(CustomVersionedPanObject):
    ROOT = Root.VSYS  # pylint: disable=E1101
    SUFFIX = ENTRY
    CHILDTYPES = (AntiSpywareProfileBotnetDomainList,)

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/botnet-domains")
        self._params = tuple()  # type: ignore[var-annotated]


class AntiSpywareProfileRule(VersionedPanObject):
    ROOT = Root.VSYS  # pylint: disable=E1101
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/rules")
        # params
        self._params = (
            VersionedParamPath("severity", vartype="member", path="severity"),
            VersionedParamPath("is_reset_both", vartype="exist", path="action/reset-both"),
            VersionedParamPath("is_reset_client", vartype="exist", path="action/reset-client"),
            VersionedParamPath("is_reset_server", vartype="exist", path="action/reset-server"),
            VersionedParamPath("is_alert", vartype="exist", path="action/alert"),
            VersionedParamPath("is_default", vartype="exist", path="action/default"),
            VersionedParamPath("is_allow", vartype="exist", path="action/allow"),
            VersionedParamPath("is_drop", vartype="exist", path="action/drop"),
            VersionedParamPath("is_block_ip", vartype="exist", path="action/block-ip")
        )


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
        self._params = tuple()  # type: ignore[var-annotated]


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
        self._params = (
            VersionedParamPath("severity", vartype="member", path="severity"),
            VersionedParamPath("is_reset_both", vartype="exist", path="action/reset-both"),
            VersionedParamPath("is_reset_client", vartype="exist", path="action/reset-client"),
            VersionedParamPath("is_reset_server", vartype="exist", path="action/reset-server"),
            VersionedParamPath("is_alert", vartype="exist", path="action/alert"),
            VersionedParamPath("is_default", vartype="exist", path="action/default"),
            VersionedParamPath("is_allow", vartype="exist", path="action/allow"),
            VersionedParamPath("is_drop", vartype="exist", path="action/drop"),
            VersionedParamPath("is_block_ip", vartype="exist", path="action/block-ip")
        )


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
        self._params = tuple()  # type: ignore[var-annotated]


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
        self._params = (
            VersionedParamPath("block", vartype="member", path="block"),
            VersionedParamPath("alert", vartype="member", path="alert"),
            VersionedParamPath("credential_enforce_alert", vartype="member",
                               path="credential-enforcement/alert"),
            VersionedParamPath("credential_enforce_block", vartype="member",
                               path="credential-enforcement/block")
        )


def run_op_command(device: Union[Panorama, Firewall], cmd: str, **kwargs) -> ET.Element:
    """
    Run OP command.

    Returns:
        Element: XML element object.
    """
    result = device.op(cmd, **kwargs)
    if "status" in result and result.attrib.get("status") != "success":
        raise OpCommandError(f"Operational command {cmd} failed!")

    return result


def find_text_in_element(element, tag: str) -> str:
    """
    Find a text in an XML element.

    Args:
        element (Element): XML element.
        tag (str): the XML tag to search for.

    Returns:
        str: the text of the tag that was searched.
    """
    result = element.find(tag)
    # This has to be an exact check, as an element that has no text will evaluate to none.
    if result is None:
        raise LookupError(f"Tag {tag} not found in element.")

    if not hasattr(result, "text"):
        raise LookupError(f"Tag {tag} has no text.")

    return result.text if result.text else ""


def get_element_attribute(element, attribute: str) -> str:
    """
    Find a text in an XML element.

    Args:
        element (Element): XML element.
        attribute (str): the attribute of the element.
    """
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
        self.panorama_objects: Dict[str, Panorama] = {}
        self.firewall_objects: Dict[str, Firewall] = {}
        self.ha_pair_serials: dict = {}
        self.ha_active_devices: dict = {}
        self.username: str = ""
        self.password: str = ""
        self.api_key: str = ""

    def get_peer(self, serial: str):
        """Given a serial, get it's peer, if part of a HA pair."""
        return self.ha_pair_serials.get(serial)

    def get_all_child_firewalls(self, device: Panorama):
        """
        Connect to Panorama and retrieves the full list of managed devices.
        This list will only retrieve devices that are connected to panorama.
        Devices are stored by their serial number.
        :param device: Panorama PanDevice instance
        """
        ha_pair_dict = {}
        device_op_command_result = run_op_command(device, "show devices all")
        for device_entry in device_op_command_result.findall("./result/devices/entry"):
            serial_number: str = find_text_in_element(device_entry, "./serial")
            connected: str = find_text_in_element(device_entry, "./connected")
            if connected == "yes":
                new_firewall_object = Firewall(serial=serial_number)
                device.add(new_firewall_object)
                self.add_device_object(new_firewall_object)
                ha_peer_serial_element = device_entry.find("./ha/peer/serial")
                ha_peer_serial = None
                if ha_peer_serial_element is not None and hasattr(ha_peer_serial_element, "text"):
                    ha_peer_serial = ha_peer_serial_element.text

                if ha_peer_serial is not None:
                    # The key is always the active device.
                    ha_status: str = find_text_in_element(device_entry, "./ha/state")
                    if ha_status == "active":
                        self.ha_active_devices[serial_number] = ha_peer_serial

                    ha_pair_dict[serial_number] = ha_peer_serial
                else:
                    self.ha_active_devices[serial_number] = "STANDALONE"

        # This is only true if Panorama is in HA mode as well.
        if self.ha_pair_serials:
            self.ha_pair_serials = {**self.ha_pair_serials, **ha_pair_dict}
        else:
            self.ha_pair_serials = ha_pair_dict

    def add_device_object(self, device: Union[PanDevice, Panorama, Firewall]):
        """
        Given a PANdevice device object, works out how to add it to this Topology instance.
        Firewalls get added directly to the object. If `device` is Panorama, then it's queried for all
        connected Firewalls, which are then also added to the object.
        This function also checks the HA state of all firewalls using the Panorama output.
        :param device: Either Panorama or Firewall Pandevice instance
        """
        if isinstance(device, Panorama):
            serial_number_or_hostname = device.serial if device.serial else device.hostname

            # Check if HA is active and if so, what the system state is.
            # Only associate Firewalls with the ACTIVE Panorama instance
            panorama_ha_state_result = run_op_command(device, "show high-availability state")
            enabled = panorama_ha_state_result.find("./result/enabled")
            if enabled is not None:
                if enabled.text == "yes":
                    try:
                        state = find_text_in_element(panorama_ha_state_result, "./result/local-info/state")
                    except LookupError:
                        state = find_text_in_element(panorama_ha_state_result, "./result/group/local-info/state")

                    if "active" in state:
                        peer_serial = None
                        try:
                            # For panorama, there is no serial stored in the HA output, so we can't get it.
                            # Instead, we can get the mgmt IP in it's place.
                            peer_serial = find_text_in_element(panorama_ha_state_result, "./result/peer-info/mgmt-ip")
                        except LookupError:
                            peer_serial = None

                        self.ha_active_devices[serial_number_or_hostname] = peer_serial
                        self.ha_pair_serials[serial_number_or_hostname] = peer_serial
                        if peer_serial:
                            self.ha_pair_serials[peer_serial] = serial_number_or_hostname

                        self.get_all_child_firewalls(device)
                        self.panorama_objects[serial_number_or_hostname] = device
                        return
                else:
                    self.get_all_child_firewalls(device)
            else:
                self.get_all_child_firewalls(device)

            # This is a bit of a hack - if no ha, treat it as active
            self.ha_active_devices[serial_number_or_hostname] = "STANDALONE"
            self.panorama_objects[serial_number_or_hostname] = device

            return

        elif isinstance(device, Firewall):
            self.firewall_objects[device.serial] = device
            return

        raise TypeError(f"{type(device)} is not valid as a topology object.")

    def panorama_devices(self) -> ValuesView[Panorama]:
        """
        Returns the Panorama objects in the topology
        """
        return self.panorama_objects.values()

    def firewall_devices(self) -> ValuesView[Firewall]:
        """
        Returns the firewall devices in the topology
        """
        return self.firewall_objects.values()

    def top_level_devices(self) -> Iterator[Union[Firewall, Panorama]]:
        """
        Returns a list of the highest level devices. This is normally Panorama, or in a pure NGFW deployment,
        this would be a list of all the `Firewall` instances.
        Top level devices may or may not have any children.
        """
        if self.panorama_objects:
            for value in self.panorama_devices():
                yield value

            return

        if self.firewall_objects:
            for value in self.firewall_devices():
                yield value

    def active_devices(self, filter_str: Optional[str] = None) -> Iterator[Union[Firewall, Panorama]]:
        """
        Yields active devices in the topology - Active refers to the HA state of the device. If the device
        is not in a HA pair, it is active by default.
        :param filter_str: The filter string to filter the devices on
        """
        # If the ha_active_devices dict is not empty, we have gotten HA info from panorama.
        # This means we don't need to refresh the state.
        for device in self.all(filter_str):
            if self.ha_active_devices:
                # Handle case of no SN or hostname
                serial_or_hostname = device.serial
                if not serial_or_hostname:
                    serial_or_hostname = device.hostname

                if serial_or_hostname in self.ha_active_devices:
                    yield device
            else:
                status = device.refresh_ha_active()
                if status == "active" or not status:
                    yield device

    def active_top_level_devices(self, device_filter_string: Optional[str] = None):
        """
        Same as `active_devices`, but only returns top level devices as opposed to all active devices.
        :param device_filter_string: The string to filter the devices by
        """
        return [x for x in self.top_level_devices() if x in self.active_devices(device_filter_string)]

    @staticmethod
    def filter_devices(devices: Dict[str, PanDevice], filter_str: Optional[str] = None):
        """
        Filters a list of devices to find matching entries based on the string.
        If the filter string matches a device serial or IP exactly, then returns just that one device.
        If not, it will compare the device hostname instead for a match.
        :param devices: The list of PanDevice instances to filter by the filter string
        :param filter_str: The filter string to filter the devices on
        """
        # Exact match based on device serial number
        if not filter_str:
            return devices

        if filter_str in devices:
            return {
                filter_str: devices.get(filter_str)
            }

        for serial, device in devices.items():
            if device.hostname == filter_str:
                return {
                    serial: device
                }

    def firewalls(self, filter_string: Optional[str] = None, target: Optional[str] = None) -> Iterator[Firewall]:
        """
        Returns an iterable of firewalls in the topology
        :param filter_string: The filter string to filter he devices on
        :param target: Instead of a filter string, target can be used to only ever return one device.
        """
        if target:
            yield self.get_single_device(filter_string=target)
            return

        firewall_objects = Topology.filter_devices(self.firewall_objects, filter_string)
        if not firewall_objects:
            raise DemistoException("Filter string returned no devices known to this topology.")

        for firewall in firewall_objects.values():
            yield firewall

    def all(
        self, filter_string: Optional[str] = None, target: Optional[str] = None
    ) -> Iterator[Union[Firewall, Panorama]]:
        """
        Returns an iterable for all devices in the topology
        :param filter_string: The filter string to filter he devices on
        :param target: Instead of a filter string, target can be used to only ever return one device.
        """
        if target:
            yield self.get_single_device(filter_string=target)
            return

        all_devices = {**self.firewall_objects, **self.panorama_objects}
        all_devices = Topology.filter_devices(all_devices, filter_string)
        # Raise if we get an empty dict back
        if not all_devices:
            raise DemistoException("Filter string returned no devices known to this topology.")

        for device in all_devices.values():
            yield device

    def get_single_device(self, filter_string: str) -> Union[Firewall, Panorama]:
        """
        Returns JUST ONE device, based on the filter string, and errors if the filter returns more.
        Safeguard for functions that should only ever operate on a single device.
        :param filter_string: The exact ID of the device to return from the topology.
        """
        all_devices = {**self.firewall_objects, **self.panorama_objects}
        if device := all_devices.get(filter_string):
            return device

        raise DemistoException(f"filter_str {filter_string} is not the exact ID of a host in this topology; "
                               + f"use a more specific filter string.")

    def get_by_filter_str(self, filter_string: Optional[str] = None) -> dict:
        """
        Filters all devices and returns a dictionary of matching.
        :param filter_string: The filter string to filter he devices on
        """
        return Topology.filter_devices({**self.firewall_objects, **self.panorama_objects}, filter_string)

    @classmethod
    def build_from_string(
        cls, hostnames: str, username: str, password: str, port: Optional[int] = None, api_key: Optional[str] = None
    ):
        """
        Splits a csv list of hostnames and builds the topology based on it. This allows you to pass a series of PanOS hostnames
        into the topology instead of building it from each device.
        This function will convert each hostname/username/password/api_key combination into a PanDevice
        object type, add them into a new instance of `Topology`, then return it.
        :param hostnames: A string of hostnames in CSV format, ex. hostname1,hostname2
        :param username: The PAN-OS username
        :param password: the PAN-OS password
        :param port: The PAN-OS port
        :param api_key: The PAN-OS api key
        """
        topology = cls()
        for hostname in hostnames.split(","):
            try:
                if api_key:
                    device = PanDevice.create_from_device(
                        hostname=hostname,
                        api_key=api_key,
                        port=port
                    )
                else:
                    device = PanDevice.create_from_device(
                        hostname=hostname,
                        api_username=username,
                        api_password=password,
                        port=port
                    )
                # Set the timeout
                device.timeout = DEVICE_TIMEOUT
                topology.add_device_object(device)
            except (panos.errors.PanURLError, panos.errors.PanXapiError, HTTPError) as e:
                demisto.debug(f"Failed to connected to {hostname}, {e}")
                # If a device fails to respond, don't add it to the topology.

        topology.username = username
        topology.password = password
        topology.api_key = str(api_key or "")

        return topology

    @classmethod
    def build_from_device(cls, ip: str, username: str, password: str):
        """
        Creates a PanDevice object out of a single IP/username/password and adds it to the topology.
        :param ip: The IP address or hostname of the device
        :param username: The PAN-OS username
        :param password: the PAN-OS password
        """
        device: PanDevice = PanDevice.create_from_device(
            hostname=ip,
            api_username=username,
            api_password=password,
        )
        # Set the timeout
        device.timeout = DEVICE_TIMEOUT
        topology = cls()
        topology.add_device_object(device)

        topology.username = username
        topology.password = password

        return topology

    def get_direct_device(self, firewall: Firewall, ip_address: Optional[str] = None) -> PanDevice:
        """
        Given a firewall object that's proxied via Panorama, create a device that uses a direct API connection
        instead. Used by any command that can't be routed via Panorama.
        :param firewall: The `Firewall` device to directly connect to
        """
        if firewall.hostname:
            # If it's already a direct connection
            return firewall

        ip_address = ip_address or (firewall.show_system_info().get("system") or {}).get("ip-address")

        return PanDevice.create_from_device(
            hostname=ip_address,
            api_username=self.username,
            api_password=self.password,
            api_key=self.api_key
        )

    def get_all_object_containers(
        self,
        device_filter_string: Optional[str] = None,
        container_name: Optional[str] = None,
        top_level_devices_only: Optional[bool] = False,
    ) -> List[Tuple[PanDevice, Union[Panorama, Firewall, DeviceGroup, Template, Vsys]]]:
        """
        Given a device, returns all the possible configuration containers that can contain objects -
        vsys, device-groups, templates and template-stacks.
        :param device_filter_string: The filter string to filter he devices on
        :param container_name: The string name of the device group, template-stack, or vsys to return
        :param top_level_devices_only: If set, only containers will be returned from the top level devices, usually Panorama.
        """
        containers = []
        # for device in self.all(device_filter_string):
        # Changed to only refer to active devices, no passives.
        device_retrieval_func = self.active_devices
        if top_level_devices_only:
            device_retrieval_func = self.active_top_level_devices  # type: ignore[assignment]

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

            if isinstance(device, Panorama):
                # Add the "shared" device if Panorama. Firewalls will always have vsys1
                containers.append((device, device))

        return_containers = []

        if container_name:
            for container in containers:
                if container_name == "shared":
                    if isinstance(container[1], Panorama):
                        return_containers.append(container)
                if not isinstance(container[1], (Panorama, Firewall)):
                    if container[1].name == container_name:
                        return_containers.append(container)
        else:
            return_containers = containers

        return return_containers


"""
--- Dataclass Definitions Start Below ---
Dataclasses are split into three types;
 SummaryData: Classes that hold only summary data, and are safe to display in the incident layout
 ResultData: Classes that hold a full representation of the data, used to pass between tasks only

The dataclasses are used for automatic generation of the integration YAML, as well as controlling the
format of the result data being sent to XSOAR.
In each dataclass, the attributes are used as below;
    _output_prefix: The prefix of the context output
    _title: The human readable title for human readable tables (using TableToMarkdown)

    _summary_cls: For commands with very large resultant data, the summary dataclass stores a cutdown
        summary to avoid overloading incident layouts.
    _result_cls:
Some dataclasses don't split the data by summary and result data, because they should never return a large
amount. As such, _summary_cls and _result_cls are optional.
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
    summary_data: List[ShowArpCommandSummaryData]
    result_data: List[ShowArpCommandResultData]

    _output_prefix = OUTPUT_PREFIX + "ShowArp"
    _title = "PAN-OS ARP Table"

    # The below is required for integration autogen, we can't inspect the original class from the List[]
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
    summary_data: List[ShowRoutingCommandSummaryData]
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

    def __post_init__(self):
        # Self.age can be null if the route is static, so set it to 0 in this case so it's still a valid int.
        if self.age:
            self.age = int(self.age)
        else:
            self.age = 0


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
    summary_data: List[ShowRoutingRouteSummaryData]
    result_data: List[ShowRoutingRouteResultData]

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
    av_version: str = "not_installed"
    av_release_date: str = "not_installed"
    app_version: str = "not_installed"
    app_release_date: str = "not_installed"
    threat_version: str = "not_installed"
    threat_release_date: str = "not_installed"
    wildfire_version: str = "not_installed"
    wildfire_release_date: str = "not_installed"
    url_filtering_version: str = "not_installed"


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
    summary_data: List[ShowSystemInfoSummaryData]
    result_data: List[ShowSystemInfoResultData]

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
    summary_data: List[ShowCounterGlobalSummaryData]
    result_data: List[ShowCounterGlobalResultData]

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
    summary_data: List[ShowRoutingProtocolBGPPeersSummaryData]
    result_data: List[ShowRoutingProtocolBGPPeersResultData]

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
    summary_data: List[GetDeviceConnectivityResultData]
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
    summary_data: List[SoftwareVersion]
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
    positionInQ: int
    progress: int
    warnings: Any = None
    description: str = ""

    _output_prefix = OUTPUT_PREFIX + "JobStatus"
    _title = "PAN-OS Job Status"
    _outputs_key_field = "id"

    def __post_init__(self):
        self.id = int(self.id)


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
    summary_data: List[GenericSoftwareStatus]
    result_data: None = None

    _output_prefix = OUTPUT_PREFIX + "DownloadStatus"
    _title = "PAN-OS Software Download request Status"

    _summary_cls = GenericSoftwareStatus


@dataclass
class InstallSoftwareCommandResult:
    summary_data: List[GenericSoftwareStatus]
    result_data: None = None

    _output_prefix = OUTPUT_PREFIX + "InstallStatus"
    _title = "PAN-OS Software Install request Status"

    _summary_cls = GenericSoftwareStatus


@dataclass
class RestartSystemCommandResult:
    summary_data: List[GenericSoftwareStatus]
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
    last_commit_all_state_sp: str
    hostname: Optional[str] = ""
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
    last_commit_all_state_tpl: str
    hostname: str = ""
    name: str = ""

    _output_prefix = OUTPUT_PREFIX + "TemplateStackOp"
    _title = "PAN-OS Operational Template Stack status"
    _outputs_key_field = "name"


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


def dataclass_from_dict(device: Union[Panorama, Firewall], object_dict: dict, class_type: Callable):
    """
    Given a dictionary and a datacalass, converts the dictionary into the dataclass type.
    :param device: The PAnDevice instance that this result data belongs to
    :param object_dict: the dictionary of the object data
    :param class_type the dataclass to convert the dict into
    """
    if device.hostname:
        object_dict["hostid"] = device.hostname
    if device.serial:
        object_dict["hostid"] = device.serial

    result_dict = {}
    for key, value in object_dict.items():
        d_key = key.replace("-", "_")
        dataclass_field = next((x for x in fields(class_type) if x.name == d_key), None)  # type: ignore[arg-type]
        if dataclass_field:
            result_dict[d_key] = value

    return class_type(**result_dict)


def flatten_xml_to_dict(element: ET.Element, object_dict: dict, class_type: type):
    """
    Given an XML element, a dictionary, and a class, flattens the XML into the class.
    This is a recursive function that will resolve child elements.
    :param element: XML element object
    :param object_dict: A dictionary to populate with the XML tag text
    :param class_type: The class type that this XML will be converted to - filters the XML tags by it's attributes
    """
    for child_element in element:
        tag = child_element.tag

        # Replace hyphens in tags with underscores to match python attributes
        tag = tag.replace("-", "_")
        dataclass_field = next((x for x in fields(class_type) if x.name == tag), None)  # type: ignore[arg-type]
        if dataclass_field:
            object_dict[tag] = child_element.text

        if len(child_element) > 0:
            object_dict = {**object_dict, **flatten_xml_to_dict(child_element, object_dict, class_type)}

    return object_dict


def dataclass_from_element(device: Union[Panorama, Firewall], class_type: type, element: Optional[ET.Element]):
    """
    Turns an XML `Element` Object into an instance of the provided dataclass. Dataclass parameters must match
    element: Optional[Element]
    child XML tags exactly.
    :param device: Instance of `Panorama` or `Firewall` object
    :param class_type: The dataclass to convert the XML into
    :param element: The XML element to convert to the dataclass of type `class_type`
    """
    object_dict = {}
    if not element:
        return

    if device.hostname:
        object_dict["hostid"] = device.hostname
    if device.serial:
        object_dict["hostid"] = device.serial

    # Handle the XML attributes, if any and if they match dataclass field
    for attr_name, attr_value in element.attrib.items():
        dataclass_field = next((x for x in fields(class_type) if x.name == attr_name), None)  # type: ignore[arg-type]
        if dataclass_field:
            object_dict[attr_name] = attr_value

    try:
        return class_type(**flatten_xml_to_dict(element, object_dict, class_type))
    except TypeError as error:  # catch cases where values are missing from the element
        demisto.debug(f'{class_type.__name__!r} cannot be instantiated with element: {elem2json(element, "")}\n{error=}')
        return


def resolve_host_id(device: PanDevice):
    """
    Gets the ID of the host from a PanDevice object. This may be an IP address or serial number.
    :param device: `Pandevice` object instance, can also be a `Firewall` or `Panorama` type.
    """
    host_id: str = ""
    if device.hostname:
        host_id = device.hostname
    if device.serial:
        host_id = device.serial

    return host_id


def resolve_container_name(container: Union[Panorama, Firewall, DeviceGroup, Template, Vsys]):
    """
    Gets the name of a given PanDevice container or if it's not a container, returns shared.
    :param container: Named container, or device instance
    """
    if isinstance(container, (Panorama, Firewall)):
        return "shared"

    return container.name


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
    summary_data: List[ConfigurationHygieneCheck]
    result_data: List[ConfigurationHygieneIssue]

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


class HygieneRemediation:
    """Functions that remediate problems generated by HygieneLookups"""

    @staticmethod
    def fix_log_forwarding_profile_enhanced_logging(topology: Topology,
                                                    issues: List[ConfigurationHygieneIssue]) -> List[ConfigurationHygieneFix]:
        """
        Given a list of hygiene issues, sourced by `pan-os-hygiene-check-log-forwarding`, enables enhanced application logging to
        fix that issue.
        :param issues: List of log forwarding issues due to no enhanced application logging.
        """
        result = []
        for issue in issues:
            for device, container in topology.get_all_object_containers(
                issue.hostid,
                container_name=issue.container_name
            ):
                log_forwarding_profiles: List[LogForwardingProfile] = LogForwardingProfile.refreshall(
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
        issues: List[ConfigurationHygieneIssue],
        log_forwarding_profile: str
    ) -> List[ConfigurationHygieneFix]:
        """
        Given a list of Configuration Hygiene Issues, referencing security zones that do not have any log forwarding settings,
        sets the provided log forwarding profile, thus fixing them.
        :param issues: List of security zone issues due to no log forwarding setting
        :param log_forwarding_profile: The log forwarding profile to set.
        """
        result = []
        for issue in issues:
            for device, container in topology.get_all_object_containers(
                issue.hostid,
                container_name=issue.container_name,
            ):
                security_zones: List[Zone] = Zone.refreshall(container)
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
    def get_all_rules_in_container(container: Union[Panorama, Firewall, DeviceGroup, Template, Vsys],
                                   object_class: Union[SecurityRule, NatRule]):
        """
        Given a container (DG/template) and the class representing a type of rule object in pan-os-python, gets all the
        associated objects.
        :param container: Device group or template
        :param object_class: The pan-os-python class of objects to retrieve
        """
        if object_class not in [SecurityRule, NatRule]:
            raise ValueError(f"Given class {object_class} cannot be retrieved by this function.")

        firewall_rulebase = Rulebase()
        pre_rulebase = PreRulebase()
        post_rulebase = PostRulebase()
        container.add(pre_rulebase)
        container.add(post_rulebase)
        container.add(firewall_rulebase)
        objects = object_class.refreshall(firewall_rulebase)
        objects += object_class.refreshall(pre_rulebase)
        objects += object_class.refreshall(post_rulebase)

        return objects

    @staticmethod
    def get_all_security_rules_in_container(container: Union[Panorama, Firewall, DeviceGroup, Template, Vsys]
                                            ) -> List[SecurityRule]:
        """
        Gets all the security rule objects from the given VSYS or device group and return them.
        :param container: The object to search for the rules in, as passed to pan-os-python
        """
        return HygieneRemediation.get_all_rules_in_container(container, SecurityRule)

    @staticmethod
    def fix_secuity_rule_log_settings(topology: Topology,
                                      issues: List[ConfigurationHygieneIssue],
                                      log_forwarding_profile_name: str) -> List[ConfigurationHygieneFix]:
        """
        Given a list of Configuration Hygiene Issues, referencing security rules that have no log settings, sets the provided
        log forwarding profile.
        :param issues: List of security zone issues due to no log forwarding setting
        :param log_forwarding_profile_name: The log forwarding profile to set.
        """
        result = []
        for issue in issues:
            for device, container in topology.get_all_object_containers(
                issue.hostid,
                container_name=issue.container_name
            ):
                security_rules = HygieneRemediation.get_all_security_rules_in_container(container)
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
                                                 issues: List[ConfigurationHygieneIssue],
                                                 security_profile_group_name: str,
                                                 ) -> List[ConfigurationHygieneFix]:
        """
        Given a list of Configuration Hygiene Issues, referencing security rules that have no threat settings, sets the provided
        security profile group.
        :param issues: List of security rule issues that have no threat settings.
        :param security_profile_group_name: The security porfile group to set.
        """
        result = []
        for issue in issues:
            for device, container in topology.get_all_object_containers(
                issue.hostid,
                container_name=issue.container_name
            ):
                security_rules = HygieneRemediation.get_all_security_rules_in_container(container)
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

    SUPPORTED_OBJECT_TYPES = {
        "AddressObject": AddressObject,
        "AddressGroup": AddressGroup,
        "ServiceObject": ServiceObject,
        "ServiceGroup": ServiceGroup,
        "ApplicationObject": ApplicationObject,
        "ApplicationGroup": ApplicationGroup,
        "SecurityProfileGroup": SecurityProfileGroup,
        "SecurityRule": SecurityRule,
        "NatRule": NatRule,
        "LogForwardingProfile": LogForwardingProfile,
    }

    @staticmethod
    def get_object_reference(
        topology: Topology,
        object_type: str,
        device_filter_string: Optional[str] = None,
        container_filter: Optional[str] = None,
        object_name: Optional[str] = None,
        use_regex: Optional[str] = None
    ) -> List[PanosObjectReference]:
        """
        Given a string object type, returns all the matching objects by reference. The object type matches a pan-os-python
        object exactly. Note this ONLY returns the "pointer" to the objects, that is, it's location in the config, not all the
        object attributes.

        :param topology: `Topology` instance
        :param device_filter_string: String to filter the devices we search for objects within.
        :param object_type: String object type to look for, this matches exactly with Pan-os-python supported objects
        :param container_filter: Container we look for objects in, such as a device group or template-stack
        :param object_name: The name of the object to find; can be regex if use_regex is set
        :param use_regex: Whether we should use regex matching for the object_name
        """

        object_class = ObjectGetter.SUPPORTED_OBJECT_TYPES.get(object_type)
        if not object_class:
            raise DemistoException(f"Object type {object_type} is not gettable with this integration.")

        object_references = []
        for device, container in topology.get_all_object_containers(
            device_filter_string,
            container_name=container_filter
        ):
            unfiltered_objects = []
            # If the object class is a security rule we need to handle it specially
            if object_class in [SecurityRule, NatRule]:
                unfiltered_objects = HygieneRemediation.get_all_rules_in_container(container, object_class)
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
                    # Regex compilation errors should raise if the regex flag is chosen
                    except re.error:
                        raise DemistoException(f"Invalid regex; {object_name}")

        return object_references


class HygieneCheckRegister:
    """Stores all the hygiene checks this integration is capable of and their associated details."""

    def __init__(self, register: dict):
        self.register: Dict[str, ConfigurationHygieneCheck] = register

    def get(self, issue_code: str) -> ConfigurationHygieneCheck:
        """
        Gets a single Hygiene check by it's string issue code.
        :param issue_code: The string issue code, such as BP-V-1
        """
        if issue_check := self.register.get(issue_code):
            return issue_check
        raise DemistoException("Invalid Hygiene check issue name")

    def values(self):
        return self.register.values()

    @classmethod
    def get_hygiene_check_register(cls, issue_codes: List[str]):
        """
        Builds the hygiene check register which stores a representation of all the hygiene checks supported by this integration,
        filtered by the list of issue_codes provided
        This function allows a hygiene lookup command to check for the presence of specific hygiene issues and set the result
        accordingly.

        :param issue_codes: List of string issue codes to return hygiene check objects for.
        """
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
                description="Fails if no URL Filtering profile is configured with recommended category settings.",
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
        device_filter_str: Optional[str] = None,
    ):
        """
        Evaluates the log forwarding profiles configured througout the environment to validate at least one is present with the
        correct settings required for log visibility.
        :param topology: `Topology` instance
        :param device_filter_str: Filter checks to a specific device or devices
        """
        issues = []
        lf_profile_list: List[LogForwardingProfile] = []
        check_register = HygieneCheckRegister.get_hygiene_check_register([
            "BP-V-1",
            "BP-V-2",
            "BP-V-3"
        ])
        for device, container in topology.get_all_object_containers(device_filter_str):
            log_forwarding_profiles: List[LogForwardingProfile] = LogForwardingProfile.refreshall(container)
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
                    if log_forwarding_profile_match_list.log_type in required_log_types:
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
        profiles: Union[List[VulnerabilityProfile], List[AntiSpywareProfile]],
        minimum_block_severities: List[str],
        minimum_alert_severities: List[str]
    ) -> Union[List[VulnerabilityProfile], List[AntiSpywareProfile]]:
        """
        Given a list of threat (vulnerability or spyware) profiles, return any that conform to best practices.

        :param profiles: A list of ..Profile pan-os-python objects
        :param minimum_alert_severities: A string list of severities that MUST be in a alert mode
        :param minimum_block_severities: A string list of severities that MUST be in block mode
        """
        conforming_profiles = []
        for profile in profiles:
            block_severities = minimum_block_severities.copy()
            alert_severities = minimum_alert_severities.copy()

            for rule in profile.children:
                block_actions = [rule.is_reset_both, rule.is_reset_client, rule.is_reset_server,
                                 rule.is_drop, rule.is_block_ip]
                alert_actions = [rule.is_default, rule.is_alert]
                is_blocked = any(block_actions)
                is_alert = any(alert_actions)
                for rule_severity in rule.severity:
                    # If the block severities are blocked
                    if is_blocked and rule_severity in block_severities:
                        block_severities.remove(rule_severity)
                        if rule_severity in alert_severities:
                            alert_severities.remove(rule_severity)
                    # If the alert severities are blocked
                    elif is_blocked and rule_severity in alert_severities:
                        if rule_severity in alert_severities:
                            alert_severities.remove(rule_severity)
                    # If the alert severities are alert/default
                    elif is_alert and rule_severity in alert_severities:
                        if rule_severity in alert_severities:
                            alert_severities.remove(rule_severity)

            if not block_severities and not alert_severities:
                conforming_profiles.append(profile)

        return conforming_profiles

    @staticmethod
    def check_vulnerability_profiles(
        topology: Topology,
        device_filter_str: Optional[str] = None,
        minimum_block_severities: Optional[List[str]] = None,
        minimum_alert_severities: Optional[List[str]] = None
    ) -> ConfigurationHygieneCheckResult:
        """
        Checks the environment to ensure at least one vulnerability profile is configured according to visibility best practices.
        The minimum severities can be tweaked to customize what "best practices" is.

        :param topology: `Topology` instance
        :param device_filter_str: Filter checks to a specific device or devices
        :param minimum_alert_severities: A string list of severities that MUST be in a alert mode
        :param minimum_block_severities: A string list of severities that MUST be in block mode
        """

        if not minimum_block_severities:
            minimum_block_severities = BestPractices.VULNERABILITY_BLOCK_SEVERITIES
        if not minimum_alert_severities:
            minimum_alert_severities = BestPractices.VULNERABILITY_ALERT_THRESHOLD

        conforming_profiles: Union[List[VulnerabilityProfile], List[AntiSpywareProfile]] = []
        issues = []

        check_register = HygieneCheckRegister.get_hygiene_check_register([
            "BP-V-4"
        ])

        # BP-V-4 - Check at least one vulnerability profile exists with the correct settings.
        for device, container in topology.get_all_object_containers(device_filter_str):
            vulnerability_profiles: List[VulnerabilityProfile] = VulnerabilityProfile.refreshall(container)
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
        device_filter_str: Optional[str] = None,
        minimum_block_severities: Optional[List[str]] = None,
        minimum_alert_severities: Optional[List[str]] = None
    ) -> ConfigurationHygieneCheckResult:
        """
        Checks the environment to ensure at least one Spyware profile is configured according to visibility best practices.
        The minimum severities can be tweaked to customize what "best practices" is.

        :param topology: `Topology` instance
        :param device_filter_str: Filter checks to a specific device or devices
        :param minimum_alert_severities: A string list of severities that MUST be in a alert mode
        :param minimum_block_severities: A string list of severities that MUST be in block mode
        """
        if not minimum_block_severities:
            minimum_block_severities = BestPractices.SPYWARE_BLOCK_SEVERITIES
        if not minimum_alert_severities:
            minimum_alert_severities = BestPractices.SPYWARE_ALERT_THRESHOLD

        conforming_profiles: Union[List[VulnerabilityProfile], List[AntiSpywareProfile]] = []
        issues = []
        check_register = HygieneCheckRegister.get_hygiene_check_register([
            "BP-V-5"
        ])
        # BP-V-5 - Check at least one AS profile exists with the correct settings.
        for device, container in topology.get_all_object_containers(device_filter_str):
            spyware_profiles: List[AntiSpywareProfile] = AntiSpywareProfile.refreshall(container)
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
    def get_conforming_url_filtering_profiles(profiles: List[URLFilteringProfile]) -> List[URLFilteringProfile]:
        """
        Returns the url filtering profiles, if any, that meet current recommended best practices for Visibility.
        :param profiles: List of `URLFilteringProfile` objects.
        """
        conforming_profiles = []
        for profile in profiles:
            if profile.block:
                block_result = all(elem in profile.block for elem in BestPractices.URL_BLOCK_CATEGORIES)
                if block_result:
                    conforming_profiles.append(profile)

        return conforming_profiles

    @staticmethod
    def get_all_conforming_url_filtering_profiles(
            topology: Topology, device_filter_str: Optional[str] = None) -> List[PanosObjectReference]:
        """
        Retrieves all the conforming URL filtering profiles from the topology, if any.
        :param topology: `Topology` instance
        :param device_filter_str: Filter checks to a specific device or devices
        """
        result = []
        for device, container in topology.get_all_object_containers(device_filter_str):
            url_filtering_profiles: List[URLFilteringProfile] = URLFilteringProfile.refreshall(container)

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
        minimum_block_severities: List[str],
        minimum_alert_severities: List[str],
        device_filter_str: Optional[str] = None,
    ) -> List[PanosObjectReference]:
        """
        Searches the configuration for all spyware profiles that conform to best practices using the given minimum severities.

        :param topology: `Topology` Instance
        :param device_filter_str: Filter checks to a specific device or devices
        :param minimum_alert_severities: A string list of severities that MUST be in a alert mode
        :param minimum_block_severities: A string list of severities that MUST be in block mode
        """
        result = []
        for device, container in topology.get_all_object_containers(device_filter_str):
            spyware_profiles: List[AntiSpywareProfile] = AntiSpywareProfile.refreshall(container)
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
        minimum_block_severities: List[str],
        minimum_alert_severities: List[str],
        device_filter_str: Optional[str] = None,
    ) -> List[PanosObjectReference]:
        """
        Searches the configuration for all vulnerability profiles that conform to PAN best practices using the given minimum
        severities.

        :param topology: `Topology` Instance
        :param device_filter_str: Filter checks to a specific device or devices
        :param minimum_alert_severities: A string list of severities that MUST be in a alert mode
        :param minimum_block_severities: A string list of severities that MUST be in block mode
        """
        result = []
        for device, container in topology.get_all_object_containers(device_filter_str):
            spyware_profiles: List[VulnerabilityProfile] = VulnerabilityProfile.refreshall(container)
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
    def check_url_filtering_profiles(topology: Topology, device_filter_str: Optional[str] = None):
        """
        Checks the configured URL filtering profiles to make sure at least one is configured according to PAN best practices
        for visibility.

        :param topology: `Topology` Instance
        :param device_filter_str: Filter checks to a specific device or devices
        """
        issues: List[ConfigurationHygieneIssue] = []
        conforming_profiles: List[URLFilteringProfile] = []
        check_register = HygieneCheckRegister.get_hygiene_check_register([
            "BP-V-6"
        ])
        # BP-V-6 - Check at least one URL Filtering profile exists with the correct settings.
        for device, container in topology.get_all_object_containers(device_filter_str):
            url_filtering_profiles: List[URLFilteringProfile] = URLFilteringProfile.refreshall(container)
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
    def check_security_zones(topology: Topology, device_filter_str: Optional[str] = None) -> ConfigurationHygieneCheckResult:
        """
        Check all security zones are configured with Log Forwarding profiles.
        :param device_filter_str: Filter checks to a specific device or devices
        """
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
            security_zones: List[Zone] = Zone.refreshall(container)
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
    def check_security_rules(topology: Topology, device_filter_str: Optional[str] = None) -> ConfigurationHygieneCheckResult:
        """
        Check all security rules, in all rulebases, are configured with Log Forwarding and threat profiles.
        :param device_filter_str: Filter checks to a specific device or devices
        """
        issues = []

        check_register = HygieneCheckRegister.get_hygiene_check_register([
            "BP-V-8",
            "BP-V-9",
            "BP-V-10",
        ])
        for device, container in topology.get_all_object_containers(device_filter_str):
            # Because we check all the rulebases, we need to refresh the rules from all rulebases.
            security_rules = HygieneRemediation.get_all_security_rules_in_container(container)
            for security_rule in security_rules:
                # Check for "log at session end" enabled
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
                # Check a log forwarding profile is set
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

                # BP-V-10 - Check either a group or profile is configured. If a specific profile is set, we assume it's OK.
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
    """Commands that can only be run, or are relevant only on Panorama."""
    GET_DEVICEGROUPS_COMMAND = "show devicegroups"
    GET_TEMPLATE_STACK_COMMAND = "show template-stack"

    @staticmethod
    def get_device_groups(
        topology: Topology,
        device_filter_str: Optional[str] = None,
    ) -> List[DeviceGroupInformation]:
        """
        Get all the device groups from Panorama and their associated devices.
        :param topology: `Topology` instance.
        :param device_filter_str: If provided, filters this command to only the devices specified.
        """
        result = []
        for device in topology.active_top_level_devices(device_filter_str):
            if isinstance(device, Panorama):
                response = run_op_command(device, PanoramaCommand.GET_DEVICEGROUPS_COMMAND)
                for device_group_xml in response.findall("./result/devicegroups/entry"):
                    dg_name = get_element_attribute(device_group_xml, "name")
                    for device_xml in device_group_xml.findall("./devices/entry"):
                        device_group_information: DeviceGroupInformation = dataclass_from_element(
                            device, DeviceGroupInformation, device_xml
                        )
                        device_group_information.name = dg_name
                        result.append(device_group_information)

        return result

    @staticmethod
    def get_template_stacks(
        topology: Topology,
        device_filter_str: Optional[str] = None,
    ) -> List[TemplateStackInformation]:
        """
        Get all the template-stacks from Panorama and their associated devices.
        :param topology: `Topology` instance.
        :param device_filter_str: If provided, filters this command to only the devices specified.
        """

        result = []
        for device in topology.active_top_level_devices(device_filter_str):
            if isinstance(device, Panorama):
                response = run_op_command(device, PanoramaCommand.GET_TEMPLATE_STACK_COMMAND)
                for template_stack_xml in response.findall("./result/template-stack/entry"):
                    template_name = get_element_attribute(template_stack_xml, "name")
                    for device_xml in template_stack_xml.findall("./devices/entry"):
                        result_template_stack_information: TemplateStackInformation = dataclass_from_element(
                            device, TemplateStackInformation, device_xml
                        )
                        result_template_stack_information.name = template_name
                        result.append(result_template_stack_information)

        return result

    @staticmethod
    def push_style(topology: Topology, device: Union[Firewall, Panorama], style: str, filter: Optional[List[str]] = None):
        """
        Given a pan-os-python push style, a device and the topology object, work out what DGs and templates we need to push,
        then push them.
        :param topology: `Topology` instance
        :param device: The device to push to - will always be a Panorama instance
        :param style: The pan-os-python commit style; can be 'device group' or 'template stack'
        :param filter: Optionally only push the following named device-groups or template stacks.
        """
        result = []
        if style == "device group":
            commit_groups: Union[List[DeviceGroupInformation], List[TemplateStackInformation]] = \
                PanoramaCommand.get_device_groups(topology, resolve_host_id(device))
            commit_group_names = set([x.name for x in commit_groups])
        elif style == "template stack":
            commit_groups = PanoramaCommand.get_template_stacks(topology, resolve_host_id(device))
            commit_group_names = set([x.name for x in commit_groups])
        else:
            raise DemistoException(f"Provided push style {style} is invalid. Please specify `device group` or `template stack`")

        if filter:
            commit_group_names = set([x for x in commit_group_names if x in filter])

        for commit_group_name in commit_group_names:
            commit_command = PanoramaCommitAll(
                style=style,
                name=commit_group_name
            )
            result_job_id = device.commit(cmd=commit_command)
            result.append(PushStatus(
                hostid=resolve_host_id(device),
                commit_type=style.replace(" ", ""),
                name=commit_group_name,
                job_id=result_job_id,
                commit_all_status="Initiated",
                device_status="",
                device=""
            ))

        return result


class UniversalCommand:
    """Command list for commands that are consistent between PANORAMA and NGFW"""
    SYSTEM_INFO_COMMAND = "show system info"
    SHOW_JOBS_COMMAND = "show jobs all"
    SHOW_JOBS_ID_PREFIX = "show jobs id \"{}\""

    @staticmethod
    def get_system_info(
        topology: Topology,
        device_filter_str: Optional[str] = None,
        target: Optional[str] = None
    ) -> ShowSystemInfoCommandResult:
        """
        Get the running system information
        :param topology: `Topology` instance.
        :param device_filter_str: If provided, filters this command to only the devices specified.
        :param target: Single target device, by serial number
        """
        result_data: List[ShowSystemInfoResultData] = []
        summary_data: List[ShowSystemInfoSummaryData] = []
        for device in topology.all(filter_string=device_filter_str, target=target):
            response = run_op_command(device, UniversalCommand.SYSTEM_INFO_COMMAND)
            result_data.append(dataclass_from_element(device, ShowSystemInfoResultData,
                                                      response.find("./result/system")))
            summary_data.append(dataclass_from_element(device, ShowSystemInfoSummaryData,
                                                       response.find("./result/system")))

        return ShowSystemInfoCommandResult(result_data=result_data, summary_data=summary_data)

    @staticmethod
    def get_available_software(
        topology: Topology,
        device_filter_str: Optional[str] = None,
        target: Optional[str] = None
    ) -> SoftwareVersionCommandResult:
        """
        Get all available software updates
        :param topology: `Topology` instance.
        :param device_filter_str: If provided, filters this command to only the devices specified.
        """
        summary_data = []
        for device in topology.all(filter_string=device_filter_str, target=target):
            device.software.check()
            for version_dict in device.software.versions.values():
                summary_data.append(dataclass_from_dict(device, version_dict, SoftwareVersion))

        return SoftwareVersionCommandResult(summary_data=summary_data)

    @staticmethod
    def download_software(
        topology: Topology,
        version: str,
        sync: bool = False,
        device_filter_str: Optional[str] = None,
        target: Optional[str] = None
    ) -> DownloadSoftwareCommandResult:
        """
        Download the given software version to the device. This is an async command, and returns
        immediately.
        :param topology: `Topology` instance.
        :param device_filter_str: If provided, filters this command to only the devices specified.
        :param sync: If provided, command will block while downloading
        :param version: The software version to download
        """
        result = []
        for device in topology.all(filter_string=device_filter_str, target=target):
            device.software.download(version, sync=sync)
            result.append(GenericSoftwareStatus(
                hostid=resolve_host_id(device),
                started=True
            ))

        return DownloadSoftwareCommandResult(summary_data=result)

    @staticmethod
    def install_software(
        topology: Topology, version: str,
        sync: Optional[bool] = False,
        device_filter_str: Optional[str] = None,
        target: Optional[str] = None
    ) -> InstallSoftwareCommandResult:
        """
        Start the installation process for the given software version.
        :param version The software version to install
        :param sync: Whether to install in a synchronous or async manner - defaults to false
        :param device_filter_str: The filter string to match devices against
        :param `Topology` class instance
        """
        result = []
        for device in topology.all(filter_string=device_filter_str, target=target):
            device.software.install(version, sync=sync)
            result.append(GenericSoftwareStatus(
                hostid=resolve_host_id(device),
                started=True
            ))

        return InstallSoftwareCommandResult(summary_data=result)

    @staticmethod
    def reboot(topology: Topology, hostid: str) -> RestartSystemCommandResult:
        """
        Reboots the system.
        :param topology: `Topology` instance.
        :param hostid: The host to reboot - this function will only ever reboot one device at a time.
        """
        result = []
        device = topology.get_single_device(filter_string=hostid)
        device.restart()
        result.append(GenericSoftwareStatus(
            hostid=resolve_host_id(device),
            started=True
        ))

        return RestartSystemCommandResult(summary_data=result)

    @staticmethod
    def check_system_availability(topology: Topology, hostid: str) -> CheckSystemStatus:
        """
        Checks if the provided device is up by attempting to connect to it and run a show system info.

        This function will show a device as disconnected in the following scenarios;
            * If the device is not present in the topology, which means it's not appearing in the output of show devices on
            Panorama
            * If the device is in the topology but it is not returning a "normal" operatational mode.

        :param topology: `Topology` instance.
        :param hostid: hostid of device to check.
        """
        devices: dict = topology.get_by_filter_str(hostid)
        # first check if the system exists in the topology; if not, we've failed to connect altogether
        if not devices:
            return CheckSystemStatus(hostid=hostid, up=False)

        show_system_info = UniversalCommand.get_system_info(topology, hostid)
        show_system_info_result = show_system_info.result_data[0]
        if show_system_info_result.operational_mode != "normal":
            return CheckSystemStatus(
                hostid=hostid,
                up=False
            )

        return CheckSystemStatus(hostid=hostid, up=True)

    @staticmethod
    def show_jobs(
        topology: Topology,
        device_filter_str: Optional[str] = None,
        job_type: Optional[str] = None,
        status=None,
        id: Optional[int] = None,
        target: Optional[str] = None
    ) -> Union[list[ShowJobsAllResultData], ShowJobsAllResultData]:
        """
        Returns all jobs running on the system.
        :param topology: `Topology` instance.
        :param device_filter_str: If provided, filters this command to only the devices specified.
        :param job_type: Filters the results by the provided job type
        :param status: Filters the results by the status of the job
        :param id: Only returns the specific job by it's ID
        """
        result_data = []
        for device in topology.all(filter_string=device_filter_str, target=target):
            command = UniversalCommand.SHOW_JOBS_ID_PREFIX.format(id) if id else UniversalCommand.SHOW_JOBS_COMMAND
            try:
                response = run_op_command(device, command)
            except Exception:
                demisto.debug(f'Could not find The given ID {id} in the specific device {device}')
                continue
            for job in response.findall("./result/job"):
                result_data_obj: ShowJobsAllResultData = dataclass_from_element(device, ShowJobsAllResultData, job)

                if (
                    result_data_obj is not None
                    and (result_data_obj.status == status or not status)
                    and (result_data_obj.type == job_type or not job_type)
                ):
                    result_data.append(result_data_obj)
            break
        # The below is very important for XSOAR to de-duplicate the returned key. If there is only one obj
        # being returned, return it as a dict instead of a list.
        if len(result_data) == 1:
            return result_data[0]  # type: ignore

        if not result_data and id:  # in case of an empty list and a specific ID, it means ID not found in all devices
            raise DemistoException(f"The given ID {id} is not found in all device of the topology")

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
    def get_arp_table(
        topology: Topology, device_filter_str: Optional[str] = None, target: Optional[str] = None
    ) -> ShowArpCommandResult:
        """
        Gets the ARP (Address Resolution Protocol) table
        :param topology: `Topology` instance.
        :param device_filter_str: If provided, filters this command to only the devices specified.
        :param target: Single serial number to target with this command
        """
        result_data: List[ShowArpCommandResultData] = []
        summary_data: List[ShowArpCommandSummaryData] = []
        for firewall in topology.firewalls(filter_string=device_filter_str, target=target):
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
    def get_counter_global(
        topology: Topology, device_filter_str: Optional[str] = None, target: Optional[str] = None
    ) -> ShowCounterGlobalCommmandResult:
        """
        Gets the global counter details
        :param topology: `Topology` instance.
        :param device_filter_str: If provided, filters this command to only the devices specified.
        :param target: Single serial number to target with this command
        """
        result_data: List[ShowCounterGlobalResultData] = []
        summary_data: List[ShowCounterGlobalSummaryData] = []
        for firewall in topology.firewalls(filter_string=device_filter_str, target=target):
            response = run_op_command(firewall, FirewallCommand.GLOBAL_COUNTER_COMMAND)
            for entry in response.findall("./result/global/counters/entry"):
                summary_data.append(dataclass_from_element(firewall, ShowCounterGlobalSummaryData, entry))
                result_data.append(dataclass_from_element(firewall, ShowCounterGlobalResultData, entry))

        return ShowCounterGlobalCommmandResult(
            result_data=result_data,
            summary_data=summary_data
        )

    @staticmethod
    def get_routing_summary(
        topology: Topology, device_filter_str: Optional[str] = None, target: Optional[str] = None
    ) -> ShowRouteSummaryCommandResult:
        """
        Gets the routing summary table
        :param topology: `Topology` instance.
        :param device_filter_str: If provided, filters this command to only the devices specified.
        :param target: Single serial number to target with this command
        """
        summary_data = []
        for firewall in topology.firewalls(filter_string=device_filter_str, target=target):
            response = run_op_command(firewall, FirewallCommand.ROUTING_SUMMARY_COMMAND)
            summary_data.append(dataclass_from_element(firewall, ShowRoutingCommandSummaryData,
                                                       response.find("./result/entry/All-Routes")))

        return ShowRouteSummaryCommandResult(
            summary_data=summary_data,
            result_data=[]
        )

    @staticmethod
    def get_bgp_peers(
        topology: Topology, device_filter_str: Optional[str] = None, target: Optional[str] = None
    ) -> ShowRoutingProtocolBGPCommandResult:
        """
        Gets all BGP peers
        :param topology: `Topology` instance.
        :param device_filter_str: If provided, filters this command to only the devices specified.
        :param target: Single serial number to target with this command
        """
        summary_data = []
        result_data = []
        for firewall in topology.firewalls(filter_string=device_filter_str, target=target):
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
    def get_device_state(topology: Topology, target: str, ip_address: Optional[str] = None):
        """
        Returns an exported device state, as binary data. Note that this will attempt to connect directly to the target
        firewall, as it cannot be exported via the Panorama proxy. If there are network issues that prevent that, this command
        will time out.
        :param topology: `Topology` instance.
        :param target: The target serial number to retrieve the device state from.
        :param ip_address: An ip address to use for service route enabled firewalls.
        """

        for firewall in topology.firewalls(target=target):
            # Connect directly to the firewall
            direct_firewall_connection = topology.get_direct_device(firewall, ip_address)
            direct_firewall_connection.xapi.export(category="device-state")
            return direct_firewall_connection.xapi.export_result.get("content")

    @staticmethod
    def get_ha_status(
        topology: Topology, device_filter_str: Optional[str] = None, target: Optional[str] = None
    ) -> List[ShowHAState] | ShowHAState:
        """
        Gets the HA status of the device. If HA is not enabled, assumes the device is active.
        :param topology: `Topology` instance.
        :param device_filter_str: If provided, filters this command to only the devices specified.
        :param target: Single serial number to target with this command
        """
        result: List[ShowHAState] = []
        for firewall in topology.all(filter_string=device_filter_str, target=target):
            firewall_host_id: str = resolve_host_id(firewall)

            peer_serial: str = topology.get_peer(firewall_host_id) or ''
            # if this is firewall instance, there is no peer_serial, hence checking this only for Panorama instance.
            if not peer_serial and DEVICE_GROUP:
                result.append(ShowHAState(
                    hostid=firewall_host_id,
                    status="HA Not enabled.",
                    active=True,
                    peer=""
                ))
            else:
                state_information_element = run_op_command(firewall, FirewallCommand.HA_STATE_COMMAND)
                # Check both places for state to cover firewalls and panorama
                try:
                    state = find_text_in_element(state_information_element, "./result/group/local-info/state")
                except LookupError as e:
                    demisto.debug(f'Could not find HA state at ./result/group/local-info/state, error: {e}')
                    try:
                        state = find_text_in_element(state_information_element, "./result/local-info/state")
                    except LookupError as e:  # if the state was not found at all, that means HA is not enabled.
                        demisto.debug(f'Could not find HA state at ./result/local-info/state, error: {e}')
                        result.append(ShowHAState(
                            hostid=firewall_host_id,
                            status="HA Not enabled.",
                            active=True,
                            peer=""
                        ))
                        continue

                if "active" in state:
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
        """
        Changes the HA status of the  device to the specified state.
        :param topology: `Topology` instance.
        :param hostid: The ID of the host to change
        :param state: The HA state to change the device to
        """
        firewall = topology.get_single_device(hostid)
        run_op_command(firewall, f'{FirewallCommand.REQUEST_STATE_PREFIX} {state}')
        return HighAvailabilityStateStatus(
            hostid=resolve_host_id(firewall),
            state=state
        )

    @staticmethod
    def get_routes(
        topology: Topology, device_filter_str: Optional[str] = None, target: Optional[str] = None
    ) -> ShowRoutingRouteCommandResult:
        """
        Gets the entire routing table.
        :param topology: `Topology` instance.
        :param device_filter_str: If provided, filters this command to only the devices specified.
        :param target: Single serial number to target with this command
        """
        summary_data = []
        result_data = []
        for firewall in topology.firewalls(filter_string=device_filter_str, target=target):
            response = run_op_command(firewall, FirewallCommand.ROUTING_ROUTE_COMMAND)
            for entry in response.findall("./result/entry"):
                result_data.append(
                    dataclass_from_element(firewall, ShowRoutingRouteResultData, entry))

        # Calculate summary as number of routes by network interface and VR
        row: ShowRoutingRouteResultData
        count_data: Dict[str, dict] = {}
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

        return ShowRoutingRouteCommandResult(summary_data=summary_data, result_data=result_data)


"""
-- XSOAR Specific Code Starts below --
"""


def test_topology_connectivity(topology: Topology):
    """To get to the test-module command we must connect to the devices, thus no further test is required."""
    if len(topology.firewall_objects) + len(topology.panorama_objects) == 0:
        raise ConnectionError("No firewalls or panorama instances could be connected.")

    return "ok"


def get_arp_tables(
    topology: Topology, device_filter_string: Optional[str] = None, target: Optional[str] = None
) -> ShowArpCommandResult:
    """
    Gets all arp tables from all firewalls in the topology.
    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only show specific hostnames or serial numbers.
    :param target: Single serial number to target with this command
    """
    return FirewallCommand.get_arp_table(topology, device_filter_string, target)


def get_route_summaries(
    topology: Topology, device_filter_string: Optional[str] = None, target: Optional[str] = None
) -> ShowRouteSummaryCommandResult:
    """
    Pulls all route summary information from the topology
    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only show specific hostnames or serial numbers.
    :param target: Single serial number to target with this command
    """
    return FirewallCommand.get_routing_summary(topology, device_filter_string, target)


def get_routes(topology: Topology,
               device_filter_string: Optional[str] = None, target: Optional[str] = None
               ) -> ShowRoutingRouteCommandResult:
    """
    Pulls all route summary information from the topology
    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only show specific hostnames or serial numbers.
    :param target: Single serial number to target with this command
    """
    return FirewallCommand.get_routes(topology, device_filter_string, target)


def get_system_info(
    topology: Topology,
    device_filter_string: Optional[str] = None,
    target: Optional[str] = None
) -> ShowSystemInfoCommandResult:
    """
    Gets information from all PAN-OS systems in the topology.
    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only show specific hostnames or serial numbers.
    :param target: Single target device, by serial number
    """
    return UniversalCommand.get_system_info(topology, device_filter_string, target)


def get_device_groups(
    topology: Topology,
    device_filter_string: Optional[str] = None,
) -> List[DeviceGroupInformation]:
    """
    Gets the operational information of the device groups in the topology.
    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only show specific hostnames or serial numbers.
    """
    return PanoramaCommand.get_device_groups(topology, device_filter_string)


def get_template_stacks(
    topology: Topology,
    device_filter_string: Optional[str] = None,
) -> List[TemplateStackInformation]:
    """
    Gets the operational information of the template-stacks in the topology.
    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only show specific hostnames or serial numbers.
    """
    return PanoramaCommand.get_template_stacks(topology, device_filter_string)


def get_global_counters(
    topology: Topology,
    device_filter_string: Optional[str] = None,
    target: Optional[str] = None
) -> ShowCounterGlobalCommmandResult:
    """
    Gets global counter information from all the PAN-OS firewalls in the topology
    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only show specific hostnames or serial numbers.
    :param target: Single serial number to target with this command
    """
    return FirewallCommand.get_counter_global(topology, device_filter_string, target)


def get_bgp_peers(
    topology: Topology,
    device_filter_string: Optional[str] = None,
    target: Optional[str] = None
) -> ShowRoutingProtocolBGPCommandResult:
    """
    Retrieves all BGP peer information from the PAN-OS firewalls in the topology.
    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only show specific hostnames or serial numbers.
    :param target: Single serial number to target with this command
    """
    return FirewallCommand.get_bgp_peers(topology, device_filter_string, target)


def get_available_software(
    topology: Topology,
    device_filter_string: Optional[str] = None,
    target: Optional[str] = None
) -> SoftwareVersionCommandResult:
    """
    Check the devices for software that is available to be installed.
    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only show specific hostnames or serial numbers.
    :param target: Single serial number to target with this command
    """
    return UniversalCommand.get_available_software(topology, device_filter_string, target)


def get_ha_state(
    topology: Topology,
    device_filter_string: Optional[str] = None,
    target: Optional[str] = None
) -> List[ShowHAState] | ShowHAState:
    """
    Get the HA state and associated details from the given device and any other details.
    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only show specific hostnames or serial numbers.
    :param target: Single serial number to target with this command
    :param target: Single serial number to target with this command
    """
    return FirewallCommand.get_ha_status(topology, device_filter_string, target)


def get_jobs(
    topology: Topology,
    device_filter_string: Optional[str] = None,
    status: Optional[str] = None,
    job_type: Optional[str] = None,
    id: Optional[str] = None,
    target: Optional[str] = None
) -> Union[list[ShowJobsAllResultData], ShowJobsAllResultData]:
    """
    Get all the jobs from the devices in the environment, or a single job when ID is specified.

    Jobs are sorted by the most recent queued and are returned in a way that's consumable by Generic Polling.
    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only show specific hostnames or serial numbers.
    :param status: Filter returned jobs by status
    :param job_type: Filter returned jobs by type
    :param id: Filter by ID
    :param target: Single serial number to target with this command
    """
    _id = arg_to_number(id)

    return UniversalCommand.show_jobs(
        topology,
        device_filter_string,
        job_type=job_type,
        status=status,
        id=_id,
        target=target
    )


def download_software(
    topology: Topology,
    version: str,
    device_filter_string: Optional[str] = None,
    sync: Optional[bool] = False,
    target: Optional[str] = None
) -> DownloadSoftwareCommandResult:
    """
    Download The provided software version onto the device.
    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only install to sepecific devices or serial numbers
    :param version: software version to upgrade to, ex. 9.1.2
    :param sync: If provided, runs the download synchronously - make sure 'execution-timeout' is increased.
    :param target: Single serial number to target with this command
    """
    return UniversalCommand.download_software(
        topology, version, device_filter_str=device_filter_string, sync=argToBoolean(sync), target=target)


def install_software(
    topology: Topology,
    version: str,
    device_filter_string: Optional[str] = None,
    sync: Optional[bool] = False,
    target: Optional[str] = None
) -> InstallSoftwareCommandResult:
    """
    Install the given software version onto the device. Download the software first with
    pan-os-platform-download-software

    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only install to specific devices or serial numbers
    :param version: software version to upgrade to, ex. 9.1.2
    :param sync: If provided, runs the download synchronously - make sure 'execution-timeout' is increased.
    """
    return UniversalCommand.install_software(
        topology, version, device_filter_str=device_filter_string, sync=argToBoolean(sync), target=target)


def reboot(topology: Topology, target: str) -> RestartSystemCommandResult:
    """
    Reboot the given host.

    :param topology: `Topology` instance !no-auto-argument
    :param target: ID of host (serial or hostname) to reboot
    """
    return UniversalCommand.reboot(topology, hostid=target)


def system_status(topology: Topology, target: str) -> CheckSystemStatus:
    """
    Checks the status of the given device, checking whether it's up or down and the operational mode normal

    :param topology: `Topology` instance !no-auto-argument
    :param target: ID of host (serial or hostname) to check.
    """
    return UniversalCommand.check_system_availability(topology, hostid=target)


def update_ha_state(topology: Topology, target: str, state: str) -> HighAvailabilityStateStatus:
    """
    Checks the status of the given device, checking whether it's up or down and the operational mode normal

    :param topology: `Topology` instance !no-auto-argument
    :param target: ID of host (serial or hostname) to update the state.
    :param state: New state.
    """
    return FirewallCommand.change_status(topology, hostid=target, state=state)


"""Hygiene Commands"""


def check_log_forwarding(
    topology: Topology,
    device_filter_string: Optional[str] = None
) -> ConfigurationHygieneCheckResult:
    """
    Checks all log forwarding profiles to confirm at least one meets PAN best practices.  This will validate profiles
    configured anywhere in Panorama or the firewalls - device groups, virtual systems, and templates.

    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only check given device
    """
    return HygieneLookups.check_log_forwarding_profiles(topology, device_filter_str=device_filter_string)


def check_vulnerability_profiles(
    topology: Topology,
    device_filter_string: Optional[str] = None,
    minimum_block_severities: str = "critical,high",
    minimum_alert_severities: str = "medium,low"
) -> ConfigurationHygieneCheckResult:
    """
    Checks the configured Vulnerability profiles to ensure at least one meets best practices. This will validate profiles
    configured anywhere in Panorama or the firewalls - device groups, virtual systems, and templates.

    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only check given device
    :param minimum_block_severities: csv list of severities that must be in drop/reset/block-ip mode.
    :param minimum_alert_severities: csv list of severities that must be in alert/default or higher mode.
    """
    return HygieneLookups.check_vulnerability_profiles(
        topology,
        device_filter_str=device_filter_string,
        minimum_block_severities=argToList(minimum_block_severities),
        minimum_alert_severities=argToList(minimum_alert_severities)
    )


def check_spyware_profiles(
    topology: Topology,
    device_filter_string: Optional[str] = None,
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
    return HygieneLookups.check_spyware_profiles(
        topology,
        device_filter_str=device_filter_string,
        minimum_block_severities=argToList(minimum_block_severities),
        minimum_alert_severities=argToList(minimum_alert_severities)
    )


def check_url_filtering_profiles(
    topology: Topology,
    device_filter_string: Optional[str] = None
) -> ConfigurationHygieneCheckResult:
    """
    Checks the configured URL Filtering profiles to ensure at least one meets best practices.

    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only check given device
    """
    return HygieneLookups.check_url_filtering_profiles(
        topology,
        device_filter_str=device_filter_string,
    )


def get_conforming_url_filtering_profiles(
    topology: Topology,
    device_filter_string: Optional[str] = None
) -> List[PanosObjectReference]:
    """
    Returns a list of existing PANOS URL filtering objects that conform to best practices.

    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only check given device
    """
    return HygieneLookups.get_all_conforming_url_filtering_profiles(
        topology,
        device_filter_str=device_filter_string,
    )


def get_conforming_spyware_profiles(
    topology: Topology,
    device_filter_string: Optional[str] = None,
    minimum_block_severities: str = "critical,high",
    minimum_alert_severities: str = "medium,low"
) -> List[PanosObjectReference]:
    """
    Returns all Anti-spyware profiles that conform to best practices.

    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only check given device
    :param minimum_block_severities: csv list of severities that must be in drop/reset/block-ip mode.
    :param minimum_alert_severities: csv list of severities that must be in alert/default or higher mode.
    """
    return HygieneLookups.get_all_conforming_spyware_profiles(
        topology,
        device_filter_str=device_filter_string,
        minimum_block_severities=argToList(minimum_block_severities),
        minimum_alert_severities=argToList(minimum_alert_severities)
    )


def get_conforming_vulnerability_profiles(
    topology: Topology,
    device_filter_string: Optional[str] = None,
    minimum_block_severities: str = "critical,high",
    minimum_alert_severities: str = "medium,low"
) -> List[PanosObjectReference]:
    """
    Returns all Vulnerability profiles that conform to best practices.

    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only check given device
    :param minimum_block_severities: csv list of severities that must be in drop/reset/block-ip mode.
    :param minimum_alert_severities: csv list of severities that must be in alert/default or higher mode.
    """
    return HygieneLookups.get_all_conforming_vulnerability_profiles(
        topology,
        device_filter_str=device_filter_string,
        minimum_block_severities=argToList(minimum_block_severities),
        minimum_alert_severities=argToList(minimum_alert_severities)
    )


def check_security_zones(topology: Topology, device_filter_string: Optional[str] = None) -> ConfigurationHygieneCheckResult:
    """
    Check configured security zones have correct settings.

    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only check given device
    """
    return HygieneLookups.check_security_zones(topology, device_filter_str=device_filter_string)


def check_security_rules(topology: Topology, device_filter_string: Optional[str] = None) -> ConfigurationHygieneCheckResult:
    """
    Check security rules are configured correctly.

    :param topology: `Topology` instance !no-auto-argument
    :param device_filter_string: String to filter to only check given device
    """
    return HygieneLookups.check_security_rules(topology, device_filter_str=device_filter_string)


def hygiene_issue_dict_to_object(issue_dicts: Union[List[dict], dict]) -> List[ConfigurationHygieneIssue]:
    """
    Converts the given list of hygiene issues, which is a list of dictionaries, into the dataclass objects.
    This simplifies the handling of the issues within the fix functions.

    :param issue_dicts: List of dictionaries which represent instances of `ConfigurationHygieneIssue`
    """
    if isinstance(issue_dicts, dict):
        issue_dicts = [issue_dicts]

    issues: List[ConfigurationHygieneIssue] = []
    for issue_dict in issue_dicts:
        container_name = issue_dict.get("containername") or issue_dict.get("container_name")
        issue_code = issue_dict.get("issuecode") or issue_dict.get("issue_code")
        issue_dict["container_name"] = container_name
        issue_dict["issue_code"] = issue_code
        if issue_dict.get("containername"):
            del (issue_dict["containername"])

        if issue_dict.get("issuecode"):
            del (issue_dict["issuecode"])

        issues.append(
            ConfigurationHygieneIssue(**issue_dict)
        )
    return issues


def fix_log_forwarding(topology: Topology, issue: List) -> List[ConfigurationHygieneFix]:
    """
    :param topology: `Topology` instance !no-auto-argument
    :param issue: Dictionary of Hygiene issue, from a hygiene check command. Can be a list.
    """
    return HygieneRemediation.fix_log_forwarding_profile_enhanced_logging(topology, issues=hygiene_issue_dict_to_object(issue))


def fix_security_zone_log_setting(
    topology: Topology,
    issue: List,
    log_forwarding_profile_name: str
) -> List[ConfigurationHygieneFix]:
    """
    Fixes security zones that are configured without a valid log forwarding profile.
    :param topology: `Topology` instance !no-auto-argument
    :param issue: Dictionary of Hygiene issue, from a hygiene check command. Can be a list.
    :param log_forwarding_profile_name: Name of log forwarding profile to set.
    """
    return HygieneRemediation.fix_security_zone_no_log_setting(
        topology,
        log_forwarding_profile=log_forwarding_profile_name,
        issues=hygiene_issue_dict_to_object(issue)
    )


def fix_security_rule_log_setting(
    topology: Topology,
    issue: List,
    log_forwarding_profile_name: str
) -> List[ConfigurationHygieneFix]:
    """
    Fixed security rules that have incorrect log settings by adding a log forwarding profile and setting
    log at session end.
    :param topology: `Topology` instance !no-auto-argument
    :param issue: Dictionary of Hygiene issue, from a hygiene check command. Can be list.
    :param log_forwarding_profile_name: Name of log forwarding profile to use as log setting.
    """
    return HygieneRemediation.fix_secuity_rule_log_settings(
        topology,
        log_forwarding_profile_name=log_forwarding_profile_name,
        issues=hygiene_issue_dict_to_object(issue)
    )


def fix_security_rule_security_profile_group(
    topology: Topology,
    issue: List,
    security_profile_group_name: str
) -> List[ConfigurationHygieneFix]:
    """
    Fixed security rules that have no configured SPG by setting one.

    :param topology: `Topology` instance !no-auto-argument
    :param issue: Dictionary of Hygiene issue, from a hygiene check command
    :param security_profile_group_name: Name of Security profile group to use as log setting.
    """
    return HygieneRemediation.fix_security_rule_security_profile_group(
        topology,
        security_profile_group_name=security_profile_group_name,
        issues=hygiene_issue_dict_to_object(issue)
    )


class ObjectTypeEnum(enum.Enum):
    ADDRESS = "AddressObject"
    ADDRESS_GROUP = "AddressGroup"
    SERVICE_GROUP = "ServiceGroup"
    SERVICE = "ServiceObject"
    APPLICATION = "ApplicationObject"
    APPLICATION_GROUP = "ApplicationGroup"
    LOG_FORWARDING_PROFILE = "LogForwardingProfile"
    SECURITY_PROFILE_GROUP = "SecurityProfileGroup"


def get_object(
    topology: Topology,
    object_type: ObjectTypeEnum,
    device_filter_string: Optional[str] = None,
    object_name: Optional[str] = None,
    parent: Optional[str] = None,
    use_regex: Optional[str] = None
) -> List[PanosObjectReference]:
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
    return ObjectGetter.get_object_reference(
        topology=topology,
        device_filter_string=device_filter_string,
        object_name=object_name,
        # Fixing the ignore below would rfequire adding union handling to code generation script.
        object_type=object_type,  # type: ignore
        container_filter=parent,
        use_regex=use_regex
    )


def get_device_state(topology: Topology, target: str, filename: str = None, ip_address: Optional[str] = None) -> dict:
    """
    Get the device state from the provided device target (serial number). Note that this will attempt to connect directly to the
    firewall as there is no way to get the device state for a firewall via Panorama.

    :param topology: `Topology` instance !no-auto-argument
    :param target: String to filter to only show specific hostnames or serial numbers.
    :param ip_address: Manually determined ip address of a Service Route firewall.
    """
    if not filename:
        file_name = f"{target}_device_state.tar.gz"
    else:
        file_name = f"{target}_{filename}_device_state.tar.gz"

    return fileResult(
        filename=file_name,
        data=FirewallCommand.get_device_state(topology, target, ip_address),
        file_type=EntryType.ENTRY_INFO_FILE
    )


def get_topology() -> Topology:
    """
    Builds and returns the Topology instance
    """
    params = demisto.params()
    server_url = params.get('server')
    port = arg_to_number(arg=params.get('port', '443'))
    parsed_url = urlparse(server_url)
    hostname = parsed_url.hostname
    api_key = str(params.get('key')) or str((params.get('credentials') or {}).get('password', ''))  # type: ignore

    return Topology.build_from_string(
        hostname,
        username="",
        password="",
        api_key=api_key,
        port=port
    )


def dataclasses_to_command_results(
    result: Any,
    empty_result_message: str = "No results.",
    override_table_name: Optional[str] = "",
    override_table_headers: Optional[List[str]] = None
):
    """
    Given a dataclass or list of dataclasses, convert it into a tabular format and finally return CommandResults to demisto.
    :param result: Dataclass or list of dataclasses
    :param empty_result_message: If the result data is none, return this message
    :param override_table_name: If given, the name of the table is set to this value specifically instead of the name in the
        dataclass.
    :param override_table_headers: If given, the markdown table will show these headers instead in the order provided.
    """
    if not result:
        return CommandResults(
            readable_output=empty_result_message,
        )

    # Convert the dataclasses into dicts
    outputs: Union[list, dict] = {}
    summary_list = []

    if not hasattr(result, "summary_data"):
        # If this isn't a regular summary/result return, but instead, is just one object or a list of flat
        # objects
        if isinstance(result, list):
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
            outputs["Result"] = [vars(x) for x in result.result_data if hasattr(x, "__dict__")]  # type: ignore

        title = result._title
        output_prefix = result._output_prefix

    extra_args = {}
    if hasattr(result, "_outputs_key_field"):
        extra_args["outputs_key_field"] = getattr(result, "_outputs_key_field")

    readable_output = tableToMarkdown(
        override_table_name or title,
        summary_list,
        removeNull=True,
        headers=override_table_headers
    )
    command_result = CommandResults(
        outputs_prefix=output_prefix,
        outputs=outputs,
        readable_output=readable_output,
        **extra_args
    )
    return command_result


def pan_os_get_running_config(args: dict):
    """
    Get running config file
    """

    params = {
        'type': 'op',
        'key': API_KEY,
        'cmd': '<show><config><running></running></config></show>'
    }

    if args.get("target"):
        params["target"] = args.get("target")
    file_name_arg = args.get("filename")
    target = args.get("target")
    if file_name_arg != 'running_config' and file_name_arg and target:
        file_name = target + '_' + file_name_arg + '_running_config'
    else:
        file_name = file_name_arg
    result = http_request(URL, 'POST', params=params, is_xml=True)
    return fileResult(file_name, result)


def pan_os_get_merged_config(args: dict):
    """
    Get merged config file
    """

    params = {
        'type': 'op',
        'key': API_KEY,
        'cmd': '<show><config><merged></merged></config></show>'
    }

    if args.get("target"):
        params["target"] = args.get("target")

    result = http_request(URL, 'POST', params=params, is_xml=True)

    return fileResult("merged_config", result)


def build_template_xpath(name: Optional[str]):
    _xpath = "/config/devices/entry[@name='localhost.localdomain']/template"
    if name:
        _xpath = f"{_xpath}/entry[@name='{name}']"
    return _xpath


def parse_list_templates_response(entries):
    def parse_template_variables(_variables):

        # when there is only one variable it is not returned as a list
        if isinstance(_variables, dict):
            _variables = [_variables]

        return [
            {
                'Name': variable.get('@name'),
                'Type': list(variable.get('type'))[0] if variable.get('type') else None,
                'Value': list(variable.get('type').values())[0] if variable.get('type') else None,
                'Description': variable.get('description')
            }
            for variable in _variables
        ]

    table, context = [], []

    for entry in entries:
        parse_pan_os_un_committed_data(entry, ['@admin', '@dirtyId', '@time'])
        name = entry.get('@name')
        description = entry.get('description')
        variables = entry.get('variable', {}).get('entry', [])
        context.append(
            {
                'Name': name,
                'Description': description,
                'Variable': parse_template_variables(variables)
            }
        )
        table.append(
            {
                'Name': name,
                'Description': description,
                'Variable': extract_objects_info_by_key(variables, '@name')
            }
        )

    return table, context


def pan_os_list_templates(template_name: Optional[str]):
    params = {
        'type': 'config',
        'action': 'get',
        'key': API_KEY,
        'xpath': build_template_xpath(template_name)
    }

    return http_request(URL, 'GET', params=params)


def pan_os_list_templates_command(args):
    template_name = args.get('template_name')
    if not DEVICE_GROUP and VSYS:
        raise DemistoException('The pan-os-list-templates command should only be used for Panorama instances')

    raw_response = pan_os_list_templates(template_name)
    result = raw_response.get('response', {}).get('result', {})

    # the 'entry' key could be a single dict as well.
    entries = dict_safe_get(result, ['template', 'entry'], default_return_value=result.get('entry'))
    if not isinstance(entries, list):  # when only one template is returned it could be returned as a dict.
        entries = [entries]

    if not template_name:
        # if name was provided, api returns one entry so no need to do limit/pagination
        page = arg_to_number(args.get('page'))
        page_size = arg_to_number(args.get('page_size')) or DEFAULT_LIMIT_PAGE_SIZE
        limit = arg_to_number(args.get('limit')) or DEFAULT_LIMIT_PAGE_SIZE
        entries = do_pagination(entries, page=page, page_size=page_size, limit=limit)

    table, templates = parse_list_templates_response(entries)

    return CommandResults(
        raw_response=raw_response,
        outputs=templates,
        readable_output=tableToMarkdown(
            'Templates:',
            table,
            removeNull=True
        ),
        outputs_prefix='Panorama.Template',
        outputs_key_field='Name'
    )


def build_nat_xpath(name: Optional[str], pre_post: str, element: Optional[str] = None, filters: dict | None = None,
                    query: str | None = None):
    _xpath = f"{XPATH_RULEBASE}{pre_post}/nat"

    if query:
        _xpath = f"{_xpath}/rules/entry[{query}]"
    elif xpath_filter := build_xpath_filter(name_match=name, filters=filters):
        _xpath = f"{_xpath}/rules/entry[{xpath_filter}]"

    if element:
        _xpath = f"{_xpath}/{element}"

    return _xpath


def get_pan_os_nat_rules(show_uncommited: bool, name: Optional[str] = None, pre_post: Optional[str] = None,
                         filters: dict | None = None, query: str | None = None):
    if DEVICE_GROUP and not pre_post:  # panorama instances must have the pre_post argument!
        raise DemistoException(f'The pre_post argument must be provided for panorama instance')

    params = {
        'type': 'config',
        'action': 'get' if show_uncommited else 'show',
        'key': API_KEY,
        # rulebase is for firewall instance.
        'xpath': build_nat_xpath(name, 'rulebase' if VSYS else pre_post, filters=filters, query=query)  # type: ignore[arg-type]
    }

    return http_request(URL, 'POST', params=params)


def parse_pan_os_list_nat_rules(entries: Union[List, Dict], show_uncommited) -> List[Dict]:
    def parse_source_translation(_entry):

        source_translation_object = _entry.get('source-translation', {})

        for _source_translation_type in ('dynamic-ip', 'dynamic-ip-and-port', 'static-ip'):
            if _source_translation := source_translation_object.get(_source_translation_type):
                pretty_context = camelize_string(src_str=_source_translation_type, delim='-')
                if _source_translation_type == 'dynamic-ip-and-port':
                    if interface := _source_translation.get('interface-address'):
                        return {pretty_context: {
                            'InterfaceAddress': extract_objects_info_by_key(interface, 'interface')}
                        }

                return {pretty_context: {
                    'TranslatedAddress': extract_objects_info_by_key(_source_translation, 'translated-address')}
                }
        return None

    def parse_destination_translation(_entry):
        destination_translation_object = {}
        if destination_translation := _entry.get('destination-translation'):
            if translated_port := destination_translation.get('translated-port'):
                destination_translation_object['TranslatedPort'] = translated_port
            if translated_address := destination_translation.get('translated-address'):
                destination_translation_object['TranslatedAddress'] = translated_address
            if dns_rewrite := destination_translation.get('dns-rewrite'):
                destination_translation_object['DNSRewrite'] = dns_rewrite.get('direction')
        return destination_translation_object if destination_translation_object else None

    def parse_dynamic_destination_translation(_entry):
        dynamic_destination_translation_object = {}
        if destination_translation := _entry.get('dynamic-destination-translation'):
            if translated_port := destination_translation.get('translated-port'):
                dynamic_destination_translation_object['TranslatedPort'] = translated_port
            if translated_address := destination_translation.get('translated-address'):
                dynamic_destination_translation_object['TranslatedAddress'] = translated_address
            if distribution := destination_translation.get('distribution'):
                dynamic_destination_translation_object['DistributionMethod'] = distribution
        return dynamic_destination_translation_object if dynamic_destination_translation_object else None

    if show_uncommited:
        for entry in entries:
            parse_pan_os_un_committed_data(entry, keys_to_remove=['@admin', '@time', '@dirtyId', '@uuid', '@loc'])

    return [
        {
            'Name': entry.get('@name'),
            'Tags': extract_objects_info_by_key(entry, 'tag'),
            'SourceZone': extract_objects_info_by_key(entry, 'from'),
            'DestinationZone': extract_objects_info_by_key(entry, 'to'),
            'SourceAddress': extract_objects_info_by_key(entry, 'source'),
            'DestinationAddress': extract_objects_info_by_key(entry, 'destination'),
            'DestinationInterface': extract_objects_info_by_key(entry, 'to-interface'),
            'Service': extract_objects_info_by_key(entry, 'service'),
            'Description': extract_objects_info_by_key(entry, 'description'),
            'Disabled': extract_objects_info_by_key(entry, 'disabled') or 'no',
            'SourceTranslation': parse_source_translation(entry),
            'DestinationTranslation': parse_destination_translation(entry),
            'DynamicDestinationTranslation': parse_dynamic_destination_translation(entry)
        } for entry in entries
    ]


def pan_os_list_nat_rules_command(args):
    name = args.get('name')
    pre_post = args.get('pre_post')
    show_uncommitted = argToBoolean(args.get('show_uncommitted', False))
    filters = assign_params(
        tags=argToList(args.get('tags')),
        nat_type=args.get('nat_type')
    )
    if nat_type := filters.pop('nat_type', None):  # Replace the key name from 'nat_type' to 'nat-type'.
        filters['nat-type'] = nat_type
    query = args.get('query')

    raw_response = get_pan_os_nat_rules(name=name, pre_post=pre_post,
                                        show_uncommited=show_uncommitted, filters=filters, query=query)
    result = raw_response.get('response', {}).get('result', {})

    # the 'entry' key could be a single dict as well.
    entries = dict_safe_get(result, ['nat', 'rules', 'entry'], default_return_value=[]) or result.get('entry')
    if not isinstance(entries, list):  # when only one nat rule is returned it could be returned as a dict.
        entries = [entries]

    if disabled := args.get('disabled'):
        entries = filter_rules_by_status(disabled, entries)

    if not name:
        # filter the nat-rules by limit - name means we get only a single entry anyway.
        page = arg_to_number(args.get('page'))
        page_size = arg_to_number(args.get('page_size')) or DEFAULT_LIMIT_PAGE_SIZE
        limit = arg_to_number(args.get('limit')) or DEFAULT_LIMIT_PAGE_SIZE
        entries = do_pagination(entries, page=page, page_size=page_size, limit=limit)

    nat_rules = parse_pan_os_list_nat_rules(entries, show_uncommited=show_uncommitted)

    return CommandResults(
        raw_response=raw_response,
        outputs=nat_rules,
        readable_output=tableToMarkdown(
            'Nat Policy Rules:',
            nat_rules,
            removeNull=True,
            headerTransform=pascalToSpace,
            headers=[
                'Name', 'Tags', 'SourceZone', 'DestinationZone', 'SourceAddress', 'Disabled',
                'DestinationAddress', 'DestinationInterface', 'Service', 'Description'
            ]
        ),
        outputs_prefix='Panorama.NAT',
        outputs_key_field='Name'
    )


def create_nat_rule(args):
    def _set_up_body_request():
        def _set_up_destination_translation_body_request():
            destination_translation_type = args.get('destination_translation_type')
            if destination_translation_type != 'none':
                destination_translation_body_request = {}
                if destination_translated_port := args.get('destination_translated_port'):
                    destination_translation_body_request['translated-port'] = destination_translated_port
                if destination_translated_address := args.get('destination_translated_address'):
                    destination_translation_body_request['translated-address'] = destination_translated_address
                if destination_translation_type == 'static_ip':
                    if destination_dns_rewrite_direction := args.get('destination_dns_rewrite_direction'):
                        destination_translation_body_request['dns-rewrite'] = {
                            'direction': destination_dns_rewrite_direction
                        }
                    return {'destination-translation': destination_translation_body_request}
                else:  # destination_translation_type == dynamic-ip
                    if method := args.get('destination_translation_distribution_method'):
                        destination_translation_body_request['distribution'] = method
                    return {'dynamic-destination-translation': destination_translation_body_request}
            return {}

        def _set_up_source_translation_body_request():
            source_translation_type = args.get('source_translation_type')
            if source_translation_type != 'none':
                source_translated_address_type = args.get('source_translated_address_type')
                if source_translated_address_type == 'translated-address':
                    source_translated_address = args.get('source_translated_address')
                    if source_translated_address:
                        return {
                            'source-translation': {
                                source_translation_type: prepare_pan_os_objects_body_request(
                                    'translated-address',
                                    source_translated_address,
                                    is_list=False if source_translation_type == 'static-ip' else True
                                    # dynamic-ip and dynamic-ip-and-port can be a list of IPs
                                )
                            }
                        }
                    else:
                        raise DemistoException(
                            'source_translated_address must be provided '
                            'if source_translated_address_type == translated-address'
                        )
                else:  # interface-address
                    source_translated_interface = args.get('source_translated_interface')
                    if source_translated_interface:
                        if source_translation_type == 'dynamic-ip-and-port':
                            return {
                                'source-translation': {
                                    'dynamic-ip-and-port': {
                                        'interface-address': prepare_pan_os_objects_body_request(
                                            'interface', source_translated_interface, is_list=False
                                        )
                                    }
                                }
                            }
                        else:
                            raise DemistoException(
                                'interface-address can only be set when source_translation_type == dynamic-ip-and-port'
                            )
                    else:
                        raise DemistoException(
                            'source_translated_interface must be '
                            'provided if source_translation_type == interface-address'
                        )
            return {}

        def _set_up_original_packet_objects_body_request():
            _packets_objects_body_request = {}
            arguments_to_pan_os_paths = {
                'destination_zone': ('to', True),
                'source_zone': ('from', True),
                'source_address': ('source', True),
                'destination_address': ('destination', True),
                'tags': ('tag', True),
                'service': ('service', False),
                'description': ('description', False),
                'nat_type': ('nat-type', False),
                'destination_interface': ('to-interface', False)
            }

            for argument, (pan_os_object_path, is_listable_arg) in arguments_to_pan_os_paths.items():
                if argument_value := args.get(argument):
                    _packets_objects_body_request.update(
                        prepare_pan_os_objects_body_request(pan_os_object_path, argument_value, is_list=is_listable_arg)
                    )

            return _packets_objects_body_request

        _body_request = {}

        if negate_destination := args.get('negate_destination'):
            _body_request['target'] = {
                'negate': negate_destination
            }

        _body_request.update(_set_up_source_translation_body_request())
        _body_request.update(_set_up_destination_translation_body_request())
        _body_request.update(_set_up_original_packet_objects_body_request())

        return _body_request

    if DEVICE_GROUP and not args.get('pre_post'):
        raise DemistoException(f'The pre_post argument must be provided for panorama instance')

    params = {
        'xpath': build_nat_xpath(name=args.get('rulename'), pre_post='rulebase' if VSYS else args.get('pre_post')),
        'element': dict_to_xml(_set_up_body_request()),
        'action': 'set',
        'type': 'config',
        'key': API_KEY
    }

    if args.get('audit_comment'):
        params['audit-comment'] = args.get('audit_comment')

    return http_request(URL, 'POST', params=params)


def pan_os_create_nat_rule_command(args):
    rule_name = args.get('rulename')
    raw_response = create_nat_rule(args)

    return CommandResults(
        raw_response=raw_response,
        readable_output=f'Nat rule {rule_name} was created successfully.'
    )


def pan_os_delete_nat_rule(rule_name, pre_post):
    params = {
        'xpath': build_nat_xpath(name=rule_name, pre_post='rulebase' if VSYS else pre_post),
        'action': 'delete',
        'type': 'config',
        'key': API_KEY
    }

    if DEVICE_GROUP and not pre_post:
        raise DemistoException(f'The pre_post argument must be provided for panorama instance')

    return http_request(URL, 'POST', params=params)


def pan_os_delete_nat_rule_command(args):
    rule_name = args.get('rulename')
    pre_post = args.get('pre_post')
    raw_response = pan_os_delete_nat_rule(rule_name, pre_post)

    return CommandResults(
        raw_response=raw_response,
        readable_output=f'Nat rule {rule_name} was deleted successfully.'
    )


def pan_os_edit_nat_rule(
    rule_name, pre_post, behavior, element_to_change, element_value, object_name, is_listable=True
):
    xpath = build_nat_xpath(name=rule_name, pre_post='rulebase' if VSYS else pre_post, element=element_to_change)

    if element_to_change == 'audit-comment':
        # to update audit-comment of a nat rule, it is required to build a 'cmd' parameter
        params = build_audit_comment_params(
            rule_name, pre_post='rulebase' if VSYS else pre_post, audit_comment=element_value, policy_type='nat'
        )
    else:
        params = {
            'xpath': xpath,
            'element': dict_to_xml(build_body_request_to_edit_pan_os_object(
                behavior=behavior,
                object_name=object_name,
                element_value=element_value,
                is_listable=is_listable,
                xpath=xpath,
                should_contain_entries=True,
                is_commit_required=False
            )
            ),
            'action': 'edit',
            'type': 'config',
            'key': API_KEY
        }

    return http_request(URL, 'POST', params=params)


def pan_os_edit_nat_rule_command(args):
    rule_name, pre_post = args.get('rulename'), args.get('pre_post')
    element_value, element_to_change = args.get('element_value'), args.get('element_to_change')
    behavior = args.get('behavior')

    if DEVICE_GROUP and not pre_post:
        raise DemistoException(f'The pre_post argument must be provided for panorama instance')

    un_listable_objects = {
        'nat_type',
        'destination_interface',
        'destination_translation_dynamic_port',
        'destination_translation_dynamic_ip',
        'destination_translation_dynamic_distribution_method',
        'destination_translation_port',
        'destination_translation_ip',
        'source_translation_interface',
        'source_translation_static_ip',
        'negate_destination',
        'disabled',
        'description',
        'service'
    }

    if behavior != 'replace' and element_to_change in un_listable_objects:
        raise ValueError(f'cannot remove/add {element_to_change}, only replace operation is allowed')

    elements_to_change_mapping_pan_os_paths = {
        'source_zone': ('from', 'from', True),
        'destination_zone': ('to', 'to', True),
        'source_address': ('source', 'source', True),
        'destination_address': ('destination', 'destination', True),
        'nat_type': ('nat-type', 'nat-type', False),
        'destination_interface': ('to-interface', 'to-interface', False),
        'negate_destination': ('target/negate', 'negate', False),
        'tags': ('tag', 'tag', True),
        'disabled': ('disabled', 'disabled', False),
        'service': ('service', 'service', False),
        'description': ('description', 'description', False),
        'source_translation_dynamic_ip': (
            'source-translation/dynamic-ip/translated-address', 'translated-address', True
        ),
        'source_translation_static_ip': (
            'source-translation/static-ip/translated-address', 'translated-address', False
        ),
        'source_translation_dynamic_ip_and_port': (
            'source-translation/dynamic-ip-and-port/translated-address', 'translated-address', True
        ),
        'source_translation_interface': (
            'source-translation/dynamic-ip-and-port/interface-address/interface', 'interface', False
        ),
        'destination_translation_dynamic_port': (
            'dynamic-destination-translation/translated-port', 'translated-port', False
        ),
        'destination_translation_dynamic_ip': (
            'dynamic-destination-translation/translated-address', 'translated-address', False
        ),
        'destination_translation_dynamic_distribution_method': (
            'dynamic-destination-translation/distribution', 'distribution', False
        ),
        'destination_translation_port': ('destination-translation/translated-port', 'translated-port', False),
        'destination_translation_ip': ('destination-translation/translated-address', 'translated-address', False),
        'audit-comment': ('audit-comment', '', False)
    }

    element_to_change, object_name, is_listable = elements_to_change_mapping_pan_os_paths.get(
        element_to_change)  # type: ignore[misc]

    raw_response = pan_os_edit_nat_rule(
        rule_name=rule_name,
        pre_post=pre_post,
        behavior=behavior,
        element_to_change=element_to_change,
        element_value=element_value,
        object_name=object_name,
        is_listable=is_listable
    )

    return CommandResults(
        raw_response=raw_response,
        readable_output=f'Nat rule {rule_name} was edited successfully.'
    )


def build_virtual_routers_xpath(name: Optional[str] = None):
    network_xpath, _ = set_xpath_network()
    _xpath = f'{network_xpath}/virtual-router'
    if name:
        _xpath = f"{_xpath}/entry[@name='{name}']"
    return _xpath


def pan_os_list_virtual_routers(name: Optional[str], show_uncommitted: bool):
    params = {
        'type': 'config',
        'action': 'get' if show_uncommitted else 'show',
        'key': API_KEY,
        'xpath': build_virtual_routers_xpath(name)  # type: ignore[arg-type]
    }

    return http_request(URL, 'POST', params=params)


def parse_pan_os_list_virtual_routers(entries, show_uncommitted):
    if show_uncommitted:
        for entry in entries:
            parse_pan_os_un_committed_data(entry, ['@admin', '@dirtyId', '@time'])

    human_readable, context = [], []

    for entry in entries:
        name = entry.get('@name')
        interface = extract_objects_info_by_key(entry, 'interface')
        rip = entry.get('protocol', {}).get('rip')
        ospf = entry.get('protocol', {}).get('ospf')
        ospf_v3 = entry.get('protocol', {}).get('ospfv3')
        bgp = entry.get('protocol', {}).get('bgp')
        multicast = entry.get('multicast')

        human_readable.append(
            {
                'Name': name,
                'Interface': interface,
                'RIP': extract_objects_info_by_key(rip or {}, 'enable'),
                'OSPF': extract_objects_info_by_key(ospf or {}, 'enable'),
                'OSPFv3': extract_objects_info_by_key(ospf_v3 or {}, 'enable'),
                'BGP': extract_objects_info_by_key(bgp or {}, 'enable'),
                'Multicast': extract_objects_info_by_key(multicast or {}, 'enable'),
                'Static Route': extract_objects_info_by_key(
                    entry.get('routing-table', {}).get('ip', {}).get('static-route', {}).get(
                        'entry', {}),
                    '@name'
                ),
                'Redistribution Profile': extract_objects_info_by_key(
                    ((entry.get('protocol') or {}).get('redist-profile') or {}).get('entry', {}), '@name'
                )
            }
        )
        context.append(
            {
                'Name': name,
                'Interface': interface,
                'RIP': rip,
                'OSPF': ospf,
                'OSPFv3': ospf_v3,
                'BGP': bgp,
                'Multicast': multicast,
                'StaticRoute': entry.get('routing-table'),
                'RedistributionProfile': entry.get('protocol', {}).get('redist-profile'),
                'ECMP': entry.get('ecmp')
            }
        )

    return human_readable, context


def pan_os_list_virtual_routers_command(args):
    name = args.get('virtual_router')
    show_uncommitted = argToBoolean(args.get('show_uncommitted', False))

    raw_response = pan_os_list_virtual_routers(name=name, show_uncommitted=show_uncommitted)
    result = raw_response.get('response', {}).get('result', {})

    entries = dict_safe_get(result, ['virtual-router', 'entry'], default_return_value=result.get('entry'))
    if not isinstance(entries, list):
        entries = [entries]

    if not name:
        # if name was provided, api returns one entry so no need to do limit/pagination
        page = arg_to_number(args.get('page'))
        page_size = arg_to_number(args.get('page_size')) or DEFAULT_LIMIT_PAGE_SIZE
        limit = arg_to_number(args.get('limit')) or DEFAULT_LIMIT_PAGE_SIZE
        entries = do_pagination(entries, page=page, page_size=page_size, limit=limit)

    table, context = parse_pan_os_list_virtual_routers(entries=entries, show_uncommitted=show_uncommitted)

    return CommandResults(
        raw_response=raw_response,
        outputs=context,
        readable_output=tableToMarkdown('Virtual Routers:', table, removeNull=True),
        outputs_prefix='Panorama.VirtualRouter',
        outputs_key_field='Name'
    )


def build_redistribution_profile_xpath(
    virtual_router_name: Optional[str], redistribution_profile_name: Optional[str], element: Optional[str] = None
):
    _xpath = f"{build_virtual_routers_xpath(virtual_router_name)}/protocol/redist-profile"
    if redistribution_profile_name:
        _xpath = f"{_xpath}/entry[@name='{redistribution_profile_name}']"
    if element:
        _xpath = f"{_xpath}/{element}"
    return _xpath


def pan_os_list_redistribution_profile(virtual_router_name: Optional[str], redistribution_profile_name: Optional[str]):
    params = {
        'type': 'config',
        'action': 'get',
        'key': API_KEY,
        'xpath': build_redistribution_profile_xpath(virtual_router_name, redistribution_profile_name)  # type: ignore[arg-type]
    }

    return http_request(URL, 'POST', params=params)


def parse_pan_os_list_redistribution_profiles(entries):
    def extract_bgp_and_ospf_filters(_entry, _filters_types):
        if not _entry:
            return None

        filters_by_types = {
            camelize_string(src_str=filter_type, delim='-'): extract_objects_info_by_key(_entry, filter_type)
            for filter_type in _filters_types if _entry.get(filter_type)
        }

        return filters_by_types if filters_by_types else None

    for entry in entries:  # by default we can get also un-committed redistribution rules objects.
        parse_pan_os_un_committed_data(entry, ['@admin', '@dirtyId', '@time'])

    return [
        {
            'Name': entry.get('@name'),
            'Priority': extract_objects_info_by_key(entry, 'priority'),
            'Action': list(entry.get('action', {}))[0] if entry.get('action') else None,
            'FilterInterface': extract_objects_info_by_key(entry.get('filter', {}), 'interface'),
            'FilterType': extract_objects_info_by_key(entry.get('filter', {}), 'type'),
            'FilterDestination': extract_objects_info_by_key(entry.get('filter', {}), 'destination'),
            'FilterNextHop': extract_objects_info_by_key(entry.get('filter', {}), 'nexthop'),
            'BGP': extract_bgp_and_ospf_filters(
                entry.get('filter', {}).get('bgp'), _filters_types=['community', 'extended-community']
            ),
            'OSPF': extract_bgp_and_ospf_filters(
                entry.get('filter', {}).get('ospf'), _filters_types=['path-type', 'area', 'tag']
            )
        } for entry in entries
    ]


def pan_os_list_redistribution_profile_command(args):
    redistribution_profile_name = args.get('name')
    virtual_router_name = args.get('virtual_router')

    raw_response = pan_os_list_redistribution_profile(virtual_router_name, redistribution_profile_name)

    result = raw_response.get('response', {}).get('result', {})
    entries = result.get('redist-profile', {}).get('entry') or [result.get('entry')]
    if not isinstance(entries, list):
        entries = [entries]

    if not redistribution_profile_name:
        limit = arg_to_number(args.get('limit')) or 50
        entries = do_pagination(entries, limit=limit)

    redistribution_profiles = parse_pan_os_list_redistribution_profiles(entries)

    return CommandResults(
        raw_response=raw_response,
        outputs=redistribution_profiles,
        readable_output=tableToMarkdown(
            f'Redistribution profiles of virtual router {virtual_router_name}:',
            redistribution_profiles,
            removeNull=True,
            headerTransform=pascalToSpace,
            headers=['Name', 'Priority', 'Action', 'FilterType', 'FilterDestination', 'FilterNextHop', 'BGP', 'OSPF']
        ),
        outputs_prefix='Panorama.RedistributionProfile',
        outputs_key_field='Name'
    )


def pan_os_create_redistribution_profile(args):
    def _set_up_body_request():
        def _set_up_ospf_filter_body_request():
            _ospf_filter_body_request = {}
            if filter_ospf_path_type := args.get('filter_ospf_path_type'):
                _ospf_filter_body_request.update(prepare_pan_os_objects_body_request('path-type', filter_ospf_path_type))
            if filter_ospf_area := args.get('filter_ospf_area'):
                _ospf_filter_body_request.update(prepare_pan_os_objects_body_request('area', filter_ospf_area))
            if filter_ospf_tag := args.get('filter_ospf_tag'):
                _ospf_filter_body_request.update(prepare_pan_os_objects_body_request('tag', filter_ospf_tag))

            return {'ospf': _ospf_filter_body_request} if _ospf_filter_body_request else {}

        def _set_up_bgp_filter_body_request():
            _bgp_filter_body_request = {}
            if filter_bgp_community := args.get('filter_bgp_community'):
                _bgp_filter_body_request.update(prepare_pan_os_objects_body_request('community', filter_bgp_community))
            if filter_bgp_extended_community := args.get('filter_bgp_extended_community'):
                _bgp_filter_body_request.update(
                    prepare_pan_os_objects_body_request('extended-community', filter_bgp_extended_community)
                )
            return {'bgp': _bgp_filter_body_request} if _bgp_filter_body_request else {}

        def _set_up_general_filter_body_request():
            _general_filters_body_request = {}
            _arguments_to_pan_os_paths = {
                'filter_source_type': 'type',
                'interface': 'interface',
                'destination': 'destination',
                'nexthop': 'nexthop'
            }

            for argument, pan_os_object_path in _arguments_to_pan_os_paths.items():
                if argument_value := args.get(argument):
                    _general_filters_body_request.update(prepare_pan_os_objects_body_request(pan_os_object_path, argument_value))

            return _general_filters_body_request

        _body_request = {}

        if priority := args.get('priority'):
            _body_request['priority'] = priority
        if action := args.get('action'):
            _body_request['action'] = f'<{action}/>'

        if {
            'filter_source_type', 'destination', 'nexthop', 'interface', 'filter_ospf_area', 'filter_ospf_tag',
            'filter_ospf_path_type', 'filter_bgp_community', 'filter_bgp_extended_community'
        }.intersection(set(args)):
            _body_request['filter'] = {}
            _body_request['filter'].update(_set_up_ospf_filter_body_request())
            _body_request['filter'].update(_set_up_bgp_filter_body_request())
            _body_request['filter'].update(_set_up_general_filter_body_request())

        return _body_request

    params = {
        'xpath': build_redistribution_profile_xpath(
            virtual_router_name=args.get('virtual_router'), redistribution_profile_name=args.get('name')
        ),
        'element': dict_to_xml(_set_up_body_request(), contains_xml_chars=True),
        'action': 'set',
        'type': 'config',
        'key': API_KEY
    }

    return http_request(URL, 'POST', params=params)


def pan_os_create_redistribution_profile_command(args):
    redistribution_profile_name = args.get('name')
    raw_response = pan_os_create_redistribution_profile(args)

    return CommandResults(
        raw_response=raw_response,
        readable_output=f'Redistribution profile {redistribution_profile_name} was created successfully.'
    )


def pan_os_edit_redistribution_profile(
    virtual_router_name,
    redistribution_profile_name,
    element_to_change,
    element_value,
    object_name,
    is_listable,
    behavior
):
    xpath = build_redistribution_profile_xpath(
        virtual_router_name, redistribution_profile_name, element=element_to_change
    )

    params = {
        'xpath': xpath,
        'element': dict_to_xml(build_body_request_to_edit_pan_os_object(
            behavior=behavior,
            object_name=object_name,
            element_value=element_value,
            is_listable=is_listable,
            xpath=xpath,
            should_contain_entries=False,
            is_commit_required=False
        )
        ),
        'action': 'edit',
        'type': 'config',
        'key': API_KEY
    }

    return http_request(URL, 'POST', params=params)


def pan_os_edit_redistribution_profile_command(args):
    virtual_router_name, redistribution_profile_name = args.get('virtual_router'), args.get('name')
    element_value, element_to_change = args.get('element_value'), args.get('element_to_change')
    behavior = args.get('behavior')

    un_listable_objects = {'priority', 'action'}

    if behavior != 'replace' and element_to_change in un_listable_objects:
        raise ValueError(f'cannot remove/add {element_to_change}, only replace operation is allowed')

    elements_to_change_mapping_pan_os_paths = {
        'filter_type': ('filter/type', 'type', True),
        'filter_destination': ('filter/destination', 'destination', True),
        'filter_nexthop': ('filter/nexthop', 'nexthop', True),
        'filter_interface': ('filter/interface', 'interface', True),
        'priority': ('priority', 'priority', False),
        'action': ('action', 'action', False),
        'filter_ospf_area': ('filter/ospf/area', 'area', True),
        'filter_ospf_tag': ('filter/ospf/tag', 'tag', True),
        'filter_ospf_path_type': ('filter/ospf/path-type', 'path-type', True),
        'filter_bgp_community': ('filter/bgp/community', 'community', True),
        'filter_bgp_extended_community': ('filter/bgp/community', 'extended-community', True)
    }

    element_to_change, object_name, is_listable = elements_to_change_mapping_pan_os_paths.get(
        element_to_change)  # type: ignore[misc]

    raw_response = pan_os_edit_redistribution_profile(
        virtual_router_name=virtual_router_name,
        redistribution_profile_name=redistribution_profile_name,
        element_to_change=element_to_change,
        element_value=element_value,
        object_name=object_name,
        is_listable=is_listable,
        behavior=behavior
    )

    return CommandResults(
        raw_response=raw_response,
        readable_output=f'Redistribution profile {redistribution_profile_name} was edited successfully.'
    )


def pan_os_delete_delete_redistribution_profile(virtual_router, redistribution_profile):
    params = {
        'xpath': build_redistribution_profile_xpath(virtual_router, redistribution_profile),
        'action': 'delete',
        'type': 'config',
        'key': API_KEY
    }

    return http_request(URL, 'POST', params=params)


def pan_os_delete_redistribution_profile_command(args):
    redistribution_profile, virtual_router = args.get('name'), args.get('virtual_router')
    raw_response = pan_os_delete_delete_redistribution_profile(virtual_router, redistribution_profile)

    return CommandResults(
        raw_response=raw_response,
        readable_output=f'Redistribution profile {redistribution_profile} was deleted successfully.'
    )


def build_pbf_xpath(name, pre_post, element_to_change=None, filters: dict | None = None, query: str | None = None):
    _xpath = f'{XPATH_RULEBASE}{pre_post}/pbf'

    if query:
        _xpath = f"{_xpath}/rules/entry[{query}]"
    elif xpath_filter := build_xpath_filter(name_match=name, filters=filters):
        _xpath = f"{_xpath}/rules/entry[{xpath_filter}]"

    if element_to_change:
        _xpath = f'{_xpath}/{element_to_change}'
    return _xpath


def pan_os_list_pbf_rules(name, pre_post, show_uncommitted, filters, query):
    if DEVICE_GROUP and not pre_post:  # panorama instances must have the pre_post argument!
        raise DemistoException(f'The pre_post argument must be provided for panorama instance')

    params = {
        'type': 'config',
        'action': 'get' if show_uncommitted else 'show',
        'key': API_KEY,
        # rulebase is for firewall instance.
        'xpath': build_pbf_xpath(name, 'rulebase' if VSYS else pre_post, filters=filters, query=query)  # type: ignore[arg-type]
    }

    return http_request(URL, 'GET', params=params)


def parse_pan_os_list_pbf_rules(entries, show_uncommitted):
    if show_uncommitted:
        for entry in entries:
            parse_pan_os_un_committed_data(entry, keys_to_remove=['@admin', '@time', '@dirtyId', '@uuid', '@loc'])

    human_readable, context = [], []

    for entry in entries:
        name = extract_objects_info_by_key(entry, '@name')
        description = extract_objects_info_by_key(entry, 'description')
        tags = extract_objects_info_by_key(entry, 'tag')
        source_zone = extract_objects_info_by_key(entry.get('from', {}), 'zone')
        source_interface = extract_objects_info_by_key(entry.get('from', {}), 'interface')
        source_address = extract_objects_info_by_key(entry, 'source')
        source_user = extract_objects_info_by_key(entry, 'source-user')
        destination_address = extract_objects_info_by_key(entry, 'destination')
        disabled = extract_objects_info_by_key(entry, 'disabled')

        human_readable.append(
            {
                'Name': name,
                'Description': description,
                'Tags': tags,
                'Source Zone': source_zone,
                'Source Interface': source_interface,
                'Source Address': source_address,
                'Source User': source_user,
                'Destination Address': destination_address,
                'Action': list(entry['action'])[0] if entry.get('action') else None,
                'Disabled': disabled
            }
        )

        context.append(
            {
                'Name': name,
                'Description': description,
                'Tags': tags,
                'SourceZone': source_zone,
                'SourceInterface': source_interface,
                'SourceAddress': source_address,
                'SourceUser': source_user,
                'DestinationAddress': destination_address,
                'Action': entry.get('action'),
                'EnforceSymmetricReturn': entry.get('enforce-symmetric-return'),
                'Target': entry.get('target'),
                'Application': extract_objects_info_by_key(entry, 'application'),
                'Service': extract_objects_info_by_key(entry, 'service'),
                'Disabled': disabled
            }
        )

    return human_readable, context


def pan_os_list_pbf_rules_command(args):
    name = args.get('rulename')
    pre_post = args.get('pre_post')
    show_uncommitted = argToBoolean(args.get('show_uncommitted', False))
    filters = assign_params(
        tags=argToList(args.get('tags')),
    )
    query = args.get('query')

    raw_response = pan_os_list_pbf_rules(name=name, pre_post=pre_post,
                                         show_uncommitted=show_uncommitted, filters=filters, query=query)
    result = raw_response.get('response', {}).get('result', {})

    # the 'entry' key could be a single dict as well.
    entries = dict_safe_get(result, ['pbf', 'rules', 'entry'], default_return_value=result.get('entry'))
    if not isinstance(entries, list):  # when only one nat rule is returned it could be returned as a dict.
        entries = [entries]

    if not name:
        # filter the pbf-rules by limit - name means we get only a single entry anyway.
        page = arg_to_number(args.get('page'))
        page_size = arg_to_number(args.get('page_size')) or DEFAULT_LIMIT_PAGE_SIZE
        limit = arg_to_number(args.get('limit')) or DEFAULT_LIMIT_PAGE_SIZE
        entries = do_pagination(entries, page=page, page_size=page_size, limit=limit)

    if action := args.get('action'):  # Due to API limitations, we need to filter the action manually.
        entries = list(filter(lambda x: action in x.get('action', {}), entries))
    if disabled := args.get('disabled'):
        entries = filter_rules_by_status(disabled, entries)

    table, pbf_rules = parse_pan_os_list_pbf_rules(entries, show_uncommitted=show_uncommitted)

    return CommandResults(
        raw_response=raw_response,
        outputs=pbf_rules,
        readable_output=tableToMarkdown('Policy Based Forwarding Rules:', table, removeNull=True),
        outputs_prefix='Panorama.PBF',
        outputs_key_field='Name'
    )


def pan_os_create_pbf_rule(args):
    def _set_up_body_request():
        def _set_up_action_body_request():
            _action_body_request = {}  # type: ignore[var-annotated]
            if action := args.get('action'):
                if action == 'forward':
                    _action_body_request['action'] = {'forward': {}}
                    nexthop = args.get('nexthop')
                    if nexthop != 'none':
                        nexthop_value = args.get('nexthop_value')
                        if not nexthop_value:
                            raise DemistoException('nexthop_value argument must be set when nexthop is not none')
                        _action_body_request['action']['forward']['nexthop'] = {nexthop: nexthop_value}
                    if egress_interface := args.get('egress_interface'):
                        _action_body_request['action']['forward']['egress-interface'] = egress_interface
                    else:
                        raise DemistoException(f'egress_interface argument must be set when action == forward')
                else:
                    _action_body_request.update(
                        prepare_pan_os_objects_body_request('action', action, is_empty_tag=True)
                    )
            return _action_body_request

        def _set_up_enforce_symmetric_return_body_request():
            _enforce_symmetric_return_body_request = {}
            # enforce_symmetric_return = 'yes' or 'no' always
            enforce_symmetric_return = args.get('enforce_symmetric_return')
            _enforce_symmetric_return_body_request['enforce-symmetric-return'] = {'enabled': enforce_symmetric_return}

            if enforce_symmetric_return == 'yes' and (nexthop_address_list := args.get('nexthop_address_list')):
                _enforce_symmetric_return_body_request['enforce-symmetric-return'].update(
                    prepare_pan_os_objects_body_request('nexthop-address-list', nexthop_address_list, is_entry=True)
                )
            return _enforce_symmetric_return_body_request

        def _setup_general_rule_body_request():
            _general_rule_body_request = {}
            objects_mapping_pan_os = {
                'source_address': ('source', True),
                'destination_address': ('destination', True),
                'source_user': ('source-user', True),
                'application': ('application', True),
                'service': ('service', True),
                'description': ('description', False),
                'negate_source': ('negate-source', False),
                'negate_destination': ('negate-destination', False)
            }

            for argument, (pan_os_object_path, is_listable) in objects_mapping_pan_os.items():
                if argument_value := args.get(argument):
                    _general_rule_body_request.update(
                        prepare_pan_os_objects_body_request(pan_os_object_path, argument_value, is_list=is_listable)
                    )
            return _general_rule_body_request

        _body_request = {}
        _body_request.update(_set_up_action_body_request())
        _body_request.update(_set_up_enforce_symmetric_return_body_request())
        _body_request.update(_setup_general_rule_body_request())

        if source_zone := args.get('source_zone'):
            _body_request['from'] = prepare_pan_os_objects_body_request('zone', source_zone)

        return _body_request

    if DEVICE_GROUP and not args.get('pre_post'):
        raise DemistoException(f'The pre_post argument must be provided for panorama instance')

    params = {
        'xpath': build_pbf_xpath(name=args.get('rulename'), pre_post='rulebase' if VSYS else args.get('pre_post')),
        'element': dict_to_xml(_set_up_body_request(), contains_xml_chars=True),
        'action': 'set',
        'type': 'config',
        'key': API_KEY
    }

    if args.get('audit_comment'):
        params['audit-comment'] = args.get('audit_comment')

    return http_request(URL, 'POST', params=params)


def pan_os_create_pbf_rule_command(args):
    rule_name = args.get('rulename')
    raw_response = pan_os_create_pbf_rule(args)

    return CommandResults(
        raw_response=raw_response,
        readable_output=f'PBF rule {rule_name} was created successfully.'
    )


def pan_os_edit_pbf_rule(
    rule_name, element_value, pre_post, element_to_change, object_name, is_listable, behavior
):
    xpath = build_pbf_xpath(
        name=rule_name, pre_post='rulebase' if VSYS else pre_post, element_to_change=element_to_change
    )

    if element_to_change == 'audit-comment':
        # to update audit-comment of a pbf rule, it is required to build a 'cmd' parameter
        params = build_audit_comment_params(
            rule_name, pre_post='rulebase' if VSYS else pre_post, audit_comment=element_value, policy_type='pbf'
        )
    else:
        params = {
            'xpath': xpath,
            'element': dict_to_xml(build_body_request_to_edit_pan_os_object(
                behavior=behavior,
                object_name=object_name,
                element_value=element_value,
                is_listable=is_listable,
                xpath=xpath,
                is_entry=True if object_name == 'nexthop-address-list' else False,
                is_empty_tag=True if object_name == 'action' else False
            ),
                contains_xml_chars=True
            ),
            'action': 'edit',
            'type': 'config',
            'key': API_KEY
        }

    return http_request(URL, 'POST', params=params)


def pan_os_edit_pbf_rule_command(args):
    rule_name, pre_post = args.get('rulename'), args.get('pre_post')
    element_value, element_to_change = args.get('element_value'), args.get('element_to_change')
    behavior = args.get('behavior')

    un_listable_objects = {
        'action_forward_no_pbf', 'action_forward_discard', 'description', 'negate_source', 'negate_destination',
        'enforce_symmetric_return', 'action_forward_egress_interface', 'action_forward_nexthop_fqdn',
        'action_forward_nexthop_ip', 'action_forward_no_pbf', 'action_forward_discard', 'disabled'
    }

    if behavior != 'replace' and element_to_change in un_listable_objects:
        raise ValueError(f'cannot remove/add {element_to_change}, only replace operation is allowed')

    elements_to_change_mapping_pan_os_paths = {
        'action_forward_discard': ('action', 'action', False),
        'action_forward_no_pbf': ('action', 'action', False),
        'action_forward_nexthop_ip': ('action/forward/nexthop/ip-address', 'ip-address', False),
        'action_forward_nexthop_fqdn': ('action/forward/nexthop/fqdn', 'fqdn', False),
        'action_forward_egress_interface': ('action/forward/egress-interface', 'egress-interface', False),
        'source_zone': ('from/zone', 'zone', True),
        'enforce_symmetric_return': ('enforce-symmetric-return/enabled', 'enabled', False),
        'nexthop_address_list': ('enforce-symmetric-return/nexthop-address-list', 'nexthop-address-list', False),
        'source_address': ('source', 'source', True),
        'destination_address': ('destination', 'destination_address', True),
        'source_user': ('source-user', 'source-user', True),
        'application': ('application', 'application', True),
        'service': ('service', 'service', True),
        'description': ('description', 'description', False),
        'negate_source': ('negate-source', 'negate-source', False),
        'negate_destination': ('negate-destination', 'negate-destination', False),
        'disabled': ('disabled', 'disabled', False),
        'audit-comment': ('audit-comment', '', False)
    }

    if DEVICE_GROUP and not pre_post:  # panorama instances must have the pre_post argument!
        raise DemistoException(f'The pre_post argument must be provided for panorama instance')

    if element_to_change == 'action_forward_no_pbf':
        element_value = 'no-pbf'

    if element_to_change == 'action_forward_discard':
        element_value = 'discard'

    element_to_change, object_name, is_listable = elements_to_change_mapping_pan_os_paths.get(
        element_to_change)  # type: ignore[misc]

    raw_response = pan_os_edit_pbf_rule(
        rule_name=rule_name,
        pre_post=pre_post,
        element_to_change=element_to_change,
        element_value=element_value,
        object_name=object_name,
        is_listable=is_listable,
        behavior=behavior
    )

    return CommandResults(
        raw_response=raw_response,
        readable_output=f'PBF {rule_name} was edited successfully.'
    )


def pan_os_delete_pbf_rule(rule_name, pre_post):
    params = {
        'xpath': build_pbf_xpath(name=rule_name, pre_post='rulebase' if VSYS else pre_post),
        'action': 'delete',
        'type': 'config',
        'key': API_KEY
    }

    if DEVICE_GROUP and not pre_post:
        raise DemistoException(f'The pre_post argument must be provided for panorama instance')

    return http_request(URL, 'POST', params=params)


def pan_os_delete_pbf_rule_command(args):
    rule_name = args.get('rulename')
    pre_post = args.get('pre_post')

    raw_response = pan_os_delete_pbf_rule(rule_name, pre_post)

    return CommandResults(
        raw_response=raw_response,
        readable_output=f'PBF rule {rule_name} was deleted successfully.'
    )


def build_application_groups_xpath(name: Optional[str], element: Optional[str] = None):
    _xpath = f"{XPATH_OBJECTS}application-group"
    if name:
        _xpath = f"{_xpath}/entry[@name='{name}']"
    if element:
        _xpath = f"{_xpath}/{element}"
    return _xpath


def pan_os_list_application_groups(name: Optional[str], show_uncommitted: bool):
    params = {
        'type': 'config',
        'action': 'get' if show_uncommitted else 'show',
        'key': API_KEY,
        'xpath': build_application_groups_xpath(name)  # type: ignore[arg-type]
    }

    return http_request(URL, 'POST', params=params)


def pan_os_list_application_groups_command(args):
    name = args.get('name')
    show_uncommitted = argToBoolean(args.get('show_uncommitted', False))

    raw_response = pan_os_list_application_groups(name=name, show_uncommitted=show_uncommitted)
    result = raw_response.get('response', {}).get('result', {})

    entries = result.get('application-group', {}).get('entry') or [result.get('entry')]
    if not isinstance(entries, list):
        entries = [entries]

    if not name:
        # if name was provided, api returns one entry so no need to do limit/pagination
        page = arg_to_number(args.get('page'))
        page_size = arg_to_number(args.get('page_size')) or 50
        limit = arg_to_number(args.get('limit')) or 50
        entries = do_pagination(entries, page=page, page_size=page_size, limit=limit)

    if show_uncommitted:
        for entry in entries:
            parse_pan_os_un_committed_data(entry, keys_to_remove=['@admin', '@time', '@dirtyId'])

    application_groups = []
    for entry in entries:
        applications = extract_objects_info_by_key(entry, 'members')
        if not isinstance(applications, list):
            applications = [applications]
        application_groups.append(
            {
                'Name': extract_objects_info_by_key(entry, '@name'),
                'Applications': applications,
                'Members': len(applications)
            }
        )

    return CommandResults(
        raw_response=raw_response,
        outputs=application_groups,
        readable_output=tableToMarkdown(
            f'Application groups:',
            application_groups,
            removeNull=True
        ),
        outputs_prefix='Panorama.ApplicationGroup',
        outputs_key_field='Name'
    )


def pan_os_create_application_group(application_group_name, applications):
    params = {
        'xpath': build_application_groups_xpath(application_group_name),
        'element': dict_to_xml(prepare_pan_os_objects_body_request('members', applications)),
        'action': 'set',
        'type': 'config',
        'key': API_KEY
    }

    return http_request(URL, 'POST', params=params)


def pan_os_create_application_group_command(args):
    application_group_name = args.get('name')
    applications = argToList(args.get('applications'))

    raw_response = pan_os_create_application_group(application_group_name, applications)

    return CommandResults(
        raw_response=raw_response,
        readable_output=f'application-group {application_group_name} was created successfully.',
        outputs={'Name': application_group_name, 'Applications': applications, 'Members': len(applications)},
        outputs_key_field='Name',
        outputs_prefix='Panorama.ApplicationGroup',
    )


def pan_os_edit_application_group(name, applications, action):
    xpath = build_application_groups_xpath(name=name, element='members')

    params = {
        'xpath': xpath,
        'element': dict_to_xml(
            build_body_request_to_edit_pan_os_object(
                behavior=action, object_name='members',
                element_value=applications, is_listable=True, xpath=xpath, is_commit_required=False
            )
        ),
        'action': 'edit',
        'type': 'config',
        'key': API_KEY
    }

    return http_request(URL, 'POST', params=params)


def pan_os_edit_application_group_command(args):
    application_group_name = args.get('name')
    applications = argToList(args.get('applications'))
    action = args.get('action')

    raw_response = pan_os_edit_application_group(name=application_group_name, applications=applications, action=action)

    updated_applications = panorama_get_current_element(
        element_to_change='members',
        xpath=build_application_groups_xpath(application_group_name, 'members'),
        is_commit_required=False
    )

    return CommandResults(
        raw_response=raw_response,
        readable_output=f'application-group {application_group_name} was edited successfully.',
        outputs={
            'Name': application_group_name, 'Applications': updated_applications, 'Members': len(updated_applications)
        },
        outputs_key_field='Name',
        outputs_prefix='Panorama.ApplicationGroup',
    )


def pan_os_delete_application_group(name):
    params = {
        'xpath': build_application_groups_xpath(name),
        'action': 'delete',
        'type': 'config',
        'key': API_KEY
    }

    return http_request(URL, 'POST', params=params)


def pan_os_delete_application_group_command(args):
    application_group_name = args.get('name')

    raw_response = pan_os_delete_application_group(application_group_name)

    return CommandResults(
        raw_response=raw_response,
        readable_output=f'application-group {application_group_name} was deleted successfully.'
    )


def build_tag_xpath(is_shared: bool = False, name: str = None) -> str:
    """Builds the tag request xpath.

    Args:
        is_shared (bool): Whether the device group is shared.
        name (str): The tag name.

    Returns:
        str: The xpath to send the request with.
    """
    _xpath = f"{XPATH_RULEBASE}tag"
    if is_shared:
        _xpath = "/config/shared/tag"
    if name:
        _xpath = f"{_xpath}/entry[@name='{name}']"
    return _xpath


def build_tag_element(disable_override: bool, comment: str, new_name: str = None, color: Optional[str] = None) -> str:
    """Build the request element in XML format

    Args:
        disable_override (bool): Whether to disable overriding the tag.
        comment (str): The comment for the tag.
        new_name (str): When editing - the new name for the tag.
        color (str): The color of the tag.

    Returns:
        str: The element in XML format.
    """
    element = ""
    if DEVICE_GROUP:
        if api_disable_override := 'yes' if disable_override else 'no':
            element = f'<disable-override>{api_disable_override}</disable-override>'
    element += f'<comments>{comment}</comments>'
    if color:
        element += f'<color>{color}</color>'
    if new_name:
        element = f'<entry name="{new_name}">{element}</entry>'
    return element


def pan_os_list_tag(is_shared: bool = False) -> tuple[dict, list]:
    """builds the params and sends the request to get the list of tags.

    Args:
        is_shared (bool): If True, then the list of tags are from the shared device group.

    Returns:
        dict: The raw response of the tags list from panorama.
        list: The list of tags from response.
    """
    params = {
        'type': 'config',
        'action': 'get',
        'key': API_KEY,
        'xpath': build_tag_xpath(is_shared=is_shared)
    }

    raw_response = http_request(URL, 'GET', params=params)
    tags_list_result = extract_tags_list(raw_response)
    add_location(tags_list_result, is_shared_tags=is_shared)
    return raw_response, tags_list_result


def prettify_tags(tags: list) -> list:
    """Prettify the keys in the tags for the HR table.

    Args:
        tags (list): The tags list.

    Return:
        list: the result of the prettify list for the table.
    """
    result = []

    for tag in tags:
        tag['name'] = tag.pop('@name')  # remove the '@'
        new_tag = {'Name': tag['name'], 'Location': tag['location']}

        if 'color' in tag:
            new_tag['Color'] = tag['color']

        if 'comments' in tag:
            new_tag['Comment'] = tag['comments']

        result.append(new_tag)
    return result


def extract_tags_list(raw_response: dict) -> list:
    """Extracts the tags list result from the API's raw response.

    Args:
        raw_response (dict): The raw response.

    Returns:
        list: The list of tags from the response.
    """
    tags_list_result = raw_response.get("response", {}).get("result", {}).get("tag", {})
    tags_list_result = [] if tags_list_result is None else tags_list_result.get("entry", [])

    if not isinstance(tags_list_result, list):
        tags_list_result = [tags_list_result]
    return tags_list_result


def add_location(tags_list: list, is_shared_tags: bool = False) -> None:
    """Adds the location property to the tags.

    Args:
        tags_list (list): The given tags list.
        is_shared_tags (bool, optional): Whether the tags are from shared location.
    """
    for tag in tags_list:
        tag.update({'location': DEVICE_GROUP if not is_shared_tags else 'shared'})


def pan_os_list_tag_command(args: dict) -> CommandResults:
    """Sends the request and returns the result of the command pan-os-list-tag.

    Args:
        args (dict): The command arguments.

    Returns:
        CommandResults: The command results with raw response, outputs and readable outputs.
    """
    include_shared = argToBoolean(args.get('include_shared_tags', False))

    raw_response, tags_list_result = pan_os_list_tag()

    if include_shared:
        _, shared_tags_list_result = pan_os_list_tag(include_shared)
        tags_list_result.extend(shared_tags_list_result)

    for tag in tags_list_result:
        parse_pan_os_un_committed_data(tag, ['@admin', '@dirtyId', '@time'])

    prettify_tags_list = prettify_tags(tags_list_result)
    return CommandResults(
        raw_response=raw_response,
        outputs=tags_list_result,
        readable_output=tableToMarkdown(
            f'Tags:',
            prettify_tags_list,
            ['Name', 'Color', 'Comment', 'Location']
        ),
        outputs_prefix='Panorama.Tag',
        outputs_key_field='name'
    )


def pan_os_create_tag(
    tag_name: str,
    disable_override: bool,
    is_shared: bool,
    comment: str
) -> dict:
    """builds the params and sends the request to create the tag.

    Args:
        tag_name (str): The tag name.
        disable_override (bool): Whether to disable overriding the tag.
        is_shared (bool): Whether to create the tag in the shared device group.
        comment (str): The tag comment.

    Returns:
        dict: The raw response from panorama's API.
    """
    params = {
        'xpath': build_tag_xpath(name=tag_name, is_shared=is_shared),
        'element': build_tag_element(disable_override, comment),
        'action': 'set',
        'type': 'config',
        'key': API_KEY
    }

    return http_request(URL, 'GET', params=params)


def pan_os_create_tag_command(args: dict) -> CommandResults:
    """Creates a tag in Panorama.

    Args:
        args (dict): The commmand arguments to create the tag with.

    Returns:
        CommandResults: The command results with raw response and readable outputs.
    """
    tag_name = args.get('name', '')
    disable_override = argToBoolean(args.get('disable_override', False))
    is_shared = argToBoolean(args.get('is_shared', False))
    comment = args.get('comment', '')

    raw_response = pan_os_create_tag(tag_name,
                                     disable_override,
                                     is_shared,
                                     comment)

    return CommandResults(
        raw_response=raw_response,
        readable_output=f'The tag with name "{tag_name}" was created successfully.',
    )


def pan_os_edit_tag(
    tag_name: str,
    new_tag_name: str,
    disable_override: bool,
    comment: str,
    color: Optional[str]
) -> dict:
    """builds the params and sends the request to edit the tag.

    Args:
        tag_name (str): The tag name to edit.
        new_tag_name (str): The new tag name.
        disable_override (bool): Whether to disable overriding the tag.
        comment (str): The tag comment.

    Returns:
        dict: The raw response from panorama's API.
    """
    params = {
        'xpath': build_tag_xpath(name=tag_name),
        'element': build_tag_element(disable_override, comment, new_name=new_tag_name, color=color),
        'action': 'edit',
        'type': 'config',
        'key': API_KEY
    }

    try:
        response = http_request(URL, 'GET', params=params)
    except Exception as e:
        if 'Status code: 12' in str(e):
            # try in shared group
            params['xpath'] = build_tag_xpath(name=tag_name, is_shared=True)
            response = http_request(URL, 'GET', params=params)
        else:
            raise

    return response


def pan_os_edit_tag_command(args: dict) -> CommandResults:
    """Edits the given tag in Panorama.

    Args:
        args (dict): The command arguments to edit the tag.

    Returns:
        CommandResults: The command results with raw response and readable outputs.
    """
    tag_name = args.get('name', '')
    new_tag_name = args.get('new_name', tag_name)
    disable_override = args.get('disable_override')
    comment = args.get('comment', '')

    # To not override tag properties that are not given in the arguments
    # we need to list the tags and take these properties from there
    _, tags_list = pan_os_list_tag()
    tags_list.extend(pan_os_list_tag(is_shared=True)[1])
    tag_to_edit_from_list = [tag for tag in tags_list if tag['@name'] == tag_name]

    try:
        tag_to_edit = tag_to_edit_from_list[0]
    except IndexError as e:
        raise DemistoException(f"Can't find the tag with name '{tag_name}' in tags list.\n"
                               f"Please run the pan-os-list-tag command and verify that the tag '{tag_name}' exists.")

    parse_pan_os_un_committed_data(tag_to_edit, ['@admin', '@dirtyId', '@time'])

    disable_override = disable_override if disable_override else tag_to_edit.get("disable-override", "no")
    disable_override = argToBoolean(disable_override)
    comment = comment if comment else tag_to_edit.get("comments", "")
    color = tag_to_edit.get("color", "")

    raw_response = pan_os_edit_tag(tag_name, new_tag_name, disable_override, comment, color)

    return CommandResults(
        raw_response=raw_response,
        readable_output=f'The tag with name "{tag_name}" was edited successfully.',
    )


def pan_os_delete_tag(tag_name: str) -> dict:
    """builds the params and sends the request to delete the tag.

    Args:
        tag_name (str): The tag name to delete.

    Returns:
        dict: The raw response from panorama's API.
    """
    params = {
        'xpath': build_tag_xpath(name=tag_name),
        'action': 'delete',
        'type': 'config',
        'key': API_KEY
    }

    try:
        response = http_request(URL, 'GET', params=params)
    except Exception as e:
        if 'Object not present' in str(e) or 'Status code: 12' in str(e):
            # try in shared group
            params['xpath'] = build_tag_xpath(name=tag_name, is_shared=True)
            response = http_request(URL, 'GET', params=params)
        else:
            raise

    return response


def pan_os_delete_tag_command(args: dict) -> CommandResults:
    """Deletes the tag from panorama

    Args:
        args (dict): The command arguments.

    Returns:
        CommandResults: The command results with raw response and readable outputs.
    """
    tag_name = args.get('name', '')

    raw_response = pan_os_delete_tag(tag_name)

    return CommandResults(
        raw_response=raw_response,
        readable_output=f'The tag with name "{tag_name}" was deleted successfully.',
    )


def prettify_security_profile_groups(sp_groups_list: list) -> list:
    """Prettify the keys in the security profile groups for the HR table.

    Args:
        sp_groups_list (list): The security profile groups list

    Returns:
        list: List of prettified security profile groups.
    """
    profile_to_change_map = {
        "virus": "Antivirus Profile",
        "spyware": "Anti-Spyware Profile",
        "vulnerability": "Vulnerability Protection Profile",
        "url-filtering": "URL Filtering Profile",
        "file-blocking": "File Blocking Profile",
        "data-filtering": "Data Filtering Profile",
        "wildfire-analysis": "WildFire Analysis Profile",
    }

    prettified_sp_groups_list = []
    for sp_group in sp_groups_list:

        prettified_sp_group = {"Name": sp_group["name"], "Location": sp_group["location"]}
        for key in sp_group:

            if key not in ("name", "location"):
                sp_group[key] = extract_objects_info_by_key(sp_group, key)
                prettified_sp_group[profile_to_change_map.get(key, key)] = sp_group[key]

        prettified_sp_groups_list.append(prettified_sp_group)

    return prettified_sp_groups_list


def pan_os_list_security_profile_groups(args: dict) -> tuple:
    """Sends the request to get the security profile groups and formats the results.

    Args:
        args (dict): The command arguments.

    Returns:
        tuple: The raw respons and a list of the formatted security profile groups.
    """
    xpath = f"{XPATH_RULEBASE}profile-group/entry"
    if group_name := args.get("group_name"):
        xpath += f"[@name='{group_name}']"

    params = {
        "type": "config",
        "action": "get",
        "key": API_KEY,
        "xpath": xpath
    }

    raw_response = http_request(URL, 'GET', params=params)
    sp_groups_response_list = raw_response.get("response", {}).get("result", {}).get("entry") or []
    if not isinstance(sp_groups_response_list, list):
        sp_groups_response_list = [sp_groups_response_list]

    for sp_group in sp_groups_response_list:
        parse_pan_os_un_committed_data(sp_group, ['@admin', '@dirtyId', '@time'])
        sp_group["name"] = sp_group.pop("@name", "")
        sp_group["location"] = sp_group.pop("@loc", "")

    return raw_response, sp_groups_response_list


def pan_os_list_security_profile_groups_command(args: dict) -> CommandResults:
    """
    Returns a list of security profile groups.

    Args:
        args (dict): The command arguments.

    Returns:
        CommandResults: The command results with raw response, outputs and readable outputs.
    """
    raw_response, sp_groups_list = pan_os_list_security_profile_groups(args=args)
    prettified_sp_groups_list = prettify_security_profile_groups(sp_groups_list)

    return CommandResults(
        raw_response=raw_response,
        outputs=sp_groups_list,
        readable_output=tableToMarkdown(
            f'Security Profile Groups:',
            prettified_sp_groups_list,
            ["Name", "Location", "Antivirus Profile", "Anti-Spyware Profile", "Vulnerability Protection Profile",
             "URL Filtering Profile", "File Blocking Profile", "Data Filtering Profile", "WildFire Analysis Profile"],
        ),
        outputs_prefix='Panorama.ProfileGroup',
        outputs_key_field='name'
    )


def pan_os_create_security_profile_group_command(args: dict) -> CommandResults:
    """
    Creates a security profile groups in the given Panorama instance.

    Args:
        args (dict): The command arguments.

    Returns:
        CommandResults: The command results with raw response and readable outputs.
    """
    group_name = args.get('group_name')
    params = {
        "type": "config",
        "action": "set",
        "key": API_KEY,
        "xpath": f"{XPATH_RULEBASE}profile-group/entry[@name='{group_name}']",
        "element": (add_argument(args.get("antivirus_profile"), "virus", True)
                    + add_argument(args.get("anti_spyware_profile"), "spyware", True)
                    + add_argument(args.get("vulnerability_protection_profile"), "vulnerability", True)
                    + add_argument(args.get("URL_filtering_profile"), "url-filtering", True)
                    + add_argument(args.get("file_blocking_profile"), "file-blocking", True)
                    + add_argument(args.get("data_filtering_profile"), "data-filtering", True)
                    + add_argument(args.get("wildfire_analysis_profile"), "wildfire-analysis", True))
    }

    raw_response = http_request(URL, "GET", params=params)
    return CommandResults(
        raw_response=raw_response,
        readable_output=f'Successfully created Security Profile Group: "{group_name}"',
    )


def build_edit_sp_group_xpath_and_element(group_name: str, profile_to_change: str, profile_value: str, sp_group=None) -> tuple:
    """
    Builds the `xpath` and `element` params for the edit sp groups request.
    In case of emptying the profile, we take the other profiles from the current sp group.

    Args:
        group_name (str): The group name to edit.
        profile_to_change (str): The profile to change.
        profile_value (str): The new profile value.
        sp_group: The current sp group.

    Returns:
        tuple: The xpath and element request params.
    """
    profile_to_change_map = {
        "Antivirus Profile": "virus",
        "Anti-Spyware Profile": "spyware",
        "Vulnerability Protection Profile": "vulnerability",
        "URL Filtering Profile": "url-filtering",
        "File Blocking Profile": "file-blocking",
        "Data Filtering Profile": "data-filtering",
        "WildFire Analysis Profile": "wildfire-analysis",
    }

    element = ""
    xpath = f"{XPATH_RULEBASE}profile-group/entry[@name='{group_name}']"

    if sp_group:
        element += f'<entry name="{group_name}">'
        for profile_not_to_change in profile_to_change_map:
            if profile_not_to_change != profile_to_change:
                element += add_argument(extract_objects_info_by_key(sp_group, profile_to_change_map.get(profile_not_to_change)),  # type: ignore
                                        profile_to_change_map.get(profile_not_to_change), True)  # type: ignore
        element += "</entry>"

    else:
        element += add_argument(profile_value, profile_to_change_map.get(profile_to_change), True)  # type: ignore
        xpath += f"/{profile_to_change_map.get(profile_to_change)}"

    return xpath, element


def pan_os_edit_security_profile_group_command(args: dict) -> CommandResults:
    """
    Edits a given security profile groups in the given Panorama instance.

    Args:
        args (dict): The command arguments.

    Returns:
        CommandResults: The command results with raw response and readable outputs.
    """
    group_name = args.get("group_name", "")
    profile_to_change = args.get("profile_to_change", "")
    profile_value = args.get("profile_value", "")

    params = {
        "type": "config",
        "action": "edit",
        "key": API_KEY,
    }

    if profile_value.lower() == "none":
        _, sp_group = pan_os_list_security_profile_groups(args=args)

        if not sp_group:
            raise Exception(f'Could not find security profile group "{group_name}"')
        sp_group = sp_group[0]

        xpath, element = build_edit_sp_group_xpath_and_element(group_name, profile_to_change, profile_value, sp_group)
        params.update({
            "xpath": xpath,
            "element": element
        })
    else:
        xpath, element = build_edit_sp_group_xpath_and_element(group_name, profile_to_change, profile_value)
        params.update({
            "xpath": xpath,
            "element": element
        })

    raw_response = http_request(URL, "GET", params=params)
    return CommandResults(
        raw_response=raw_response,
        readable_output=f'Successfully edited Security Profile Group: "{group_name}"',
    )


def pan_os_delete_security_profile_group_command(args: dict) -> CommandResults:
    """
    Deletes a given security profile groups in the given Panorama instance.

    Args:
        args (dict): The command arguments.

    Returns:
        CommandResults: The command results with raw response and readable outputs.
    """
    group_name = args.get("group_name")

    params = {
        "type": "config",
        "action": "delete",
        "key": API_KEY,
        "xpath": f"{XPATH_RULEBASE}profile-group/entry[@name='{group_name}']",
    }

    raw_response = http_request(URL, "GET", params=params)
    return CommandResults(
        raw_response=raw_response,
        readable_output=f'Successfully deleted Security Profile Group: "{group_name}"',
    )


def pan_os_get_audit_comment_command(args: dict) -> CommandResults:
    """
    executes the command pan-os-get-audit-comment to get the audit comment for a given policy rule.

    Args:
        args (dict): The command arguments.

    Returns:
        CommandResults: The command results with raw response, outputs and readable outputs.
    """
    if DEVICE_GROUP and not PRE_POST:
        raise DemistoException(f'The pre_post argument must be provided for panorama instance')

    rule_name = args.get("rule_name") or ""
    rule_type = args.get("rule_type") or ""
    params = build_audit_comment_params(
        name=rule_name,
        pre_post='rulebase' if VSYS else f'{PRE_POST.lower()}-rulebase',
        policy_type=RULE_TYPES_MAP[rule_type],
        xml_type='show',
    )

    raw_response = http_request(URL, 'GET', params=params)
    comment = (raw_response["response"]["result"] or {}).get("entry", {}).get("comment", "") or ""
    outputs = {
        "rule_name": rule_name,
        "rule_type": rule_type,
        "comment": comment
    }

    return CommandResults(
        raw_response=raw_response,
        outputs=outputs,
        readable_output=tableToMarkdown(
            f'Audit Comment for Rule: {rule_name}',
            outputs,
            headerTransform=string_to_table_header,
        ),
        outputs_prefix='Panorama.AuditComment',
        outputs_key_field=['rule_name', 'rule_type']
    )


def get_all_profile_names_from_profile_type(profile_type: str, device_group: str) -> list:
    """
    Retrieves all profile names from a specified profile type.

    Args:
        profile_type: The type of profile to retrieve, 'vulnerability' or 'spyware'.
        device_group: If device_group was provided as a command argument, it will override the configured one.

    Returns:
        A list of profile names associated with the specified profile type.
    """
    # if device_group was provided as a command argument, it will override the configured one
    if device_group:
        if device_group == "shared":
            xpath = "/config/shared/"
        else:
            xpath = (
                "/config/devices/entry/device-group/entry[@name='"
                + device_group
                + "']/"
            )
    else:
        xpath = "/config/devices/entry/vsys/entry[@name='" + VSYS + "']/"
    xpath += f"profiles/{profile_type}"

    raw_response = get_security_profile(xpath)
    profiles = raw_response.get("response", {}).get("result", {}).get(f"{profile_type}", {}). get("entry", [])

    if not isinstance(profiles, list):
        profiles = [profiles]

    profile_names = [entry.get("@name") for entry in profiles if entry.get("@name")]

    return profile_names


def check_profile_type_by_given_profile_name(profile_name: str, device_group: str) -> str:
    """
    Checks the profile type based on a given profile name.

    Args:
        profile_name: The name of the profile to check.
        device_group: If device_group was provided as a command argument, it will override the configured one.

    Returns:
        The profile type: 'Vulnerability Protection Profile' or 'Anti Spyware Profile'.
    """
    vulnerability_protection_profile_names = get_all_profile_names_from_profile_type('vulnerability', device_group)
    anti_spyware_profile_names = get_all_profile_names_from_profile_type('spyware', device_group)

    if profile_name in vulnerability_protection_profile_names and profile_name in anti_spyware_profile_names:
        raise DemistoException(
            "Profile name was found both in Vulnerability Protection Profiles and in Anti Spyware Profiles. Please specify profile_type.")

    elif profile_name in vulnerability_protection_profile_names:
        return 'vulnerability'

    elif profile_name in anti_spyware_profile_names:
        return 'spyware'

    else:
        raise DemistoException("Profile name was not found in Vulnerability Protection Profiles or in Anti Spyware Profiles.")


def build_xpath_for_profile_exception_commands(profile_name: str, profile_type: str, device_group: str, action_type: str, extracted_id: Optional[str] = None) -> str:
    """
    Creates and return xpath based on the profile type and pan-os/panorama instance.

    Args:
        profile_name: The profile name.
        profile_type: The profile type.
        device_group: The device group if was sent as a commands argument.
        action_type: Action type for api request.
        extracted_id: The id of the exception.

    Returns:
        The xpath.
    """
    if not profile_type:
        raise DemistoException("Invalid profile_type was provided. Can be Vulnerability Protection or Anti Spyware.")

    xpath = ''
    if device_group:
        xpath = f"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{device_group}']/profiles/{profile_type}/entry[@name='{profile_name}']/threat-exception"

    elif VSYS:
        xpath = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{VSYS}']/profiles/{profile_type}/entry[@name='{profile_name}']/threat-exception"

    if action_type in [ExceptionCommandType.EDIT.value, ExceptionCommandType.DELETE.value]:
        xpath += f"/entry[@name='{extracted_id}']"

    return xpath


def get_predefined_threats_list() -> list:
    """
    Get the predefined threats lists.

    Returns:
        The list of threats.
    """
    result = panorama_get_predefined_threats_list()
    predefined_threats = result.get('response', {}).get('result', {}).get('threats', {}).get("phone-home", {}).get('entry', [])
    predefined_threats += result.get('response', {}).get('result', {}).get('threats',
                                                                           {}).get("vulnerability", {}).get('entry', [])
    return predefined_threats


def get_threat_id_from_predefined_threats(threat: str) -> tuple[str, str, list]:
    """
    Search the threat id in the threats list by using the threat argument.

    Args:
        threat: The threat name, can be the CVE or the id.

    Returns:
        The id of the threat
    """
    predefined_threats = get_predefined_threats_list()

    for entry in predefined_threats:
        exception_name = entry.get("threatname", "")
        extracted_id = entry["@name"]
        cves = entry.get("cve", {}).get("member", [])

        if not isinstance(cves, list):
            cves = [cves]

        search_keys = [exception_name.lower(), extracted_id] + [cve.lower() for cve in cves]

        if threat.lower() in search_keys:
            return extracted_id, exception_name, cves

    raise DemistoException("Threat was not found.")


def build_element_for_profile_exception_commands(extracted_id: str, action: str, packet_capture: str, exempt_ip: str, ip_track_by: str, ip_duration_sec: str) -> str:
    """
    Build the element for the api that the profile exception commands use.

    Args:
        extracted_id: Not a mandatory field for building element.
        action: A mandatory field for building element, default value: default.
        packet_capture: Not a mandtatory field for building element.
        exempt_ip: Not a mandtatory field for building element.
        ip_track_by: Mandatory when action == 'block-ip'
        ip_duration_sec: Mandatory when action == 'block-ip'

    Returns:
        The element for the api request
    """

    element = f"""
        <entry name="{extracted_id}">
        """
    if action == 'block-ip':
        element += f"""
            <action>
                <block-ip>
                    <track-by>{ip_track_by}</track-by>
                    <duration>{ip_duration_sec}</duration>
                </block-ip>
            </action>
        """
    else:
        element += f"""
            <action>
                <{action}/>
            </action>
        """
    if packet_capture:
        element += f"""
            <packet-capture>{packet_capture}</packet-capture>
        """
    if exempt_ip:
        element += f"""
            <exempt-ip>
     	        <entry name="{exempt_ip}"/>
            </exempt-ip>
        """
    element += f"""
        </entry>
    """
    return element


def profile_exception_crud_requests(args: dict, action_type: str) -> Any:
    """
    Build the element for the api that the profile exception commands use.

    Args:
        args: The command arguments.
        action_type: The action type, can be: set, edit, delete, get.

    Returns:
        results: A dict for raw_response, exception_id, exception_name, profile_type
    """
    xpath_exceptions_actions_types_map = {
        'Alert': 'alert',
        'Allow': 'allow',
        'Block IP': 'block-ip',
        'Drop': 'drop',
        'Reset Both': 'reset-both',
        'Reset Client': 'reset-client',
        'Reset Server': 'reset-server',
        'default': 'default'
    }

    exceptions_packet_capture_types_map = {
        'Disable': 'disable',
        'Single Packet': 'single-packet',
        'Extended Capture': 'extended-capture'
    }

    exceptions_ip_track_by_types_map = {
        'Source': 'source',
        'Source And Destination': 'source-and-destination'
    }

    exception_profile_types_map = {
        'Vulnerability Protection Profile': 'vulnerability',
        'Anti Spyware Profile': 'spyware'
    }

    profile_name = args.get('profile_name', "")
    profile_type = exception_profile_types_map.get(args.get('profile_type', ''), '')
    threat = args.get('threat', '')
    xpath_action = xpath_exceptions_actions_types_map[args.get('action', 'default')]
    packet_capture = exceptions_packet_capture_types_map.get(args.get('packet_capture', ''), '')
    exempt_ip = args.get('exempt_ip', '')
    device_group = args.get('device_group', DEVICE_GROUP)
    ip_track_by = exceptions_ip_track_by_types_map.get(args.get('ip_track_by', ''), '')
    ip_duration_sec = args.get('ip_duration_sec', '')
    exception_id = ""
    exception_name = ""
    params: dict
    if xpath_action == 'block-ip' and (not ip_track_by or not ip_duration_sec):
        raise DemistoException(
            "ip_track_by and ip_duration_sec are required when action is 'Block IP'."
        )

    if not profile_type:
        profile_type = check_profile_type_by_given_profile_name(profile_name, device_group)

    if action_type != ExceptionCommandType.LIST.value:
        exception_id, exception_name, _ = get_threat_id_from_predefined_threats(threat)

    xpath = build_xpath_for_profile_exception_commands(profile_name, profile_type, device_group, action_type, exception_id)

    if action_type in [ExceptionCommandType.ADD.value, ExceptionCommandType.EDIT.value]:
        element = build_element_for_profile_exception_commands(
            exception_id, xpath_action, packet_capture, exempt_ip, ip_track_by, ip_duration_sec)
        params = {
            'type': 'config',
            'action': action_type,
            'xpath': xpath,
            'key': API_KEY,
            'element': element
        }

    elif action_type in [ExceptionCommandType.DELETE.value, ExceptionCommandType.LIST.value]:
        params = {
            'type': 'config',
            'action': action_type,
            'xpath': xpath,
            'key': API_KEY,
        }
    else:
        params = {}
        demisto.debug(f"{action_type=} -> {params=}")

    try:
        raw_response = http_request(URL, 'GET', params=params)
        return {
            'raw_response': raw_response,
            'exception_id': exception_id,
            'exception_name': exception_name,
            'profile_type': profile_type,
            'profile_name': profile_name
        }
    except Exception as e:
        if e.args and "Object not present" in e.args[0]:
            return CommandResults(
                readable_output=f'Exceptions list is empty',
            )
        else:
            raise DemistoException("Exception was not found in exceptions list.")


def pan_os_add_profile_exception_command(args: dict) -> CommandResults:
    """
    Adds an exception to a Vulnerability Protection or to a Anti Spyware Profile. Must include profile_name, profile_type and threat_name.

    Args:
        args: The command arguments.

    Returns:
        A confirmation for adding the exception.
    """
    results = profile_exception_crud_requests(args, ExceptionCommandType.ADD.value)
    raw_response = results.get('raw_response')
    exception_id = results.get('exception_id')
    exception_name = results.get('exception_name')
    profile_type = results.get('profile_type')
    profile_name = results.get('profile_name')
    return CommandResults(
        raw_response=raw_response,
        readable_output=f'Successfully created exception "{exception_name}" with threat ID {exception_id} in the "{profile_name}" profile of type "{profile_type}".'
    )


def pan_os_edit_profile_exception_command(args: dict) -> CommandResults:
    """
    Edits an exception in a Vulnerability Protection or in a Anti Spyware Profile. Must include profile_name, profile_type and threat_name.

    Args:
        args: The command arguments.

    Returns:
        A confirmation for editing the exception.
    """
    results = profile_exception_crud_requests(args, ExceptionCommandType.EDIT.value)
    raw_response = results.get('raw_response')
    exception_id = results.get('exception_id')
    exception_name = results.get('exception_name')
    profile_type = results.get('profile_type')
    profile_name = results.get('profile_name')
    return CommandResults(
        raw_response=raw_response,
        readable_output=f'Successfully edited exception "{exception_name}" with threat ID {exception_id} in the "{profile_name}" profile of type "{profile_type}".'
    )


def pan_os_delete_profile_exception_command(args: dict) -> CommandResults:
    """
    Deletes an exception in a Vulnerability Protection or in a Anti Spyware Profile. Must include profile_name, profile_type and threat_name.

    Args:
        args: The command arguments.

    Returns:
        A confirmation for deleting the exception.
    """
    results = profile_exception_crud_requests(args, ExceptionCommandType.DELETE.value)
    raw_response = results.get('raw_response')
    exception_id = results.get('exception_id')
    exception_name = results.get('exception_name')
    profile_type = results.get('profile_type')
    profile_name = results.get('profile_name')
    return CommandResults(
        raw_response=raw_response,
        readable_output=f'Successfully deleted exception "{exception_name}" with threat ID {exception_id} in the "{profile_name}" profile of type "{profile_type}".'
    )


def pan_os_list_profile_exception_command(args: dict) -> CommandResults:
    """
    Lists all the exceptions from a Vulnerability Protection Profile or from a Anti Spyware Profile. Must include profile_name, profile_type.

    Args:
        args: The command arguments.

    Returns:
        A confirmation for deleting the exception.
    """
    profile_name = args.get('profile_name')
    results = profile_exception_crud_requests(args, ExceptionCommandType.LIST.value)
    if isinstance(results, CommandResults):
        return results

    profile_type = results.get('profile_type', '')
    raw_response = results.get('raw_response', {})
    exceptions_response_list = raw_response.get('response', {}).get('result', {}).get('threat-exception', [])
    if not isinstance(exceptions_response_list, list):
        exceptions_response_list = [exceptions_response_list]

    context_exceptions_list = []
    hr = []
    for exceptions in exceptions_response_list:
        parse_pan_os_un_committed_data(exceptions, ['@admin', '@dirtyId', '@time'])
        exceptions = exceptions.get('entry')
        if not exceptions:
            break
        if not isinstance(exceptions, list):
            exceptions = [exceptions]
        for entry in exceptions:
            exception_id = entry['@name']
            exception_actions = ", ".join(entry['action'].keys())
            exception_packet_capture = entry.get('packet-capture')
            exception_exempt_id = entry.get('exempt-ip', {}).get('entry', {}).get('@name')
            _, exception_name, cve = get_threat_id_from_predefined_threats(exception_id)

            excpetion_context = {
                'id': exception_id,
                'name': exception_name,
                'CVE': cve,
                'action': exception_actions,
                'packet-capture': exception_packet_capture,
                'exempt-ip': exception_exempt_id
            }

            cleaned_excpetion_context = {k: v for k, v in excpetion_context.items() if v}

            context_exceptions_list.append(cleaned_excpetion_context)

            hr.append({'ID': exception_id,
                       'Name': exception_name,
                       'CVE': cve,
                       'Action': exception_actions,
                       'Exempt IP': exception_exempt_id,
                       'Packet Capture': exception_packet_capture,
                       })

    outputs = {
        'Name': profile_name,
        'Exception': context_exceptions_list,
    }
    context_path = f'Panorama.{profile_type.capitalize()}'  # type: ignore
    return CommandResults(
        raw_response=raw_response,
        outputs=outputs,
        readable_output=tableToMarkdown(
            name='Profile Exceptions',
            t=hr,
            headers=['ID', 'Name', 'CVE', 'Action', 'Exempt IP', 'Packet Capture'],
            removeNull=True,
        ),
        outputs_prefix=context_path,
        outputs_key_field='Name'
    )


def build_master_key_create_or_update_cmd(args: dict, action: Literal['create', 'update']) -> str:
    """Builds the XML command for creating or updating the default master key on Panorama / PAN-OS.

    Args:
        args (dict): The command arguments.
        action ('create'| 'update'): Whether to create a new master key or update an existing one.

    Returns:
        str: XML string of the master key create or update command.
    """
    xml_args = [
        add_argument(arg=args.get('lifetime_in_hours'), field_name='lifetime', member=False),
        add_argument(arg=args.get('reminder_in_hours'), field_name='reminder', member=False),
    ]

    match action:
        case 'create':
            xml_args.append(
                add_argument(arg=args.get('master_key'), field_name='new-master-key', member=False),
            )
        case 'update':
            xml_args.extend(
                [
                    add_argument(arg=args.get('new_master_key'), field_name='new-master-key', member=False),
                    add_argument(arg=args.get('current_master_key'), field_name='current-master-key', member=False),
                ]
            )
        case _:
            raise ValueError(f"Invalid action value: '{action}'. Expected 'create' or 'update'.")

    # Whether to encrypt the master key using a Hardware Security Module (HSM) encryption key; currently a static value by demand
    xml_args.append(add_argument_yes_no(arg='no', field_name='on-hsm'))
    master_key_element = add_argument(arg=''.join(xml_args), field_name='master-key', member=False)

    return add_argument(arg=master_key_element, field_name='request', member=False)


def create_or_update_master_key(args: dict, action: Literal['create', 'update']) -> CommandResults:
    """Builds an XML command and sends a request to create or update the master key based on the given action.

    Args:
        args (dict): The command arguments.
        action ('create'| 'update'): Whether to create a new master key or update an existing one.

    Returns:
        CommandResults: Contains readable output and raw response.
    """
    master_key_cmd = build_master_key_create_or_update_cmd(args, action=action)
    raw_response: dict = http_request(URL, 'GET', params={'type': 'op', 'key': API_KEY, 'cmd': master_key_cmd})
    response_result = raw_response['response']['result']  # human readable message

    # Creating or updating the encryption master key by definition invalidates the current API key, refer to the integration docs.
    demisto.info(f'The master key of {URL} has been {action}d. The current API key has been invalidated.')

    return CommandResults(
        readable_output=f'{response_result}. \n\n⚠️ The current API key is no longer valid! (by design) '
        'Generate a new API key and update it in the integration instance configuration to keep using the integration.',
        raw_response=raw_response,
    )


def pan_os_create_master_key_command(args: dict) -> CommandResults:
    """Creates a new default master key on Panorama / PAN-OS.

    Args:
        args (dict): The command arguments.

    Returns:
        CommandResults: Contains readable output and raw response.
    """
    return create_or_update_master_key(args, action='create')


def pan_os_update_master_key_command(args: dict) -> CommandResults:
    """Updates the default master key on Panorama / PAN-OS.

    Args:
        args (dict): The command arguments.

    Returns:
        CommandResults: Contains readable output and raw response.
    """
    return create_or_update_master_key(args, action='update')


def pan_os_get_master_key_details_command() -> CommandResults:
    """Shows the details of the default master key on Panorama / PAN-OS.

    Args:
        args (dict): The command arguments.

    Returns:
        CommandResults: Contains context output, readable output, and raw response.
    """
    system_element = add_argument(arg='<masterkey-properties/>', field_name='system', member=False)
    show_master_key_cmd = add_argument(arg=system_element, field_name='show', member=False)

    raw_response: dict = http_request(URL, 'GET', params={'type': 'op', 'key': API_KEY, 'cmd': show_master_key_cmd})
    response_result = raw_response['response']['result']

    result_to_human_readable = {'auto-renew-mkey': 'Auto-renew master key', "on-hsm": "Encryption on HSM"}
    human_readable = tableToMarkdown(
        'Master Key Details',
        response_result,
        headers=['auto-renew-mkey', 'on-hsm', 'remind-at', 'expire-at'],
        headerTransform=lambda key: result_to_human_readable.get(key, ' '.join(key.split('-')).capitalize()),
    )

    return CommandResults(
        outputs_prefix='Panorama.MasterKey',
        outputs=response_result,
        raw_response=raw_response,
        readable_output=human_readable,
    )


""" Fetch Incidents """


def get_query_by_job_id_request(log_type: str, query: str, max_fetch: int, offset_fetch: int) -> str:
    """get the Job ID linked to a particular query.

    Args:
        log_type (str): query log type
        query (str): query for the fetch
        max_fetch (int): maximum number of entries to fetch
        offset_fetch (int): number if entries to skip

    Returns:
        job_id (str): returns the Job ID associated with the given query
    """
    params = assign_params(key=API_KEY, type='log',
                           log_type=LOG_TYPE_TO_REQUEST[log_type], query=query, nlogs=max_fetch, dir='forward', skip=offset_fetch)
    demisto.debug(f'{params=}')
    response = http_request(URL, 'GET', params=params)
    return dict_safe_get(response, ('response', 'result', 'job'))  # type: ignore


def get_query_entries_by_id_request(job_id: str, fetch_job_polling_max_num_attempts: int) -> Dict[str, Any]:
    """get the entries of a particular Job ID.

    Args:
        job_id (int): ID of a query job
        fetch_job_polling_max_num_attempts (int): The maximal number of attempts to try and pull results.

    Returns:
        Dict[str,Any]: a dictionary of the raw entries linked to the Job ID
    """
    params = assign_params(key=API_KEY, type='log', action='get', job_id=job_id)

    # if the job has not finished, wait for 1 second and try again (until success or max retries)
    for try_num in range(1, fetch_job_polling_max_num_attempts + 1):
        response = http_request(URL, 'GET', params=params)
        status = response.get('response', {}).get('result', {}).get('job', {}).get('status', '')
        demisto.debug(f'Job ID {job_id}, response status: {status}')
        demisto.debug(f'raw response: {response}')
        if status == 'FIN':
            return response
        else:
            demisto.debug(f'Attempt number: {try_num}. Job not completed, Retrying in 1 second...')
            # due to short job life, saving the unfinished job id's to the context to query in the next fetch cycle is not a valid solution.
            time.sleep(1)
    demisto.debug(
        f'Maximum attempt number: {try_num} has reached. Job ID {job_id} might be not completed which could result in missing incidents.')
    return {}


def get_query_entries(log_type: str, query: str, max_fetch: int, fetch_job_polling_max_num_attempts: int, offset_fetch: int) -> List[Dict[Any, Any]]:
    """get query entries according to a specific query.

    Args:
        log_type (str): query log type
        query (str): query for the fetch
        max_fetch (int): maximum number of entries to fetch
        fetch_job_polling_max_num_attempts (int): The maximal number of attempts to try and pull results from a job.
        offset_fetch (int): number of incidents to skip

    Returns:
        List[Dict[Any,Any]]): a list of raw entries for the specified query
    """
    # first http request: send request with query, valid response will contain a job id.
    job_id = get_query_by_job_id_request(log_type, query, max_fetch, offset_fetch)
    demisto.debug(f'{job_id=}')

    # second http request: send request with job id, valid response will contain a dictionary of entries.
    query_entries = get_query_entries_by_id_request(job_id, fetch_job_polling_max_num_attempts)
    entries = []
    # extract all entries from response
    if result := dict_safe_get(query_entries, ('response', 'result', 'log', 'logs', 'entry')):
        if isinstance(result, list):
            entries = result
        elif isinstance(result, dict):
            entries = [result]
        else:
            raise DemistoException(f'Could not parse fetch results: {result}')

    entries_log_info = ' '.join(f"{entry.get('seqno', '')}:{entry.get('time_generated')}" for entry in entries)
    demisto.debug(f'{log_type} log type: {len(entries)} raw incidents (entries) found.')
    demisto.debug(f'fetched raw incidents (entries) are (ID:time_generated): {entries_log_info}')
    return entries


def add_time_filter_to_query_parameter(query: str, last_fetch: datetime, time_key: str) -> str:
    """append time filter parameter to original query parameter.

    Args:
        query (str): a string representing a query
        last_fetch (datetime): last fetch time for the specific log type

    Returns:
        str: a string representing a query with added time filter parameter
    """
    return f"{query} and ({time_key} geq '{last_fetch.strftime(QUERY_DATE_FORMAT)}')"


def find_largest_id_per_device(incident_entries: List[Dict[str, Any]]) -> Dict[str, str]:
    """
    This function finds the largest sequence id per device in the incident entries list.
    Args:
        incident_entries (List[Dict[str, Any]]): list of dictionaries representing raw incident entries
    Returns:
        new_largest_id: a dictionary of the largest sequence id per device
    """

    new_largest_id: Dict[str, str] = {}
    for entry in incident_entries:
        device_name: str = entry.get('device_name', '')
        incident_id: str = entry.get('seqno', '')
        if not device_name or not incident_id:
            continue
        # Upsert the device's id if it's a new device, or it's a larger id
        if device_name not in new_largest_id or int(incident_id) > int(new_largest_id[device_name]):
            new_largest_id[device_name] = incident_id
    demisto.debug(f'{new_largest_id=}')
    return new_largest_id


def filter_fetched_entries(entries_dict: dict[str, list[dict[str, Any]]], id_dict: LastIDs):
    """
    This function removes entries that have already been fetched in the previous fetch cycle.
    Args:
        entries_dict (Dict[str, List[Dict[str,Any]]]): a dictionary of log type and its raw entries
        id_dict (LastIDs): a dictionary of devices and their largest id so far
    Returns:
        new_entries_dict (Dict[str, List[Dict[str,Any]]]): a dictionary of log type and its raw entries without entries that have already been fetched in the previous fetch cycle
    """
    new_entries_dict: dict = {}
    for log_type, logs in entries_dict.items():
        demisto.debug(f'Filtering {log_type} type enties, recived {len(logs)} to filter.')
        if log_type == 'Correlation':
            # use dict_safe_get because 'Correlation' can have a dict from older versions
            last_log_id = dict_safe_get(id_dict, ['Correlation'], 0, int, False)
            demisto.debug(f'{last_log_id=}')
            first_new_log_index = next(
                (i for i, log in enumerate(logs)
                 if int(log.get("@logid")) > last_log_id),  # type: ignore
                len(logs)
            )
            demisto.debug(f'{first_new_log_index=}')
            new_entries_dict['Correlation'] = logs[first_new_log_index:]
        else:
            for log in logs:
                device_name = log.get("device_name", '')
                current_log_id = arg_to_number(log.get("seqno"))
                # get the latest id for that device, if that device is not in the dict, set the id to 0
                latest_id_per_device = cast(int, dict_safe_get(id_dict, (log_type, device_name), 0))
                demisto.debug(f'{latest_id_per_device=} for {log_type=} and {device_name=}')
                if not current_log_id or not device_name:
                    demisto.debug(f'Could not parse seqno or device name from log: {log}, skipping.')
                    continue
                if current_log_id > arg_to_number(latest_id_per_device):  # type: ignore
                    new_entries_dict.setdefault(log_type, []).append(log)
        demisto.debug(f'Filtered {log_type} type entries, left with {len(new_entries_dict.get(log_type, []))} entries.')

    return new_entries_dict


def fetch_incidents_request(queries_dict: QueryMap, max_fetch_dict: MaxFetch,
                            fetch_start_datetime_dict: Dict[str, datetime],
                            fetch_job_polling_max_num_attempts: int,
                            offset_fetch_dict: Offset) -> dict[str, list[dict[str, Any]]]:
    """get raw entires of incidents according to provided queries, log types and max_fetch parameters.

    Args:
        queries_dict (QueryMap): chosen log type queries dictionaries
        max_fetch_dict (MaxFetch): max incidents per fetch parameter per log type dictionary
        fetch_start_datetime_dict (Dict[str,datetime]): updated last fetch time per log type dictionary
        fetch_job_polling_max_num_attempts (int): The maximal number of attempts to try and pull results for each log type
        offset_fetch_dict (Offset): offset incidents per fetch parameter per log type dictionary
    Returns:
        dict[str, list[dict[str, Any]]]: a dictionary of all fetched raw incidents entries
    """
    def log_type_to_time_param(log_type: str) -> str:
        return {'Correlation': 'match_time'}.get(log_type, 'time_generated')

    entries = {}
    for log_type, query in queries_dict.items():
        max_fetch = max_fetch_dict[log_type]  # type: ignore[literal-required]
        offset_fetch = offset_fetch_dict.get(log_type, 0)  # type: ignore[literal-required]
        fetch_start_time = fetch_start_datetime_dict.get(log_type)
        if fetch_start_time:
            query = add_time_filter_to_query_parameter(query, fetch_start_time, log_type_to_time_param(log_type))  # type: ignore
        entries[log_type] = get_query_entries(log_type, query, max_fetch,   # type: ignore
                                              fetch_job_polling_max_num_attempts, offset_fetch)   # type: ignore
    return entries


def corr_incident_entry_to_incident_context(incident_entry: Dict[str, Any]) -> Dict[str, Any]:
    """convert correlation incident entry to basic cortex incident format.

    Args:
        incident_entry (Dict[str, Any]): raw correlation incident entry represented by a dictionary

    Returns:
        dict[str,any]: context formatted incident entry represented by a dictionary
    """
    incident_entry['type'] = 'CORRELATION'
    match_time = incident_entry.get('match_time', '')
    occurred = (
        occurred_datetime.strftime(DATE_FORMAT)
        if (occurred_datetime := dateparser.parse(match_time, settings={'TIMEZONE': 'UTC'}))
        else None
    )

    return {
        'name': f"Correlation {incident_entry.get('@logid')}",
        'occurred': occurred,
        'rawJSON': json.dumps(incident_entry),
    }


def incident_entry_to_incident_context(incident_entry: Dict[str, Any]) -> Dict[str, Any]:
    """convert raw incident entry to basic cortex incident format.

    Args:
        incident_entry (Dict[str, Any]): raw incident entry represented by a dictionary

    Returns:
        dict[str,any]: context formatted incident entry represented by a dictionary
    """
    time_generated = incident_entry.get('time_generated', '')
    occurred = (
        occurred_datetime.strftime(DATE_FORMAT)
        if (occurred_datetime := dateparser.parse(time_generated, settings={'TIMEZONE': 'UTC'}))
        else None
    )

    return {
        'name': f"{incident_entry.get('device_name')} {incident_entry.get('seqno')}",
        'occurred': occurred,
        'rawJSON': json.dumps(incident_entry),
    }


def get_fetch_start_datetime_dict(last_fetch_dict: LastFetchTimes,
                                  first_fetch: str, queries_dict: QueryMap
                                  ) -> Dict[str, datetime]:
    """calculate fetch start time for each log type query.
    - if last fetch time already exists for a log type, it will not be changed (only converted to datetime object).
    - if last fetch time does not exist for the log_type, it will be changed into first_fetch parameter (and converted to datetime object).
    - example: {'log_name':'2022-12-18T05:58:17'} --> {'log_name': datetime.datetime(2022, 12, 18, 5, 58, 17)}

    Args:
        last_fetch_dict (LastFetchTimes): last fetch dictionary
        first_fetch (str): first fetch parameter
        queries_dict (QueryMap): queries per log type dictionary

    Returns:
        Dict[str,datetime]: log_type:datetime pairs dictionary
    """
    fetch_start_datetime_dict = {}
    first_fetch_parsed = dateparser.parse(first_fetch, settings={'TIMEZONE': 'UTC'})

    # add new log types to last_fetch_dict
    if queries_dict:
        last_fetch_dict |= {  # type: ignore[assignment, typeddict-item]
            log_type: ''
            for log_type in queries_dict
            if log_type not in last_fetch_dict
        }

    # update fetch_start_datetime_dict with relevant last fetch time per log type in datetime UTC format
    # if there is no prior last fetch time available for a log type - it will be set it to first_fetch
    for log_type, last_fetch in last_fetch_dict.items():
        if not last_fetch and first_fetch_parsed:
            fetch_start_datetime_dict[log_type] = first_fetch_parsed
        else:
            updated_last_fetch = dateparser.parse(last_fetch, settings={'TIMEZONE': 'UTC'})  # type: ignore[arg-type]
            if updated_last_fetch:
                fetch_start_datetime_dict[log_type] = updated_last_fetch
        demisto.debug(
            f'last fetch for {log_type} log type was at: {last_fetch}, new time to fetch start time is: {fetch_start_datetime_dict[log_type]}.')

    return fetch_start_datetime_dict


def log_types_queries_to_dict(params: dict[str, str]) -> QueryMap:
    """converts chosen log type queries from parameters to a queries dictionary.
    Example:
    for parameters: log_types=['X_log_type'], X_log_type_query='(example query for X_log_type)'
    the dictionary returned is: {'X_log_type':'(example query for X_log_type)'}

    Args:
        params (dict[str, str]): instance configuration parameters

    Returns:
        QueryMap: queries per log type dictionary
    """
    queries_dict = QueryMap()  # type: ignore[typeddict-item]
    if log_types := params.get('log_types'):
        # if 'All' is chosen in Log Type (log_types) parameter then all query parameters are used, else only the chosen query parameters are used.
        active_log_type_queries = FETCH_INCIDENTS_LOG_TYPES if 'All' in log_types else log_types
        queries_dict |= {  # type: ignore[assignment, typeddict-item]
            log_type: log_type_query
            for log_type in active_log_type_queries
            if (log_type_query := params.get(f'{log_type.lower()}_query'))
        }
    return queries_dict


def get_parsed_incident_entries(incident_entries_dict: dict[str, list[dict[str, Any]]],
                                last_fetch_dict: LastFetchTimes,
                                last_id_dict: LastIDs) -> list[dict[str, Any]]:
    """for each log type incident entries array, parse the raw incidents into context incidents.
    if necessary, update the latest fetch time and last ID values in their corresponding dictionaries.

    Args:
        incident_entries_dict (Dict[str, List[Dict[str, Any]]]): list of dictionaries representing raw incident entries
        last_fetch_dict (Dict[str, str]): last fetch dictionary
        last_id_dict (Dict[str, Dict]): last id dictionary

    Returns:
        Dict[str,Any]: parsed context incident dictionary
    """
    parsed_incident_entries = []
    for log_type, incident_entries in incident_entries_dict.items():
        if incident_entries:
            if log_type == 'Correlation':
                last_id_dict['Correlation'] = int(incident_entries_dict['Correlation'][-1]['@logid'])
                parsed_incident_entries += list(map(corr_incident_entry_to_incident_context, incident_entries))
                last_fetch_string = max({entry.get('match_time', '') for entry in incident_entries})
                demisto.debug(f'{last_fetch_string=}')
            else:
                if updated_last_id := find_largest_id_per_device(incident_entries):
                    # upsert last_id_dict with the latest ID for each device for each log type, without removing devices that were not fetched in this fetch cycle.
                    last_id_dict[log_type].update(updated_last_id) if last_id_dict.get(  # type: ignore[literal-required]
                        log_type) else last_id_dict.update({log_type: updated_last_id})  # type: ignore[misc]
                parsed_incident_entries += list(map(incident_entry_to_incident_context, incident_entries))
                last_fetch_string = max({entry.get('time_generated', '') for entry in incident_entries})

            updated_last_fetch = dateparser.parse(last_fetch_string, settings={'TIMEZONE': 'UTC'})
            if updated_last_fetch:
                last_fetch_dict[log_type] = str(updated_last_fetch)  # type: ignore[literal-required]
            demisto.debug(
                f'{log_type} log type: {len(incident_entries)} incidents with unique ID list: {[incident.get("name", "") for incident in incident_entries]}')
    demisto.debug(f'Updated last run is: {last_fetch_dict}. Updated last ID is: {last_id_dict}')
    return parsed_incident_entries


def update_offset_dict(incident_entries_dict: dict[str, list[dict[str, Any]]],
                       last_fetch_dict: LastFetchTimes,
                       offset_fetch_dict: Offset):
    """
        for each log type incident entries array, parse the raw incidents into context incidents.
        if necessary, update the latest fetch time and last ID values in their corresponding dictionaries.

        Args:
            incident_entries_dict (Dict[str, List[Dict[str, Any]]]): list of dictionaries representing raw incident entries
            last_fetch_dict (Dict[str, str]): last fetch dictionary
            offset_fetch_dict (Dict[str, Dict]): last offset dictionary

    """
    for log_type, incident_entries in incident_entries_dict.items():
        if incident_entries:
            last_fetch_time = dateparser.parse(last_fetch_dict.get(log_type, ''), settings={  # type: ignore
                                               'TIMEZONE': 'UTC'})
            for entry in incident_entries:
                time_field = 'match_time' if log_type == 'Correlation' else 'time_generated'
                if not (log_time := dateparser.parse(entry.get(time_field, ''), settings={'TIMEZONE': 'UTC'})):
                    raise DemistoException(f"{time_field=} is not a valid date in entry of {log_type=}.\n{entry=}")

                if (not log_type in offset_fetch_dict
                    or not last_fetch_time
                        or log_time > last_fetch_time):
                    offset_fetch_dict[log_type] = 1  # type: ignore[literal-required]
                    last_fetch_time = log_time
                elif log_time == last_fetch_time:
                    offset_fetch_dict[log_type] += 1  # type: ignore[literal-required]


def fetch_incidents(last_run: LastRun, first_fetch: str,
                    queries_dict: QueryMap,
                    max_fetch_dict: MaxFetch,
                    fetch_job_polling_max_num_attempts: int
                    ) -> tuple[LastRun, list[dict[str, list]]]:
    """run one cycle of fetch incidents.

    Args:
        last_run (LastMap): contains last run information
        first_fetch (str): first time to fetch from (First fetch timestamp parameter)
        queries_dict (QueryMap): queries per log type dictionary
        max_fetch_dict (MaxFetch): max incidents per fetch parameter per log type dictionary
        fetch_job_polling_max_num_attempts (int): The maximal number of attempts to try and pull results for each log type

    Returns:
        (LastRun, List[Dict[str, list]]): last fetch per log type dictionary, last unique id per log type dictionary, parsed incidents tuple
    """
    last_fetch_dict = last_run.get('last_fetch_dict', {})
    last_id_dict = last_run.get('last_id_dict', {})
    offset_dict = last_run.get('offset_dict', {})
    demisto.debug(f'last fetch time dictionary from previous fetch is: {last_fetch_dict=}.')
    demisto.debug(f'last id dictionary from previous fetch is: {last_id_dict=}.')
    demisto.debug(f'last offset dictionary from previous fetch is: {offset_dict=}.')

    fetch_start_datetime_dict = get_fetch_start_datetime_dict(
        last_fetch_dict, first_fetch, queries_dict)  # type: ignore[arg-type]
    demisto.debug(f'updated last fetch per log type: {fetch_start_datetime_dict=}.')

    incident_entries_dict = fetch_incidents_request(queries_dict, max_fetch_dict, fetch_start_datetime_dict,
                                                    fetch_job_polling_max_num_attempts, offset_dict)
    demisto.debug('raw incident entries fetching has completed.')

    # Update offset if needed
    update_offset_dict(incident_entries_dict, last_fetch_dict, offset_dict)

    # remove duplicated incidents from incident_entries_dict
    unique_incident_entries_dict = filter_fetched_entries(
        entries_dict=incident_entries_dict, id_dict=last_id_dict)  # type: ignore[arg-type]

    parsed_incident_entries_list = get_parsed_incident_entries(
        unique_incident_entries_dict, last_fetch_dict, last_id_dict)  # type: ignore[arg-type]

    new_last_run = LastRun(last_fetch_dict=last_fetch_dict, last_id_dict=last_id_dict,  # type: ignore[typeddict-item]
                           offset_dict=offset_dict)  # type: ignore[typeddict-item]

    return new_last_run, parsed_incident_entries_list  # type: ignore[return-value]


def test_fetch_incidents_parameters(fetch_params):
    if log_types := fetch_params.get('log_types'):
        # if 'All' is chosen in Log Type (log_types) parameter then all query parameters are used, else only the chosen query parameters are used.
        active_log_type_queries = FETCH_INCIDENTS_LOG_TYPES if 'All' in log_types else log_types
        if 'match_time' in fetch_params.get('correlation_query', ''):
            raise DemistoException(
                "Correlation Log Type Query parameter cannot contain 'match_time' filter. Please remove it from the query.")
        for log_type in active_log_type_queries:
            log_type_query = fetch_params.get(f'{log_type.lower()}_query', "")
            if not log_type_query:
                raise DemistoException(f"{log_type} Log Type Query parameter is empty. Please enter a valid query.")
            if 'time_generated' in log_type_query:
                raise DemistoException(
                    f"{log_type} Log Type Query parameter cannot contain 'time_generated' filter. Please remove it from the query.")
            if 'seqno' in log_type_query:
                raise DemistoException(
                    f"{log_type} Log Type Query parameter cannot contain 'seqno' filter. Please remove it from the query.")

    else:
        raise DemistoException("fetch incidents is checked but no Log Types were selected to fetch from the dropdown menu.")


def main():  # pragma: no cover
    try:
        args = demisto.args()
        params = demisto.params()
        additional_malicious = argToList(params.get('additional_malicious'))
        additional_suspicious = argToList(params.get('additional_suspicious'))
        reliability = params.get('integrationReliability')
        initialize_instance(args=args, params=params)
        command = demisto.command()
        LOG(f'Command being called is: {command}')

        # Remove proxy if not set to true in params
        handle_proxy()

        if command == 'test-module':
            # Log the API version
            if is_debug_mode():
                demisto.debug(f'PAN-OS Version (debug-mode): {get_pan_os_version()}')
            panorama_test(params)

        # Fetch incidents
        elif command == 'fetch-incidents':
            last_run: LastRun = demisto.getLastRun()  # type: ignore
            first_fetch = params['first_fetch']
            configured_max_fetch = arg_to_number(params['max_fetch'])
            queries = log_types_queries_to_dict(params)
            fetch_max_attempts = arg_to_number(params['fetch_job_polling_max_num_attempts'])
            max_fetch = cast(MaxFetch, dict.fromkeys(queries, configured_max_fetch))

            new_last_run, incident_entries = fetch_incidents(
                last_run, first_fetch, queries, max_fetch, fetch_max_attempts)  # type: ignore[arg-type]

            demisto.setLastRun(new_last_run)
            demisto.incidents(incident_entries)

        elif command == 'panorama' or command == 'pan-os':
            panorama_command(args)

        elif command == 'panorama-commit' or command == 'pan-os-commit':
            return_results(panorama_commit_command(args))

        elif command == 'panorama-commit-status' or command == 'pan-os-commit-status':
            panorama_commit_status_command(args)

        elif command == 'panorama-push-to-device-group' or command == 'pan-os-push-to-device-group':
            return_results(panorama_push_to_device_group_command(args))
        elif command == 'pan-os-push-to-template':
            panorama_push_to_template_command(args)
        elif command == 'pan-os-push-to-template-stack':
            panorama_push_to_template_stack_command(args)
        elif command == 'panorama-push-status' or command == 'pan-os-push-status':
            panorama_push_status_command(args)

        # Addresses commands
        elif command == 'panorama-list-addresses' or command == 'pan-os-list-addresses':
            panorama_list_addresses_command(args)

        elif command == 'panorama-get-address' or command == 'pan-os-get-address':
            panorama_get_address_command(args)

        elif command == 'panorama-create-address' or command == 'pan-os-create-address':
            panorama_create_address_command(args)

        elif command == 'pan-os-edit-address':
            return_results(pan_os_edit_address_command(args))

        elif command == 'panorama-delete-address' or command == 'pan-os-delete-address':
            panorama_delete_address_command(args)

        # Address groups commands
        elif command == 'panorama-list-address-groups' or command == 'pan-os-list-address-groups':
            panorama_list_address_groups_command(args)

        elif command == 'panorama-get-address-group' or command == 'pan-os-get-address-group':
            panorama_get_address_group_command(args)

        elif command == 'panorama-create-address-group' or command == 'pan-os-create-address-group':
            panorama_create_address_group_command(args)

        elif command == 'panorama-delete-address-group' or command == 'pan-os-delete-address-group':
            panorama_delete_address_group_command(args.get('name'))

        elif command == 'panorama-edit-address-group' or command == 'pan-os-edit-address-group':
            panorama_edit_address_group_command(args)

        # Services commands
        elif command == 'panorama-list-services' or command == 'pan-os-list-services':
            panorama_list_services_command(args.get('tag'))

        elif command == 'panorama-get-service' or command == 'pan-os-get-service':
            panorama_get_service_command(args.get('name'))

        elif command == 'panorama-create-service' or command == 'pan-os-create-service':
            panorama_create_service_command(args)

        elif command == 'panorama-delete-service' or command == 'pan-os-delete-service':
            panorama_delete_service_command(args.get('name'))

        # Service groups commands
        elif command == 'panorama-list-service-groups' or command == 'pan-os-list-service-groups':
            panorama_list_service_groups_command(args.get('tags'))

        elif command == 'panorama-get-service-group' or command == 'pan-os-get-service-group':
            panorama_get_service_group_command(args.get('name'))

        elif command == 'panorama-create-service-group' or command == 'pan-os-create-service-group':
            panorama_create_service_group_command(args)

        elif command == 'panorama-delete-service-group' or command == 'pan-os-delete-service-group':
            panorama_delete_service_group_command(args.get('name'))

        elif command == 'panorama-edit-service-group' or command == 'pan-os-edit-service-group':
            panorama_edit_service_group_command(args)

        # Custom Url Category commands
        elif command == 'panorama-get-custom-url-category' or command == 'pan-os-get-custom-url-category':
            panorama_get_custom_url_category_command(args.get('name'))

        elif command == 'panorama-create-custom-url-category' or command == 'pan-os-create-custom-url-category':
            panorama_create_custom_url_category_command(args)

        elif command == 'panorama-delete-custom-url-category' or command == 'pan-os-delete-custom-url-category':
            panorama_delete_custom_url_category_command(args.get('name'))

        elif command == 'panorama-edit-custom-url-category' or command == 'pan-os-edit-custom-url-category':
            panorama_edit_custom_url_category_command(args)

        # URL Filtering capabilities
        elif command == 'url':
            if USE_URL_FILTERING:  # default is false
                panorama_get_url_category_command(
                    url_cmd='url',
                    url=args.get('url'),
                    additional_suspicious=additional_suspicious,
                    additional_malicious=additional_malicious,
                    reliability=reliability
                )
            # do not error out

        elif command == 'panorama-get-url-category' or command == 'pan-os-get-url-category':
            panorama_get_url_category_command(
                url_cmd='url',
                url=args.get('url'),
                additional_suspicious=additional_suspicious,
                additional_malicious=additional_malicious,
                target=args.get('target'),
                reliability=reliability
            )

        elif command == 'panorama-get-url-category-from-cloud' or command == 'pan-os-get-url-category-from-cloud':
            panorama_get_url_category_command(
                url_cmd='url-info-cloud',
                url=args.get('url'),
                additional_suspicious=additional_suspicious,
                additional_malicious=additional_malicious,
                reliability=reliability
            )

        elif command == 'panorama-get-url-category-from-host' or command == 'pan-os-get-url-category-from-host':
            panorama_get_url_category_command(
                url_cmd='url-info-host',
                url=args.get('url'),
                additional_suspicious=additional_suspicious,
                additional_malicious=additional_malicious,
                reliability=reliability
            )

        # URL Filter
        elif command == 'panorama-get-url-filter' or command == 'pan-os-get-url-filter':
            panorama_get_url_filter_command(args.get('name'))

        elif command == 'panorama-create-url-filter' or command == 'pan-os-create-url-filter':
            panorama_create_url_filter_command(args)

        elif command == 'panorama-edit-url-filter' or command == 'pan-os-edit-url-filter':
            panorama_edit_url_filter_command(args)

        elif command == 'panorama-delete-url-filter' or command == 'pan-os-delete-url-filter':
            panorama_delete_url_filter_command(demisto.args().get('name'))

        # EDL
        elif command == 'panorama-list-edls' or command == 'pan-os-list-edls':
            panorama_list_edls_command()

        elif command == 'panorama-get-edl' or command == 'pan-os-get-edl':
            panorama_get_edl_command(demisto.args().get('name'))

        elif command == 'panorama-create-edl' or command == 'pan-os-create-edl':
            panorama_create_edl_command(args)

        elif command == 'panorama-edit-edl' or command == 'pan-os-edit-edl':
            panorama_edit_edl_command(args)

        elif command == 'panorama-delete-edl' or command == 'pan-os-delete-edl':
            panorama_delete_edl_command(demisto.args().get('name'))

        elif command == 'panorama-refresh-edl' or command == 'pan-os-refresh-edl':
            panorama_refresh_edl_command(args)

        # Registered IPs
        elif command == 'panorama-register-ip-tag' or command == 'pan-os-register-ip-tag':
            panorama_register_ip_tag_command(args)

        elif command == 'panorama-unregister-ip-tag' or command == 'pan-os-unregister-ip-tag':
            panorama_unregister_ip_tag_command(args)

        # Registered Users
        elif command == 'panorama-register-user-tag' or command == 'pan-os-register-user-tag':
            panorama_register_user_tag_command(args)

        elif command == 'panorama-unregister-user-tag' or command == 'pan-os-unregister-user-tag':
            panorama_unregister_user_tag_command(args)

        # Security Rules Managing
        elif command == 'panorama-list-rules' or command == 'pan-os-list-rules':
            panorama_list_rules_command(args)

        elif command == 'panorama-move-rule' or command == 'pan-os-move-rule':
            panorama_move_rule_command(args)

        # Security Rules Configuration
        elif command == 'panorama-create-rule' or command == 'pan-os-create-rule':
            panorama_create_rule_command(args)

        elif command == 'panorama-custom-block-rule' or command == 'pan-os-custom-block-rule':
            panorama_custom_block_rule_command(args)

        elif command == 'panorama-edit-rule' or command == 'pan-os-edit-rule':
            panorama_edit_rule_command(args)

        elif command == 'panorama-delete-rule' or command == 'pan-os-delete-rule':
            panorama_delete_rule_command(args.get('rulename'))

        # Traffic Logs - deprecated
        elif command == 'panorama-query-traffic-logs' or command == 'pan-os-query-traffic-logs':
            panorama_query_traffic_logs_command(args)

        elif command == 'panorama-check-traffic-logs-status' or command == 'pan-os-check-traffic-logs-status':
            panorama_check_traffic_logs_status_command(args.get('job_id'))

        elif command == 'panorama-get-traffic-logs' or command == 'pan-os-get-traffic-logs':
            panorama_get_traffic_logs_command(args.get('job_id'))

        # Logs
        elif command == 'panorama-query-logs' or command == 'pan-os-query-logs':
            return_results(panorama_query_logs_command(args))

        elif command == 'panorama-check-logs-status' or command == 'pan-os-check-logs-status':
            panorama_check_logs_status_command(args.get('job_id'))

        elif command == 'panorama-get-logs' or command == 'pan-os-get-logs':
            panorama_get_logs_command(args)

        # Pcaps
        elif command == 'panorama-list-pcaps' or command == 'pan-os-list-pcaps':
            panorama_list_pcaps_command(args)

        elif command == 'panorama-get-pcap' or command == 'pan-os-get-pcap':
            panorama_get_pcap_command(args)

        # Application
        elif command == 'panorama-list-applications' or command == 'pan-os-list-applications':
            panorama_list_applications_command(args)

        # Test security policy match
        elif command == 'panorama-security-policy-match' or command == 'pan-os-security-policy-match':
            panorama_security_policy_match_command(args)

        # Static Routes
        elif command == 'panorama-list-static-routes' or command == 'pan-os-list-static-routes':
            panorama_list_static_routes_command(args)

        elif command == 'panorama-get-static-route' or command == 'pan-os-get-static-route':
            panorama_get_static_route_command(args)

        elif command == 'panorama-add-static-route' or command == 'pan-os-add-static-route':
            panorama_add_static_route_command(args)

        elif command == 'panorama-delete-static-route' or command == 'pan-os-delete-static-route':
            panorama_delete_static_route_command(args)

        # Firewall Upgrade
        # Check device software version
        elif command == 'panorama-show-device-version' or command == 'pan-os-show-device-version':
            panorama_show_device_version_command(args.get('target'))

        # Download the latest content update
        elif command == 'panorama-download-latest-content-update' or command == 'pan-os-download-latest-content-update':
            panorama_download_latest_content_update_command(args)

        # Download the latest content update
        elif command == 'panorama-content-update-download-status' or command == 'pan-os-content-update-download-status':
            panorama_content_update_download_status_command(args)

        # Install the latest content update
        elif command == 'panorama-install-latest-content-update' or command == 'pan-os-install-latest-content-update':
            panorama_install_latest_content_update_command(args.get('target'))

        # Content update install status
        elif command == 'panorama-content-update-install-status' or command == 'pan-os-content-update-install-status':
            panorama_content_update_install_status_command(args)

        # Check PAN-OS latest software update
        elif command == 'panorama-check-latest-panos-software' or command == 'pan-os-check-latest-panos-software':
            return_results(panorama_check_latest_panos_software_command(args.get('target')))

        # Download target PAN-OS version
        elif command == 'panorama-download-panos-version' or command == 'pan-os-download-panos-version':
            panorama_download_panos_version_command(args)

        # PAN-OS download status
        elif command == 'panorama-download-panos-status' or command == 'pan-os-download-panos-status':
            panorama_download_panos_status_command(args)

        # PAN-OS software install
        elif command == 'panorama-install-panos-version' or command == 'pan-os-install-panos-version':
            panorama_install_panos_version_command(args)

        # PAN-OS install status
        elif command == 'panorama-install-panos-status' or command == 'pan-os-install-panos-status':
            panorama_install_panos_status_command(args)

        # Reboot Panorama Device
        elif command == 'panorama-device-reboot' or command == 'pan-os-device-reboot':
            panorama_device_reboot_command(args)

        # PAN-OS Set vulnerability to drop
        elif command == 'panorama-block-vulnerability' or command == 'pan-os-block-vulnerability':
            panorama_block_vulnerability(args)

        # Get pre-defined threats list from the firewall
        elif command == 'panorama-get-predefined-threats-list' or command == 'pan-os-get-predefined-threats-list':
            panorama_get_predefined_threats_list_command(args.get('target'))

        elif command == 'panorama-show-location-ip' or command == 'pan-os-show-location-ip':
            panorama_show_location_ip_command(args.get('ip_address'))

        elif command == 'panorama-get-licenses' or command == 'pan-os-get-licenses':
            panorama_get_license_command()

        elif command == 'panorama-get-security-profiles' or command == 'pan-os-get-security-profiles':
            get_security_profiles_command(args.get('security_profile'))

        elif command == 'panorama-apply-security-profile' or command == 'pan-os-apply-security-profile':
            apply_security_profile_command(args)

        elif command == 'pan-os-remove-security-profile':
            apply_security_profile_command(args)

        elif command == 'panorama-get-ssl-decryption-rules' or command == 'pan-os-get-ssl-decryption-rules':
            get_ssl_decryption_rules_command(**args)

        elif command == 'panorama-get-wildfire-configuration' or command == 'pan-os-get-wildfire-configuration':
            get_wildfire_configuration_command(**args)

        elif command == 'panorama-get-wildfire-best-practice' or command == 'pan-os-get-wildfire-best-practice':
            get_wildfire_best_practice_command()

        elif command == 'panorama-enforce-wildfire-best-practice' or command == 'pan-os-enforce-wildfire-best-practice':
            enforce_wildfire_best_practice_command(**args)

        elif command == 'panorama-url-filtering-block-default-categories' \
                or command == 'pan-os-url-filtering-block-default-categories':
            url_filtering_block_default_categories_command(**args)

        elif command == 'panorama-get-anti-spyware-best-practice' or command == 'pan-os-get-anti-spyware-best-practice':
            get_anti_spyware_best_practice_command()

        elif command == 'panorama-get-file-blocking-best-practice' \
                or command == 'pan-os-get-file-blocking-best-practice':
            get_file_blocking_best_practice_command()

        elif command == 'panorama-get-antivirus-best-practice' or command == 'pan-os-get-antivirus-best-practice':
            get_antivirus_best_practice_command()

        elif command == 'panorama-get-vulnerability-protection-best-practice' \
                or command == 'pan-os-get-vulnerability-protection-best-practice':
            get_vulnerability_protection_best_practice_command()

        elif command == 'panorama-get-url-filtering-best-practice' \
                or command == 'pan-os-get-url-filtering-best-practice':
            get_url_filtering_best_practice_command()

        elif command == 'panorama-create-antivirus-best-practice-profile' \
                or command == 'pan-os-create-antivirus-best-practice-profile':
            create_antivirus_best_practice_profile_command(**args)

        elif command == 'panorama-create-anti-spyware-best-practice-profile' \
                or command == 'pan-os-create-anti-spyware-best-practice-profile':
            create_anti_spyware_best_practice_profile_command(**args)

        elif command == 'panorama-create-vulnerability-best-practice-profile' \
                or command == 'pan-os-create-vulnerability-best-practice-profile':
            create_vulnerability_best_practice_profile_command(**args)

        elif command == 'panorama-create-url-filtering-best-practice-profile' \
                or command == 'pan-os-create-url-filtering-best-practice-profile':
            create_url_filtering_best_practice_profile_command(**args)

        elif command == 'panorama-create-file-blocking-best-practice-profile' \
                or command == 'pan-os-create-file-blocking-best-practice-profile':
            create_file_blocking_best_practice_profile_command(**args)

        elif command == 'panorama-create-wildfire-best-practice-profile' \
                or command == 'pan-os-create-wildfire-best-practice-profile':
            create_wildfire_best_practice_profile_command(**args)

        elif command == 'panorama-show-user-id-interfaces-config' or command == 'pan-os-show-user-id-interfaces-config':
            show_user_id_interface_config_command(args)

        elif command == 'panorama-show-zones-config' or command == 'pan-os-show-zones-config':
            show_zone_config_command(args)

        elif command == 'panorama-list-configured-user-id-agents' or command == 'pan-os-list-configured-user-id-agents':
            list_configured_user_id_agents_command(args)

        elif command == 'panorama-upload-content-update-file' or command == 'pan-os-upload-content-update-file':
            return_results(panorama_upload_content_update_file_command(args))

        elif command == 'panorama-install-file-content-update' or command == 'pan-os-install-file-content-update':
            panorama_install_file_content_update_command(args)
        elif command == 'pan-os-platform-get-arp-tables':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    get_arp_tables(topology, **demisto.args()),
                    empty_result_message="No ARP entries."
                )
            )
        elif command == 'pan-os-platform-get-route-summary':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    get_route_summaries(topology, **demisto.args()),
                    empty_result_message="Empty route summary result."
                )
            )
        elif command == 'pan-os-platform-get-routes':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    get_routes(topology, **demisto.args()),
                    empty_result_message="Empty route summary result."
                )
            )
        elif command == 'pan-os-platform-get-system-info':
            topology = get_topology()
            return_results(dataclasses_to_command_results(get_system_info(topology, **demisto.args())))
        elif command == 'pan-os-platform-get-device-groups':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    get_device_groups(topology, **demisto.args()),
                    empty_result_message="No device groups found."
                )
            )
        elif command == 'pan-os-platform-get-template-stacks':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    get_template_stacks(topology, **demisto.args()),
                    empty_result_message="No template stacks found."
                )
            )
        elif command == 'pan-os-platform-get-global-counters':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    get_global_counters(topology, **demisto.args()),
                    empty_result_message="No Global Counters Found"
                )
            )
        elif command == 'pan-os-platform-get-bgp-peers':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    get_bgp_peers(topology, **demisto.args()),
                    empty_result_message="No BGP Peers found."
                )
            )
        elif command == 'pan-os-platform-get-available-software':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    get_available_software(topology, **demisto.args()),
                    empty_result_message="No Available software images found"
                )
            )
        elif command == 'pan-os-platform-get-ha-state':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    get_ha_state(topology, **demisto.args()),
                    empty_result_message="No HA information available"
                )
            )
        elif command == 'pan-os-platform-get-jobs':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    get_jobs(topology, **demisto.args()),
                    empty_result_message="No jobs returned"
                )
            )
        elif command == 'pan-os-platform-download-software':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    download_software(topology, **demisto.args()),
                    empty_result_message="Software download not started"
                )
            )
        elif command == 'pan-os-apply-dns-signature-policy':
            return_results(
                apply_dns_signature_policy_command(args)
            )
        elif command == 'pan-os-platform-install-software':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    install_software(topology, **demisto.args()),
                    empty_result_message="Software Install not started"
                )
            )
        elif command == 'pan-os-platform-reboot':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    reboot(topology, **demisto.args()),
                    empty_result_message="Device not rebooted, or did not respond."
                )
            )
        elif command == 'pan-os-platform-get-system-status':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    system_status(topology, **demisto.args()),
                    empty_result_message="No system status."
                )
            )
        elif command == 'pan-os-platform-update-ha-state':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    update_ha_state(topology, **demisto.args()),
                    empty_result_message="HA State either wasn't change or the device did not respond."
                )
            )
        elif command == 'pan-os-hygiene-check-log-forwarding':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    check_log_forwarding(topology, **demisto.args()),
                    empty_result_message="At least one log forwarding profile is configured according to best practices."
                )
            )
        elif command == 'pan-os-hygiene-check-vulnerability-profiles':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    check_vulnerability_profiles(topology, **demisto.args()),
                    empty_result_message="At least one vulnerability profile is configured according to best practices."
                )
            )
        elif command == 'pan-os-hygiene-conforming-vulnerability-profiles':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    get_conforming_vulnerability_profiles(topology, **demisto.args()),
                    empty_result_message="No Conforming Vulnerability Profiles.",
                    override_table_headers=["hostid", "name", "object_type", "container_name"],
                    override_table_name="Best Practices conforming Vulnerability profiles"
                )
            )
        elif command == 'pan-os-hygiene-check-spyware-profiles':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    check_spyware_profiles(topology, **demisto.args()),
                    empty_result_message="At least one Spyware profile is configured according to best practices."
                )
            )
        elif command == 'pan-os-hygiene-check-url-filtering-profiles':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    check_url_filtering_profiles(topology, **demisto.args()),
                    empty_result_message="At least one Spyware profile is configured according to best practices."
                )
            )
        elif command == 'pan-os-hygiene-conforming-url-filtering-profiles':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    get_conforming_url_filtering_profiles(topology, **demisto.args()),
                    empty_result_message="No conforming URL filtering profiles.",
                    override_table_headers=["hostid", "name", "object_type", "container_name"],
                    override_table_name="Best Practices conforming URL Filtering profiles"
                )
            )
        elif command == 'pan-os-hygiene-conforming-spyware-profiles':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    get_conforming_spyware_profiles(topology, **demisto.args()),
                    empty_result_message="No conforming Spyware profiles.",
                    override_table_headers=["hostid", "name", "object_type", "container_name"],
                    override_table_name="Best Practices conforming Anti-spyware profiles"
                )
            )
        elif command == 'pan-os-hygiene-check-security-zones':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    check_security_zones(topology, **demisto.args()),
                    empty_result_message="All security zones are configured correctly."
                )
            )
        elif command == 'pan-os-hygiene-check-security-rules':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    check_security_rules(topology, **demisto.args()),
                    empty_result_message="All security rules are configured correctly."
                )
            )
        elif command == 'pan-os-hygiene-fix-log-forwarding':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    fix_log_forwarding(topology, **demisto.args()),
                    empty_result_message="Nothing to fix."
                )
            )
        elif command == 'pan-os-hygiene-fix-security-zone-log-settings':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    fix_security_zone_log_setting(topology, **demisto.args()),
                    empty_result_message="Nothing to fix."
                )
            )
        elif command == 'pan-os-hygiene-fix-security-rule-log-settings':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    fix_security_rule_log_setting(topology, **demisto.args()),
                    empty_result_message="Nothing to fix."
                )
            )
        elif command == 'pan-os-hygiene-fix-security-rule-profile-settings':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    fix_security_rule_security_profile_group(topology, **demisto.args()),
                    empty_result_message="Nothing to fix."
                )
            )
        elif command == 'pan-os-config-get-object':
            topology = get_topology()
            return_results(
                dataclasses_to_command_results(
                    get_object(topology, **demisto.args()),
                    empty_result_message="No objects found."
                )
            )
        elif command == 'pan-os-platform-get-device-state':
            topology = get_topology()
            # This just returns a fileResult object directly.
            return_results(get_device_state(topology, **demisto.args()))
        elif command == 'pan-os-get-merged-config':
            return_results(pan_os_get_merged_config(args))
        elif command == 'pan-os-get-running-config':
            return_results(pan_os_get_running_config(args))
        elif command == 'pan-os-list-nat-rules':
            return_results(pan_os_list_nat_rules_command(args))
        elif command == 'pan-os-create-nat-rule':
            return_results(pan_os_create_nat_rule_command(args))
        elif command == 'pan-os-delete-nat-rule':
            return_results(pan_os_delete_nat_rule_command(args))
        elif command == 'pan-os-edit-nat-rule':
            return_results(pan_os_edit_nat_rule_command(args))
        elif command == 'pan-os-list-virtual-routers':
            return_results(pan_os_list_virtual_routers_command(args))
        elif command == 'pan-os-list-redistribution-profiles':
            return_results(pan_os_list_redistribution_profile_command(args))
        elif command == 'pan-os-create-redistribution-profile':
            return_results(pan_os_create_redistribution_profile_command(args))
        elif command == 'pan-os-edit-redistribution-profile':
            return_results(pan_os_edit_redistribution_profile_command(args))
        elif command == 'pan-os-delete-redistribution-profile':
            return_results(pan_os_delete_redistribution_profile_command(args))
        elif command == 'pan-os-list-pbf-rules':
            return_results(pan_os_list_pbf_rules_command(args))
        elif command == 'pan-os-create-pbf-rule':
            return_results(pan_os_create_pbf_rule_command(args))
        elif command == 'pan-os-edit-pbf-rule':
            return_results(pan_os_edit_pbf_rule_command(args))
        elif command == 'pan-os-delete-pbf-rule':
            return_results(pan_os_delete_pbf_rule_command(args))
        elif command == 'pan-os-list-application-groups':
            return_results(pan_os_list_application_groups_command(args))
        elif command == 'pan-os-create-application-group':
            return_results(pan_os_create_application_group_command(args))
        elif command == 'pan-os-edit-application-group':
            return_results(pan_os_edit_application_group_command(args))
        elif command == 'pan-os-delete-application-group':
            return_results(pan_os_delete_application_group_command(args))
        elif command == 'pan-os-list-templates':
            return_results(pan_os_list_templates_command(args))
        elif command == 'pan-os-list-tag':
            return_results(pan_os_list_tag_command(args))
        elif command == 'pan-os-create-tag':
            return_results(pan_os_create_tag_command(args))
        elif command == 'pan-os-edit-tag':
            return_results(pan_os_edit_tag_command(args))
        elif command == 'pan-os-delete-tag':
            return_results(pan_os_delete_tag_command(args))
        elif command == 'pan-os-list-device-groups':
            return_results(list_device_groups_names())
        elif command == 'pan-os-export-tech-support-file':
            return_results(export_tsf_command(args))
        elif command == 'pan-os-list-security-profile-group':
            return_results(pan_os_list_security_profile_groups_command(args))
        elif command == 'pan-os-create-security-profile-group':
            return_results(pan_os_create_security_profile_group_command(args))
        elif command == 'pan-os-edit-security-profile-group':
            return_results(pan_os_edit_security_profile_group_command(args))
        elif command == 'pan-os-delete-security-profile-group':
            return_results(pan_os_delete_security_profile_group_command(args))
        elif command == 'pan-os-get-audit-comment':
            return_results(pan_os_get_audit_comment_command(args))
        elif command == 'pan-os-add-profile-exception':
            return_results(pan_os_add_profile_exception_command(args))
        elif command == 'pan-os-edit-profile-exception':
            return_results(pan_os_edit_profile_exception_command(args))
        elif command == 'pan-os-delete-profile-exception':
            return_results(pan_os_delete_profile_exception_command(args))
        elif command == 'pan-os-list-profile-exception':
            return_results(pan_os_list_profile_exception_command(args))
        elif command == 'pan-os-create-master-key':
            return_results(pan_os_create_master_key_command(args))
        elif command == 'pan-os-update-master-key':
            return_results(pan_os_update_master_key_command(args))
        elif command == 'pan-os-get-master-key-details':
            return_results(pan_os_get_master_key_details_command())
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')
    except Exception as err:
        return_error(str(err), error=traceback.format_exc())

    finally:
        LOG.print_log()


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
