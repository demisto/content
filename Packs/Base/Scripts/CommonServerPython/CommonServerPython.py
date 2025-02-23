"""Common functions script
This script will be appended to each server script before being executed.
Please notice that to add custom common code, add it to the CommonServerUserPython script.
Note that adding code to CommonServerUserPython can override functions in CommonServerPython
"""
# If you change this section, make sure you update the line offset magic number
from __future__ import print_function

import base64
import binascii
import gc
import json
import logging
import os
import re
import socket
import sys
import time
import traceback
import types
import urllib
import gzip
import ssl
from random import randint
import xml.etree.cElementTree as ET
from collections import OrderedDict
from datetime import datetime, timedelta
from abc import abstractmethod
from distutils.version import LooseVersion
from threading import Lock
from functools import wraps
from inspect import currentframe

import demistomock as demisto
import warnings


def __line__():
    cf = currentframe()
    return cf.f_back.f_lineno  # type: ignore[union-attr]


# The number is the line offset from the beginning of the file. If you added an import, update this number accordingly.
_MODULES_LINE_MAPPING = {
    'CommonServerPython': {'start': __line__() - 45, 'end': float('inf')},
}

XSIAM_EVENT_CHUNK_SIZE = 2 ** 20  # 1 Mib
XSIAM_EVENT_CHUNK_SIZE_LIMIT = 9 * (10 ** 6)  # 9 MB, note that the allowed max size for 1 entry is 5MB.
# So if you're using a "heavy" API it is recommended to use maximum of 4MB chunk size.
MAX_ALLOWED_ENTRY_SIZE = 5 * (10 ** 6)  # 5 MB, this is the maximum allowed size of a single entry.
# So if you're using a "heavy" API it is recommended to use maximum of 9MB chunk size.
ASSETS = "assets"
EVENTS = "events"
DATA_TYPES = [EVENTS, ASSETS]
MASK = '<XX_REPLACED>'
SEND_PREFIX = "send: b'"
SAFE_SLEEP_START_TIME = datetime.now()
MAX_ERROR_MESSAGE_LENGTH = 50000
NUM_OF_WORKERS = 20
HAVE_SUPPORT_MULTITHREADING_CALLED_ONCE = False


def register_module_line(module_name, start_end, line, wrapper=0):
    global _MODULES_LINE_MAPPING
    default_module_info = {'start': 0, 'start_wrapper': 0, 'end': float('inf'), 'end_wrapper': float('inf')}
    try:
        if start_end not in ('start', 'end'):
            raise ValueError('Invalid start_end argument. Acceptable values are: start, end.')
        if not isinstance(line, int) or line < 0:
            raise ValueError('Invalid line argument. Expected non-negative integer, '
                             'got {}({})'.format(type(line), line))

        _MODULES_LINE_MAPPING.setdefault(module_name, default_module_info).update(
            {start_end: line, '{}_wrapper'.format(start_end): line + wrapper}
        )
    except Exception as exc:
        demisto.info(
            'failed to register module line. '
            'module: "{}" start_end: "{}" line: "{}".\nError: {}'.format(module_name, start_end, line, exc))


def _find_relevant_module(line):
    global _MODULES_LINE_MAPPING

    relevant_module = ''
    for module, info in _MODULES_LINE_MAPPING.items():
        if info['start'] <= line <= info['end']:
            if not relevant_module:
                relevant_module = module
            elif info['start'] > _MODULES_LINE_MAPPING[relevant_module]['start']:
                relevant_module = module

    return relevant_module


def fix_traceback_line_numbers(trace_str):

    def is_adjusted_block(start, end, adjusted_lines):
        return any(
            block_start < start < end < block_end
            for block_start, block_end in adjusted_lines.items()
        )

    for number in re.findall(r'line (\d+)', trace_str):
        line_num = int(number)
        module = _find_relevant_module(line_num)
        if module:
            module_start_line = _MODULES_LINE_MAPPING.get(module, {'start': 0})['start']
            actual_number = line_num - module_start_line

            # in case of ApiModule injections, adjust the line numbers of the code after the injection
            # should avoid adjust ApiModule twice in case of ApiModuleA -> import ApiModuleB
            adjusted_lines = {}  # type: ignore[var-annotated]
            modules_info = list(_MODULES_LINE_MAPPING.values())
            modules_info.sort(key=lambda obj: int(obj.get('start_wrapper', obj['start'])))
            for module_info in modules_info:
                block_start = module_info.get('start_wrapper', module_info['start'])
                block_end = module_info.get('end_wrapper', module_info['end'])
                if block_start > module_start_line and block_end < line_num \
                        and not is_adjusted_block(block_start, block_end, adjusted_lines):
                    actual_number -= block_end - block_start
                    adjusted_lines[block_start] = block_end

            # a traceback line is of the form: File "<string>", line 8853, in func5
            trace_str = trace_str.replace(
                'File "<string>", line {},'.format(number),
                'File "<{}>", line {},'.format(module, actual_number)
            )

    return trace_str


OS_LINUX = False
OS_MAC = False
OS_WINDOWS = False
if sys.platform.startswith('linux'):
    OS_LINUX = True
elif sys.platform.startswith('darwin'):
    OS_MAC = True
elif sys.platform.startswith('win32'):
    OS_WINDOWS = True


class WarningsHandler(object):

    @staticmethod
    def handle_warning(message, category, filename, lineno, file=None, line=None):
        try:
            msg = warnings.formatwarning(message, category, filename, lineno, line)
            demisto.info("python warning: " + msg)
        except Exception:
            # ignore the warning if it can't be handled for some reason
            pass

    def __init__(self):
        self.org_handler = warnings.showwarning
        warnings.showwarning = WarningsHandler.handle_warning

    def __del__(self):
        warnings.showwarning = self.org_handler


_warnings_handler = WarningsHandler()
# ignore warnings from logging as a result of not being setup
logging.raiseExceptions = False

# imports something that can be missed from docker image
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util import Retry
    from typing import Optional, Dict, List, Any, Union, Set, cast

    from urllib3 import disable_warnings

    disable_warnings()

    import dateparser  # type: ignore
    from datetime import timezone  # type: ignore
except Exception:
    if sys.version_info[0] < 3:
        # in python 2 an exception in the imports might still be raised even though it is caught.
        # for more info see https://cosmicpercolator.com/2016/01/13/exception-leaks-in-python-2-and-3/
        sys.exc_clear()

CONTENT_RELEASE_VERSION = '0.0.0'
CONTENT_BRANCH_NAME = 'master'
IS_PY3 = sys.version_info[0] == 3
PY_VER_MINOR = sys.version_info[1]
STIX_PREFIX = "STIX "
# pylint: disable=undefined-variable

ZERO = timedelta(0)
HOUR = timedelta(hours=1)

# The max number of profiling related rows to print to the log on memory dump
PROFILING_DUMP_ROWS_LIMIT = 20

if IS_PY3:
    STRING_TYPES = (str, bytes)  # type: ignore
    STRING_OBJ_TYPES = (str,)
    import concurrent.futures

else:
    STRING_TYPES = (str, unicode)  # type: ignore # noqa: F821
    STRING_OBJ_TYPES = STRING_TYPES  # type: ignore
# pylint: enable=undefined-variable

# DEPRECATED - use EntryType enum instead
entryTypes = {
    'note': 1,
    'downloadAgent': 2,
    'file': 3,
    'error': 4,
    'pinned': 5,
    'userManagement': 6,
    'image': 7,
    'playgroundError': 8,
    'entryInfoFile': 9,
    'warning': 11,
    'map': 15,
    'debug': 16,
    'widget': 17
}

ENDPOINT_STATUS_OPTIONS = [
    'Online',
    'Offline',
    'Unknown'
]

ENDPOINT_ISISOLATED_OPTIONS = [
    'Yes',
    'No',
    'Pending isolation',
    'Pending unisolation'
]


class EntryType(object):
    """
    Enum: contains all the entry types (e.g. NOTE, ERROR, WARNING, FILE, etc.)
    :return: None
    :rtype: ``None``
    """
    NOTE = 1
    DOWNLOAD_AGENT = 2
    FILE = 3
    ERROR = 4
    PINNED = 5
    USER_MANAGEMENT = 6
    IMAGE = 7
    PLAYGROUND_ERROR = 8
    ENTRY_INFO_FILE = 9
    VIDEO_FILE = 10
    WARNING = 11
    STATIC_VIDEO_FILE = 12
    MAP_ENTRY_TYPE = 15
    WIDGET = 17
    EXECUTION_METRICS = 19


class IncidentStatus(object):
    """
    Enum: contains all the incidents status types (e.g. pending, active, done, archive)
    :return: None
    :rtype: ``None``
    """
    PENDING = 0
    ACTIVE = 1
    DONE = 2
    ARCHIVE = 3


class IncidentSeverity(object):
    """
    Enum: contains all the incident severity types
    :return: None
    :rtype: ``None``
    """
    UNKNOWN = 0
    INFO = 0.5
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# DEPRECATED - use EntryFormat enum instead
formats = {
    'html': 'html',
    'table': 'table',
    'json': 'json',
    'text': 'text',
    'dbotResponse': 'dbotCommandResponse',
    'markdown': 'markdown'
}


class EntryFormat(object):
    """
    Enum: contains all the entry formats (e.g. HTML, TABLE, JSON, etc.)
    """
    HTML = 'html'
    TABLE = 'table'
    JSON = 'json'
    TEXT = 'text'
    DBOT_RESPONSE = 'dbotCommandResponse'
    MARKDOWN = 'markdown'

    @classmethod
    def is_valid_type(cls, _type):
        # type: (str) -> bool
        return _type in (
            EntryFormat.HTML,
            EntryFormat.TABLE,
            EntryFormat.JSON,
            EntryFormat.TEXT,
            EntryFormat.MARKDOWN,
            EntryFormat.DBOT_RESPONSE
        )


class FileAttachmentType(object):
    """
    Enum: contains the file attachment types,
          Used to add metadata to the description of the attachment
          whether the file content is expected to be inline or attached as a file

    :return:: The file attachment type
    :rtype: ``str``
    """
    ATTACHED = "attached_file"


brands = {
    'xfe': 'xfe',
    'vt': 'virustotal',
    'wf': 'WildFire',
    'cy': 'cylance',
    'cs': 'crowdstrike-intel'
}
providers = {
    'xfe': 'IBM X-Force Exchange',
    'vt': 'VirusTotal',
    'wf': 'WildFire',
    'cy': 'Cylance',
    'cs': 'CrowdStrike'
}
thresholds = {
    'xfeScore': 4,
    'vtPositives': 10,
    'vtPositiveUrlsForIP': 30
}


class DBotScoreType(object):
    """
    Enum: contains all the indicator types
    DBotScoreType.IP
    DBotScoreType.FILE
    DBotScoreType.DOMAIN
    DBotScoreType.URL
    DBotScoreType.CVE
    DBotScoreType.ACCOUNT
    DBotScoreType.CRYPTOCURRENCY
    DBotScoreType.EMAIL
    DBotScoreType.ATTACKPATTERN
    DBotScoreType.CUSTOM

    :return: None
    :rtype: ``None``
    """
    IP = 'ip'
    FILE = 'file'
    DOMAIN = 'domain'
    URL = 'url'
    CVE = 'cve'
    ACCOUNT = 'account'
    CIDR = 'cidr',
    DOMAINGLOB = 'domainglob'
    CERTIFICATE = 'certificate'
    CRYPTOCURRENCY = 'cryptocurrency'
    EMAIL = 'email'
    ATTACKPATTERN = 'attackpattern'
    CUSTOM = 'custom'

    def __init__(self):
        # required to create __init__ for create_server_docs.py purpose
        pass

    @classmethod
    def is_valid_type(cls, _type):
        # type: (str) -> bool

        return _type in (
            DBotScoreType.IP,
            DBotScoreType.FILE,
            DBotScoreType.DOMAIN,
            DBotScoreType.URL,
            DBotScoreType.CVE,
            DBotScoreType.ACCOUNT,
            DBotScoreType.CIDR,
            DBotScoreType.DOMAINGLOB,
            DBotScoreType.CERTIFICATE,
            DBotScoreType.CRYPTOCURRENCY,
            DBotScoreType.EMAIL,
            DBotScoreType.ATTACKPATTERN,
            DBotScoreType.CUSTOM,
        )


class DBotScoreReliability(object):
    """
    Enum: Source reliability levels
    Values are case sensitive

    :return: None
    :rtype: ``None``
    """

    A_PLUS = 'A+ - 3rd party enrichment'
    A = 'A - Completely reliable'
    B = 'B - Usually reliable'
    C = 'C - Fairly reliable'
    D = 'D - Not usually reliable'
    E = 'E - Unreliable'
    F = 'F - Reliability cannot be judged'

    def __init__(self):
        # required to create __init__ for create_server_docs.py purpose
        pass

    @staticmethod
    def is_valid_type(_type):
        # type: (str) -> bool

        return _type in (
            DBotScoreReliability.A_PLUS,
            DBotScoreReliability.A,
            DBotScoreReliability.B,
            DBotScoreReliability.C,
            DBotScoreReliability.D,
            DBotScoreReliability.E,
            DBotScoreReliability.F,
        )

    @staticmethod
    def get_dbot_score_reliability_from_str(reliability_str):  # pragma: no cover
        if reliability_str == DBotScoreReliability.A_PLUS:
            return DBotScoreReliability.A_PLUS
        elif reliability_str == DBotScoreReliability.A:
            return DBotScoreReliability.A
        elif reliability_str == DBotScoreReliability.B:
            return DBotScoreReliability.B
        elif reliability_str == DBotScoreReliability.C:
            return DBotScoreReliability.C
        elif reliability_str == DBotScoreReliability.D:
            return DBotScoreReliability.D
        elif reliability_str == DBotScoreReliability.E:
            return DBotScoreReliability.E
        elif reliability_str == DBotScoreReliability.F:
            return DBotScoreReliability.F
        raise Exception("Please use supported reliability only.")


INDICATOR_TYPE_TO_CONTEXT_KEY = {
    'ip': 'Address',
    'email': 'Address',
    'url': 'Data',
    'domain': 'Name',
    'cve': 'ID',
    'md5': 'file',
    'sha1': 'file',
    'sha256': 'file',
    'crc32': 'file',
    'sha512': 'file',
    'ctph': 'file',
    'ssdeep': 'file'
}


class ErrorTypes(object):
    """
    Enum: contains all the available error types
    :return: None
    :rtype: ``None``
    """
    SUCCESS = 'Successful'
    QUOTA_ERROR = 'QuotaError'
    GENERAL_ERROR = 'GeneralError'
    AUTH_ERROR = 'AuthError'
    SERVICE_ERROR = 'ServiceError'
    CONNECTION_ERROR = 'ConnectionError'
    PROXY_ERROR = 'ProxyError'
    SSL_ERROR = 'SSLError'
    TIMEOUT_ERROR = 'TimeoutError'
    RETRY_ERROR = "RetryError"


class FeedIndicatorType(object):
    """Type of Indicator (Reputations), used in TIP integrations"""
    Account = "Account"
    CVE = "CVE"
    Domain = "Domain"
    DomainGlob = "DomainGlob"
    Email = "Email"
    File = "File"
    FQDN = "Domain"
    Host = "Host"
    IP = "IP"
    CIDR = "CIDR"
    IPv6 = "IPv6"
    IPv6CIDR = "IPv6CIDR"
    Registry = "Registry Key"
    SSDeep = "ssdeep"
    URL = "URL"
    AS = "ASN"
    MUTEX = "Mutex"
    Malware = "Malware"
    Identity = "Identity"
    Location = "Location"
    Software = "Software"
    X509 = "X509 Certificate"

    @staticmethod
    def is_valid_type(_type):
        return _type in (
            FeedIndicatorType.Account,
            FeedIndicatorType.CVE,
            FeedIndicatorType.Domain,
            FeedIndicatorType.DomainGlob,
            FeedIndicatorType.Email,
            FeedIndicatorType.File,
            FeedIndicatorType.Host,
            FeedIndicatorType.IP,
            FeedIndicatorType.CIDR,
            FeedIndicatorType.IPv6,
            FeedIndicatorType.IPv6CIDR,
            FeedIndicatorType.Registry,
            FeedIndicatorType.SSDeep,
            FeedIndicatorType.URL,
            FeedIndicatorType.AS,
            FeedIndicatorType.MUTEX,
            FeedIndicatorType.Malware,
            FeedIndicatorType.Identity,
            FeedIndicatorType.Location,
            FeedIndicatorType.Software,
            FeedIndicatorType.X509,
        )

    @staticmethod
    def list_all_supported_indicators():
        indicator_types = []
        for key, val in vars(FeedIndicatorType).items():
            if not key.startswith('__') and type(val) == str:
                indicator_types.append(val)
        return indicator_types

    @staticmethod
    def ip_to_indicator_type(ip):
        """Returns the indicator type of the input IP.

        :type ip: ``str``
        :param ip: IP address to get it's indicator type.

        :return:: Indicator type from FeedIndicatorType, or None if invalid IP address.
        :rtype: ``str``
        """
        if re.match(ipv4cidrRegex, ip):
            return FeedIndicatorType.CIDR

        elif re.match(ipv4Regex, ip):
            return FeedIndicatorType.IP

        elif re.match(ipv6cidrRegex, ip):
            return FeedIndicatorType.IPv6CIDR

        elif re.match(ipv6Regex, ip):
            return FeedIndicatorType.IPv6

        else:
            return None

    @staticmethod
    def indicator_type_by_server_version(indicator_type):
        """Returns the indicator type of the input by the server version.
        If the server version is 6.2 and greater, remove the STIX prefix of the type

        :type indicator_type: ``str``
        :param indicator_type: Type of an indicator.

        :return:: Indicator type .
        :rtype: ``str``
        """
        if indicator_type.startswith(STIX_PREFIX):
            return indicator_type[len(STIX_PREFIX):]
        return indicator_type


# -------------------------------- Threat Intel Objects ----------------------------------- #

class ThreatIntel:
    """
    XSOAR Threat Intel Objects
    :return: None
    :rtype: ``None``
    """

    class ObjectsNames(object):
        """
        Enum: Threat Intel Objects names.
        :return: None
        :rtype: ``None``
        """
        CAMPAIGN = 'Campaign'
        ATTACK_PATTERN = 'Attack Pattern'
        REPORT = 'Report'
        MALWARE = 'Malware'
        COURSE_OF_ACTION = 'Course of Action'
        INTRUSION_SET = 'Intrusion Set'
        TOOL = 'Tool'
        THREAT_ACTOR = 'Threat Actor'
        INFRASTRUCTURE = 'Infrastructure'
        TACTIC = 'Tactic'

    class ObjectsScore(object):
        """
        Enum: Threat Intel Objects Score.
        :return: None
        :rtype: ``None``
        """
        CAMPAIGN = 3
        ATTACK_PATTERN = 2
        REPORT = 3
        MALWARE = 3
        COURSE_OF_ACTION = 0
        INTRUSION_SET = 3
        TOOL = 2
        THREAT_ACTOR = 3
        INFRASTRUCTURE = 2
        TACTIC = 0

    class KillChainPhases(object):
        """
        Enum: Kill Chain Phases names.
        :return: None
        :rtype: ``None``
        """
        BUILD_CAPABILITIES = "Build Capabilities"
        PRIVILEGE_ESCALATION = "Privilege Escalation"
        ADVERSARY_OPSEC = "Adversary Opsec"
        CREDENTIAL_ACCESS = "Credential Access"
        EXFILTRATION = "Exfiltration"
        LATERAL_MOVEMENT = "Lateral Movement"
        DEFENSE_EVASION = "Defense Evasion"
        PERSISTENCE = "Persistence"
        COLLECTION = "Collection"
        IMPACT = "Impact"
        INITIAL_ACCESS = "Initial Access"
        DISCOVERY = "Discovery"
        EXECUTION = "Execution"
        INSTALLATION = "Installation"
        DELIVERY = "Delivery"
        WEAPONIZATION = "Weaponization"
        ACT_ON_OBJECTIVES = "Actions on Objectives"
        COMMAND_AND_CONTROL = "Command \u0026 Control"


def is_debug_mode():
    """Return if this script/command was passed debug-mode=true option

    :return: true if debug-mode is enabled
    :rtype: ``bool``
    """
    # use `hasattr(demisto, 'is_debug')` to ensure compatibility with server version <= 4.5
    return hasattr(demisto, 'is_debug') and demisto.is_debug


def get_schedule_metadata(context):
    """
        Get the entry schedule metadata if available

        :type context: ``dict``
        :param context: Context in which the command was executed.

        :return: Dict with metadata of scheduled entry
        :rtype: ``dict``
    """
    schedule_metadata = {}
    parent_entry = context.get('ParentEntry', {})
    if parent_entry:
        schedule_metadata = assign_params(
            is_polling=True if parent_entry.get('polling') else False,
            polling_command=parent_entry.get('pollingCommand'),
            polling_args=parent_entry.get('pollingArgs'),
            times_ran=int(parent_entry.get('timesRan', 0)) + 1,
            start_date=parent_entry.get('startDate'),
            end_date=parent_entry.get('endingDate')
        )
    return schedule_metadata


def detect_file_indicator_type(indicator_value):
    """
      Detect the type of the file indicator.

      :type indicator_value: ``str``
      :param indicator_value: The indicator whose type we want to check. (required)

      :return: The type of the indicator.
      :rtype: ``str``
    """
    if ":" in indicator_value:
        return 'ssdeep'
    if re.match(sha256Regex, indicator_value):
        return 'sha256'
    if re.match(md5Regex, indicator_value):
        return 'md5'
    if re.match(sha1Regex, indicator_value):
        return 'sha1'
    if re.match(sha512Regex, indicator_value):
        return 'sha512'

    return None


def auto_detect_indicator_type(indicator_value):
    """
      Infer the type of the indicator.

      :type indicator_value: ``str``
      :param indicator_value: The indicator whose type we want to check. (required)

      :return: The type of the indicator.
      :rtype: ``str``
    """
    try:
        import tldextract
    except Exception:
        raise Exception("Missing tldextract module, In order to use the auto detect function please use a docker"
                        " image with it installed such as: demisto/jmespath")

    indicator_value = indicator_value.replace('[.]', '.').replace('[@]', '@')  # Refang indicator prior to checking

    if re.match(ipv4cidrRegex, indicator_value):
        return FeedIndicatorType.CIDR

    if re.match(ipv6cidrRegex, indicator_value):
        return FeedIndicatorType.IPv6CIDR

    if re.match(ipv4Regex, indicator_value):
        return FeedIndicatorType.IP

    if re.match(ipv6Regex, indicator_value):
        return FeedIndicatorType.IPv6

    if re.match(cveRegex, indicator_value):
        return FeedIndicatorType.CVE

    if re.match(md5Regex, indicator_value):
        return FeedIndicatorType.File

    if re.match(sha1Regex, indicator_value):
        return FeedIndicatorType.File

    if re.match(sha256Regex, indicator_value):
        return FeedIndicatorType.File

    if re.match(sha512Regex, indicator_value):
        return FeedIndicatorType.File

    if re.match(emailRegex, indicator_value):
        return FeedIndicatorType.Email

    if re.match(urlRegex, indicator_value):
        return FeedIndicatorType.URL

    try:
        tldextract_version = tldextract.__version__
        if LooseVersion(tldextract_version) < '3.0.0':
            no_cache_extract = tldextract.TLDExtract(cache_file=False, suffix_list_urls=None)
        else:
            no_cache_extract = tldextract.TLDExtract(cache_dir=False, suffix_list_urls=None)

        if no_cache_extract(indicator_value).suffix:
            if '*' in indicator_value:
                return FeedIndicatorType.DomainGlob
            return FeedIndicatorType.Domain

    except Exception:
        demisto.debug('tldextract failed to detect indicator type. indicator value: {}'.format(indicator_value))

    demisto.debug('Failed to detect indicator type. Indicator value: {}'.format(indicator_value))
    return None


def add_http_prefix_if_missing(address=''):
    """
        This function adds `http://` prefix to the proxy address in case it is missing.

        :type address: ``string``
        :param address: Proxy address.

        :return: proxy address after the 'http://' prefix was added, if needed.
        :rtype: ``string``
    """
    PROXY_PREFIXES = ['http://', 'https://', 'socks5://', 'socks5h://', 'socks4://', 'socks4a://']
    if not address:
        return ''
    for prefix in PROXY_PREFIXES:
        if address.startswith(prefix):
            return address
    return 'http://' + address


def handle_proxy_for_long_running(proxy_param_name='proxy', checkbox_default_value=False, handle_insecure=True,
                                  insecure_param_name=None):
    """
        Handle logic for long running integration routing traffic through the system proxy.
        Should usually be called at the beginning of the integration, depending on proxy checkbox state.
        Long running integrations on hosted tenants XSOAR8 and XSIAM has a dedicated env. var.: CRTX_HTTP_PROXY.
        Fallback call to handle_proxy in cases long running integration on engine or XSOAR6

        :type proxy_param_name: ``string``
        :param proxy_param_name: name of the "use system proxy" integration parameter

        :type checkbox_default_value: ``bool``
        :param checkbox_default_value: Default value of the proxy param checkbox

        :type handle_insecure: ``bool``
        :param handle_insecure: Whether to check the insecure param and unset env variables

        :type insecure_param_name: ``string``
        :param insecure_param_name: Name of insecure param. If None will search insecure and unsecure

        :return: proxies dict for the 'proxies' parameter of 'requests' functions and use_ssl boolean
        :rtype: ``Tuple[dict, boolean]``
    """
    proxies = {}
    crtx_http_proxy = os.environ.get('CRTX_HTTP_PROXY', None)
    if crtx_http_proxy:
        demisto.error('Setting proxies according to CRTX_HTTP_PROXY: {}'.format(crtx_http_proxy))
        proxies = {
            'http': crtx_http_proxy,
            'https': crtx_http_proxy
        }
        handle_insecure = True
        return proxies, handle_insecure
    return handle_proxy(proxy_param_name, checkbox_default_value, handle_insecure, insecure_param_name), handle_insecure


def handle_proxy(proxy_param_name='proxy', checkbox_default_value=False, handle_insecure=True,
                 insecure_param_name=None):
    """
        Handle logic for routing traffic through the system proxy.
        Should usually be called at the beginning of the integration, depending on proxy checkbox state.

        Additionally will unset env variables REQUESTS_CA_BUNDLE and CURL_CA_BUNDLE if handle_insecure is speficied (default).
        This is needed as when these variables are set and a requests.Session object is used, requests will ignore the
        Sesssion.verify setting. See: https://github.com/psf/requests/blob/master/requests/sessions.py#L703

        :type proxy_param_name: ``string``
        :param proxy_param_name: name of the "use system proxy" integration parameter

        :type checkbox_default_value: ``bool``
        :param checkbox_default_value: Default value of the proxy param checkbox

        :type handle_insecure: ``bool``
        :param handle_insecure: Whether to check the insecure param and unset env variables

        :type insecure_param_name: ``string``
        :param insecure_param_name: Name of insecure param. If None will search insecure and unsecure

        :return: proxies dict for the 'proxies' parameter of 'requests' functions
        :rtype: ``dict``
    """
    proxies = {}  # type: dict
    if demisto.params().get(proxy_param_name, checkbox_default_value):
        ensure_proxy_has_http_prefix()
        proxies = {
            'http': os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy', ''),
            'https': os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy', '')
        }
    else:
        skip_proxy()

    if handle_insecure:
        if insecure_param_name is None:
            param_names = ('insecure', 'unsecure')
        else:
            param_names = (insecure_param_name,)  # type: ignore[assignment]
        for p in param_names:
            if demisto.params().get(p, False):
                skip_cert_verification()

    return proxies


def skip_proxy():
    """
    The function deletes the proxy environment vars in order to http requests to skip routing through proxy

    :return: None
    :rtype: ``None``
    """
    for k in ('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy'):
        if k in os.environ:
            del os.environ[k]


def ensure_proxy_has_http_prefix():
    """
    The function checks if proxy environment vars are missing http/https prefixes, and adds http if so.

    :return: None
    :rtype: ``None``
    """
    for k in ('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy'):
        if k in os.environ:
            proxy_env_var = os.getenv(k)
            if proxy_env_var:
                os.environ[k] = add_http_prefix_if_missing(os.environ[k])


def skip_cert_verification():
    """
    The function deletes the self signed certificate env vars in order to http requests to skip certificate validation.

    :return: None
    :rtype: ``None``
    """
    for k in ('REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE'):
        if k in os.environ:
            del os.environ[k]


def urljoin(url, suffix=""):
    """
        Will join url and its suffix

        Example:
        "https://google.com/", "/"   => "https://google.com/"
        "https://google.com", "/"   => "https://google.com/"
        "https://google.com", "api"   => "https://google.com/api"
        "https://google.com", "/api"  => "https://google.com/api"
        "https://google.com/", "api"  => "https://google.com/api"
        "https://google.com/", "/api" => "https://google.com/api"

        :type url: ``string``
        :param url: URL string (required)

        :type suffix: ``string``
        :param suffix: the second part of the url

        :return: Full joined url
        :rtype: ``string``
    """
    if url[-1:] != "/":
        url = url + "/"

    if suffix.startswith("/"):
        suffix = suffix[1:]
        return url + suffix

    return url + suffix


def positiveUrl(entry):
    """
       Deprecated
       :type entry: ``dict``
       :param entry: URL entry (required)
       :return: True if bad, false otherwise
       :rtype: ``bool``
    """
    if entry['Type'] != entryTypes['error'] and entry['ContentsFormat'] == formats['json']:
        if entry['Brand'] == brands['xfe']:
            return demisto.get(entry, 'Contents.url.result.score') > thresholds['xfeScore']
        if entry['Brand'] == brands['vt']:
            return demisto.get(entry, 'Contents.positives') > thresholds['vtPositives']
        if entry['Brand'] == brands['cs'] and demisto.get(entry, 'Contents'):
            c = demisto.get(entry, 'Contents')[0]
            return demisto.get(c, 'indicator') and demisto.get(c, 'malicious_confidence') in ['high', 'medium']
    return False


def positiveFile(entry):  # pragma: no cover
    """
       Deprecated
       :type entry: ``dict``
       :param entry: File entry (required)
       :return: True if bad, false otherwise
       :rtype: ``bool``
    """
    if entry['Type'] != entryTypes['error'] and entry['ContentsFormat'] == formats['json']:
        if entry['Brand'] == brands['xfe'] and (demisto.get(entry, 'Contents.malware.family')
                                                or demisto.gets(entry, 'Contents.malware.origins.external.family')):
            return True
        if entry['Brand'] == brands['vt']:
            return demisto.get(entry, 'Contents.positives') > thresholds['vtPositives']
        if entry['Brand'] == brands['wf']:
            return demisto.get(entry, 'Contents.wildfire.file_info.malware') == 'yes'
        if entry['Brand'] == brands['cy'] and demisto.get(entry, 'Contents'):
            contents = demisto.get(entry, 'Contents')
            k = contents.keys()
            if k and len(k) > 0:
                v = contents[k[0]]
                if v and demisto.get(v, 'generalscore'):
                    return v['generalscore'] < -0.5
        if entry['Brand'] == brands['cs'] and demisto.get(entry, 'Contents'):
            c = demisto.get(entry, 'Contents')[0]
            return demisto.get(c, 'indicator') and demisto.get(c, 'malicious_confidence') in ['high', 'medium']
    return False


def vtCountPositives(entry):
    """
       Counts the number of detected URLs in the entry

       :type entry: ``dict``
       :param entry: Demisto entry (required)

       :return: The number of detected URLs
       :rtype: ``int``
    """
    positives = 0
    if demisto.get(entry, 'Contents.detected_urls'):
        for detected in demisto.get(entry, 'Contents.detected_urls'):
            if demisto.get(detected, 'positives') > thresholds['vtPositives']:
                positives += 1
    return positives


def positiveIp(entry):  # pragma: no cover
    """
       Checks if the given entry from a file reputation query is positive (known bad) (deprecated)

       :type entry: ``dict``
       :param entry: IP entry (required)

       :return: True if bad, false otherwise
       :rtype: ``bool``
    """
    if entry['Type'] != entryTypes['error'] and entry['ContentsFormat'] == formats['json']:
        if entry['Brand'] == brands['xfe']:
            return demisto.get(entry, 'Contents.reputation.score') > thresholds['xfeScore']
        if entry['Brand'] == brands['vt'] and demisto.get(entry, 'Contents.detected_urls'):
            return vtCountPositives(entry) > thresholds['vtPositiveUrlsForIP']
        if entry['Brand'] == brands['cs'] and demisto.get(entry, 'Contents'):
            c = demisto.get(entry, 'Contents')[0]
            return demisto.get(c, 'indicator') and demisto.get(c, 'malicious_confidence') in ['high', 'medium']
    return False


def formatEpochDate(t):
    """
       Convert a time expressed in seconds since the epoch to a string representing local time

       :type t: ``int``
       :param t: Time represented in seconds (required)

       :return: A string representing local time
       :rtype: ``str``
    """
    if t:
        return time.ctime(t)
    return ''


def shortCrowdStrike(entry):  # pragma: no cover
    """
       Deprecated

       :type entry: ``dict``
       :param entry: CrowdStrike result entry (required)

       :return: A Demisto entry containing the shortened CrowdStrike info
       :rtype: ``dict``
    """
    if entry['Type'] != entryTypes['error'] and entry['ContentsFormat'] == formats['json']:
        if entry['Brand'] == brands['cs'] and demisto.get(entry, 'Contents'):
            c = demisto.get(entry, 'Contents')[0]
            csRes = '## CrowdStrike Falcon Intelligence'
            csRes += '\n\n### Indicator - ' + demisto.gets(c, 'indicator')
            labels = demisto.get(c, 'labels')
            if labels:
                csRes += '\n### Labels'
                csRes += '\nName|Created|Last Valid'
                csRes += '\n----|-------|----------'
                for label in labels:
                    csRes += '\n' + demisto.gets(label, 'name') + '|' + \
                             formatEpochDate(demisto.get(label, 'created_on')) + '|' + \
                             formatEpochDate(demisto.get(label, 'last_valid_on'))

            relations = demisto.get(c, 'relations')
            if relations:
                csRes += '\n### Relations'
                csRes += '\nIndicator|Type|Created|Last Valid'
                csRes += '\n---------|----|-------|----------'
                for r in relations:
                    csRes += '\n' + demisto.gets(r, 'indicator') + '|' + demisto.gets(r, 'type') + '|' + \
                             formatEpochDate(demisto.get(label, 'created_date')) + '|' + \
                             formatEpochDate(demisto.get(label, 'last_valid_date'))

            return {'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': csRes}
    return entry


def shortUrl(entry):  # pragma: no cover
    """
       Deprecated

       :type entry: ``dict``
       :param entry: URL result entry (required)

       :return: A Demisto entry containing the shortened URL info
       :rtype: ``dict``
    """
    if entry['Type'] != entryTypes['error'] and entry['ContentsFormat'] == formats['json']:
        c = entry['Contents']
        if entry['Brand'] == brands['xfe']:
            return {'ContentsFormat': formats['table'], 'Type': entryTypes['note'], 'Contents': {
                'Country': c['country'], 'MalwareCount': demisto.get(c, 'malware.count'),
                'A': demisto.gets(c, 'resolution.A'), 'AAAA': demisto.gets(c, 'resolution.AAAA'),
                'Score': demisto.get(c, 'url.result.score'), 'Categories': demisto.gets(c, 'url.result.cats'),
                'URL': demisto.get(c, 'url.result.url'), 'Provider': providers['xfe'],
                'ProviderLink': 'https://exchange.xforce.ibmcloud.com/url/' + demisto.get(c, 'url.result.url')}}
        if entry['Brand'] == brands['vt']:
            return {'ContentsFormat': formats['table'], 'Type': entryTypes['note'], 'Contents': {
                'ScanDate': c['scan_date'], 'Positives': c['positives'], 'Total': c['total'],
                'URL': c['url'], 'Provider': providers['vt'], 'ProviderLink': c['permalink']}}
        if entry['Brand'] == brands['cs'] and demisto.get(entry, 'Contents'):
            return shortCrowdStrike(entry)
    return {'ContentsFormat': 'text', 'Type': 4, 'Contents': 'Unknown provider for result: ' + entry['Brand']}


def shortFile(entry):  # pragma: no cover
    """
       Deprecated

       :type entry: ``dict``
       :param entry: File result entry (required)

       :return: A Demisto entry containing the shortened file info
       :rtype: ``dict``
    """
    if entry['Type'] != entryTypes['error'] and entry['ContentsFormat'] == formats['json']:
        c = entry['Contents']
        if entry['Brand'] == brands['xfe']:
            cm = c['malware']
            return {'ContentsFormat': formats['table'], 'Type': entryTypes['note'], 'Contents': {
                'Family': cm['family'], 'MIMEType': cm['mimetype'], 'MD5': cm['md5'][2:] if 'md5' in cm else '',
                'CnCServers': demisto.get(cm, 'origins.CncServers.count'),
                'DownloadServers': demisto.get(cm, 'origins.downloadServers.count'),
                'Emails': demisto.get(cm, 'origins.emails.count'),
                'ExternalFamily': demisto.gets(cm, 'origins.external.family'),
                'ExternalCoverage': demisto.get(cm, 'origins.external.detectionCoverage'),
                'Provider': providers['xfe'],
                'ProviderLink': 'https://exchange.xforce.ibmcloud.com/malware/' + cm['md5'].replace('0x', '')}}
        if entry['Brand'] == brands['vt']:
            return {'ContentsFormat': formats['table'], 'Type': entryTypes['note'], 'Contents': {
                'Resource': c['resource'], 'ScanDate': c['scan_date'], 'Positives': c['positives'],
                'Total': c['total'], 'SHA1': c['sha1'], 'SHA256': c['sha256'], 'Provider': providers['vt'],
                'ProviderLink': c['permalink']}}
        if entry['Brand'] == brands['wf']:
            c = demisto.get(entry, 'Contents.wildfire.file_info')
            if c:
                return {'Contents': {'Type': c['filetype'], 'Malware': c['malware'], 'MD5': c['md5'],
                                     'SHA256': c['sha256'], 'Size': c['size'], 'Provider': providers['wf']},
                        'ContentsFormat': formats['table'], 'Type': entryTypes['note']}
        if entry['Brand'] == brands['cy'] and demisto.get(entry, 'Contents'):
            contents = demisto.get(entry, 'Contents')
            k = contents.keys()
            if k and len(k) > 0:
                v = contents[k[0]]
                if v and demisto.get(v, 'generalscore'):
                    return {'Contents': {'Status': v['status'], 'Code': v['statuscode'], 'Score': v['generalscore'],
                                         'Classifiers': str(v['classifiers']), 'ConfirmCode': v['confirmcode'],
                                         'Error': v['error'], 'Provider': providers['cy']},
                            'ContentsFormat': formats['table'], 'Type': entryTypes['note']}
        if entry['Brand'] == brands['cs'] and demisto.get(entry, 'Contents'):
            return shortCrowdStrike(entry)
    return {'ContentsFormat': formats['text'], 'Type': entryTypes['error'],
            'Contents': 'Unknown provider for result: ' + entry['Brand']}


def shortIp(entry):
    """
       Deprecated

       :type entry: ``dict``
       :param entry: IP result entry (required)

       :return: A Demisto entry containing the shortened IP info
       :rtype: ``dict``
    """
    if entry['Type'] != entryTypes['error'] and entry['ContentsFormat'] == formats['json']:
        c = entry['Contents']
        if entry['Brand'] == brands['xfe']:
            cr = c['reputation']
            return {'ContentsFormat': formats['table'], 'Type': entryTypes['note'], 'Contents': {
                'IP': cr['ip'], 'Score': cr['score'], 'Geo': str(cr['geo']), 'Categories': str(cr['cats']),
                'Provider': providers['xfe']}}
        if entry['Brand'] == brands['vt']:
            return {'ContentsFormat': formats['table'], 'Type': entryTypes['note'],
                    'Contents': {'Positive URLs': vtCountPositives(entry), 'Provider': providers['vt']}}
        if entry['Brand'] == brands['cs'] and demisto.get(entry, 'Contents'):
            return shortCrowdStrike(entry)
    return {'ContentsFormat': formats['text'], 'Type': entryTypes['error'],
            'Contents': 'Unknown provider for result: ' + entry['Brand']}


def shortDomain(entry):
    """
       Deprecated

       :type entry: ``dict``
       :param entry: Domain result entry (required)

       :return: A Demisto entry containing the shortened domain info
       :rtype: ``dict``
    """
    if entry['Type'] != entryTypes['error'] and entry['ContentsFormat'] == formats['json']:
        if entry['Brand'] == brands['vt']:
            return {'ContentsFormat': formats['table'], 'Type': entryTypes['note'],
                    'Contents': {'Positive URLs': vtCountPositives(entry), 'Provider': providers['vt']}}
    return {'ContentsFormat': formats['text'], 'Type': entryTypes['error'],
            'Contents': 'Unknown provider for result: ' + entry['Brand']}


def get_error(execute_command_result):
    """
        execute_command_result must contain error entry - check the result first with is_error function
        if there is no error entry in the result then it will raise an Exception

        :type execute_command_result: ``dict`` or  ``list``
        :param execute_command_result: result of demisto.executeCommand()

        :return: Error message extracted from the demisto.executeCommand() result
        :rtype: ``string``
    """

    if not is_error(execute_command_result):
        raise ValueError("execute_command_result has no error entry. before using get_error use is_error")

    if isinstance(execute_command_result, dict):
        return execute_command_result['Contents']

    error_messages = []
    for entry in execute_command_result:
        is_error_entry = type(entry) == dict and entry['Type'] == entryTypes['error']
        if is_error_entry:
            error_messages.append(entry['Contents'])

    return '\n'.join(error_messages)


def is_error(execute_command_result):
    """
        Check if the given execute_command_result has an error entry

        :type execute_command_result: ``dict`` or ``list``
        :param execute_command_result: Demisto entry (required) or result of demisto.executeCommand()

        :return: True if the execute_command_result has an error entry, false otherwise
        :rtype: ``bool``
    """
    if execute_command_result is None:
        return False

    if isinstance(execute_command_result, list):
        if len(execute_command_result) > 0:
            for entry in execute_command_result:
                if type(entry) == dict and entry['Type'] == entryTypes['error']:
                    return True

    return type(execute_command_result) == dict and execute_command_result['Type'] == entryTypes['error']


isError = is_error


def FormatADTimestamp(ts):
    """
       Formats an Active Directory timestamp into human readable time representation

       :type ts: ``int``
       :param ts: The timestamp to be formatted (required)

       :return: A string represeting the time
       :rtype: ``str``
    """
    return (datetime(year=1601, month=1, day=1) + timedelta(seconds=int(ts) / 10 ** 7)).ctime()


def PrettifyCompactedTimestamp(x):
    """
       Formats a compacted timestamp string into human readable time representation

       :type x: ``str``
       :param x: The timestamp to be formatted (required)

       :return: A string represeting the time
       :rtype: ``str``
    """
    return '%s-%s-%sT%s:%s:%s' % (x[:4], x[4:6], x[6:8], x[8:10], x[10:12], x[12:])


def NormalizeRegistryPath(strRegistryPath):
    """
       Normalizes a registry path string

       :type strRegistryPath: ``str``
       :param strRegistryPath: The registry path (required)

       :return: The normalized string
       :rtype: ``str``
    """
    dSub = {
        'HKCR': 'HKEY_CLASSES_ROOT',
        'HKCU': 'HKEY_CURRENT_USER',
        'HKLM': 'HKEY_LOCAL_MACHINE',
        'HKU': 'HKEY_USERS',
        'HKCC': 'HKEY_CURRENT_CONFIG',
        'HKPD': 'HKEY_PERFORMANCE_DATA'
    }
    for k in dSub:
        if strRegistryPath[:len(k)] == k:
            return dSub[k] + strRegistryPath[len(k):]

    return strRegistryPath


def scoreToReputation(score):
    """
       Converts score (in number format) to human readable reputation format

       :type score: ``int``
       :param score: The score to be formatted (required)

       :return: The formatted score
       :rtype: ``str``
    """
    to_str = {
        4: 'Critical',
        3: 'Bad',
        2: 'Suspicious',
        1: 'Good',
        0.5: 'Informational',
        0: 'Unknown'
    }
    return to_str.get(score, 'None')


def b64_encode(text):
    """
    Base64 encode a string. Wrapper function around base64.b64encode which will accept a string
    In py3 will encode the string to binary using utf-8 encoding and return a string result decoded using utf-8

    :param text: string to encode
    :type text: str
    :return: encoded string
    :rtype: str
    """
    if not text:
        return ''
    elif isinstance(text, bytes):
        to_encode = text
    else:
        to_encode = text.encode('utf-8', 'ignore')

    res = base64.b64encode(to_encode)
    if IS_PY3:
        res = res.decode('utf-8')  # type: ignore
    return res


def b64_decode(b64_str):
    """
    Decode a str in a base 64 format to a picture.
    Replaces the use of base64.b64decode function which doesn't add padding to the supplied str.

    :param b64_str: string to decode
    :type b64_str: str
    :return: decoded binary
    :rtype: bytes
    """
    b64 = b64_str.encode('ascii')
    b64 += b'=' * (-len(b64) % 4)  # add padding
    return binascii.a2b_base64(b64)


def encode_string_results(text):
    """
    Encode string as utf-8, if any unicode character exists.

    :param text: string to encode
    :type text: str
    :return: encoded string
    :rtype: str
    """
    if not isinstance(text, STRING_OBJ_TYPES):
        return text
    try:
        return str(text)
    except UnicodeEncodeError:
        return text.encode("utf8", "replace")


def safe_load_json(json_object):  # pragma: no cover
    """
    Safely loads a JSON object from an argument. Allows the argument to accept either a JSON in string form,
    or an entry ID corresponding to a JSON file.

    :param json_object: Entry ID or JSON string.
    :type json_object: str
    :return: Dictionary object from a parsed JSON file or string.
    :rtype: dict
    """
    safe_json = None
    if isinstance(json_object, dict) or isinstance(json_object, list):
        return json_object
    if (json_object.startswith('{') and json_object.endswith('}')) or (
            json_object.startswith('[') and json_object.endswith(']')):
        try:
            safe_json = json.loads(json_object)
        except ValueError as e:
            return_error(
                'Unable to parse JSON string. Please verify the JSON is valid. - ' + str(e))
    else:
        try:
            path = demisto.getFilePath(json_object)
            with open(path['path'], 'rb') as data:
                try:
                    safe_json = json.load(data)
                except Exception:  # lgtm [py/catch-base-exception]
                    safe_json = json.loads(data.read())
        except Exception as e:
            return_error('Unable to parse JSON file. Please verify the JSON is valid or the Entry'
                         'ID is correct. - ' + str(e))
    return safe_json


def datetime_to_string(datetime_obj):
    """
    Converts a datetime object into a string. When used with `json.dumps()` for the `default` parameter,
    e.g. `json.dumps(response, default=datetime_to_string)` datetime_to_string allows entire JSON objects
    to be safely added to context without causing any datetime marshalling errors.
    :param datetime_obj: Datetime object.
    :type datetime_obj: datetime.datetime
    :return: String representation of a datetime object.
    :rtype: str
    """
    if isinstance(datetime_obj, datetime):  # type: ignore
        return datetime_obj.__str__()


def remove_empty_elements(d):
    """
    Recursively remove empty lists, empty dicts, or None elements from a dictionary.
    :param d: Input dictionary.
    :type d: dict
    :return: Dictionary with all empty lists, and empty dictionaries removed.
    :rtype: dict
    """

    def empty(x):
        return x is None or x == {} or x == []

    if not isinstance(d, (dict, list)):
        return d
    elif isinstance(d, list):
        return [v for v in (remove_empty_elements(v) for v in d) if not empty(v)]
    else:
        return {k: v for k, v in ((k, remove_empty_elements(v)) for k, v in d.items()) if not empty(v)}


class SmartGetDict(dict):
    """A dict that when called with get(key, default) will return the default passed
    value, even if there is a value of "None" in the place of the key. Example with built-in dict:
    ```
    >>> d = {}
    >>> d['test'] = None
    >>> d.get('test', 1)
    >>> print(d.get('test', 1))
    None
    ```
    Example with SmartGetDict:
    ```
    >>> d = SmartGetDict()
    >>> d['test'] = None
    >>> d.get('test', 1)
    >>> print(d.get('test', 1))
    1
    ```

    :return: SmartGetDict
    :rtype: ``SmartGetDict``

    """

    def get(self, key, default=None):
        res = dict.get(self, key)
        if res is not None:
            return res
        return default


if (not os.getenv('COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS')) and hasattr(demisto, 'params') and demisto.params():
    demisto.callingContext['params'] = SmartGetDict(demisto.params())


def aws_table_to_markdown(response, table_header):
    """
    Converts a raw response from AWS into a markdown formatted table. This function checks to see if
    there is only one nested dict in the top level of the dictionary and will use the nested data.
    :param response: Raw response from AWS
    :type response: dict
    :param table_header: The header string to use for the table.
    :type table_header: str
    :return: Markdown formatted table as a string.
    :rtype: str
    """
    if isinstance(response, dict):
        if len(response) == 1:
            if isinstance(response[list(response.keys())[0]], dict) or isinstance(
                    response[list(response.keys())[0]], list):
                if isinstance(response[list(response.keys())[0]], list):
                    list_response = response[list(response.keys())[0]]
                    if not list_response:
                        human_readable = tableToMarkdown(table_header, list_response)
                    elif isinstance(list_response[0], str):
                        human_readable = tableToMarkdown(
                            table_header, response)
                    else:
                        human_readable = tableToMarkdown(
                            table_header, response[list(response.keys())[0]])
                else:
                    human_readable = tableToMarkdown(
                        table_header, response[list(response.keys())[0]])
            else:
                human_readable = tableToMarkdown(table_header, response)
        else:
            human_readable = tableToMarkdown(table_header, response)
    else:
        human_readable = tableToMarkdown(table_header, response)
    return human_readable


def stringEscape(st):
    """
       Escape newline chars in the given string.

       :type st: ``str``
       :param st: The string to be modified (required).

       :return: A modified string.
       :rtype: ``str``
    """
    return st.replace('\r', '\\r').replace('\n', '\\n').replace('\t', '\\t')


def stringUnEscape(st):
    """
       Unescape newline chars in the given string.

       :type st: ``str``
       :param st: The string to be modified (required).

       :return: A modified string.
       :rtype: ``str``
    """
    return st.replace('\\r', '\r').replace('\\n', '\n').replace('\\t', '\t')


class IntegrationLogger(object):
    """
      a logger for python integrations:
      use `LOG(<message>)` to add a record to the logger (message can be any object with __str__)
      use `LOG.print_log(verbose=True/False)` to display all records in War-Room (if verbose) and server log.
      use `add_replace_strs` to add sensitive strings that should be replaced before going to the log.

      :type message: ``str``
      :param message: The message to be logged

      :return: No data returned
      :rtype: ``None``
    """

    def __init__(self, debug_logging=False):
        self.messages = []  # type: list
        self.write_buf = []  # type: list
        self.replace_strs = []  # type: list
        self.curl = []  # type: list
        self.buffering = True
        self.debug_logging = debug_logging
        # if for some reason you don't want to auto add credentials.password to replace strings
        # set the os env COMMON_SERVER_NO_AUTO_REPLACE_STRS. Either in CommonServerUserPython, or docker env
        if (not os.getenv('COMMON_SERVER_NO_AUTO_REPLACE_STRS') and hasattr(demisto, 'getParam')):
            # add common params
            sensitive_params = ('key', 'private', 'password', 'secret', 'token', 'credentials', 'service_account')
            if demisto.params():
                self._iter_sensistive_dict_obj(demisto.params(), sensitive_params)

    def _iter_sensistive_dict_obj(self, dict_obj, sensitive_params):
        for (k, v) in dict_obj.items():
            if isinstance(v, dict):  # credentials object case. recurse into the object
                self._iter_sensistive_dict_obj(v, sensitive_params)
                if v.get('identifier') and v.get('password'):  # also add basic auth case
                    basic_auth = '{}:{}'.format(v.get('identifier'), v.get('password'))
                    self.add_replace_strs(b64_encode(basic_auth))
            elif isinstance(v, STRING_OBJ_TYPES):
                k_lower = k.lower()
                for p in sensitive_params:
                    if p in k_lower:
                        self.add_replace_strs(v, b64_encode(v))

    def encode(self, message):
        try:
            res = str(message)
        except UnicodeEncodeError as exception:
            # could not decode the message
            # if message is an Exception, try encode the exception's message
            if isinstance(message, Exception) and message.args and isinstance(message.args[0], STRING_OBJ_TYPES):
                res = message.args[0].encode('utf-8', 'replace')  # type: ignore
            elif isinstance(message, STRING_OBJ_TYPES):
                # try encode the message itself
                res = message.encode('utf-8', 'replace')  # type: ignore
            else:
                res = "Failed encoding message with error: {}".format(exception)
        for s in self.replace_strs:
            res = res.replace(s, MASK)
        return res

    def __call__(self, message):
        text = self.encode(message)
        if self.buffering:
            self.messages.append(text)
            if self.debug_logging:
                demisto.debug(text)
        else:
            demisto.info(text)
        return text

    def add_replace_strs(self, *args):
        '''
            Add strings which will be replaced when logging.
            Meant for avoiding passwords and so forth in the log.
        '''
        to_add = []
        for a in args:
            if a:
                a = self.encode(a)
                to_add.append(stringEscape(a))
                to_add.append(stringUnEscape(a))
                js = json.dumps(a)
                if js.startswith('"'):
                    js = js[1:]
                if js.endswith('"'):
                    js = js[:-1]
                to_add.append(js)
                if IS_PY3:
                    from urllib import parse as urllib_parse
                    to_add.append(urllib_parse.quote_plus(a))  # type: ignore[attr-defined]
                else:
                    to_add.append(urllib.quote_plus(a))  # type: ignore[attr-defined]

        self.replace_strs.extend(to_add)

    def set_buffering(self, state):
        """
        set whether the logger buffers messages or writes staight to the demisto log

        :param state: True/False
        :type state: boolean
        """
        self.buffering = state

    def print_log(self, verbose=False):
        if self.write_buf:
            self.messages.append("".join(self.write_buf))
        if self.messages:
            text = 'Full Integration Log:\n' + '\n'.join(self.messages)
            if verbose:
                demisto.log(text)  # pylint: disable=E9012
            if not self.debug_logging:  # we don't print out if in debug_logging as already all message where printed
                demisto.info(text)
            self.messages = []

    def build_curl(self, text):
        """
        Parses the HTTP client "send" log messages and generates cURL queries out of them.

        :type text: ``str``
        :param text: The HTTP client log message.

        :return: No data returned
        :rtype: ``None``
        """
        http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
        data = text.split(SEND_PREFIX)[1]
        if data and data[0] in {'{', '<'}:
            # it is the request url query params/post body - will always come after we already have the url and headers
            # `<` is for xml body
            self.curl[-1] += "-d '{}".format(data)
        elif any(http_method in data for http_method in http_methods):
            method = ''
            url = ''
            headers = []
            headers_to_skip = ['Content-Length', 'User-Agent', 'Accept-Encoding', 'Connection']
            request_parts = repr(data).split('\\\\r\\\\n')  # splitting lines on repr since data is a bytes-string
            for line, part in enumerate(request_parts):
                if line == 0:
                    method, url, _ = part[1:].split()  # ignoring " at first char
                elif line != len(request_parts) - 1:  # ignoring the last line which is empty
                    if part.startswith('Host:'):
                        _, host = part.split('Host: ')
                        url = 'https://{}{}'.format(host, url)
                    else:
                        if any(header_to_skip in part for header_to_skip in headers_to_skip):
                            continue
                        headers.append(part)
            curl_headers = ''
            for header in headers:
                if header:
                    curl_headers += '-H "{}" '.format(header)
            curl = 'curl -X {} {} {}'.format(method, url, curl_headers)
            if demisto.params().get('proxy'):
                proxy_address = os.environ.get('https_proxy')
                if proxy_address:
                    curl += '--proxy {} '.format(proxy_address)
            else:
                curl += '--noproxy "*" '
            if demisto.params().get('insecure'):
                curl += '-k '
            self.curl.append(curl)

    def write(self, msg):
        # same as __call__ but allows IntegrationLogger to act as a File like object.
        msg = self.encode(msg)
        has_newline = False
        if '\n' in msg:
            has_newline = True
            # if new line is last char we trim it out
            if msg[-1] == '\n':
                msg = msg[:-1]
        self.write_buf.append(msg)
        if has_newline:
            text = "".join(self.write_buf)
            if self.buffering:
                self.messages.append(text)
            else:
                if is_debug_mode():
                    if text.startswith(('send:', 'header:')):
                        try:
                            # ensures the logged data follows a standard convention
                            text = text.replace("send: b\"", "send: b'")
                            text = censor_request_logs(text)
                        except Exception as e:  # should fail silently
                            demisto.debug('Failed censoring request logs - {}'.format(str(e)))
                    if text.startswith('send:'):
                        try:
                            self.build_curl(text)
                        except Exception as e:  # should fail silently
                            demisto.debug('Failed generating curl - {}'.format(str(e)))
                demisto.info(text)
            self.write_buf = []

    def print_override(self, *args, **kwargs):
        # print function that can be used to override print usage of internal modules
        # will print to the log if the print target is stdout/stderr
        try:
            import __builtin__  # type: ignore
        except ImportError:
            # Python 3
            import builtins as __builtin__  # type: ignore
        file_ = kwargs.get('file')
        if (not file_) or file_ == sys.stdout or file_ == sys.stderr:
            kwargs['file'] = self
        __builtin__.print(*args, **kwargs)


"""
a logger for python integrations:
use `LOG(<message>)` to add a record to the logger (message can be any object with __str__)
use `LOG.print_log()` to display all records in War-Room and server log.
"""
LOG = IntegrationLogger(debug_logging=is_debug_mode())


def formatAllArgs(args, kwds):
    """
    makes a nice string representation of all the arguments

    :type args: ``list``
    :param args: function arguments (required)

    :type kwds: ``dict``
    :param kwds: function keyword arguments (required)

    :return: string representation of all the arguments
    :rtype: ``string``
    """
    formattedArgs = ','.join([repr(a) for a in args]) + ',' + str(kwds).replace(':', "=").replace(" ", "")[1:-1]
    return formattedArgs


def logger(func):
    """
    decorator function to log the function call using LOG

    :type func: ``function``
    :param func: function to call (required)

    :return: returns the func return value.
    :rtype: ``any``
    """

    def func_wrapper(*args, **kwargs):
        LOG('calling {}({})'.format(func.__name__, formatAllArgs(args, kwargs)))
        ret_val = func(*args, **kwargs)
        if is_debug_mode():
            LOG('Return value [{}]: {}'.format(func.__name__, str(ret_val)))
        return ret_val

    return func_wrapper


def formatCell(data, is_pretty=True, json_transform=None):
    """
       Convert a given object to md while decending multiple levels


       :type data: ``str`` or ``list`` or ``dict``
       :param data: The cell content (required)

       :type is_pretty: ``bool``
       :param is_pretty: Should cell content be prettified (default is True)

       :type json_transform: ``JsonTransformer``
       :param json_transform: The Json transform object to transform the data

       :return: The formatted cell content as a string
       :rtype: ``str``
    """
    if json_transform is None:
        json_transform = JsonTransformer(flatten=True)

    return json_transform.json_to_str(data, is_pretty)


def flattenCell(data, is_pretty=True):
    """
       Flattens a markdown table cell content into a single string

       :type data: ``str`` or ``list``
       :param data: The cell content (required)

       :type is_pretty: ``bool``
       :param is_pretty: Should cell content be pretified (default is True)

       :return: A sting representation of the cell content
       :rtype: ``str``
    """
    indent = 4 if is_pretty else None
    if isinstance(data, STRING_TYPES):
        return data
    elif isinstance(data, list):
        string_list = []
        for d in data:
            try:
                if IS_PY3 and isinstance(d, bytes):
                    string_list.append(d.decode('utf-8'))
                else:
                    string_list.append(str(d))
            except UnicodeEncodeError:
                string_list.append(d.encode('utf-8'))

        return ',\n'.join(string_list)
    else:
        return json.dumps(data, indent=indent, ensure_ascii=False, default=str)


def FormatIso8601(t):
    """
       Convert a time expressed in seconds to ISO 8601 time format string

       :type t: ``int``
       :param t: Time expressed in seconds (required)

       :return: An ISO 8601 time format string
       :rtype: ``str``
    """
    return t.strftime("%Y-%m-%dT%H:%M:%S")


def argToList(arg, separator=',', transform=None):
    """
       Converts a string representation of args to a python list

       :type arg: ``str`` or ``list``
       :param arg: Args to be converted (required)

       :type separator: ``str``
       :param separator: A string separator to separate the strings, the default is a comma.

       :type transform: ``callable``
       :param transform: A function transformer to transfer the returned list arguments.

       :return: A python list of args
       :rtype: ``list``
    """
    if not arg:
        return []

    result = []
    if isinstance(arg, list):
        result = arg
    elif isinstance(arg, STRING_TYPES):
        is_comma_separated = True
        if arg[0] == '[' and arg[-1] == ']':
            try:
                result = json.loads(arg)
                is_comma_separated = False
            except Exception:
                demisto.debug('Failed to load {} as JSON, trying to split'.format(arg))  # type: ignore[str-bytes-safe]
        if is_comma_separated:
            result = [s.strip() for s in arg.split(separator)]
    else:
        result = [arg]

    if transform:
        return [transform(s) for s in result]

    return result


def remove_duplicates_from_list_arg(args, field):
    """
        Removes duplicates from a list after calling argToList.
        For example: args: {'ids': "1,2,1"}, field='ids'
        The return output will be ["1", "2"]

        :type args: ``dict``
        :param args: Args to be converted (required)

        :type field: ``str``
        :param field: Field in args to be converted into list without duplicates (required)

        :return: A python list of args without duplicates
        :rtype: ``list``
    """
    convert_to_list = argToList(args.get(field))
    return list(set(convert_to_list))


def argToBoolean(value):
    """
        Boolean-ish arguments that are passed through demisto.args() could be type bool or type string.
        This command removes the guesswork and returns a value of type bool, regardless of the input value's type.
        It will also return True for 'yes' and False for 'no'.

        :param value: the value to evaluate
        :type value: ``string|bool``

        :return: a boolean representatation of 'value'
        :rtype: ``bool``
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, STRING_OBJ_TYPES):
        if value.lower() in ['true', 'yes']:
            return True
        elif value.lower() in ['false', 'no']:
            return False
        else:
            raise ValueError('Argument does not contain a valid boolean-like value')
    else:
        raise ValueError('Argument is neither a string nor a boolean')


def appendContext(key, data, dedup=False):
    """
       Append data to the investigation context

       :type key: ``str``
       :param key: The context path (required)

       :type data: ``any``
       :param data: Data to be added to the context (required)

       :type dedup: ``bool``
       :param dedup: True if de-duplication is required. Default is False.

       :return: No data returned
       :rtype: ``None``
    """
    if data is None:
        return
    existing = demisto.get(demisto.context(), key)

    if existing:
        if isinstance(existing, STRING_TYPES):
            if isinstance(data, STRING_TYPES):
                new_val = data + ',' + existing  # type: ignore[operator]
            else:
                new_val = data + existing  # will raise a self explanatory TypeError

        elif isinstance(existing, dict):
            if isinstance(data, dict):
                new_val = [existing, data]  # type: ignore[assignment]
            elif isinstance(data, list) and all([isinstance(sub_data, dict) for sub_data in data]):
                # For cases the context have only one value but we append a few values at once.
                new_val = [existing] + data  # type: ignore[assignment]
            else:
                new_val = data + existing  # will raise a self explanatory TypeError

        elif isinstance(existing, list):
            if isinstance(data, list):
                existing.extend(data)
            else:
                existing.append(data)
            new_val = existing  # type: ignore[assignment]

        else:
            new_val = [existing, data]  # type: ignore[assignment]

        if dedup and isinstance(new_val, list):
            new_val = list(set(new_val))

        demisto.setContext(key, new_val)
    else:
        demisto.setContext(key, data)


def url_to_clickable_markdown(data, url_keys):
    """
    Turn the given urls fields in to clickable url, used for the markdown table.

    :type data: ``[Union[str, List[Any], Dict[str, Any]]]``
    :param data: a dictionary or a list containing data with some values that are urls

    :type url_keys: ``List[str]``
    :param url_keys: the keys of the url's wished to turn clickable

    :return: markdown format for clickable url
    :rtype: ``[Union[str, List[Any], Dict[str, Any]]]``
    """

    if isinstance(data, list):
        data = [url_to_clickable_markdown(item, url_keys) for item in data]

    elif isinstance(data, dict):
        data = {key: create_clickable_url(value) if key in url_keys else url_to_clickable_markdown(data[key], url_keys)
                for key, value in data.items()}

    return data


def create_clickable_url(url, text=None):
    """
    Make the given url clickable when in markdown format by concatenating itself, with the proper brackets

    :type url: ``Union[List[str], str]``
    :param url: the url of interest or a list of urls

    :type text: ``Union[List[str], str, None]``
    :param text: the text of the url or a list of texts of urls.

    :return: Markdown format for clickable url
    :rtype: ``Union[List[str], str]``

    """
    if not url:
        return None
    elif isinstance(url, list):
        if isinstance(text, list):
            assert len(url) == len(text), 'The URL list and the text list must be the same length.'
            return ['[{}]({})'.format(text, item) for text, item in zip(text, url)]
        return ['[{}]({})'.format(item, item) for item in url]
    return '[{}]({})'.format(text or url, url)


class JsonTransformer:
    """
    A class to transform a json to

    :type flatten: ``bool``
    :param flatten: Should we flatten the json using `flattenCell` (for BC)

    :type keys: ``Set[str]``
    :param keys: Set of keys to keep

    :type is_nested: ``bool``
    :param is_nested: If look for nested

    :type func: ``Callable``
    :param func: A function to parse the json

    :return: None
    :rtype: ``None``
    """

    def __init__(self, flatten=False, keys=None, is_nested=False, func=None):
        """
        Constructor for JsonTransformer

        :type flatten: ``bool``
        :param flatten:  Should we flatten the json using `flattenCell` (for BC)

        :type keys: ``Iterable[str]``
        :param keys: an iterable of relevant keys list from the json. Notice we save it as a set in the class

        :type is_nested: ``bool``
        :param is_nested: Whether to search in nested keys or not

        :type func: ``Callable``
        :param func: A function to parse the json
        """
        if keys is None:
            keys = []
        self.keys = set(keys)
        self.is_nested = is_nested
        self.func = func
        self.flatten = flatten

    def json_to_str(self, json_input, is_pretty=True):
        if self.func:
            return self.func(json_input)
        if isinstance(json_input, STRING_TYPES):
            return json_input
        if self.flatten:
            if not isinstance(json_input, dict):
                return flattenCell(json_input, is_pretty)
            return '\n'.join(
                [u'{key}: {val}'.format(key=k, val=flattenCell(v, is_pretty)) for k, v in json_input.items()])  # for BC

        str_lst = []
        prev_path = []  # type: ignore
        for path, key, val in self.json_to_path_generator(json_input):
            str_path = ''
            full_tabs = '\t' * len(path)
            if path != prev_path:  # need to construct tha `path` string only of it changed from the last one
                common_prefix_index = len(os.path.commonprefix((prev_path, path)))  # type: ignore
                path_suffix = path[common_prefix_index:]

                str_path_lst = []
                for i, p in enumerate(path_suffix):
                    is_list = isinstance(p, int)
                    tabs = (common_prefix_index + i) * '\t'
                    path_value = p if not is_list else '-'
                    delim = ':\n' if not is_list else ''
                    str_path_lst.append('{tabs}**{path_value}**{delim}'.format(tabs=tabs, path_value=path_value, delim=delim))
                str_path = ''.join(str_path_lst)
                prev_path = path
                if path and isinstance(path[-1], int):
                    # if it is a beginning of a list, there is only one tab left
                    full_tabs = '\t'

            str_lst.append(
                '{path}{tabs}***{key}***: {val}'.format(path=str_path, tabs=full_tabs, key=key, val=flattenCell(val, is_pretty)))

        return '\n'.join(str_lst)

    def json_to_path_generator(self, json_input, path=None):
        """
        :type json_input: ``list`` or ``dict``
        :param json_input: The json input to transform
        :type path: ``List[str + int]``
        :param path: The path of the key, value pair inside the json

        :rtype ``Tuple[List[str + int], str, str]``
        :return:  A tuple. the second and third elements are key, values, and the first is their path in the json
        """
        if path is None:
            path = []
        is_in_path = not self.keys or any(p for p in path if p in self.keys)
        if isinstance(json_input, dict):
            for k, v in json_input.items():
                if is_in_path or k in self.keys:  # found data to return
                    # recurse until finding a primitive value
                    if not isinstance(v, dict) and not isinstance(v, list):
                        yield path, k, v
                    else:
                        for res in self.json_to_path_generator(v, path + [k]):  # this is yield from for python2 BC
                            yield res

                elif self.is_nested:
                    # recurse all the json_input to find the relevant data
                    for res in self.json_to_path_generator(v, path + [k]):  # this is yield from for python2 BC
                        yield res

        if isinstance(json_input, list):
            if not json_input or (not isinstance(json_input[0], list) and not isinstance(json_input[0], dict)):
                # if the items of the lists are primitive, put the values in one line
                yield path, 'values', ', '.join(json_input)
            else:
                for i, item in enumerate(json_input):
                    for res in self.json_to_path_generator(item, path + [i]):  # this is yield from for python2 BC
                        yield res


def tableToMarkdown(name, t, headers=None, headerTransform=None, removeNull=False, metadata=None, url_keys=None,
                    date_fields=None, json_transform_mapping=None, is_auto_json_transform=False, sort_headers=True):
    """
       Converts a demisto table in JSON form to a Markdown table

       :type name: ``str``
       :param name: The name of the table (required)

       :type t: ``dict`` or ``list``
       :param t: The JSON table - List of dictionaries with the same keys or a single dictionary (required)

       :type headers: ``list`` or ``string``
       :param headers: A list of headers to be presented in the output table (by order). If string will be passed
            then table will have single header. Default will include all available headers.

       :type headerTransform: ``function``
       :param headerTransform: A function that formats the original data headers (optional)

       :type removeNull: ``bool``
       :param removeNull: Remove empty columns from the table. Default is False

       :type metadata: ``str``
       :param metadata: Metadata about the table contents

       :type url_keys: ``list``
       :param url_keys: a list of keys in the given JSON table that should be turned in to clickable

       :type date_fields: ``list``
       :param date_fields: A list of date fields to format the value to human-readable output.

        :type json_transform_mapping: ``Dict[str, JsonTransformer]``
        :param json_transform_mapping: A mapping between a header key to corresponding JsonTransformer

        :type is_auto_json_transform: ``bool``
        :param is_auto_json_transform: Boolean to try to auto transform complex json

        :type sort_headers: ``bool``
        :param sort_headers: Sorts the table based on its headers only if the headers parameter is not specified

       :return: A string representation of the markdown table
       :rtype: ``str``
    """
    # Turning the urls in the table to clickable
    if url_keys:
        t = url_to_clickable_markdown(t, url_keys)

    mdResult = ''
    if name:
        mdResult = '### ' + name + '\n'

    if metadata:
        mdResult += metadata + '\n'

    if not t or len(t) == 0:
        mdResult += '**No entries.**\n'
        return mdResult

    if not headers and isinstance(t, dict) and len(t.keys()) == 1:
        # in case of a single key, create a column table where each element is in a different row.
        headers = list(t.keys())
        t = list(t.values())[0]

    if not isinstance(t, list):
        t = [t]

    if headers and isinstance(headers, STRING_TYPES):
        headers = [headers]

    if not isinstance(t[0], dict):
        # the table contains only simple objects (strings, numbers)
        # should be only one header
        if headers and len(headers) > 0:
            header = headers[0]
            t = [{header: item} for item in t]
        else:
            raise Exception("Missing headers param for tableToMarkdown. Example: headers=['Some Header']")

    # in case of headers was not provided (backward compatibility)
    if not headers:
        headers = list(t[0].keys())
        if sort_headers or not IS_PY3:
            headers.sort()

    if removeNull:
        headers_aux = headers[:]
        for header in headers:
            if all(obj.get(header) in ('', None, [], {}) for obj in t):
                headers_aux.remove(header)
        headers = headers_aux

    if not json_transform_mapping:
        json_transform_mapping = {header: JsonTransformer(flatten=not is_auto_json_transform) for header in
                                  headers}

    if t and len(headers) > 0:
        newHeaders = []
        if headerTransform is None:  # noqa
            def headerTransform(s): return stringEscapeMD(s, True, True)  # noqa
        for header in headers:
            newHeaders.append(headerTransform(header))
        mdResult += '|'
        if len(newHeaders) == 1:
            mdResult += newHeaders[0]
        else:
            mdResult += '|'.join(newHeaders)
        mdResult += '|\n'
        sep = '---'
        mdResult += '|' + '|'.join([sep] * len(headers)) + '|\n'
        for entry in t:
            entry_copy = entry.copy()
            if date_fields:
                for field in date_fields:
                    try:
                        entry_copy[field] = datetime.fromtimestamp(int(entry_copy[field]) / 1000).strftime('%Y-%m-%d %H:%M:%S')
                    except Exception:
                        pass

            vals = [stringEscapeMD((formatCell(entry_copy.get(h, ''), False,
                                               json_transform_mapping.get(h)) if entry_copy.get(h) is not None else ''),
                                   True, True) for h in headers]

            # this pipe is optional
            mdResult += '| '
            try:
                mdResult += ' | '.join(vals)
            except UnicodeDecodeError:
                vals = [str(v) for v in vals]
                mdResult += ' | '.join(vals)
            mdResult += ' |\n'

    else:
        mdResult += '**No entries.**\n'

    return mdResult


tblToMd = tableToMarkdown


def createContextSingle(obj, id=None, keyTransform=None, removeNull=False):  # pragma: no cover
    """Receives a dict with flattened key values, and converts them into nested dicts

    :type obj: ``dict`` or ``list``
    :param obj: The data to be added to the context (required)

    :type id: ``str``
    :param id: The ID of the context entry

    :type keyTransform: ``function``
    :param keyTransform: A formatting function for the markdown table headers

    :type removeNull: ``bool``
    :param removeNull: True if empty columns should be removed, false otherwise

    :return: The converted context list
    :rtype: ``list``
    """
    res = {}  # type: dict
    if keyTransform is None:
        def keyTransform(s): return s  # noqa
    keys = obj.keys()
    for key in keys:
        if removeNull and obj[key] in ('', None, [], {}):
            continue
        values = key.split('.')
        current = res
        for v in values[:-1]:
            current.setdefault(v, {})
            current = current[v]
        current[keyTransform(values[-1])] = obj[key]

    if id is not None:
        res.setdefault('ID', id)

    return res


def createContext(data, id=None, keyTransform=None, removeNull=False):
    """Receives a dict with flattened key values, and converts them into nested dicts

        :type data: ``dict`` or ``list``
        :param data: The data to be added to the context (required)

        :type id: ``str``
        :param id: The ID of the context entry

        :type keyTransform: ``function``
        :param keyTransform: A formatting function for the markdown table headers

        :type removeNull: ``bool``
        :param removeNull: True if empty columns should be removed, false otherwise

        :return: The converted context list
        :rtype: ``list``
    """
    if isinstance(data, (list, tuple)):
        return [createContextSingle(d, id, keyTransform, removeNull) for d in data]
    else:
        return createContextSingle(data, id, keyTransform, removeNull)


def sectionsToMarkdown(root):
    """
       Converts a list of Demisto JSON tables to markdown string of tables

       :type root: ``dict`` or ``list``
       :param root: The JSON table - List of dictionaries with the same keys or a single dictionary (required)

       :return: A string representation of the markdown table
       :rtype: ``str``
    """
    mdResult = ''
    if isinstance(root, dict):
        for section in root:
            data = root[section]
            if isinstance(data, dict):
                data = [data]
            data = [{k: formatCell(row[k]) for k in row} for row in data]
            mdResult += tblToMd(section, data)

    return mdResult


def fileResult(filename, data, file_type=None):
    """
       Creates a file from the given data

       :type filename: ``str``
       :param filename: The name of the file to be created (required)

       :type data: ``str`` or ``bytes``
       :param data: The file data (required)

       :type file_type: ``str``
       :param file_type: one of the entryTypes file or entryInfoFile (optional)

       :return: A Demisto war room entry
       :rtype: ``dict``
    """
    if file_type is None:
        file_type = entryTypes['file']
    temp = demisto.uniqueFile()
    # pylint: disable=undefined-variable
    if (IS_PY3 and isinstance(data, str)) or (not IS_PY3 and isinstance(data, unicode)):  # type: ignore # noqa: F821
        data = data.encode('utf-8')
    # pylint: enable=undefined-variable
    with open(demisto.investigation()['id'] + '_' + temp, 'wb') as f:
        f.write(data)

    # when there is ../ in the filename, xsoar thinks that path of the file is in the previous folder(s) and because of that
    # xsoar returns empty files to war-rooms
    if isinstance(filename, str):
        replaced_filename = filename.replace("../", "")
        if filename != replaced_filename:
            filename = replaced_filename
            demisto.debug(
                "replaced {filename} with new file name {replaced_file_name}".format(
                    filename=filename, replaced_file_name=replaced_filename
                )
            )

    return {'Contents': '', 'ContentsFormat': formats['text'], 'Type': file_type, 'File': filename, 'FileID': temp}


def hash_djb2(s, seed=5381):
    """
     Hash string with djb2 hash function

     :type s: ``str``
     :param s: The input string to hash

     :type seed: ``int``
     :param seed: The seed for the hash function (default is 5381)

     :return: The hashed value
     :rtype: ``int``
    """
    hash_name = seed
    for x in s:
        hash_name = ((hash_name << 5) + hash_name) + ord(x)

    return hash_name & 0xFFFFFFFF


def file_result_existing_file(filename, saveFilename=None):
    """
       Rename an existing file

       :type filename: ``str``
       :param filename: The name of the file to be modified (required)

       :type saveFilename: ``str``
       :param saveFilename: The new file name

       :return: A Demisto war room entry
       :rtype: ``dict``
    """
    temp = demisto.uniqueFile()
    os.rename(filename, demisto.investigation()['id'] + '_' + temp)
    return {'Contents': '', 'ContentsFormat': formats['text'], 'Type': entryTypes['file'],
            'File': saveFilename if saveFilename else filename, 'FileID': temp}


def flattenRow(rowDict):
    """
       Flatten each element in the given rowDict

       :type rowDict: ``dict``
       :param rowDict: The dict to be flattened (required)

       :return: A flattened dict
       :rtype: ``dict``
    """
    return {k: formatCell(rowDict[k]) for k in rowDict}


def flattenTable(tableDict):
    """
       Flatten each row in the given tableDict

       :type tableDict: ``dict``
       :param tableDict: The table to be flattened (required)

       :return: A flattened table
       :rtype: ``dict``
    """
    return [flattenRow(row) for row in tableDict]


MARKDOWN_CHARS = r"\`*_{}[]()#+-!|"


def stringEscapeMD(st, minimal_escaping=False, escape_multiline=False):
    """
       Escape any chars that might break a markdown string

       :type st: ``str``
       :param st: The string to be modified (required)

       :type minimal_escaping: ``bool``
       :param minimal_escaping: Whether replace all special characters or table format only (optional)

       :type escape_multiline: ``bool``
       :param escape_multiline: Whether convert line-ending characters (optional)

       :return: A modified string
       :rtype: ``str``
    """
    if escape_multiline:
        st = st.replace('\r\n', '<br>')  # Windows
        st = st.replace('\r', '<br>')  # old Mac
        st = st.replace('\n', '<br>')  # Unix

    if minimal_escaping:
        for c in ('|', '`'):
            st = st.replace(c, '\\' + c)
    else:
        st = "".join(["\\" + str(c) if c in MARKDOWN_CHARS else str(c) for c in st])

    return st


def raiseTable(root, key):
    newInternal = {}
    if key in root and isinstance(root[key], dict):
        for sub in root[key]:
            if sub not in root:
                root[sub] = root[key][sub]
            else:
                newInternal[sub] = root[key][sub]
        if newInternal:
            root[key] = newInternal
        else:
            del root[key]


def zoomField(item, fieldName):
    if isinstance(item, dict) and fieldName in item:
        return item[fieldName]
    else:
        return item


def isCommandAvailable(cmd):
    """
       Check the list of available modules to see whether a command is currently available to be run.

       :type cmd: ``str``
       :param cmd: The command to check (required)

       :return: True if command is available, False otherwise
       :rtype: ``bool``
    """
    modules = demisto.getAllSupportedCommands()
    for m in modules:
        if modules[m] and isinstance(modules[m], list):
            for c in modules[m]:
                if c['name'] == cmd:
                    return True
    return False


def epochToTimestamp(epoch):
    return datetime.utcfromtimestamp(epoch / 1000.0).strftime("%Y-%m-%d %H:%M:%S")


def formatTimeColumns(data, timeColumnNames):
    for row in data:
        for k in timeColumnNames:
            row[k] = epochToTimestamp(row[k])


def strip_tag(tag):
    split_array = tag.split('}')
    if len(split_array) > 1:
        strip_ns_tag = split_array[1]
        tag = strip_ns_tag
    return tag


def elem_to_internal(elem, strip_ns=1, strip=1):
    """Convert an Element into an internal dictionary (not JSON!)."""

    d = OrderedDict()  # type: dict
    elem_tag = elem.tag
    if strip_ns:
        elem_tag = strip_tag(elem.tag)
    for key, value in list(elem.attrib.items()):
        d['@' + key] = value

    # loop over subelements to merge them
    for subelem in elem:
        v = elem_to_internal(subelem, strip_ns=strip_ns, strip=strip)

        tag = subelem.tag
        if strip_ns:
            tag = strip_tag(subelem.tag)

        value = v[tag]
        try:
            # add to existing list for this tag
            d[tag].append(value)
        except AttributeError:
            # turn existing entry into a list
            d[tag] = [d[tag], value]
        except KeyError:
            # add a new non-list entry
            d[tag] = value

    text = elem.text
    tail = elem.tail
    if strip:
        # ignore leading and trailing whitespace
        if text:
            text = text.strip()
        if tail:
            tail = tail.strip()

    if tail:
        d['#tail'] = tail

    if d:
        # use #text element if other attributes exist
        if text:
            d["#text"] = text
    else:
        # text is the value if no attributes
        d = text or None  # type: ignore
    return {elem_tag: d}


def internal_to_elem(pfsh, factory=ET.Element):
    """Convert an internal dictionary (not JSON!) into an Element.
    Whatever Element implementation we could import will be
    used by default; if you want to use something else, pass the
    Element class as the factory parameter.
    """

    attribs = OrderedDict()  # type: dict
    text = None
    tail = None
    sublist = []
    tag = list(pfsh.keys())
    if len(tag) != 1:
        raise ValueError("Illegal structure with multiple tags: %s" % tag)
    tag = tag[0]
    value = pfsh[tag]
    if isinstance(value, dict):
        for k, v in list(value.items()):
            if k[:1] == "@":
                attribs[k[1:]] = v
            elif k == "#text":
                text = v
            elif k == "#tail":
                tail = v
            elif isinstance(v, list):
                for v2 in v:
                    sublist.append(internal_to_elem({k: v2}, factory=factory))
            else:
                sublist.append(internal_to_elem({k: v}, factory=factory))
    else:
        text = value
    e = factory(tag, attribs)
    for sub in sublist:
        e.append(sub)
    e.text = text
    e.tail = tail
    return e


def elem2json(elem, options, strip_ns=1, strip=1):
    """Convert an ElementTree or Element into a JSON string."""

    if hasattr(elem, 'getroot'):
        elem = elem.getroot()

    if 'pretty' in options:
        return json.dumps(elem_to_internal(elem, strip_ns=strip_ns, strip=strip), indent=4, separators=(',', ': '))
    else:
        return json.dumps(elem_to_internal(elem, strip_ns=strip_ns, strip=strip))


def json2elem(json_data, factory=ET.Element):
    """Convert a JSON string into an Element.
    Whatever Element implementation we could import will be used by
    default; if you want to use something else, pass the Element class
    as the factory parameter.
    """

    return internal_to_elem(json.loads(json_data), factory)


def xml2json(xmlstring, options={}, strip_ns=1, strip=1):
    """
       Convert an XML string into a JSON string.

       :type xmlstring: ``str``
       :param xmlstring: The string to be converted (required)

       :return: The converted JSON
       :rtype: ``dict`` or ``list``
    """
    try:
        import defusedxml.ElementTree as defused_ET
        elem = defused_ET.fromstring(xmlstring)
    except ImportError:
        demisto.debug('defused_ET is not supported, using ET instead.')
        elem = ET.fromstring(xmlstring)
    return elem2json(elem, options, strip_ns=strip_ns, strip=strip)


def json2xml(json_data, factory=ET.Element):
    """Convert a JSON string into an XML string.
    Whatever Element implementation we could import will be used by
    default; if you want to use something else, pass the Element class
    as the factory parameter.
    """

    if not isinstance(json_data, dict):
        json_data = json.loads(json_data)

    elem = internal_to_elem(json_data, factory)
    return ET.tostring(elem, encoding='utf-8')


def get_hash_type(hash_file):
    """
       Checks the type of the given hash. Returns 'md5', 'sha1', 'sha256' or 'Unknown'.

       :type hash_file: ``str``
       :param hash_file: The hash to be checked (required)

       :return: The hash type
       :rtype: ``str``
    """
    hash_len = len(hash_file)
    if (hash_len == 32):
        return 'md5'
    elif (hash_len == 40):
        return 'sha1'
    elif (hash_len == 64):
        return 'sha256'
    elif (hash_len == 128):
        return 'sha512'
    else:
        return 'Unknown'


def is_mac_address(mac):
    """
    Test for valid mac address

    :type mac: ``str``
    :param mac: MAC address in the form of AA:BB:CC:00:11:22

    :return: True/False
    :rtype: ``bool``
    """

    if re.search(r'([0-9A-F]{2}[:]){5}([0-9A-F]){2}', mac.upper()) is not None:
        return True
    else:
        return False


def is_ipv6_valid(address):
    """
    Checks if the given string represents a valid IPv6 address.

    :type address: str
    :param address: The string to check.

    :return: True if the given string represents a valid IPv6 address.
    :rtype: ``bool``
    """
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True


def is_ip_valid(s, accept_v6_ips=False):
    """
       Checks if the given string represents a valid IP address.
       By default, will only return 'True' for IPv4 addresses.

       :type s: ``str``
       :param s: The string to be checked (required)
       :type accept_v6_ips: ``bool``
       :param accept_v6_ips: A boolean determining whether the
       function should accept IPv6 addresses

       :return: True if the given string represents a valid IP address, False otherwise
       :rtype: ``bool``
    """
    a = s.split('.')
    if accept_v6_ips and is_ipv6_valid(s):
        return True
    elif len(a) != 4:
        return False
    else:
        for x in a:
            if not x.isdigit():
                return False
            i = int(x)
            if i < 0 or i > 255:
                return False
        return True


def get_integration_name():
    """
    Getting calling integration's name
    :return: Calling integration's name
    :rtype: ``str``
    """
    return demisto.callingContext.get('context', {}).get('IntegrationBrand', '')


def get_integration_instance_name():
    """
    Getting calling integration instance name
    :return: Calling integration instance name
    :rtype: ``str``
    """
    return demisto.callingContext.get('context', {}).get('IntegrationInstance', '')


def get_script_name():
    """
    Getting calling script name
    :return: Calling script name
    :rtype: ``str``
    """
    return demisto.callingContext.get('context', {}).get('ScriptName', '')


class Common(object):
    class Indicator(object):
        """
        interface class
        """

        @abstractmethod
        def to_context(self):
            pass

        @staticmethod
        def create_context_table(data):
            """
            Gets a list of items of a specific class (such as CommunityNotes, Publications etc) and returns a context
            list.
            """
            table = []

            for item in data:
                table.append(item.to_context())

            return table

    class DBotScore(object):
        """
        DBotScore class

        :type indicator: ``str``
        :param indicator: indicator value, ip, hash, domain, url, etc

        :type indicator_type: ``DBotScoreType``
        :param indicator_type: use DBotScoreType class

        :type integration_name: ``str``
        :param integration_name: For integrations - The class will automatically determine the integration name.
                                For scripts - The class will use the given integration name.

        :type score: ``DBotScore``
        :param score: DBotScore.NONE, DBotScore.GOOD, DBotScore.SUSPICIOUS, DBotScore.BAD

        :type malicious_description: ``str``
        :param malicious_description: if the indicator is malicious and have explanation for it then set it to this field

        :type reliability: ``DBotScoreReliability``
        :param reliability: use DBotScoreReliability class

        :type message: ``str``
        :param message: Used to message on the api response, for example: When return api response is "Not found".

        :return: None
        :rtype: ``None``
        """
        NONE = 0
        GOOD = 1
        SUSPICIOUS = 2
        BAD = 3

        CONTEXT_PATH = 'DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor ' \
                       '&& val.Type == obj.Type)'

        CONTEXT_PATH_PRIOR_V5_5 = 'DBotScore'

        def __init__(self, indicator, indicator_type, integration_name='', score=None, malicious_description=None,
                     reliability=None, message=None):

            if not DBotScoreType.is_valid_type(indicator_type):
                raise TypeError('indicator_type must be of type DBotScoreType enum')

            if not Common.DBotScore.is_valid_score(score):
                raise TypeError('indicator `score` must be of type DBotScore enum')

            if reliability and not DBotScoreReliability.is_valid_type(reliability):
                raise TypeError('reliability must be of type DBotScoreReliability enum')

            self.indicator = indicator
            self.indicator_type = indicator_type
            # For integrations - The class will automatically determine the integration name.
            if demisto.callingContext.get('integration'):
                context_integration_name = get_integration_name()
                self.integration_name = context_integration_name if context_integration_name else integration_name
            else:
                self.integration_name = integration_name
            self.score = score
            self.malicious_description = malicious_description
            self.reliability = reliability
            self.message = message

        @staticmethod
        def is_valid_score(score):
            return score in (
                Common.DBotScore.NONE,
                Common.DBotScore.GOOD,
                Common.DBotScore.SUSPICIOUS,
                Common.DBotScore.BAD
            )

        @staticmethod
        def get_context_path():
            return Common.DBotScore.CONTEXT_PATH

        def to_context(self):
            dbot_context = {
                'Indicator': self.indicator,
                'Type': self.indicator_type,
                'Vendor': self.integration_name,
                'Score': self.score
            }

            if self.reliability:
                dbot_context['Reliability'] = self.reliability

            if self.message:
                dbot_context['Message'] = self.message

            ret_value = {
                Common.DBotScore.get_context_path(): dbot_context
            }
            return ret_value

        def to_readable(self):
            dbot_score_to_text = {0: 'Unknown',
                                  1: 'Good',
                                  2: 'Suspicious',
                                  3: 'Bad'}
            return dbot_score_to_text.get(self.score, 'Undefined')

    class CustomIndicator(Indicator):

        def __init__(self, indicator_type, value, dbot_score, data, context_prefix, relationships=None):
            """
            :type indicator_type: ``Str``
            :param indicator_type: The name of the indicator type.

            :type value: ``Any``
            :param value: The value of the indicator.

            :type dbot_score: ``DBotScore``
            :param dbot_score: If custom indicator has a score then create and set a DBotScore object.

            :type data: ``Dict(Str,Any)``
            :param data: A dictionary containing all the param names and their values.

            :type context_prefix: ``Str``
            :param context_prefix: Will be used as the context path prefix.

            :type relationships: ``list of EntityRelationship``
            :param relationships: List of relationships of the indicator.

            :return: None
            :rtype: ``None``
            """
            if hasattr(DBotScoreType, indicator_type.upper()):
                raise ValueError('Creating a custom indicator type with an existing type name is not allowed')
            if not value:
                raise ValueError('value is mandatory for creating the indicator')
            if not context_prefix:
                raise ValueError('context_prefix is mandatory for creating the indicator')

            self.CONTEXT_PATH = '{context_prefix}(val.value && val.value == obj.value)'. \
                format(context_prefix=context_prefix)

            self.value = value
            self.relationships = relationships

            if not isinstance(dbot_score, Common.DBotScore):
                raise ValueError('dbot_score must be of type DBotScore')

            self.dbot_score = dbot_score
            self.indicator_type = indicator_type
            self.data = data
            INDICATOR_TYPE_TO_CONTEXT_KEY[indicator_type.lower()] = indicator_type.capitalize()

            for key in self.data:
                setattr(self, key, data[key])

        def to_context(self):
            custom_context = {
                'value': self.value
            }

            custom_context.update(self.data)

            ret_value = {
                self.CONTEXT_PATH: custom_context
            }  # type: Dict[str, Any]

            if self.dbot_score:
                ret_value.update(self.dbot_score.to_context())
            ret_value[Common.DBotScore.get_context_path()]['Type'] = self.indicator_type

            if self.relationships:
                relationships_context = [relationship.to_context() for relationship in self.relationships if
                                         relationship.to_context()]
                ret_value['Relationships'] = relationships_context

            return ret_value

    class IP(Indicator):
        """
        IP indicator class - https://xsoar.pan.dev/docs/integrations/context-standards-mandatory#ip

        :type ip: ``str``
        :param ip: IP address

        :type asn: ``str``
        :param asn: The autonomous system name for the IP address, for example: "AS8948".

        :type as_owner: ``str``
        :param as_owner: The autonomous system owner of the IP.

        :type region: ``str``
        :param region: The region in which the IP is located.

        :type port: ``str``
        :param port: Ports that are associated with the IP.

        :type internal: ``bool``
        :param internal: Whether or not the IP is internal or external.

        :type updated_date: ``date``
        :param updated_date: The date that the IP was last updated.

        :type registrar_abuse_name: ``str``
        :param registrar_abuse_name: The name of the contact for reporting abuse.

        :type registrar_abuse_address: ``str``
        :param registrar_abuse_address: The address of the contact for reporting abuse.

        :type registrar_abuse_country: ``str``
        :param registrar_abuse_country: The country of the contact for reporting abuse.

        :type registrar_abuse_network: ``str``
        :param registrar_abuse_network: The network of the contact for reporting abuse.

        :type registrar_abuse_phone: ``str``
        :param registrar_abuse_phone: The phone number of the contact for reporting abuse.

        :type registrar_abuse_email: ``str``
        :param registrar_abuse_email: The email address of the contact for reporting abuse.

        :type campaign: ``str``
        :param campaign: The campaign associated with the IP.

        :type traffic_light_protocol: ``str``
        :param traffic_light_protocol: The Traffic Light Protocol (TLP) color that is suitable for the IP.

        :type community_notes: ``CommunityNotes``
        :param community_notes: Notes on the IP that were given by the community.

        :type publications: ``Publications``
        :param publications: Publications on the ip that was published.

        :type threat_types: ``ThreatTypes``
        :param threat_types: Threat types that are associated with the file.

        :type hostname: ``str``
        :param hostname: The hostname that is mapped to this IP address.

        :type geo_latitude: ``str``
        :param geo_latitude: The geolocation where the IP address is located, in the format: latitude

        :type geo_longitude: ``str``
        :param geo_longitude: The geolocation where the IP address is located, in the format: longitude.

        :type geo_country: ``str``
        :param geo_country: The country in which the IP address is located.

        :type geo_description: ``str``
        :param geo_description: Additional information about the location.

        :type detection_engines: ``int``
        :param detection_engines: The total number of engines that checked the indicator.

        :type positive_engines: ``int``
        :param positive_engines: The number of engines that positively detected the indicator as malicious.

        :type organization_name: ``str``
        :param organization_name: The organization of the IP

        :type organization_type: ``str``
        :param organization_type:The organization type of the IP

        :type tags: ``str``
        :param tags: Tags of the IP.

        :type malware_family: ``str``
        :param malware_family: The malware family associated with the IP.

        :type feed_related_indicators: ``FeedRelatedIndicators``
        :param feed_related_indicators: List of indicators that are associated with the IP.

        :type relationships: ``list of EntityRelationship``
        :param relationships: List of relationships of the indicator.

        :type blocked: ``boolean``
        :param blocked: Is the indicator blocked.

        :type description: ``str``
        :param description: A general description of the indicator

        :type stix_id: ``str``
        :param stix_id: The STIX id representing the indicator

        :type whois_records: ``WhoisRecord``
        :param whois_records: List of whois records

        :type dbot_score: ``DBotScore``
        :param dbot_score: If IP has a score then create and set a DBotScore object.

        :type organization_prevalence: ``int``
        :param organization_prevalence: The number of times the indicator is detected in the organization.

        :type global_prevalence: ``int``
        :param global_prevalence: The number of times the indicator is detected across all organizations.

        :type organization_first_seen: ``str``
        :param organization_first_seen: ISO 8601 date time string; when the indicator was first seen in the organization.

        :type organization_last_seen: ``str``
        :param organization_last_seen: ISO 8601 date time string; the last time a specific organization encountered an indicator.

        :type first_seen_by_source: ``str``
        :param first_seen_by_source: ISO 8601 date time string; when the indicator was first seen by the source vendor.

        :type last_seen_by_source: ``str``
        :param last_seen_by_source: ISO 8601 date time string; when the indicator was last seen by the source vendor.

        :return: None
        :rtype: ``None``
        """

        CONTEXT_PATH = 'IP(val.Address && val.Address == obj.Address)'

        def __init__(self, ip, dbot_score, asn=None, as_owner=None, region=None, port=None, internal=None,
                     updated_date=None, registrar_abuse_name=None, registrar_abuse_address=None,
                     registrar_abuse_country=None, registrar_abuse_network=None, registrar_abuse_phone=None,
                     registrar_abuse_email=None, campaign=None, traffic_light_protocol=None,
                     community_notes=None, publications=None, threat_types=None,
                     hostname=None, geo_latitude=None, geo_longitude=None,
                     geo_country=None, geo_description=None, detection_engines=None, positive_engines=None,
                     organization_name=None, organization_type=None, feed_related_indicators=None, tags=None,
                     malware_family=None, relationships=None, blocked=None, description=None, stix_id=None,
                     whois_records=None, organization_prevalence=None,
                     global_prevalence=None, organization_first_seen=None, organization_last_seen=None,
                     first_seen_by_source=None, last_seen_by_source=None, ip_type="IP"):

            # Main value of the indicator
            self.ip = ip
            self.ip_type = ip_type

            # Core custom fields - IP
            self.blocked = blocked
            self.community_notes = community_notes
            self.description = description
            self.tags = tags
            self.geo_country = geo_country
            self.geo_latitude = geo_latitude
            self.geo_longitude = geo_longitude
            self.internal = internal
            self.stix_id = stix_id
            self.traffic_light_protocol = traffic_light_protocol
            self.whois_records = whois_records

            # Other custom fields
            self.asn = asn
            self.as_owner = as_owner
            self.region = region
            self.port = port
            self.updated_date = updated_date
            self.registrar_abuse_name = registrar_abuse_name
            self.registrar_abuse_address = registrar_abuse_address
            self.registrar_abuse_country = registrar_abuse_country
            self.registrar_abuse_network = registrar_abuse_network
            self.registrar_abuse_phone = registrar_abuse_phone
            self.registrar_abuse_email = registrar_abuse_email
            self.campaign = campaign
            self.publications = publications
            self.threat_types = threat_types
            self.hostname = hostname
            self.geo_description = geo_description
            self.detection_engines = detection_engines
            self.positive_engines = positive_engines
            self.organization_name = organization_name
            self.organization_type = organization_type
            self.feed_related_indicators = feed_related_indicators
            self.malware_family = malware_family
            self.relationships = relationships
            self.organization_prevalence = organization_prevalence
            self.global_prevalence = global_prevalence
            self.organization_first_seen = organization_first_seen
            self.organization_last_seen = organization_last_seen
            self.first_seen_by_source = first_seen_by_source
            self.last_seen_by_source = last_seen_by_source

            if not isinstance(dbot_score, Common.DBotScore):
                raise ValueError('dbot_score must be of type DBotScore')

            self.dbot_score = dbot_score

        def to_context(self):
            ip_context = {
                'Address': self.ip
            }

            if self.blocked:
                ip_context['Blocked'] = self.blocked

            if self.asn:
                ip_context['ASN'] = self.asn

            if self.as_owner:
                ip_context['ASOwner'] = self.as_owner

            if self.region:
                ip_context['Region'] = self.region

            if self.port:
                ip_context['Port'] = self.port

            if self.internal:
                ip_context['Internal'] = self.internal

            if self.stix_id:
                ip_context['STIXID'] = self.stix_id

            if self.updated_date:
                ip_context['UpdatedDate'] = self.updated_date

            if self.registrar_abuse_name or self.registrar_abuse_address or self.registrar_abuse_country or \
                    self.registrar_abuse_network or self.registrar_abuse_phone or self.registrar_abuse_email:
                ip_context['Registrar'] = {'Abuse': {}}
                if self.registrar_abuse_name:
                    ip_context['Registrar']['Abuse']['Name'] = self.registrar_abuse_name
                if self.registrar_abuse_address:
                    ip_context['Registrar']['Abuse']['Address'] = self.registrar_abuse_address
                if self.registrar_abuse_country:
                    ip_context['Registrar']['Abuse']['Country'] = self.registrar_abuse_country
                if self.registrar_abuse_network:
                    ip_context['Registrar']['Abuse']['Network'] = self.registrar_abuse_network
                if self.registrar_abuse_phone:
                    ip_context['Registrar']['Abuse']['Phone'] = self.registrar_abuse_phone
                if self.registrar_abuse_email:
                    ip_context['Registrar']['Abuse']['Email'] = self.registrar_abuse_email

            if self.campaign:
                ip_context['Campaign'] = self.campaign

            if self.description:
                ip_context['Description'] = self.description

            if self.traffic_light_protocol:
                ip_context['TrafficLightProtocol'] = self.traffic_light_protocol

            if self.community_notes:
                ip_context['CommunityNotes'] = self.create_context_table(self.community_notes)

            if self.publications:
                ip_context['Publications'] = self.create_context_table(self.publications)

            if self.threat_types:
                ip_context['ThreatTypes'] = self.create_context_table(self.threat_types)

            if self.whois_records:
                ip_context['WhoisRecords'] = self.create_context_table(self.whois_records)

            if self.hostname:
                ip_context['Hostname'] = self.hostname

            if self.geo_latitude or self.geo_country or self.geo_description:
                ip_context['Geo'] = {}

                if self.geo_latitude and self.geo_longitude:
                    ip_context['Geo']['Location'] = '{}:{}'.format(self.geo_latitude, self.geo_longitude)

                if self.geo_country:
                    ip_context['Geo']['Country'] = self.geo_country

                if self.geo_description:
                    ip_context['Geo']['Description'] = self.geo_description

            if self.organization_name or self.organization_type:
                ip_context['Organization'] = {}

                if self.organization_name:
                    ip_context['Organization']['Name'] = self.organization_name

                if self.organization_type:
                    ip_context['Organization']['Type'] = self.organization_type

            if self.detection_engines is not None:
                ip_context['DetectionEngines'] = self.detection_engines

            if self.positive_engines is not None:
                ip_context['PositiveDetections'] = self.positive_engines

            if self.feed_related_indicators:
                ip_context['FeedRelatedIndicators'] = self.create_context_table(self.feed_related_indicators)

            if self.tags:
                ip_context['Tags'] = self.tags

            if self.malware_family:
                ip_context['MalwareFamily'] = self.malware_family

            if self.organization_prevalence is not None:  # checking for `is not None` to allow `0`-value
                ip_context['OrganizationPrevalence'] = self.organization_prevalence

            if self.global_prevalence is not None:  # checking for `is not None` to allow `0`-value
                ip_context['GlobalPrevalence'] = self.global_prevalence

            if self.organization_first_seen:
                ip_context['OrganizationFirstSeen'] = self.organization_first_seen

            if self.organization_last_seen:
                ip_context['OrganizationLastSeen'] = self.organization_last_seen

            if self.first_seen_by_source:
                ip_context['FirstSeenBySource'] = self.first_seen_by_source

            if self.last_seen_by_source:
                ip_context['LastSeenBySource'] = self.last_seen_by_source

            if self.dbot_score and self.dbot_score.score == Common.DBotScore.BAD:
                ip_context['Malicious'] = {
                    'Vendor': self.dbot_score.integration_name,
                    'Description': self.dbot_score.malicious_description
                }

            if self.relationships:
                relationships_context = [relationship.to_context() for relationship in self.relationships if
                                         relationship.to_context()]
                ip_context['Relationships'] = relationships_context

            if self.ip_type == "IP":
                context_path = Common.IP.CONTEXT_PATH

            elif self.ip_type == "IPv6":
                context_path = Common.IP.CONTEXT_PATH.replace("IP", "IPv6")

            ret_value = {
                context_path: ip_context
            }

            if self.dbot_score:
                ret_value.update(self.dbot_score.to_context())

            return ret_value

    class FileSignature(object):
        """
        FileSignature class
        :type authentihash: ``str``
        :param authentihash: The authentication hash.
        :type copyright: ``str``
        :param copyright: Copyright information.
        :type description: ``str``
        :param description: A description of the signature.
        :type file_version: ``str``
        :param file_version: The file version.
        :type internal_name: ``str``
        :param internal_name: The internal name of the file.
        :type original_name: ``str``
        :param original_name: The original name of the file.
        :return: None
        :rtype: ``None``
        """

        def __init__(self, authentihash, copyright, description, file_version, internal_name, original_name):
            self.authentihash = authentihash
            self.copyright = copyright
            self.description = description
            self.file_version = file_version
            self.internal_name = internal_name
            self.original_name = original_name

        def to_context(self):
            return {
                'Authentihash': self.authentihash,
                'Copyright': self.copyright,
                'Description': self.description,
                'FileVersion': self.file_version,
                'InternalName': self.internal_name,
                'OriginalName': self.original_name,
            }

    class FeedRelatedIndicators(object):
        """
        FeedRelatedIndicators class
         Implements Subject Indicators that are associated with Another indicator

        :type value: ``str``
        :param value: Indicators that are associated with the indicator.

        :type indicator_type: ``str``
        :param indicator_type: The type of the indicators that are associated with the indicator.

        :type description: ``str``
        :param description: The description of the indicators that are associated with the indicator.

        :return: None
        :rtype: ``None``
        """

        def __init__(self, value=None, indicator_type=None, description=None):
            self.value = value
            self.indicator_type = indicator_type
            self.description = description

        def to_context(self):
            return {
                'value': self.value,
                'type': self.indicator_type,
                'description': self.description
            }

    class Rank:
        """
        Single row in a rank grid field

        :type rank: float / int
        :param rank: A numerical rank value

        :type source: ``str``
        :param source: The name of the source from which the rank was taken
        """

        def __init__(self, rank=None, source=None):
            self.rank = rank
            self.source = source

        def to_context(self):
            return {
                'source': self.source,
                'rank': self.rank
            }

    class ExternalReference(object):
        """
        ExternalReference class
        Class to represent a single instance of an external reference for an indicator type.

        :type source_name: ``str``
        :param source_name: The name of the source referenced.

        :type source_id: ``str``
        :param source_id: The ID of the object in the external source.

        :return: None
        :rtype: ``None``
        """

        def __init__(self, source_name=None, source_id=None):
            self.source_name = source_name
            self.source_id = source_id

        def to_context(self):
            return {
                'sourcename': self.source_name,
                'sourceid': self.source_id,
            }

    class Certificates(object):
        """
        Certificates class
        Class to represent a single instance of a certificate for an indicator type.

        :type issued_to: ``str``
        :param issued_to: Who was the certificated issued to

        :type issued_by: ``str``
        :param issued_by: Who issued the certificate

        :type valid_from: ``str``
        :param valid_from: Since when is the certificate valid

        :type valid_to: ``str``
        :param valid_to: Till when is the certificate valid

        :return: None
        :rtype: ``None``
        """

        def __init__(self, issued_to=None, issued_by=None, valid_from=None, valid_to=None):
            self.issued_to = issued_to
            self.issued_by = issued_by
            self.valid_from = valid_from
            self.valid_to = valid_to

        def to_context(self):
            return {
                'issuedto': self.issued_to,
                'issuedby': self.issued_by,
                'validfrom': self.valid_from,
                'validto': self.valid_to
            }

    class Hash(object):
        """
        Hash class
        Class to represent a single instance of a hash for an indicator type.

        :type hash_type: ``str``
        :param hash_type: The type of the hash.

        :type hash_value: ``str``
        :param hash_value: The value of the hash.

        :return: None
        :rtype: ``None``
        """

        def __init__(self, hash_type=None, hash_value=None):
            self.hash_type = hash_type
            self.hash_value = hash_value

        def to_context(self):
            return {
                'type': self.hash_type,
                'value': self.hash_value,
            }

    class CommunityNotes(object):
        """
        CommunityNotes class
         Implements Subject Community Notes of a indicator

        :type note: ``str``
        :param note: Notes on the indicator that were given by the community.

        :type timestamp: ``Timestamp``
        :param timestamp: The time in which the note was published.

        :return: None
        :rtype: ``None``
        """

        def __init__(self, note=None, timestamp=None):
            self.note = note
            self.timestamp = timestamp

        def to_context(self):
            return {
                'note': self.note,
                'timestamp': self.timestamp,
            }

    class Publications(object):
        """
        Publications class
         Implements Subject Publications of a indicator

        :type source: ``str``
        :param source: The source in which the article was published.

        :type title: ``str``
        :param title: The name of the article.

        :type link: ``str``
        :param link: A link to the original article.

        :type timestamp: ``Timestamp``
        :param timestamp: The time in which the article was published.

        :return: None
        :rtype: ``None``
        """

        def __init__(self, source=None, title=None, link=None, timestamp=None):
            self.source = source
            self.title = title
            self.link = link
            self.timestamp = timestamp

        def to_context(self):
            return {
                'source': self.source,
                'title': self.title,
                'link': self.link,
                'timestamp': self.timestamp,
            }

    class Behaviors(object):
        """
        Behaviors class
         Implements Subject Behaviors of a indicator

        :type details: ``str``
        :param details:

        :type action: ``str``
        :param action:

        :return: None
        :rtype: ``None``
        """

        def __init__(self, details=None, action=None):
            self.details = details
            self.action = action

        def to_context(self):
            return {
                'details': self.details,
                'title': self.action,
            }

    class ThreatTypes(object):
        """
        ThreatTypes class
         Implements Subject ThreatTypes of a indicator

        :type threat_category: ``str``
        :param threat_category: The threat category associated to this indicator by the source vendor. For example,
         Phishing, Control, TOR, etc.

        :type threat_category_confidence: ``str``
        :param threat_category_confidence: Threat Category Confidence is the confidence level provided by the vendor
         for the threat type category
         For example a confidence of 90 for threat type category "malware" means that the vendor rates that this
         is 90% confidence of being a malware.

        :return: None
        :rtype: ``None``
        """

        def __init__(self, threat_category=None, threat_category_confidence=None):
            self.threat_category = threat_category
            self.threat_category_confidence = threat_category_confidence

        def to_context(self):
            return {
                'threatcategory': self.threat_category,
                'threatcategoryconfidence': self.threat_category_confidence,
            }

    class WhoisRecord(object):
        """
        WhoisRecord class
        Class to represent a single instance of a record for an indicator type.

        :type whois_record_type: ``str``
        :param whois_record_type: The type of the whois record.

        :type whois_record_value: ``str``
        :param whois_record_value: The value of the whois record.

        :type whois_record_date: ``Timestamp``
        :param whois_record_date: when was the whois record fetched

        :return: None
        :rtype: ``None``
        """

        def __init__(self, whois_record_type=None, whois_record_value=None, whois_record_date=None):
            self.whois_record_type = whois_record_type
            self.whois_record_value = whois_record_value
            self.whois_record_date = whois_record_date

        def to_context(self):
            return {
                'key': self.whois_record_type,
                'value': self.whois_record_value,
                'date': self.whois_record_date
            }

    class DNSRecord(object):
        """
        DNSRecord class
        Class to represent a single instance of a record for an indicator type.

        :type dns_record_type: ``str``
        :param dns_record_type: The type of the DNS record.

        :type dns_record_data: ``str``
        :param dns_record_data: The value of the whois record.

        :type dns_ttl: ``str``
        :param dns_ttl: The record TTL

        :return: None
        :rtype: ``None``
        """

        def __init__(self, dns_record_type=None, dns_ttl=None, dns_record_data=None):
            self.dns_record_type = dns_record_type
            self.dns_ttl = dns_ttl
            self.dns_record_data = dns_record_data

        def to_context(self):
            return {
                'type': self.dns_record_type,
                'ttl': self.dns_ttl,
                'data': self.dns_record_data
            }

    class CPE:
        """
        Represents one Common Platform Enumeration (CPE) object, see https://nvlpubs.nist.gov/nistpubs/legacy/ir/nistir7695.pdf

        :type cpe: ``str``
        :param cpe: a single CPE string

        :return: None
        :rtype: ``None``

        """

        def __init__(self, cpe=None):
            self.cpe = cpe

        def to_context(self):
            return {
                'CPE': self.cpe,
            }

    class File(Indicator):
        """
        File indicator class - https://xsoar.pan.dev/docs/integrations/context-standards-mandatory#file
        :type name: ``str``
        :param name: The full file name (including file extension).

        :type entry_id: ``str``
        :param entry_id: The ID for locating the file in the War Room.

        :type size: ``int``
        :param size: The size of the file in bytes.

        :type md5: ``str``
        :param md5: The MD5 hash of the file.

        :type sha1: ``str``
        :param sha1: The SHA1 hash of the file.

        :type sha256: ``str``
        :param sha256: The SHA256 hash of the file.

        :type sha512: ``str``
        :param sha512: The SHA512 hash of the file.

        :type ssdeep: ``str``
        :param ssdeep: The ssdeep hash of the file (same as displayed in file entries).

        :type extension: ``str``
        :param extension: The file extension, for example: "xls".

        :type file_type: ``str``
        :param file_type: The file type, as determined by libmagic (same as displayed in file entries).

        :type hostname: ``str``
        :param hostname: The name of the host where the file was found. Should match Path.

        :type path: ``str``
        :param path: The path where the file is located.

        :type company: ``str``
        :param company: The name of the company that released a binary.

        :type product_name: ``str``
        :param product_name: The name of the product to which this file belongs.

        :type digital_signature__publisher: ``str``
        :param digital_signature__publisher: The publisher of the digital signature for the file.

        :type signature: ``FileSignature``
        :param signature: File signature class

        :type actor: ``str``
        :param actor: The actor reference.

        :type tags: ``str``
        :param tags: Tags of the file.

        :type feed_related_indicators: ``FeedRelatedIndicators``
        :param feed_related_indicators: List of indicators that are associated with the file.

        :type malware_family: ``str``
        :param malware_family: The malware family associated with the File.

        :type campaign: ``str``
        :param campaign:

        :type traffic_light_protocol: ``str``
        :param traffic_light_protocol:

        :type community_notes: ``CommunityNotes``
        :param community_notes:  Notes on the file that were given by the community.

        :type publications: ``Publications``
        :param publications: Publications on the file that was published.

        :type threat_types: ``ThreatTypes``
        :param threat_types: Threat types that are associated with the file.

        :type imphash: ``str``
        :param imphash: The Imphash hash of the file.

        :type quarantined: ``bool``
        :param quarantined: Is the file quarantined or not.

        :type organization: ``str``
        :param organization: The organization of the file.

        :type associated_file_names: ``str``
        :param associated_file_names: File names that are known as associated to the file.

        :type behaviors: ``Behaviors``
        :param behaviors: list of behaviors associated with the file.

        :type relationships: ``list of EntityRelationship``
        :param relationships: List of relationships of the indicator.

        :type dbot_score: ``DBotScore``
        :param dbot_score: If file has a score then create and set a DBotScore object

        :type creation_date: ``str``
        :param creation_date: The date the file was created.

        :type description: ``str``
        :param description: File description.

        :type hashes: ``Hash``
        :param hashes: List of hashes associated with the file.

        :type stix_id: ``str``
        :param stix_id: File assigned STIX ID.

        :type organization_prevalence: ``int``
        :param organization_prevalence: The number of times the indicator is detected in the organization.

        :type global_prevalence: ``int``
        :param global_prevalence: The number of times the indicator is detected across all organizations.

        :type organization_first_seen: ``str``
        :param organization_first_seen: ISO 8601 date time string; when the indicator was first seen in the organization.

        :type organization_last_seen: ``str``
        :param organization_last_seen: ISO 8601 date time string; the last time a specific organization encountered an indicator.

        :type first_seen_by_source: ``str``
        :param first_seen_by_source: ISO 8601 date time string; when the indicator was first seen by the source vendor.

        :type last_seen_by_source: ``str``
        :param last_seen_by_source: ISO 8601 date time string; when the indicator was last seen by the source vendor.

        :rtype: ``None``
        :return: None
        """
        CONTEXT_PATH = 'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || ' \
                       'val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || ' \
                       'val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || ' \
                       'val.SSDeep && val.SSDeep == obj.SSDeep)'

        def __init__(self, dbot_score, name=None, entry_id=None, size=None, md5=None, sha1=None, sha256=None,
                     sha512=None, ssdeep=None, extension=None, file_type=None, hostname=None, path=None, company=None,
                     product_name=None, digital_signature__publisher=None, signature=None, actor=None, tags=None,
                     feed_related_indicators=None, malware_family=None, imphash=None, quarantined=None, campaign=None,
                     associated_file_names=None, traffic_light_protocol=None, organization=None, community_notes=None,
                     publications=None, threat_types=None, behaviors=None, relationships=None,
                     creation_date=None, description=None, hashes=None, stix_id=None, organization_prevalence=None,
                     global_prevalence=None, organization_first_seen=None, organization_last_seen=None,
                     first_seen_by_source=None, last_seen_by_source=None):

            # Main value of a file (Hashes)
            self.md5 = md5
            self.imphash = imphash
            self.sha1 = sha1
            self.sha256 = sha256
            self.sha512 = sha512
            self.ssdeep = ssdeep
            self.hashes = hashes

            # Core custom fields for File type
            self.associated_file_names = associated_file_names
            self.community_notes = community_notes
            self.creation_date = creation_date
            self.description = description
            self.extension = extension
            self.file_type = file_type
            self.path = path
            self.quarantined = quarantined
            self.size = size
            self.stix_id = stix_id
            self.tags = tags
            self.traffic_light_protocol = traffic_light_protocol

            # Other custom fields
            self.name = name
            self.entry_id = entry_id
            self.hostname = hostname
            self.company = company
            self.product_name = product_name
            self.digital_signature__publisher = digital_signature__publisher
            self.signature = signature
            self.actor = actor
            self.organization = organization
            self.feed_related_indicators = feed_related_indicators
            self.malware_family = malware_family
            self.campaign = campaign
            self.publications = publications
            self.threat_types = threat_types
            self.behaviors = behaviors
            self.organization_prevalence = organization_prevalence
            self.global_prevalence = global_prevalence
            self.organization_first_seen = organization_first_seen
            self.organization_last_seen = organization_last_seen
            self.first_seen_by_source = first_seen_by_source
            self.last_seen_by_source = last_seen_by_source

            # XSOAR Fields
            self.relationships = relationships
            self.dbot_score = dbot_score

        def to_context(self):
            file_context = {'Hashes': []}  # type: dict

            if self.name:
                file_context['Name'] = self.name

            if self.hashes:
                file_context['Hashes'] = self.create_context_table(self.hashes)

            if self.entry_id:
                file_context['EntryID'] = self.entry_id

            if self.size:
                file_context['Size'] = self.size

            if self.md5:
                file_context['MD5'] = self.md5
                file_context['Hashes'].append({'type': 'MD5',
                                               'value': self.md5})

            if self.sha1:
                file_context['SHA1'] = self.sha1
                file_context['Hashes'].append({'type': 'SHA1',
                                               'value': self.sha1})

            if self.sha256:
                file_context['SHA256'] = self.sha256
                file_context['Hashes'].append({'type': 'SHA256',
                                               'value': self.sha256})

            if self.sha512:
                file_context['SHA512'] = self.sha512
                file_context['Hashes'].append({'type': 'SHA512',
                                               'value': self.sha512})

            if self.ssdeep:
                file_context['SSDeep'] = self.ssdeep
                file_context['Hashes'].append({'type': 'SSDeep',
                                               'value': self.ssdeep})

            if self.extension:
                file_context['Extension'] = self.extension

            if self.file_type:
                file_context['Type'] = self.file_type

            if self.hostname:
                file_context['Hostname'] = self.hostname

            if self.path:
                file_context['Path'] = self.path

            if self.company:
                file_context['Company'] = self.company

            if self.product_name:
                file_context['ProductName'] = self.product_name

            if self.digital_signature__publisher:
                file_context['DigitalSignature'] = {
                    'Published': self.digital_signature__publisher
                }

            if self.signature:
                file_context['Signature'] = self.signature.to_context()

            if self.actor:
                file_context['Actor'] = self.actor

            if self.tags:
                file_context['Tags'] = self.tags

            if self.feed_related_indicators:
                file_context['FeedRelatedIndicators'] = self.create_context_table(self.feed_related_indicators)

            if self.malware_family:
                file_context['MalwareFamily'] = self.malware_family

            if self.campaign:
                file_context['Campaign'] = self.campaign

            if self.traffic_light_protocol:
                file_context['TrafficLightProtocol'] = self.traffic_light_protocol

            if self.community_notes:
                file_context['CommunityNotes'] = self.create_context_table(self.community_notes)

            if self.publications:
                file_context['Publications'] = self.create_context_table(self.publications)

            if self.threat_types:
                file_context['ThreatTypes'] = self.create_context_table(self.threat_types)

            if self.imphash:
                file_context['Imphash'] = self.imphash
                file_context['Hashes'].append({'type': 'Imphash',
                                               'value': self.imphash})

            if self.quarantined:
                file_context['Quarantined'] = self.quarantined

            if self.organization:
                file_context['Organization'] = self.organization

            if self.associated_file_names:
                file_context['AssociatedFileNames'] = self.associated_file_names

            if self.behaviors:
                file_context['Behavior'] = self.create_context_table(self.behaviors)

            if self.organization_prevalence is not None:  # checking for `is not None` to allow `0`-value
                file_context['OrganizationPrevalence'] = self.organization_prevalence

            if self.global_prevalence is not None:  # checking for `is not None` to allow `0`-value
                file_context['GlobalPrevalence'] = self.global_prevalence

            if self.organization_first_seen:
                file_context['OrganizationFirstSeen'] = self.organization_first_seen

            if self.organization_last_seen:
                file_context['OrganizationLastSeen'] = self.organization_last_seen

            if self.first_seen_by_source:
                file_context['FirstSeenBySource'] = self.first_seen_by_source

            if self.last_seen_by_source:
                file_context['LastSeenBySource'] = self.last_seen_by_source

            if self.dbot_score and self.dbot_score.score == Common.DBotScore.BAD:
                file_context['Malicious'] = {
                    'Vendor': self.dbot_score.integration_name,
                    'Description': self.dbot_score.malicious_description
                }

            if self.relationships:
                relationships_context = [relationship.to_context() for relationship in self.relationships if
                                         relationship.to_context()]
                file_context['Relationships'] = relationships_context

            ret_value = {
                Common.File.CONTEXT_PATH: file_context
            }

            if self.dbot_score:
                ret_value.update(self.dbot_score.to_context())

            return ret_value

    class CVE(Indicator):
        """
        CVE indicator class - https://xsoar.pan.dev/docs/integrations/context-standards-mandatory#cve
        :type id: ``str``
        :param id: The ID of the CVE, for example: "CVE-2015-1653".

        :type cvss: ``str``
        :param cvss: The CVSS of the CVE, for example: "10.0".

        :type published: ``str``
        :param published: The timestamp of when the CVE was published.

        :type modified: ``str``
        :param modified: The timestamp of when the CVE was last modified.

        :type description: ``str``
        :param description: A description of the CVE.

        :type relationships: ``list of EntityRelationship``
        :param relationships: List of relationships of the indicator.

        :type stix_id: ``str``
        :param stix_id: CVE sitx id.

        :type cvss_version: ``str``
        :param cvss_version: The CVE CVSS version used.

        :type cvss_score: ``str``
        :param cvss_score: The CVE CVSS Score.

        :type cvss_vector: ``str``
        :param cvss_vector: CVE full cvss vector.

        :type cvss_table: ``str``
        :param cvss_table: CVE CVSS Table used to fill the different parts of the vector.

        :type community_notes: ``str``
        :param community_notes: Community notes about the CVE.

        :type tags: ``str``
        :param tags: Tags attached to the CVE.

        :type traffic_light_protocol: ``str``
        :param traffic_light_protocol: The CVE tlp color.

        :type publications: ``str``
        :param publications: Unique system-assigned ID of the vulnerability evaluation logic

        :type dbot_score: ``DBotScore``
        :param dbot_score: If file has a score then create and set a DBotScore object

        :type vulnerable_products: ``CPE``
        :param vulnerable_products: A list of CPE objects

        :type vulnerable_configurations: ``CPE``
        :param vulnerable_configurations: A list of CPE objects

        :return: None
        :rtype: ``None``
        """
        CONTEXT_PATH = 'CVE(val.ID && val.ID == obj.ID)'

        def __init__(self, id, cvss, published, modified, description, relationships=None, stix_id=None,
                     cvss_version=None, cvss_score=None, cvss_vector=None, cvss_table=None, community_notes=None,
                     tags=None, traffic_light_protocol=None, dbot_score=None, publications=None,
                     vulnerable_products=None, vulnerable_configurations=None):

            # Main indicator value
            self.id = id

            # Core custom fields
            self.community_notes = community_notes
            self.cvss = cvss
            self.cvss_version = cvss_version
            self.cvss_score = cvss_score
            self.cvss_vector = cvss_vector
            self.cvss_table = cvss_table
            self.description = description
            self.modified = modified
            self.published = published
            self.stix_id = stix_id
            self.tags = tags
            self.traffic_light_protocol = traffic_light_protocol
            self.publications = publications

            # XSOAR Fields
            self.relationships = relationships
            self.dbot_score = dbot_score if dbot_score else Common.DBotScore(indicator=id,
                                                                             indicator_type=DBotScoreType.CVE,
                                                                             integration_name=None,
                                                                             score=Common.DBotScore.NONE)

            # Core custom fields for CVE type
            self.vulnerable_products = vulnerable_products
            self.vulnerable_configurations = vulnerable_configurations

        def to_context(self):
            cve_context = {
                'ID': self.id,
                'CVSS': {},
            }

            if self.cvss:
                cve_context['CVSS']['Score'] = self.cvss

            elif self.cvss_score:
                cve_context['CVSS']['Score'] = self.cvss_score

            if self.cvss_version:
                cve_context['CVSS']['Version'] = self.cvss_version

            if self.cvss_vector:
                cve_context['CVSS']['Vector'] = self.cvss_vector

            if self.cvss_table:
                cve_context['CVSS']['Table'] = self.cvss_table

            if self.published:
                cve_context['Published'] = self.published

            if self.modified:
                cve_context['Modified'] = self.modified

            if self.description:
                cve_context['Description'] = self.description

            if self.stix_id:
                cve_context['STIXID'] = self.stix_id

            if self.relationships:
                relationships_context = [relationship.to_context() for relationship in self.relationships if
                                         relationship.to_context()]
                cve_context['Relationships'] = relationships_context

            if self.community_notes:
                cve_context['CommunityNotes'] = self.create_context_table(self.community_notes)

            if self.tags:
                cve_context['Tags'] = self.tags

            if self.traffic_light_protocol:
                cve_context['TrafficLightProtocol'] = self.traffic_light_protocol

            ret_value = {
                Common.CVE.CONTEXT_PATH: cve_context
            }

            if self.dbot_score:
                ret_value.update(self.dbot_score.to_context())

            if self.publications:
                cve_context['Publications'] = self.create_context_table(self.publications)

            if self.vulnerable_products:
                cve_context['VulnerableProducts'] = self.create_context_table(self.vulnerable_products)

            if self.vulnerable_configurations:
                cve_context['VulnerableConfigurations'] = self.create_context_table(self.vulnerable_configurations)

            return ret_value

    class EMAIL(Indicator):
        """
        EMAIL indicator class

        :type address ``str``
        :param address: The email's address.

        :type domain: ``str``
        :param domain: The domain of the Email.

        :type blocked: ``bool``
        :param blocked: Whether the email address is blocked.

        :type relationships: ``list of EntityRelationship``
        :param relationships: List of relationships of the indicator.

        :type description: ``str``
        :param description: Description of the email address.

        :type internal: ``bool``
        :param internal: Is the email an internal address.

        :type stix_id: ``str``
        :param stix_id: The email assigned STIX ID.

        :type tags: ``str``
        :param tags: tags relevant to the email.

        :type traffic_light_protocol: ``str``
        :param traffic_light_protocol: The email address tlp color.

        :return: None
        :rtype: ``None``
        """
        CONTEXT_PATH = 'Account(val.Email.Address && val.Email.Address == obj.Email.Address)'

        def __init__(self, address, dbot_score, domain=None, blocked=None, relationships=None, description=None,
                     internal=None, stix_id=None, tags=None, traffic_light_protocol=None):
            # type (str, str, bool) -> None

            # Main indicator value
            self.address = address

            # Core custom fields
            self.blocked = blocked
            self.description = description
            self.internal = internal
            self.stix_id = stix_id
            self.tags = tags
            self.traffic_light_protocol = traffic_light_protocol

            # Deprecated
            self.domain = domain

            # XSOAR Fields
            self.dbot_score = dbot_score
            self.relationships = relationships

        def to_context(self):
            email_context = {
                'Email': {'Address': self.address}
            }

            if self.blocked:
                email_context['Blocked'] = self.blocked

            if self.domain:
                email_context['Domain'] = self.domain

            if self.description:
                email_context['Description'] = self.description

            if self.internal:
                email_context['Internal'] = self.internal

            if self.stix_id:
                email_context['STIXID'] = self.stix_id

            if self.tags:
                email_context['Tags'] = self.tags

            if self.traffic_light_protocol:
                email_context['TrafficLightProtocol'] = self.traffic_light_protocol

            if self.relationships:
                relationships_context = [relationship.to_context() for relationship in self.relationships if
                                         relationship.to_context()]
                email_context['Relationships'] = relationships_context

            ret_value = {
                Common.EMAIL.CONTEXT_PATH: email_context
            }
            if self.dbot_score:
                ret_value.update(self.dbot_score.to_context())
            return ret_value

    class URL(Indicator):
        """
        URL indicator - https://xsoar.pan.dev/docs/integrations/context-standards-mandatory#url
        :type url: ``str``
        :param url: The URL

        :type detection_engines: ``int``
        :param detection_engines: The total number of engines that checked the indicator.

        :type positive_detections: ``int``
        :param positive_detections: The number of engines that positively detected the indicator as malicious.

        :type category: ``str``
        :param category: The category associated with the indicator.

        :type feed_related_indicators: ``FeedRelatedIndicators``
        :param feed_related_indicators: List of indicators that are associated with the URL.

        :type malware_family: ``str``
        :param malware_family: The malware family associated with the URL.

        :type tags: ``str``
        :param tags: Tags of the URL.

        :type port: ``str``
        :param port: Ports that are associated with the URL.

        :type internal: ``bool``
        :param internal: Whether or not the URL is internal or external.

        :type campaign: ``str``
        :param campaign: The campaign associated with the URL.

        :type traffic_light_protocol: ``str``
        :param traffic_light_protocol: The Traffic Light Protocol (TLP) color that is suitable for the URL.

        :type threat_types: ``ThreatTypes``
        :param threat_types: Threat types that are associated with the file.

        :type asn: ``str``
        :param asn: The autonomous system name for the URL, for example: 'AS8948'.

        :type as_owner: ``str``
        :param as_owner: The autonomous system owner of the URL.

        :type geo_country: ``str``
        :param geo_country: The country in which the URL is located.

        :type organization: ``str``
        :param organization: The organization of the URL.

        :type community_notes: ``CommunityNotes``
        :param community_notes:  List of notes on the URL that were given by the community.

        :type publications: ``Publications``
        :param publications: List of publications on the URL that was published.

        :type relationships: ``list of EntityRelationship``
        :param relationships: List of relationships of the indicator.

        :type dbot_score: ``DBotScore``
        :param dbot_score: If URL has reputation then create DBotScore object

        :type blocked: ``bool``
        :param blocked: Is the URL blocked.

        :type certificates: ``Certificates``
        :param certificates: A list of certificates associated with the url.

        :type description: ``str``
        :param description: A description of the URL.

        :type stix_id: ``str``
        :param stix_id: The URL STIX ID.

        :type organization_prevalence: ``int``
        :param organization_prevalence: The number of times the indicator is detected in the organization.

        :type global_prevalence: ``int``
        :param global_prevalence: The number of times the indicator is detected across all organizations.

        :type organization_first_seen: ``str``
        :param organization_first_seen: ISO 8601 date time string; when the indicator was first seen in the organization.

        :type organization_last_seen: ``str``
        :param organization_last_seen: ISO 8601 date time string; the last time a specific organization encountered an indicator.

        :type first_seen_by_source: ``str``
        :param first_seen_by_source: ISO 8601 date time string; when the indicator was first seen by the source vendor.

        :type last_seen_by_source: ``str``
        :param last_seen_by_source: ISO 8601 date time string; when the indicator was last seen by the source vendor.

        :return: None
        :rtype: ``None``
        """
        CONTEXT_PATH = 'URL(val.Data && val.Data == obj.Data)'

        def __init__(self, url, dbot_score, detection_engines=None, positive_detections=None, category=None,
                     feed_related_indicators=None, tags=None, malware_family=None, port=None, internal=None,
                     campaign=None, traffic_light_protocol=None, threat_types=None, asn=None, as_owner=None,
                     geo_country=None, organization=None, community_notes=None, publications=None, relationships=None,
                     blocked=None, certificates=None, description=None, stix_id=None, organization_prevalence=None,
                     global_prevalence=None, organization_first_seen=None, organization_last_seen=None,
                     first_seen_by_source=None, last_seen_by_source=None):

            # Main indicator value
            self.url = url

            # Core custom fields
            self.blocked = blocked
            self.certificates = certificates
            self.community_notes = community_notes
            self.description = description
            self.internal = internal
            self.stix_id = stix_id
            self.tags = tags
            self.traffic_light_protocol = traffic_light_protocol

            # Additional custom fields
            self.detection_engines = detection_engines
            self.positive_detections = positive_detections
            self.category = category
            self.feed_related_indicators = feed_related_indicators
            self.malware_family = malware_family
            self.port = port
            self.campaign = campaign
            self.threat_types = threat_types
            self.asn = asn
            self.as_owner = as_owner
            self.geo_country = geo_country
            self.organization = organization
            self.publications = publications
            self.organization_prevalence = organization_prevalence
            self.global_prevalence = global_prevalence
            self.organization_first_seen = organization_first_seen
            self.organization_last_seen = organization_last_seen
            self.first_seen_by_source = first_seen_by_source
            self.last_seen_by_source = last_seen_by_source

            # XSOAR Fields
            self.relationships = relationships
            self.dbot_score = dbot_score

        def to_context(self):
            url_context = {
                'Data': self.url
            }

            if self.blocked:
                url_context['Blocked'] = self.blocked

            if self.certificates:
                url_context['Certificates'] = self.create_context_table(self.certificates)

            if self.description:
                url_context['Description'] = self.description

            if self.stix_id:
                url_context['STIXID'] = self.stix_id

            if self.detection_engines is not None:
                url_context['DetectionEngines'] = self.detection_engines

            if self.positive_detections is not None:
                url_context['PositiveDetections'] = self.positive_detections

            if self.category:
                url_context['Category'] = self.category

            if self.feed_related_indicators:
                url_context['FeedRelatedIndicators'] = self.create_context_table(self.feed_related_indicators)

            if self.tags:
                url_context['Tags'] = self.tags

            if self.malware_family:
                url_context['MalwareFamily'] = self.malware_family

            if self.port:
                url_context['Port'] = self.port

            if self.internal:
                url_context['Internal'] = self.internal

            if self.campaign:
                url_context['Campaign'] = self.campaign

            if self.traffic_light_protocol:
                url_context['TrafficLightProtocol'] = self.traffic_light_protocol

            if self.threat_types:
                url_context['ThreatTypes'] = self.create_context_table(self.threat_types)

            if self.asn:
                url_context['ASN'] = self.asn

            if self.as_owner:
                url_context['ASOwner'] = self.as_owner

            if self.geo_country:
                url_context['Geo'] = {'Country': self.geo_country}

            if self.organization:
                url_context['Organization'] = self.organization

            if self.community_notes:
                url_context['CommunityNotes'] = self.create_context_table(self.community_notes)

            if self.publications:
                url_context['Publications'] = self.create_context_table(self.publications)

            if self.organization_prevalence is not None:  # checking for `is not None` to allow `0`-value
                url_context['OrganizationPrevalence'] = self.organization_prevalence

            if self.global_prevalence is not None:  # checking for `is not None` to allow `0`-value
                url_context['GlobalPrevalence'] = self.global_prevalence

            if self.organization_first_seen:
                url_context['OrganizationFirstSeen'] = self.organization_first_seen

            if self.organization_last_seen:
                url_context['OrganizationLastSeen'] = self.organization_last_seen

            if self.first_seen_by_source:
                url_context['FirstSeenBySource'] = self.first_seen_by_source

            if self.last_seen_by_source:
                url_context['LastSeenBySource'] = self.last_seen_by_source

            if self.dbot_score and self.dbot_score.score == Common.DBotScore.BAD:
                url_context['Malicious'] = {
                    'Vendor': self.dbot_score.integration_name,
                    'Description': self.dbot_score.malicious_description
                }

            if self.relationships:
                relationships_context = [relationship.to_context() for relationship in self.relationships if
                                         relationship.to_context()]
                url_context['Relationships'] = relationships_context

            ret_value = {
                Common.URL.CONTEXT_PATH: url_context
            }

            if self.dbot_score:
                ret_value.update(self.dbot_score.to_context())

            return ret_value

    class Domain(Indicator):
        """ ignore docstring
        Domain indicator - https://xsoar.pan.dev/docs/integrations/context-standards-mandatory#domain

        :type whois_records: ``WhoisRecord``
        :param whois_records: List of whois records

        :type description: ``str``
        :param description: A description of the Domain.

        :type stix_id: ``str``
        :param stix_id: The domain STIX ID.

        :type blocked: ``bool``
        :param blocked: Is the domain blocked.

        :type certificates: ``Certificates``
        :param certificates: The certificates belonging to the domain.

        :type dns_records: ``DNSRecord``
        :param dns_records: A list of DNS records for the domain.

        :type organization_prevalence: ``int``
        :param organization_prevalence: The number of times the indicator is detected in the organization.

        :type global_prevalence: ``int``
        :param global_prevalence: The number of times the indicator is detected across all organizations.

        :type organization_first_seen: ``str``
        :param organization_first_seen: ISO 8601 date time string; when the indicator was first seen in the organization.

        :type organization_last_seen: ``str``
        :param organization_last_seen: ISO 8601 date time string; the last time a specific organization encountered an indicator.

        :type first_seen_by_source: ``str``
        :param first_seen_by_source: ISO 8601 date time string; when the indicator was first seen by the source vendor.

        :type last_seen_by_source: ``str``
        :param last_seen_by_source: ISO 8601 date time string; when the indicator was last seen by the source vendor.
        """
        CONTEXT_PATH = 'Domain(val.Name && val.Name == obj.Name)'

        def __init__(self, domain, dbot_score, dns=None, detection_engines=None, positive_detections=None,
                     organization=None, sub_domains=None, creation_date=None, updated_date=None, expiration_date=None,
                     domain_status=None, name_servers=None, feed_related_indicators=None, malware_family=None,
                     registrar_name=None, registrar_abuse_email=None, registrar_abuse_phone=None,
                     registrant_name=None, registrant_email=None, registrant_phone=None, registrant_country=None,
                     admin_name=None, admin_email=None, admin_phone=None, admin_country=None, tags=None,
                     domain_idn_name=None, port=None,
                     internal=None, category=None, campaign=None, traffic_light_protocol=None, threat_types=None,
                     community_notes=None, publications=None, geo_location=None, geo_country=None, geo_description=None,
                     tech_country=None, tech_name=None, tech_email=None, tech_organization=None, billing=None,
                     whois_records=None, relationships=None, description=None, stix_id=None, blocked=None,
                     certificates=None, dns_records=None, rank=None, organization_prevalence=None,
                     global_prevalence=None, organization_first_seen=None, organization_last_seen=None,
                     first_seen_by_source=None, last_seen_by_source=None):

            # Main indicator value
            self.domain = domain

            # Core custom fields
            self.blocked = blocked
            self.certificates = certificates
            self.community_notes = community_notes
            self.creation_date = creation_date
            self.description = description
            self.dns_records = dns_records
            self.expiration_date = expiration_date
            self.internal = internal
            self.stix_id = stix_id
            self.tags = tags
            self.traffic_light_protocol = traffic_light_protocol
            self.whois_records = whois_records

            # Additional custom fields
            self.dns = dns
            self.detection_engines = detection_engines
            self.positive_detections = positive_detections
            self.organization = organization
            self.sub_domains = sub_domains
            self.updated_date = updated_date
            self.rank = rank

            # Whois related records - Registrar
            self.registrar_name = registrar_name
            self.registrar_abuse_email = registrar_abuse_email
            self.registrar_abuse_phone = registrar_abuse_phone

            self.registrant_name = registrant_name
            self.registrant_email = registrant_email
            self.registrant_phone = registrant_phone
            self.registrant_country = registrant_country

            self.admin_name = admin_name
            self.admin_email = admin_email
            self.admin_phone = admin_phone
            self.admin_country = admin_country

            self.tech_country = tech_country
            self.tech_name = tech_name
            self.tech_organization = tech_organization
            self.tech_email = tech_email
            self.billing = billing

            # Additional custom records (non core)
            self.domain_status = domain_status
            self.name_servers = name_servers
            self.feed_related_indicators = feed_related_indicators
            self.malware_family = malware_family
            self.domain_idn_name = domain_idn_name
            self.port = port
            self.category = category
            self.campaign = campaign
            self.threat_types = threat_types
            self.publications = publications
            self.geo_location = geo_location
            self.geo_country = geo_country
            self.geo_description = geo_description
            self.organization_prevalence = organization_prevalence
            self.global_prevalence = global_prevalence
            self.organization_first_seen = organization_first_seen
            self.organization_last_seen = organization_last_seen
            self.first_seen_by_source = first_seen_by_source
            self.last_seen_by_source = last_seen_by_source

            # XSOAR Fields
            self.relationships = relationships
            self.dbot_score = dbot_score

        def to_context(self):
            domain_context = {
                'Name': self.domain
            }
            whois_context = {}

            if self.dns:
                domain_context['DNS'] = self.dns

            if self.detection_engines is not None:
                domain_context['DetectionEngines'] = self.detection_engines

            if self.positive_detections is not None:
                domain_context['PositiveDetections'] = self.positive_detections

            if self.registrar_name or self.registrar_abuse_email or self.registrar_abuse_phone:
                domain_context['Registrar'] = {
                    'Name': self.registrar_name,
                    'AbuseEmail': self.registrar_abuse_email,
                    'AbusePhone': self.registrar_abuse_phone
                }
                whois_context['Registrar'] = domain_context['Registrar']

            if self.registrant_name or self.registrant_phone or self.registrant_email or self.registrant_country:
                domain_context['Registrant'] = {
                    'Name': self.registrant_name,
                    'Email': self.registrant_email,
                    'Phone': self.registrant_phone,
                    'Country': self.registrant_country
                }
                whois_context['Registrant'] = domain_context['Registrant']

            if self.admin_name or self.admin_email or self.admin_phone or self.admin_country:
                domain_context['Admin'] = {
                    'Name': self.admin_name,
                    'Email': self.admin_email,
                    'Phone': self.admin_phone,
                    'Country': self.admin_country
                }
                whois_context['Admin'] = domain_context['Admin']

            if self.organization:
                domain_context['Organization'] = self.organization

            if self.sub_domains:
                domain_context['Subdomains'] = self.sub_domains

            if self.domain_status:
                domain_context['DomainStatus'] = self.domain_status
                whois_context['DomainStatus'] = domain_context['DomainStatus']

            if self.creation_date:
                domain_context['CreationDate'] = self.creation_date
                whois_context['CreationDate'] = domain_context['CreationDate']

            if self.updated_date:
                domain_context['UpdatedDate'] = self.updated_date
                whois_context['UpdatedDate'] = domain_context['UpdatedDate']

            if self.expiration_date:
                domain_context['ExpirationDate'] = self.expiration_date
                whois_context['ExpirationDate'] = domain_context['ExpirationDate']

            if self.name_servers:
                domain_context['NameServers'] = self.name_servers
                whois_context['NameServers'] = domain_context['NameServers']

            if self.tags:
                domain_context['Tags'] = self.tags

            if self.feed_related_indicators:
                domain_context['FeedRelatedIndicators'] = self.create_context_table(self.feed_related_indicators)

            if self.whois_records:
                domain_context['WhoisRecords'] = self.create_context_table(self.whois_records)

            if self.malware_family:
                domain_context['MalwareFamily'] = self.malware_family

            if self.organization_prevalence is not None:  # checking for `is not None` to allow `0`-value
                domain_context['OrganizationPrevalence'] = self.organization_prevalence

            if self.global_prevalence is not None:  # checking for `is not None` to allow `0`-value
                domain_context['GlobalPrevalence'] = self.global_prevalence

            if self.organization_first_seen:
                domain_context['OrganizationFirstSeen'] = self.organization_first_seen

            if self.organization_last_seen:
                domain_context['OrganizationLastSeen'] = self.organization_last_seen

            if self.first_seen_by_source:
                domain_context['FirstSeenBySource'] = self.first_seen_by_source

            if self.last_seen_by_source:
                domain_context['LastSeenBySource'] = self.last_seen_by_source

            if self.dbot_score and self.dbot_score.score == Common.DBotScore.BAD:
                domain_context['Malicious'] = {
                    'Vendor': self.dbot_score.integration_name,
                    'Description': self.dbot_score.malicious_description
                }

            if self.domain_idn_name:
                domain_context['DomainIDNName'] = self.domain_idn_name

            if self.port:
                domain_context['Port'] = self.port

            if self.internal:
                domain_context['Internal'] = self.internal

            if self.category:
                domain_context['Category'] = self.category

            if self.campaign:
                domain_context['Campaign'] = self.campaign

            if self.traffic_light_protocol:
                domain_context['TrafficLightProtocol'] = self.traffic_light_protocol

            if self.threat_types:
                domain_context['ThreatTypes'] = self.create_context_table(self.threat_types)

            if self.community_notes:
                domain_context['CommunityNotes'] = self.create_context_table(self.community_notes)

            if self.publications:
                domain_context['Publications'] = self.create_context_table(self.publications)

            if self.geo_location or self.geo_country or self.geo_description:
                domain_context['Geo'] = {}
                if self.geo_location:
                    domain_context['Geo']['Location'] = self.geo_location
                if self.geo_country:
                    domain_context['Geo']['Country'] = self.geo_country
                if self.geo_description:
                    domain_context['Geo']['Description'] = self.geo_description

            if self.tech_country or self.tech_name or self.tech_organization or self.tech_email:
                domain_context['Tech'] = {}
                if self.tech_country:
                    domain_context['Tech']['Country'] = self.tech_country
                if self.tech_name:
                    domain_context['Tech']['Name'] = self.tech_name
                if self.tech_organization:
                    domain_context['Tech']['Organization'] = self.tech_organization
                if self.tech_email:
                    domain_context['Tech']['Email'] = self.tech_email

            if self.billing:
                domain_context['Billing'] = self.billing

            if whois_context:
                domain_context['WHOIS'] = whois_context

            if self.relationships:
                relationships_context = [relationship.to_context() for relationship in self.relationships if
                                         relationship.to_context()]
                domain_context['Relationships'] = relationships_context

            ret_value = {
                Common.Domain.CONTEXT_PATH: domain_context
            }

            if self.dbot_score:
                ret_value.update(self.dbot_score.to_context())

            if self.dns_records:
                domain_context['DNSRecords'] = self.create_context_table(self.dns_records)

            if self.stix_id:
                domain_context['STIXID'] = self.stix_id

            if self.description:
                domain_context['Description'] = self.description

            if self.stix_id:
                domain_context['Blocked'] = self.blocked

            if self.certificates:
                domain_context['Certificates'] = self.create_context_table(self.certificates)

            if self.rank:
                domain_context['Rank'] = self.create_context_table(self.rank)

            return ret_value

    class Endpoint(Indicator):
        """ ignore docstring
        Endpoint indicator - https://xsoar.pan.dev/docs/integrations/context-standards-mandatory#endpoint
        """
        # Compare by both ID and Vendor if both exist, otherwise just by ID.
        CONTEXT_PATH = 'Endpoint(val.ID && val.ID == obj.ID && val.Vendor == obj.Vendor)'

        def __init__(self, id, hostname=None, ip_address=None, domain=None, mac_address=None,
                     os=None, os_version=None, dhcp_server=None, bios_version=None, model=None,
                     memory=None, processors=None, processor=None, relationships=None, vendor=None, status=None,
                     is_isolated=None):
            self.id = id
            self.hostname = hostname
            self.ip_address = ip_address
            self.domain = domain
            self.mac_address = mac_address
            self.os = os
            self.os_version = os_version
            self.dhcp_server = dhcp_server
            self.bios_version = bios_version
            self.model = model
            self.memory = memory
            self.processors = processors
            self.processor = processor
            self.vendor = vendor
            self.status = status
            self.is_isolated = is_isolated
            self.relationships = relationships

        def to_context(self):
            endpoint_context = {
                'ID': self.id
            }

            if self.hostname:
                endpoint_context['Hostname'] = self.hostname

            if self.ip_address:
                endpoint_context['IPAddress'] = self.ip_address

            if self.domain:
                endpoint_context['Domain'] = self.domain

            if self.mac_address:
                endpoint_context['MACAddress'] = self.mac_address

            if self.os:
                endpoint_context['OS'] = self.os

            if self.os_version:
                endpoint_context['OSVersion'] = self.os_version

            if self.dhcp_server:
                endpoint_context['DHCPServer'] = self.dhcp_server

            if self.bios_version:
                endpoint_context['BIOSVersion'] = self.bios_version

            if self.model:
                endpoint_context['Model'] = self.model

            if self.memory:
                endpoint_context['Memory'] = self.memory

            if self.processors:
                endpoint_context['Processors'] = self.processors

            if self.processor:
                endpoint_context['Processor'] = self.processor

            if self.relationships:
                relationships_context = [relationship.to_context() for relationship in self.relationships if
                                         relationship.to_context()]
                endpoint_context['Relationships'] = relationships_context

            if self.vendor:
                endpoint_context['Vendor'] = self.vendor

            if self.status:
                if self.status not in ENDPOINT_STATUS_OPTIONS:
                    raise ValueError('Status does not have a valid value such as: Online or Offline')
                endpoint_context['Status'] = self.status

            if self.is_isolated:
                if self.is_isolated not in ENDPOINT_ISISOLATED_OPTIONS:
                    raise ValueError('Is Isolated does not have a valid value such as: Yes, No, Pending'
                                     ' isolation or Pending unisolation')
                endpoint_context['IsIsolated'] = self.is_isolated

            ret_value = {
                Common.Endpoint.CONTEXT_PATH: endpoint_context
            }

            return ret_value

    class Account(Indicator):
        """
        Account indicator - https://xsoar.pan.dev/docs/integrations/context-standards-recommended#account

        :type blocked: ``boolean``
        :param blocked: Is the indicator blocked.

        :type community_notes: ``CommunityNotes``
        :param community_notes: Notes on the Account that were given by the community.

        :type dbot_score: ``DBotScore``
        :param dbot_score: If account has reputation then create DBotScore object

        :type creation_date: ``str``
        :param creation_date: The date the account was created

        :type description: ``str``
        :param description: Description of the account

        :type stix_id: ``str``
        :param stix_id: STIX ID for the account

        :type tags: ``str``
        :param tags: List of tags related to the account.

        :type traffic_light_protocol: ``str``
        :param traffic_light_protocol: The account indicator tlp color

        :type user_id: ``str``
        :param user_id: The account associated user id.

        :return: None
        :rtype: ``None``
        """
        CONTEXT_PATH = 'Account(val.id && val.id == obj.id)'

        def __init__(self, id=None, type=None, username=None, display_name=None, groups=None,
                     domain=None, email_address=None, telephone_number=None, office=None, job_title=None,
                     department=None, country=None, state=None, city=None, street=None, is_enabled=None,
                     dbot_score=None, relationships=None, blocked=None, community_notes=None, creation_date=None,
                     description=None, stix_id=None, tags=None, traffic_light_protocol=None, user_id=None,
                     manager_email=None, manager_display_name=None, risk_level=None, **kwargs):

            self.id = id
            self.type = type
            self.blocked = blocked
            self.community_notes = community_notes
            self.creation_date = creation_date
            self.description = description
            self.stix_id = stix_id
            self.username = username
            self.display_name = display_name
            self.groups = groups
            self.domain = domain
            self.email_address = email_address
            self.telephone_number = telephone_number
            self.office = office
            self.job_title = job_title
            self.department = department
            self.country = country
            self.state = state
            self.city = city
            self.street = street
            self.is_enabled = is_enabled
            self.tags = tags
            self.traffic_light_protocol = traffic_light_protocol
            self.user_id = user_id
            self.relationships = relationships
            self.manager_email_address = manager_email
            self.manager_display_name = manager_display_name
            self.risk_level = risk_level
            self.kwargs = kwargs

            if dbot_score and not isinstance(dbot_score, Common.DBotScore):
                raise ValueError('dbot_score must be of type DBotScore')

            self.dbot_score = dbot_score

        def to_context(self):
            account_context = {}

            if self.id:
                account_context['ID'] = self.id

            if self.type:
                account_context['Type'] = self.type

            if self.blocked:
                account_context['Blocked'] = self.blocked

            if self.creation_date:
                account_context['CreationDate'] = self.creation_date

            irrelevent = ['CONTEXT_PATH', 'to_context', 'dbot_score', 'id', 'create_context_table', 'kwargs']
            details = [detail for detail in dir(self) if not detail.startswith('__') and detail not in irrelevent]

            for detail in details:
                if self.__getattribute__(detail) is not None:
                    if detail == 'email_address':
                        account_context['Email'] = {
                            'Address': self.email_address
                        }
                    elif detail in ('manager_email_address', 'manager_display_name'):
                        if 'Manager' not in account_context:
                            account_context['Manager'] = {}
                        if detail == 'manager_email_address':
                            account_context['Manager']['Email'] = self.manager_email_address
                        elif detail == 'manager_display_name':
                            account_context['Manager']['DisplayName'] = self.manager_display_name
                    else:
                        Detail = camelize_string(detail, '_')
                        account_context[Detail] = self.__getattribute__(detail)

            if self.dbot_score and self.dbot_score.score == Common.DBotScore.BAD:
                account_context['Malicious'] = {
                    'Vendor': self.dbot_score.integration_name,
                    'Description': self.dbot_score.malicious_description
                }

            if self.relationships:
                relationships_context = [relationship.to_context() for relationship in self.relationships if
                                         relationship.to_context()]
                account_context['Relationships'] = relationships_context

            if self.community_notes:
                account_context['CommunityNotes'] = self.create_context_table(self.community_notes)

            if self.kwargs:
                for key, value in self.kwargs.items():
                    if key not in account_context:
                        account_context[key] = value
                    else:
                        demisto.debug(
                            'Skipping the addition of the "{key}" key to the account context as it already exists.'.format(
                                key=key)
                        )

            ret_value = {
                Common.Account.CONTEXT_PATH: account_context
            }

            if self.dbot_score:
                ret_value.update(self.dbot_score.to_context())

            return ret_value

    class Cryptocurrency(Indicator):
        """
        Cryptocurrency indicator - https://xsoar.pan.dev/docs/integrations/context-standards-mandatory#cryptocurrency
        :type address: ``str``
        :param address: The Cryptocurrency address

        :type address_type: ``str``
        :param address_type: The Cryptocurrency type - e.g. `bitcoin`.

        :type dbot_score: ``DBotScore``
        :param dbot_score:  If the address has reputation then create DBotScore object.

        :return: None
        :rtype: ``None``
        """
        CONTEXT_PATH = 'Cryptocurrency(val.Address && val.Address == obj.Address)'

        def __init__(self, address, address_type, dbot_score):
            self.address = address
            self.address_type = address_type

            self.dbot_score = dbot_score

        def to_context(self):
            crypto_context = {
                'Address': self.address,
                'AddressType': self.address_type
            }

            if self.dbot_score and self.dbot_score.score == Common.DBotScore.BAD:
                crypto_context['Malicious'] = {
                    'Vendor': self.dbot_score.integration_name,
                    'Description': self.dbot_score.malicious_description
                }

            ret_value = {
                Common.Cryptocurrency.CONTEXT_PATH: crypto_context
            }

            if self.dbot_score:
                ret_value.update(self.dbot_score.to_context())

            return ret_value

    class AttackPattern(Indicator):
        """
        Attack Pattern indicator

        :type stix_id: ``str``
        :param stix_id: The Attack Pattern STIX ID

        :type kill_chain_phases: ``str``
        :param kill_chain_phases: The Attack Pattern kill chain phases.

        :type first_seen_by_source: ``str``
        :param first_seen_by_source: The Attack Pattern first seen by source

        :type description: ``str``
        :param description: The Attack Pattern description

        :type operating_system_refs: ``str``
        :param operating_system_refs: The operating system refs of the Attack Pattern.

        :type publications: ``str``
        :param publications: The Attack Pattern publications

        :type mitre_id: ``str``
        :param mitre_id: The Attack Pattern kill mitre id.

        :type tags: ``str``
        :param tags: The Attack Pattern kill tags.

        :type dbot_score: ``DBotScore``
        :param dbot_score:  If the address has reputation then create DBotScore object.

        :type traffic_light_protocol: ``str``
        :param traffic_light_protocol: The Traffic Light Protocol (TLP) color that is suitable for the AP.

        :type community_notes: ``CommunityNotes``
        :param community_notes:  A list of community notes for the AP.

        :type external_references: ``ExternalReference``
        :param external_references:  A list of id's and description of the AP via external refs.

        :type value: ``str``
        :param value: The Attack Pattern value (name) - example: "Plist File Modification"

        :return: None
        :rtype: ``None``
        """
        CONTEXT_PATH = 'AttackPattern(val.value && val.value == obj.value)'

        def __init__(self, stix_id, kill_chain_phases=None, first_seen_by_source=None, description=None,
                     operating_system_refs=None, publications=None, mitre_id=None, tags=None,
                     traffic_light_protocol=None, dbot_score=None, community_notes=None, external_references=None, value=None):

            self.community_notes = community_notes
            self.description = description
            self.external_references = external_references
            self.first_seen_by_source = first_seen_by_source
            self.kill_chain_phases = kill_chain_phases
            self.mitre_id = mitre_id
            self.operating_system_refs = operating_system_refs
            self.publications = publications
            self.stix_id = stix_id
            self.tags = tags
            self.traffic_light_protocol = traffic_light_protocol
            self.value = value
            self.dbot_score = dbot_score

        def to_context(self):
            attack_pattern_context = {
                'STIXID': self.stix_id,
                "KillChainPhases": self.kill_chain_phases,
                "FirstSeenBySource": self.first_seen_by_source,
                'OperatingSystemRefs': self.operating_system_refs,
                "Publications": self.publications,
                "MITREID": self.mitre_id,
                "Value": self.value,
                "Tags": self.tags,
                "Description": self.description
            }

            if self.external_references:
                attack_pattern_context['ExternalReferences'] = self.create_context_table(self.external_references)

            if self.traffic_light_protocol:
                attack_pattern_context['TrafficLightProtocol'] = self.traffic_light_protocol

            if self.dbot_score and self.dbot_score.score == Common.DBotScore.BAD:
                attack_pattern_context['Malicious'] = {
                    'Vendor': self.dbot_score.integration_name,
                    'Description': self.dbot_score.malicious_description
                }

            ret_value = {
                Common.AttackPattern.CONTEXT_PATH: attack_pattern_context
            }

            if self.dbot_score:
                ret_value.update(self.dbot_score.to_context())

            return ret_value

    class CertificatePublicKey(object):
        """
        CertificatePublicKey class
        Defines an X509  PublicKey used in Common.Certificate

        :type algorithm: ``str``
        :param algorithm: The encryption algorithm: DSA, RSA, EC or UNKNOWN (Common.CertificatePublicKey.Algorithm enum)

        :type length: ``int``
        :param length: The length of the public key

        :type publickey: ``Optional[str]``
        :param publickey: publickey

        :type p: ``Optional[str]``
        :param p: P parameter used in DSA algorithm

        :type q: ``Optional[str]``
        :param q: Q parameter used in DSA algorithm

        :type g: ``Optional[str]``
        :param g: G parameter used in DSA algorithm

        :type modulus: ``Optional[str]``
        :param modulus: modulus parameter used in RSA algorithm

        :type modulus: ``Optional[int]``
        :param modulus: exponent parameter used in RSA algorithm

        :type x: ``Optional[str]``
        :param x: X parameter used in EC algorithm

        :type y: ``Optional[str]``
        :param y: Y parameter used in EC algorithm

        :type curve: ``Optional[str]``
        :param curve: curve parameter used in EC algorithm

        :return: None
        :rtype: ``None``
        """

        class Algorithm(object):
            """
            Algorithm class to enumerate available algorithms

            :return: None
            :rtype: ``None``
            """
            DSA = "DSA"
            RSA = "RSA"
            EC = "EC"
            UNKNOWN = "Unknown Algorithm"

            @staticmethod
            def is_valid_type(_type):
                return _type in (
                    Common.CertificatePublicKey.Algorithm.DSA,
                    Common.CertificatePublicKey.Algorithm.RSA,
                    Common.CertificatePublicKey.Algorithm.EC,
                    Common.CertificatePublicKey.Algorithm.UNKNOWN
                )

        def __init__(
            self,
            algorithm,  # type: str
            length,  # type: int
            publickey=None,  # type: str
            p=None,  # type: str
            q=None,  # type: str
            g=None,  # type: str
            modulus=None,  # type: str
            exponent=None,  # type: int
            x=None,  # type: str
            y=None,  # type: str
            curve=None  # type: str
        ):

            if not Common.CertificatePublicKey.Algorithm.is_valid_type(algorithm):
                raise TypeError('algorithm must be of type Common.CertificatePublicKey.Algorithm enum')

            self.algorithm = algorithm
            self.length = length
            self.publickey = publickey
            self.p = p
            self.q = q
            self.g = g
            self.modulus = modulus
            self.exponent = exponent
            self.x = x
            self.y = y
            self.curve = curve

        def to_context(self):
            publickey_context = {
                'Algorithm': self.algorithm,
                'Length': self.length
            }

            if self.publickey:
                publickey_context['PublicKey'] = self.publickey

            if self.algorithm == Common.CertificatePublicKey.Algorithm.DSA:
                if self.p:
                    publickey_context['P'] = self.p
                if self.q:
                    publickey_context['Q'] = self.q
                if self.g:
                    publickey_context['G'] = self.g

            elif self.algorithm == Common.CertificatePublicKey.Algorithm.RSA:
                if self.modulus:
                    publickey_context['Modulus'] = self.modulus
                if self.exponent:
                    publickey_context['Exponent'] = self.exponent

            elif self.algorithm == Common.CertificatePublicKey.Algorithm.EC:
                if self.x:
                    publickey_context['X'] = self.x
                if self.y:
                    publickey_context['Y'] = self.y
                if self.curve:
                    publickey_context['Curve'] = self.curve

            elif self.algorithm == Common.CertificatePublicKey.Algorithm.UNKNOWN:
                pass

            return publickey_context

    class GeneralName(object):
        """
        GeneralName class
        Implements GeneralName interface from rfc5280
        Enumerates the available General Name Types

        :type gn_type: ``str``
        :param gn_type: General Name Type

        :type gn_value: ``str``
        :param gn_value: General Name Value

        :return: None
        :rtype: ``None``
        """
        OTHERNAME = 'otherName'
        RFC822NAME = 'rfc822Name'
        DNSNAME = 'dNSName'
        DIRECTORYNAME = 'directoryName'
        UNIFORMRESOURCEIDENTIFIER = 'uniformResourceIdentifier'
        IPADDRESS = 'iPAddress'
        REGISTEREDID = 'registeredID'

        @staticmethod
        def is_valid_type(_type):
            return _type in (
                Common.GeneralName.OTHERNAME,
                Common.GeneralName.RFC822NAME,
                Common.GeneralName.DNSNAME,
                Common.GeneralName.DIRECTORYNAME,
                Common.GeneralName.UNIFORMRESOURCEIDENTIFIER,
                Common.GeneralName.IPADDRESS,
                Common.GeneralName.REGISTEREDID
            )

        def __init__(
            self,
            gn_value,  # type: str
            gn_type  # type: str
        ):
            if not Common.GeneralName.is_valid_type(gn_type):
                raise TypeError(
                    'gn_type must be of type Common.GeneralName enum'
                )
            self.gn_type = gn_type
            self.gn_value = gn_value

        def to_context(self):
            return {
                'Type': self.gn_type,
                'Value': self.gn_value
            }

        def get_value(self):
            return self.gn_value

    class CertificateExtension(object):
        """
        CertificateExtension class
        Defines an X509 Certificate Extensions used in Common.Certificate


        :type extension_type: ``str``
        :param extension_type: The type of Extension (from Common.CertificateExtension.ExtensionType enum, or "Other)

        :type critical: ``bool``
        :param critical: Whether the extension is marked as critical

        :type extension_name: ``Optional[str]``
        :param extension_name: Name of the extension

        :type oid: ``Optional[str]``
        :param oid: OID of the extension

        :type subject_alternative_names: ``Optional[List[Common.CertificateExtension.SubjectAlternativeName]]``
        :param subject_alternative_names: Subject Alternative Names

        :type authority_key_identifier: ``Optional[Common.CertificateExtension.AuthorityKeyIdentifier]``
        :param authority_key_identifier: Authority Key Identifier

        :type digest: ``Optional[str]``
        :param digest: digest for Subject Key Identifier extension

        :type digital_signature: ``Optional[bool]``
        :param digital_signature: Digital Signature usage for Key Usage extension

        :type content_commitment: ``Optional[bool]``
        :param content_commitment: Content Commitment usage for Key Usage extension

        :type key_encipherment: ``Optional[bool]``
        :param key_encipherment: Key Encipherment usage for Key Usage extension

        :type data_encipherment: ``Optional[bool]``
        :param data_encipherment: Data Encipherment usage for Key Usage extension

        :type key_agreement: ``Optional[bool]``
        :param key_agreement: Key Agreement usage for Key Usage extension

        :type key_cert_sign: ``Optional[bool]``
        :param key_cert_sign: Key Cert Sign usage for Key Usage extension

        :type usages: ``Optional[List[str]]``
        :param usages: Usages for Extended Key Usage extension

        :type distribution_points: ``Optional[List[Common.CertificateExtension.DistributionPoint]]``
        :param distribution_points: Distribution Points

        :type certificate_policies: ``Optional[List[Common.CertificateExtension.CertificatePolicy]]``
        :param certificate_policies: Certificate Policies

        :type authority_information_access: ``Optional[List[Common.CertificateExtension.AuthorityInformationAccess]]``
        :param authority_information_access: Authority Information Access

        :type basic_constraints: ``Optional[Common.CertificateExtension.BasicConstraints]``
        :param basic_constraints: Basic Constraints

        :type signed_certificate_timestamps: ``Optional[List[Common.CertificateExtension.SignedCertificateTimestamp]]``
        :param signed_certificate_timestamps: (PreCertificate)Signed Certificate Timestamps

        :type value: ``Optional[Union[str, List[Any], Dict[str, Any]]]``
        :param value: Raw value of the Extension (used for "Other" type)

        :return: None
        :rtype: ``None``
        """

        class SubjectAlternativeName(object):
            """
            SubjectAlternativeName class
            Implements Subject Alternative Name extension interface

            :type gn: ``Optional[Common.GeneralName]``
            :param gn: General Name Type provided as Common.GeneralName

            :type gn_type: ``Optional[str]``
            :param gn_type: General Name Type provided as string

            :type gn_value: ``Optional[str]``
            :param gn_value: General Name Value provided as string

            :return: None
            :rtype: ``None``
            """

            def __init__(
                self,
                gn=None,  # type: Optional[Common.GeneralName]
                gn_type=None,  # type: Optional[str]
                gn_value=None  # type: Optional[str]
            ):
                if gn:
                    self.gn = gn
                elif gn_type and gn_value:
                    self.gn = Common.GeneralName(
                        gn_value=gn_value,
                        gn_type=gn_type
                    )
                else:
                    raise ValueError('either GeneralName or gn_type/gn_value required to inizialize SubjectAlternativeName')

            def to_context(self):
                return self.gn.to_context()

            def get_value(self):
                return self.gn.get_value()

        class AuthorityKeyIdentifier(object):
            """
            AuthorityKeyIdentifier class
            Implements Authority Key Identifier extension interface

            :type issuer: ``Optional[List[Common.GeneralName]]``
            :param issuer: Issuer list

            :type serial_number: ``Optional[str]``
            :param serial_number: Serial Number

            :type key_identifier: ``Optional[str]``
            :param key_identifier: Key Identifier

            :return: None
            :rtype: ``None``
            """

            def __init__(
                self,
                issuer=None,  # type: Optional[List[Common.GeneralName]]
                serial_number=None,  # type: Optional[str]
                key_identifier=None  # type: Optional[str]
            ):
                self.issuer = issuer
                self.serial_number = serial_number
                self.key_identifier = key_identifier

            def to_context(self):
                authority_key_identifier_context = {}  # type: Dict[str, Any]

                if self.issuer:
                    authority_key_identifier_context['Issuer'] = self.issuer,

                if self.serial_number:
                    authority_key_identifier_context["SerialNumber"] = self.serial_number
                if self.key_identifier:
                    authority_key_identifier_context["KeyIdentifier"] = self.key_identifier

                return authority_key_identifier_context

        class DistributionPoint(object):
            """
            DistributionPoint class
            Implements Distribution Point extension interface

            :type full_name: ``Optional[List[Common.GeneralName]]``
            :param full_name: Full Name list

            :type relative_name: ``Optional[str]``
            :param relative_name: Relative Name

            :type crl_issuer: ``Optional[List[Common.GeneralName]]``
            :param crl_issuer: CRL Issuer

            :type reasons: ``Optional[List[str]]``
            :param reasons: Reason list

            :return: None
            :rtype: ``None``
            """

            def __init__(
                self,
                full_name=None,  # type: Optional[List[Common.GeneralName]]
                relative_name=None,  # type:  Optional[str]
                crl_issuer=None,  # type: Optional[List[Common.GeneralName]]
                reasons=None  # type: Optional[List[str]]
            ):
                self.full_name = full_name
                self.relative_name = relative_name
                self.crl_issuer = crl_issuer
                self.reasons = reasons

            def to_context(self):
                distribution_point_context = {}  # type: Dict[str, Union[List, str]]
                if self.full_name:
                    distribution_point_context["FullName"] = [fn.to_context() for fn in self.full_name]
                if self.relative_name:
                    distribution_point_context["RelativeName"] = self.relative_name
                if self.crl_issuer:
                    distribution_point_context["CRLIssuer"] = [ci.to_context() for ci in self.crl_issuer]
                if self.reasons:
                    distribution_point_context["Reasons"] = self.reasons

                return distribution_point_context

        class CertificatePolicy(object):
            """
            CertificatePolicy class
            Implements Certificate Policy extension interface

            :type policy_identifier: ``str``
            :param policy_identifier: Policy Identifier

            :type policy_qualifiers: ``Optional[List[str]]``
            :param policy_qualifiers: Policy Qualifier list

            :return: None
            :rtype: ``None``
            """

            def __init__(
                self,
                policy_identifier,  # type: str
                policy_qualifiers=None  # type: Optional[List[str]]
            ):
                self.policy_identifier = policy_identifier
                self.policy_qualifiers = policy_qualifiers

            def to_context(self):
                certificate_policies_context = {
                    "PolicyIdentifier": self.policy_identifier
                }  # type: Dict[str, Union[List, str]]

                if self.policy_qualifiers:
                    certificate_policies_context["PolicyQualifiers"] = self.policy_qualifiers

                return certificate_policies_context

        class AuthorityInformationAccess(object):
            """
            AuthorityInformationAccess class
            Implements Authority Information Access extension interface

            :type access_method: ``str``
            :param access_method: Access Method

            :type access_location: ``Common.GeneralName``
            :param access_location: Access Location

            :return: None
            :rtype: ``None``
            """

            def __init__(
                self,
                access_method,  # type: str
                access_location  # type: Common.GeneralName
            ):
                self.access_method = access_method
                self.access_location = access_location

            def to_context(self):
                return {
                    "AccessMethod": self.access_method,
                    "AccessLocation": self.access_location.to_context()
                }

        class BasicConstraints(object):
            """
            BasicConstraints class
            Implements Basic Constraints extension interface

            :type ca: ``bool``
            :param ca: Certificate Authority

            :type path_length: ``int``
            :param path_length: Path Length

            :return: None
            :rtype: ``None``
            """

            def __init__(
                self,
                ca,  # type: bool
                path_length=None  # type: int
            ):
                self.ca = ca
                self.path_length = path_length

            def to_context(self):
                basic_constraints_context = {
                    "CA": self.ca
                }  # type: Dict[str, Union[str, int]]

                if self.path_length:
                    basic_constraints_context["PathLength"] = self.path_length

                return basic_constraints_context

        class SignedCertificateTimestamp(object):
            """
            SignedCertificateTimestamp class
            Implementsinterface for  "SignedCertificateTimestamp" extensions

            :type entry_type: ``str``
            :param entry_type: Entry Type (from Common.CertificateExtension.SignedCertificateTimestamp.EntryType enum)

            :type version: ``str``
            :param version: Version

            :type log_id: ``str``
            :param log_id: Log ID

            :type timestamp: ``str``
            :param timestamp: Timestamp (ISO8601 string representation in UTC)

            :return: None
            :rtype: ``None``
            """

            class EntryType(object):
                """
                EntryType class
                Enumerates Entry Types for SignedCertificateTimestamp class

                :return: None
                :rtype: ``None``
                """
                PRECERTIFICATE = "PreCertificate"
                X509CERTIFICATE = "X509Certificate"

                @staticmethod
                def is_valid_type(_type):
                    return _type in (
                        Common.CertificateExtension.SignedCertificateTimestamp.EntryType.PRECERTIFICATE,
                        Common.CertificateExtension.SignedCertificateTimestamp.EntryType.X509CERTIFICATE
                    )

            def __init__(
                self,
                entry_type,  # type: str
                version,  # type: int
                log_id,  # type: str
                timestamp  # type: str
            ):
                if not Common.CertificateExtension.SignedCertificateTimestamp.EntryType.is_valid_type(entry_type):
                    raise TypeError(
                        'entry_type must be of type Common.CertificateExtension.SignedCertificateTimestamp.EntryType enum'
                    )

                self.entry_type = entry_type
                self.version = version
                self.log_id = log_id
                self.timestamp = timestamp

            def to_context(self):
                timestamps_context = {}  # type: Dict[str, Any]

                timestamps_context['Version'] = self.version
                timestamps_context["LogId"] = self.log_id
                timestamps_context["Timestamp"] = self.timestamp
                timestamps_context["EntryType"] = self.entry_type

                return timestamps_context

        class ExtensionType(object):
            """
            ExtensionType class
            Enumerates Extension Types for Common.CertificatExtension class

            :return: None
            :rtype: ``None``
            """
            SUBJECTALTERNATIVENAME = "SubjectAlternativeName"
            AUTHORITYKEYIDENTIFIER = "AuthorityKeyIdentifier"
            SUBJECTKEYIDENTIFIER = "SubjectKeyIdentifier"
            KEYUSAGE = "KeyUsage"
            EXTENDEDKEYUSAGE = "ExtendedKeyUsage"
            CRLDISTRIBUTIONPOINTS = "CRLDistributionPoints"
            CERTIFICATEPOLICIES = "CertificatePolicies"
            AUTHORITYINFORMATIONACCESS = "AuthorityInformationAccess"
            BASICCONSTRAINTS = "BasicConstraints"
            SIGNEDCERTIFICATETIMESTAMPS = "SignedCertificateTimestamps"
            PRESIGNEDCERTIFICATETIMESTAMPS = "PreCertSignedCertificateTimestamps"
            OTHER = "Other"

            @staticmethod
            def is_valid_type(_type):
                return _type in (
                    Common.CertificateExtension.ExtensionType.SUBJECTALTERNATIVENAME,
                    Common.CertificateExtension.ExtensionType.AUTHORITYKEYIDENTIFIER,
                    Common.CertificateExtension.ExtensionType.SUBJECTKEYIDENTIFIER,
                    Common.CertificateExtension.ExtensionType.KEYUSAGE,
                    Common.CertificateExtension.ExtensionType.EXTENDEDKEYUSAGE,
                    Common.CertificateExtension.ExtensionType.CRLDISTRIBUTIONPOINTS,
                    Common.CertificateExtension.ExtensionType.CERTIFICATEPOLICIES,
                    Common.CertificateExtension.ExtensionType.AUTHORITYINFORMATIONACCESS,
                    Common.CertificateExtension.ExtensionType.BASICCONSTRAINTS,
                    Common.CertificateExtension.ExtensionType.SIGNEDCERTIFICATETIMESTAMPS,
                    Common.CertificateExtension.ExtensionType.PRESIGNEDCERTIFICATETIMESTAMPS,
                    Common.CertificateExtension.ExtensionType.OTHER  # for extensions that are not handled explicitly
                )

        def __init__(
            self,
            extension_type,  # type: str
            critical,  # type: bool
            oid=None,  # type: Optional[str]
            extension_name=None,  # type: Optional[str]
            subject_alternative_names=None,  # type: Optional[List[Common.CertificateExtension.SubjectAlternativeName]]
            authority_key_identifier=None,  # type: Optional[Common.CertificateExtension.AuthorityKeyIdentifier]
            digest=None,  # type: str
            digital_signature=None,  # type: Optional[bool]
            content_commitment=None,  # type: Optional[bool]
            key_encipherment=None,  # type: Optional[bool]
            data_encipherment=None,  # type: Optional[bool]
            key_agreement=None,  # type: Optional[bool]
            key_cert_sign=None,  # type: Optional[bool]
            crl_sign=None,  # type: Optional[bool]
            usages=None,  # type: Optional[List[str]]
            distribution_points=None,  # type: Optional[List[Common.CertificateExtension.DistributionPoint]]
            certificate_policies=None,  # type: Optional[List[Common.CertificateExtension.CertificatePolicy]]
            authority_information_access=None,  # type: Optional[List[Common.CertificateExtension.AuthorityInformationAccess]]
            basic_constraints=None,  # type: Optional[Common.CertificateExtension.BasicConstraints]
            signed_certificate_timestamps=None,  # type: Optional[List[Common.CertificateExtension.SignedCertificateTimestamp]]
            value=None  # type: Optional[Union[str, List[Any], Dict[str, Any]]]
        ):
            if not Common.CertificateExtension.ExtensionType.is_valid_type(extension_type):
                raise TypeError('algorithm must be of type Common.CertificateExtension.ExtensionType enum')

            self.extension_type = extension_type
            self.critical = critical

            if self.extension_type == Common.CertificateExtension.ExtensionType.SUBJECTALTERNATIVENAME:
                self.subject_alternative_names = subject_alternative_names
                self.oid = "2.5.29.17"
                self.extension_name = "subjectAltName"

            elif self.extension_type == Common.CertificateExtension.ExtensionType.SUBJECTKEYIDENTIFIER:
                if not digest:
                    raise ValueError('digest is mandatory for SubjectKeyIdentifier extension')
                self.digest = digest
                self.oid = "2.5.29.14"
                self.extension_name = "subjectKeyIdentifier"

            elif self.extension_type == Common.CertificateExtension.ExtensionType.KEYUSAGE:
                self.digital_signature = digital_signature
                self.content_commitment = content_commitment
                self.key_encipherment = key_encipherment
                self.data_encipherment = data_encipherment
                self.key_agreement = key_agreement
                self.key_cert_sign = key_cert_sign
                self.crl_sign = crl_sign
                self.oid = "2.5.29.15"
                self.extension_name = "keyUsage"

            elif self.extension_type == Common.CertificateExtension.ExtensionType.EXTENDEDKEYUSAGE:
                if not usages:
                    raise ValueError('usages is mandatory for ExtendedKeyUsage extension')
                self.usages = usages
                self.oid = "2.5.29.37"
                self.extension_name = "extendedKeyUsage"

            elif self.extension_type == Common.CertificateExtension.ExtensionType.AUTHORITYKEYIDENTIFIER:
                self.authority_key_identifier = authority_key_identifier
                self.oid = "2.5.29.35"
                self.extension_name = "authorityKeyIdentifier"

            elif self.extension_type == Common.CertificateExtension.ExtensionType.CRLDISTRIBUTIONPOINTS:
                self.distribution_points = distribution_points
                self.oid = "2.5.29.31"
                self.extension_name = "cRLDistributionPoints"

            elif self.extension_type == Common.CertificateExtension.ExtensionType.CERTIFICATEPOLICIES:
                self.certificate_policies = certificate_policies
                self.oid = "2.5.29.32"
                self.extension_name = "certificatePolicies"

            elif self.extension_type == Common.CertificateExtension.ExtensionType.AUTHORITYINFORMATIONACCESS:
                self.authority_information_access = authority_information_access
                self.oid = "1.3.6.1.5.5.7.1.1"
                self.extension_name = "authorityInfoAccess"

            elif self.extension_type == Common.CertificateExtension.ExtensionType.BASICCONSTRAINTS:
                self.basic_constraints = basic_constraints
                self.oid = "2.5.29.19"
                self.extension_name = "basicConstraints"

            elif self.extension_type == Common.CertificateExtension.ExtensionType.PRESIGNEDCERTIFICATETIMESTAMPS:
                self.signed_certificate_timestamps = signed_certificate_timestamps
                self.oid = "1.3.6.1.4.1.11129.2.4.2"
                self.extension_name = "signedCertificateTimestampList"

            elif self.extension_type == Common.CertificateExtension.ExtensionType.SIGNEDCERTIFICATETIMESTAMPS:
                self.signed_certificate_timestamps = signed_certificate_timestamps
                self.oid = "1.3.6.1.4.1.11129.2.4.5"
                self.extension_name = "signedCertificateTimestampList"

            elif self.extension_type == Common.CertificateExtension.ExtensionType.OTHER:
                self.value = value

            # override oid, extension_name if provided as inputs
            if oid:
                self.oid = oid
            if extension_name:
                self.extension_name = extension_name

        def to_context(self):
            extension_context = {
                "OID": self.oid,
                "Name": self.extension_name,
                "Critical": self.critical
            }  # type: Dict[str, Any]

            if (
                self.extension_type == Common.CertificateExtension.ExtensionType.SUBJECTALTERNATIVENAME
                and self.subject_alternative_names is not None
            ):
                extension_context["Value"] = [san.to_context() for san in self.subject_alternative_names]

            elif (
                self.extension_type == Common.CertificateExtension.ExtensionType.AUTHORITYKEYIDENTIFIER
                and self.authority_key_identifier is not None
            ):
                extension_context["Value"] = self.authority_key_identifier.to_context()

            elif (
                self.extension_type == Common.CertificateExtension.ExtensionType.SUBJECTKEYIDENTIFIER
                and self.digest is not None
            ):
                extension_context["Value"] = {
                    "Digest": self.digest
                }

            elif self.extension_type == Common.CertificateExtension.ExtensionType.KEYUSAGE:
                key_usage = {}  # type: Dict[str, bool]
                if self.digital_signature:
                    key_usage["DigitalSignature"] = self.digital_signature
                if self.content_commitment:
                    key_usage["ContentCommitment"] = self.content_commitment
                if self.key_encipherment:
                    key_usage["KeyEncipherment"] = self.key_encipherment
                if self.data_encipherment:
                    key_usage["DataEncipherment"] = self.data_encipherment
                if self.key_agreement:
                    key_usage["KeyAgreement"] = self.key_agreement
                if self.key_cert_sign:
                    key_usage["KeyCertSign"] = self.key_cert_sign
                if self.crl_sign:
                    key_usage["CrlSign"] = self.crl_sign

                if key_usage:
                    extension_context["Value"] = key_usage

            elif (
                self.extension_type == Common.CertificateExtension.ExtensionType.EXTENDEDKEYUSAGE
                and self.usages is not None
            ):
                extension_context["Value"] = {
                    "Usages": [u for u in self.usages]
                }

            elif (
                self.extension_type == Common.CertificateExtension.ExtensionType.CRLDISTRIBUTIONPOINTS
                and self.distribution_points is not None
            ):
                extension_context["Value"] = [dp.to_context() for dp in self.distribution_points]

            elif (
                self.extension_type == Common.CertificateExtension.ExtensionType.CERTIFICATEPOLICIES
                and self.certificate_policies is not None
            ):
                extension_context["Value"] = [cp.to_context() for cp in self.certificate_policies]

            elif (
                self.extension_type == Common.CertificateExtension.ExtensionType.AUTHORITYINFORMATIONACCESS
                and self.authority_information_access is not None
            ):
                extension_context["Value"] = [aia.to_context() for aia in self.authority_information_access]

            elif (
                self.extension_type == Common.CertificateExtension.ExtensionType.BASICCONSTRAINTS
                and self.basic_constraints is not None
            ):
                extension_context["Value"] = self.basic_constraints.to_context()

            elif (
                self.extension_type in [
                    Common.CertificateExtension.ExtensionType.SIGNEDCERTIFICATETIMESTAMPS,
                    Common.CertificateExtension.ExtensionType.PRESIGNEDCERTIFICATETIMESTAMPS
                ]
                and self.signed_certificate_timestamps is not None
            ):
                extension_context["Value"] = [sct.to_context() for sct in self.signed_certificate_timestamps]

            elif (
                self.extension_type == Common.CertificateExtension.ExtensionType.OTHER
                and self.value is not None
            ):
                extension_context["Value"] = self.value

            return extension_context

    class Certificate(Indicator):
        """
        Implements the X509 Certificate interface
        Certificate indicator - https://xsoar.pan.dev/docs/integrations/context-standards-mandatory#certificate

        :type subject_dn: ``str``
        :param subject_dn: Subject Distinguished Name

        :type dbot_score: ``DBotScore``
        :param dbot_score: If Certificate has a score then create and set a DBotScore object.

        :type name: ``Optional[Union[str, List[str]]]``
        :param name: Name (if not provided output is calculated from SubjectDN and SAN)

        :type issuer_dn: ``Optional[str]``
        :param issuer_dn: Issuer Distinguished Name

        :type serial_number: ``Optional[str]``
        :param serial_number: Serial Number

        :type validity_not_after: ``Optional[str]``
        :param validity_not_after: Certificate Expiration Timestamp (ISO8601 string representation)

        :type validity_not_before: ``Optional[str]``
        :param validity_not_before: Initial Certificate Validity Timestamp (ISO8601 string representation)

        :type sha512: ``Optional[str]``
        :param sha512: The SHA-512 hash of the certificate in binary encoded format (DER)

        :type sha256: ``Optional[str]``
        :param sha256: The SHA-256 hash of the certificate in binary encoded format (DER)

        :type sha1: ``Optional[str]``
        :param sha1: The SHA-1 hash of the certificate in binary encoded format (DER)

        :type md5: ``Optional[str]``
        :param md5: The MD5 hash of the certificate in binary encoded format (DER)

        :type publickey: ``Optional[Common.CertificatePublicKey]``
        :param publickey: Certificate Public Key

        :type spki_sha256: ``Optional[str]``
        :param sha1: The SHA-256 hash of the SPKI

        :type signature_algorithm: ``Optional[str]``
        :param signature_algorithm: Signature Algorithm

        :type signature: ``Optional[str]``
        :param signature: Certificate Signature

        :type subject_alternative_name: \
        ``Optional[List[Union[str,Dict[str, str],Common.CertificateExtension.SubjectAlternativeName]]]``
        :param subject_alternative_name: Subject Alternative Name list

        :type extensions: ``Optional[List[Common.CertificateExtension]]`
        :param extensions: Certificate Extension List

        :type pem: ``Optional[str]``
        :param pem: PEM encoded certificate

        :return: None
        :rtype: ``None``
        """
        CONTEXT_PATH = 'Certificate(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || ' \
                       'val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512)'

        def __init__(
            self,
            subject_dn,  # type: str
            dbot_score=None,  # type: Optional[Common.DBotScore]
            name=None,  # type: Optional[Union[str, List[str]]]
            issuer_dn=None,  # type: Optional[str]
            serial_number=None,  # type: Optional[str]
            validity_not_after=None,  # type: Optional[str]
            validity_not_before=None,  # type: Optional[str]
            sha512=None,  # type: Optional[str]
            sha256=None,  # type: Optional[str]
            sha1=None,  # type: Optional[str]
            md5=None,  # type: Optional[str]
            publickey=None,  # type: Optional[Common.CertificatePublicKey]
            spki_sha256=None,  # type: Optional[str]
            signature_algorithm=None,  # type: Optional[str]
            signature=None,  # type: Optional[str]
            subject_alternative_name=None, \
            # type: Optional[List[Union[str,Dict[str, str],Common.CertificateExtension.SubjectAlternativeName]]]
            extensions=None,  # type: Optional[List[Common.CertificateExtension]]
            pem=None  # type: Optional[str]

        ):

            self.subject_dn = subject_dn
            self.dbot_score = dbot_score

            self.name = None
            if name:
                if isinstance(name, str):
                    self.name = [name]
                elif isinstance(name, list):
                    self.name = name
                else:
                    raise TypeError('certificate name must be of type str or List[str]')

            self.issuer_dn = issuer_dn
            self.serial_number = serial_number
            self.validity_not_after = validity_not_after
            self.validity_not_before = validity_not_before

            self.sha512 = sha512
            self.sha256 = sha256
            self.sha1 = sha1
            self.md5 = md5

            if publickey and not isinstance(publickey, Common.CertificatePublicKey):
                raise TypeError('publickey must be of type Common.CertificatePublicKey')
            self.publickey = publickey

            self.spki_sha256 = spki_sha256

            self.signature_algorithm = signature_algorithm
            self.signature = signature

            # if subject_alternative_name is set and is a list
            # make sure it is a list of strings, dicts of strings or SAN Extensions
            if (
                subject_alternative_name
                and isinstance(subject_alternative_name, list)
                and not all(
                    isinstance(san, str)
                    or isinstance(san, dict)
                    or isinstance(san, Common.CertificateExtension.SubjectAlternativeName)
                    for san in subject_alternative_name)
            ):
                raise TypeError(
                    'subject_alternative_name must be list of str or Common.CertificateExtension.SubjectAlternativeName'
                )
            self.subject_alternative_name = subject_alternative_name

            if (
                extensions
                and not isinstance(extensions, list)
                and any(isinstance(e, Common.CertificateExtension) for e in extensions)  # type: ignore
            ):
                raise TypeError('extensions must be of type List[Common.CertificateExtension]')
            self.extensions = extensions

            self.pem = pem

            if not isinstance(dbot_score, Common.DBotScore):
                raise ValueError('dbot_score must be of type DBotScore')

        def to_context(self):
            certificate_context = {
                "SubjectDN": self.subject_dn
            }  # type: Dict[str, Any]

            san_list = []  # type: List[Dict[str, str]]
            if self.subject_alternative_name:
                for san in self.subject_alternative_name:
                    if isinstance(san, str):
                        san_list.append({
                            'Value': san
                        })
                    elif isinstance(san, dict):
                        san_list.append(san)
                    elif (isinstance(san, Common.CertificateExtension.SubjectAlternativeName)):
                        san_list.append(san.to_context())

            elif self.extensions:  # autogenerate it from extensions
                for ext in self.extensions:
                    if (
                        ext.extension_type == Common.CertificateExtension.ExtensionType.SUBJECTALTERNATIVENAME
                        and ext.subject_alternative_names is not None
                    ):
                        for san in ext.subject_alternative_names:
                            san_list.append(san.to_context())

            if san_list:
                certificate_context['SubjectAlternativeName'] = san_list

            if self.name:
                certificate_context["Name"] = self.name
            else:  # autogenerate it
                name = set()  # type: Set[str]
                # add subject alternative names
                if san_list:
                    name = set([
                        sn['Value'] for sn in san_list
                        if (
                            'Value' in sn
                            and (
                                'Type' not in sn
                                or sn['Type'] in (Common.GeneralName.DNSNAME, Common.GeneralName.IPADDRESS)
                            )
                        )
                    ])

                # subject_dn is RFC4515 escaped
                # replace \, and \+ with the long escaping \2c and \2b
                long_escaped_subject_dn = self.subject_dn.replace("\\,", "\\2c")
                long_escaped_subject_dn = long_escaped_subject_dn.replace("\\+", "\\2b")
                # we then split RDN (separated by ,) and multi-valued RDN (sep by +)
                rdns = long_escaped_subject_dn.replace('+', ',').split(',')
                cn = next((rdn for rdn in rdns if rdn.startswith('CN=')), None)
                if cn:
                    name.add(cn.split('=', 1)[-1])

                if name:
                    certificate_context["Name"] = sorted(list(name))

            if self.issuer_dn:
                certificate_context["IssuerDN"] = self.issuer_dn

            if self.serial_number:
                certificate_context["SerialNumber"] = self.serial_number

            if self.validity_not_before:
                certificate_context["ValidityNotBefore"] = self.validity_not_before

            if self.validity_not_after:
                certificate_context["ValidityNotAfter"] = self.validity_not_after

            if self.sha512:
                certificate_context["SHA512"] = self.sha512

            if self.sha256:
                certificate_context["SHA256"] = self.sha256

            if self.sha1:
                certificate_context["SHA1"] = self.sha1

            if self.md5:
                certificate_context["MD5"] = self.md5

            if self.publickey and isinstance(self.publickey, Common.CertificatePublicKey):
                certificate_context["PublicKey"] = self.publickey.to_context()

            if self.spki_sha256:
                certificate_context["SPKISHA256"] = self.spki_sha256

            sig = {}  # type: Dict[str, str]
            if self.signature_algorithm:
                sig["Algorithm"] = self.signature_algorithm
            if self.signature:
                sig["Signature"] = self.signature
            if sig:
                certificate_context["Signature"] = sig

            if self.extensions:
                certificate_context["Extension"] = [e.to_context() for e in self.extensions]

            if self.pem:
                certificate_context["PEM"] = self.pem

            if self.dbot_score and self.dbot_score.score == Common.DBotScore.BAD:
                certificate_context['Malicious'] = {
                    'Vendor': self.dbot_score.integration_name,
                    'Description': self.dbot_score.malicious_description
                }

            ret_value = {
                Common.Certificate.CONTEXT_PATH: certificate_context
            }

            if self.dbot_score:
                ret_value.update(self.dbot_score.to_context())

            return ret_value

    class Tactic(Indicator):
        """
        Tactic indicator

        :type stix_id: ``str``
        :param stix_id: The Tactic STIX ID

        :type first_seen_by_source: ``str``
        :param first_seen_by_source: The Tactic first seen by source

        :type description: ``str``
        :param description: The Tactic description

        :type publications: ``str``
        :param publications: The Tactic publications

        :type mitre_id: ``str``
        :param mitre_id: The Tactic mitre id.

        :type tags: ``str``
        :param tags: The Tactic tags.

        :type dbot_score: ``DBotScore``
        :param dbot_score:  If the address has reputation then create DBotScore object.

        :type traffic_light_protocol: ``str``
        :param traffic_light_protocol: The Traffic Light Protocol (TLP) color that is suitable for the Tactic.

        :type community_notes: ``CommunityNotes``
        :param community_notes:  A list of community notes for the Tactic.

        :type external_references: ``ExternalReference``
        :param external_references:  A list of id's and description of the Tactic via external refs.

        :type value: ``str``
        :param value: The Tactic value (name) - example: "Plist File Modification"

        :return: None
        :rtype: ``None``
        """
        CONTEXT_PATH = 'Tactic(val.Name && val.Name == obj.Name)'

        def __init__(self, stix_id, first_seen_by_source=None, description=None, publications=None, mitre_id=None, tags=None,
                     traffic_light_protocol=None, dbot_score=None, community_notes=None, external_references=None, value=None):

            self.community_notes = community_notes
            self.description = description
            self.external_references = external_references
            self.first_seen_by_source = first_seen_by_source
            self.mitre_id = mitre_id
            self.publications = publications
            self.stix_id = stix_id
            self.tags = tags
            self.traffic_light_protocol = traffic_light_protocol
            self.value = value
            self.dbot_score = dbot_score

        def to_context(self):
            attack_pattern_context = {
                'STIXID': self.stix_id,
                "FirstSeenBySource": self.first_seen_by_source,
                "Publications": self.publications,
                "MITREID": self.mitre_id,
                "Value": self.value,
                "Tags": self.tags,
                "Description": self.description
            }

            if self.external_references:
                attack_pattern_context['ExternalReferences'] = self.create_context_table(self.external_references)

            if self.traffic_light_protocol:
                attack_pattern_context['TrafficLightProtocol'] = self.traffic_light_protocol

            if self.dbot_score and self.dbot_score.score == Common.DBotScore.BAD:
                attack_pattern_context['Malicious'] = {
                    'Vendor': self.dbot_score.integration_name,
                    'Description': self.dbot_score.malicious_description
                }

            ret_value = {
                Common.AttackPattern.CONTEXT_PATH: attack_pattern_context
            }

            if self.dbot_score:
                ret_value.update(self.dbot_score.to_context())

            return ret_value


class ScheduledCommand:
    """
    ScheduledCommand configuration class
    Holds the scheduled command configuration for the command result - managing the way the command should be polled.

    :type command: ``str``
    :param command: The command that'll run after next_run_in_seconds has passed.

    :type next_run_in_seconds: ``int``
    :param next_run_in_seconds: How long to wait before executing the command.

    :type args: ``Optional[Dict[str, Any]]``
    :param args: Arguments to use when executing the command.

    :type timeout_in_seconds: ``Optional[int]``
    :param timeout_in_seconds: Number of seconds until the polling sequence will timeout.

    :type items_remaining: ``Optional[int]``
    :param items_remaining: Number of items that are remaining to be polled.

    :return: None
    :rtype: ``None``
    """
    VERSION_MISMATCH_ERROR = 'This command is not supported by this XSOAR server version. Please update your server ' \
                             'version to 6.2.0 or later.'

    def __init__(
        self,
        command,  # type: str
        next_run_in_seconds,  # type: int
        args=None,  # type: Optional[Dict[str, Any]]
        timeout_in_seconds=None,  # type: Optional[int]
        items_remaining=0,  # type: Optional[int]
    ):
        self.raise_error_if_not_supported()
        self._command = command
        if next_run_in_seconds < 10:
            demisto.info('ScheduledCommandConfiguration provided value for next_run_in_seconds: '
                         '{} is '.format(next_run_in_seconds) + 'too low - minimum interval is 10 seconds. '
                                                                'next_run_in_seconds was set to 10 seconds.')
            next_run_in_seconds = 10
        self._next_run = str(next_run_in_seconds)
        self._args = args
        self._timeout = str(timeout_in_seconds) if timeout_in_seconds else None
        self._items_remaining = items_remaining

    @staticmethod
    def raise_error_if_not_supported():
        return True

    @staticmethod
    def supports_polling():
        """
        Check if the integration supports polling (if server version is greater than 6.2.0).
        Returns: Boolean
        """
        return True

    def to_results(self):
        """
        Returns the result dictionary of the polling command
        """
        return assign_params(
            PollingCommand=self._command,
            NextRun=self._next_run,
            PollingArgs=self._args,
            Timeout=self._timeout,
            PollingItemsRemaining=self._items_remaining
        )


def camelize_string(src_str, delim='_', upper_camel=True):
    """
    Transform snake_case to CamelCase

    :type src_str: ``str``
    :param src_str: snake_case string to convert.

    :type delim: ``str``
    :param delim: indicator category.

    :type upper_camel: ``bool``
    :param upper_camel: When True then transforms string to camel case with the first letter capitalised
                        (for example: demisto_content to DemistoContent), otherwise the first letter will not be capitalised
                        (for example: demisto_content to demistoContent).

    :return: A CammelCase string.
    :rtype: ``str``
    """
    if not src_str:  # empty string
        return ""
    components = src_str.split(delim)
    camelize_without_first_char = ''.join(map(lambda x: x.title(), components[1:]))
    if upper_camel:
        return components[0].title() + camelize_without_first_char
    else:
        return components[0].lower() + camelize_without_first_char


class IndicatorsTimeline:
    """
    IndicatorsTimeline class - use to return Indicator Timeline object to be used in CommandResults

    :type indicators: ``list``
    :param indicators: expects a list of indicators.

    :type category: ``str``
    :param category: indicator category.

    :type message: ``str``
    :param message: indicator message.

    :return: None
    :rtype: ``None``
    """

    def __init__(self, indicators=None, category=None, message=None):
        # type: (list, str, str) -> None
        if indicators is None:
            indicators = []

        # check if we are running from an integration or automation
        try:
            _ = demisto.params()
            default_category = 'Integration Update'
        except AttributeError:
            default_category = 'Automation Update'

        timelines = []
        timeline = {}
        for indicator in indicators:
            timeline['Value'] = indicator

            if category:
                timeline['Category'] = category
            else:
                timeline['Category'] = default_category

            if message:
                timeline['Message'] = message

            timelines.append(timeline)

        self.indicators_timeline = timelines


def arg_to_number(arg, arg_name=None, required=False):
    # type: (Any, Optional[str], bool) -> Optional[int]
    """Converts an XSOAR argument to a Python int

    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` type. It will throw a ValueError
    if the input is invalid. If the input is None, it will throw a ValueError
    if required is ``True``, or ``None`` if required is ``False.

    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None

    :return:
        returns an ``int`` if arg can be converted
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[int]``
    """

    if arg is None or arg == '':
        if required is True:
            if arg_name:
                raise ValueError('Missing "{}"'.format(arg_name))
            else:
                raise ValueError('Missing required argument')

        return None

    arg = encode_string_results(arg)

    if isinstance(arg, str):
        if arg.isdigit():
            return int(arg)

        try:
            return int(float(arg))
        except Exception:
            if arg_name:
                raise ValueError('Invalid number: "{}"="{}"'.format(arg_name, arg))
            else:
                raise ValueError('"{}" is not a valid number'.format(arg))
    if isinstance(arg, int):
        return arg

    if arg_name:
        raise ValueError('Invalid number: "{}"="{}"'.format(arg_name, arg))
    else:
        raise ValueError('"{}" is not a valid number'.format(arg))


def arg_to_datetime(arg, arg_name=None, is_utc=True, required=False, settings=None):
    # type: (Any, Optional[str], bool, bool, dict) -> Optional[datetime]
    """Converts an XSOAR argument to a datetime

    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``datetime``. It will throw a ValueError if the input is invalid.
    If the input is None, it will throw a ValueError if required is ``True``,
    or ``None`` if required is ``False.

    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type is_utc: ``bool``
    :param is_utc: if True then date converted as utc timezone, otherwise will convert with local timezone.

    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None

    :type settings: ``dict``
    :param settings: If provided, passed to dateparser.parse function.

    :return:
        returns an ``datetime`` if conversion works
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[datetime]``
    """

    if arg is None:
        if required is True:
            if arg_name:
                raise ValueError('Missing "{}"'.format(arg_name))
            else:
                raise ValueError('Missing required argument')
        return None

    if isinstance(arg, str) and arg.isdigit() or isinstance(arg, (int, float)):
        # timestamp is a str containing digits - we just convert it to int
        ms = float(arg)
        if ms > 2000000000.0:
            # in case timestamp was provided as unix time (in milliseconds)
            ms = ms / 1000.0

        if is_utc:
            return datetime.fromtimestamp(ms, tz=timezone.utc)
        else:
            return datetime.fromtimestamp(ms)
    if isinstance(arg, str):
        # we use dateparser to handle strings either in ISO8601 format, or
        # relative time stamps.
        # For example: format 2019-10-23T00:00:00 or "3 days", etc
        if settings:
            date = dateparser.parse(arg, settings=settings)  # type: ignore[arg-type]
        else:
            date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})

        if date is None:
            # if d is None it means dateparser failed to parse it
            if arg_name:
                raise ValueError('Invalid date: "{}"="{}"'.format(arg_name, arg))
            else:
                raise ValueError('"{}" is not a valid date'.format(arg))

        return date

    if arg_name:
        raise ValueError('Invalid date: "{}"="{}"'.format(arg_name, arg))
    else:
        raise ValueError('"{}" is not a valid date'.format(arg))


# -------------------------------- Relationships----------------------------------- #


class EntityRelationship:
    """
    XSOAR entity relationship.

    :type name: ``str``
    :param name: Relationship name.

    :type relationship_type: ``str``
    :param relationship_type: Relationship type. (e.g. IndicatorToIndicator...).

    :type entity_a: ``str``
    :param entity_a: A value, A aka source of the relationship.

    :type entity_a_family: ``str``
    :param entity_a_family: Entity family of A, A aka source of the relationship. (e.g. Indicator...)

    :type entity_a_type: ``str``
    :param entity_a_type: Entity A type, A aka source of the relationship. (e.g. IP/URL/...).

    :type entity_b: ``str``
    :param entity_b: B value, B aka destination of the relationship.

    :type entity_b_family: ``str``
    :param entity_b_family: Entity family of B, B aka destination of the relationship. (e.g. Indicator...)

    :type entity_b_type: ``str``
    :param entity_b_type: Entity B type, B aka destination of the relationship. (e.g. IP/URL/...).

    :type source_reliability: ``str``
    :param source_reliability: Source reliability.

    :type fields: ``dict``
    :param fields: Custom fields. (Optional)

    :type brand: ``str``
    :param brand: Source brand name. (Optional)

    :return: None
    :rtype: ``None``
    """

    class RelationshipsTypes(object):
        """
        Relationships Types objects.

        :return: None
        :rtype: ``None``
        """
        # dict which keys is a relationship type and the value is the reverse type.
        RELATIONSHIP_TYPES = ['IndicatorToIndicator']

        @staticmethod
        def is_valid_type(_type):
            # type: (str) -> bool

            return _type in EntityRelationship.RelationshipsTypes.RELATIONSHIP_TYPES

    class RelationshipsFamily(object):
        """
        Relationships Family object list.

        :return: None
        :rtype: ``None``

        """

        INDICATOR = ["Indicator"]

        @staticmethod
        def is_valid_type(_type):
            # type: (str) -> bool

            return _type in EntityRelationship.RelationshipsFamily.INDICATOR

    class Relationships(object):

        """
        Enum: Relations names and their reverse

        :return: None
        :rtype: ``None``
        """
        APPLIED = 'applied'
        ATTACHMENT_OF = 'attachment-of'
        ATTACHES = 'attaches'
        ATTRIBUTE_OF = 'attribute-of'
        ATTRIBUTED_BY = 'attributed-by'
        ATTRIBUTED_TO = 'attributed-to'
        AUTHORED_BY = 'authored-by'
        BEACONS_TO = 'beacons-to'
        BUNDLED_IN = 'bundled-in'
        BUNDLES = 'bundles'
        COMMUNICATED_WITH = 'communicated-with'
        COMMUNICATED_BY = 'communicated-by'
        COMMUNICATES_WITH = 'communicates-with'
        COMPROMISES = 'compromises'
        CONTAINS = 'contains'
        CONTROLS = 'controls'
        CREATED_BY = 'created-by'
        CREATES = 'creates'
        DELIVERED_BY = 'delivered-by'
        DELIVERS = 'delivers'
        DETECTS = 'detects'
        DETECTED_BY = 'detected-by'
        DOWNLOADS = 'downloads'
        DOWNLOADS_FROM = 'downloads-from'
        DROPPED_BY = 'dropped-by'
        DROPS = 'drops'
        DUPLICATE_OF = 'duplicate-of'
        EMBEDDED_IN = 'embedded-in'
        EMBEDS = 'embeds'
        EXECUTED = 'executed'
        EXECUTED_BY = 'executed-by'
        EXFILTRATES_TO = 'exfiltrates-to'
        EXPLOITS = 'exploits'
        HAS = 'has'
        HOSTED_ON = 'hosted-on'
        HOSTS = 'hosts'
        IMPERSONATES = 'impersonates'
        INDICATED_BY = 'indicated-by'
        INDICATOR_OF = 'indicator-of'
        INJECTED_FROM = 'injected-from'
        INJECTS_INTO = 'injects-into'
        INVESTIGATES = 'investigates'
        IS_ALSO = 'is-also'
        LOCATED_AT = 'located-at'
        MITIGATED_BY = 'mitigated-by'
        MITIGATES = 'mitigates'
        ORIGINATED_FROM = 'originated-from'
        OWNED_BY = 'owned-by'
        OWNS = 'owns'
        PART_OF = 'part-of'
        RELATED_TO = 'related-to'
        REMEDIATES = 'remediates'
        RESOLVED_BY = 'resolved-by'
        RESOLVED_FROM = 'resolved-from'
        RESOLVES_TO = 'resolves-to'
        SEEN_ON = 'seen-on'
        SENT = 'sent'
        SENT_BY = 'sent-by'
        SENT_FROM = 'sent-from'
        SENT_TO = 'sent-to'
        SIMILAR_TO = 'similar-to'
        SUB_DOMAIN_OF = 'sub-domain-of'
        SUB_TECHNIQUE_OF = 'subtechnique-of'
        PARENT_TECHNIQUE_OF = 'parent-technique-of'
        SUPRA_DOMAIN_OF = 'supra-domain-of'
        TARGETED_BY = 'targeted-by'
        TARGETS = 'targets'
        TYPES = 'Types'
        UPLOADED_TO = 'uploaded-to'
        USED_BY = 'used-by'
        USED_ON = 'used-on'
        USES = 'uses'
        VARIANT_OF = 'variant-of'

        RELATIONSHIPS_NAMES = {'applied': 'applied-on',
                               'attachment-of': 'attaches',
                               'attaches': 'attachment-of',
                               'attribute-of': 'owns',
                               'attributed-by': 'attributed-to',
                               'attributed-to': 'attributed-by',
                               'authored-by': 'author-of',
                               'beacons-to': 'communicated-by',
                               'bundled-in': 'bundles',
                               'bundles': 'bundled-in',
                               'communicated-with': 'communicated-by',
                               'communicated-by': 'communicates-with',
                               'communicates-with': 'communicated-by',
                               'compromises': 'compromised-by',
                               'contains': 'part-of',
                               'controls': 'controlled-by',
                               'created-by': 'creates',
                               'creates': 'created-by',
                               'delivered-by': 'delivers',
                               'delivers': 'delivered-by',
                               'detects': 'detected-by',
                               'detected-by': 'detects',
                               'downloads': 'downloaded-by',
                               'downloads-from': 'hosts',
                               'dropped-by': 'drops',
                               'drops': 'dropped-by',
                               'duplicate-of': 'duplicate-of',
                               'embedded-in': 'embeds',
                               'embeds': 'embedded-on',
                               'executed': 'executed-by',
                               'executed-by': 'executes',
                               'exfiltrates-to': 'exfiltrated-from',
                               'exploits': 'exploited-by',
                               'has': 'seen-on',
                               'hosted-on': 'hosts',
                               'hosts': 'hosted-on',
                               'impersonates': 'impersonated-by',
                               'indicated-by': 'indicator-of',
                               'indicator-of': 'indicated-by',
                               'injected-from': 'injects-into',
                               'injects-into': 'injected-from',
                               'investigates': 'investigated-by',
                               'is-also': 'is-also',
                               'mitigated-by': 'mitigates',
                               'mitigates': 'mitigated-by',
                               'originated-from': 'source-of',
                               'owned-by': 'owns',
                               'owns': 'owned-by',
                               'part-of': 'contains',
                               'related-to': 'related-to',
                               'remediates': 'remediated-by',
                               'resolved-by': 'resolves-to',
                               'resolved-from': 'resolves-to',
                               'resolves-to': 'resolved-from',
                               'seen-on': 'has',
                               'sent': 'attached-to',
                               'sent-by': 'sent',
                               'sent-from': 'received-by',
                               'sent-to': 'received-by',
                               'similar-to': 'similar-to',
                               'sub-domain-of': 'supra-domain-of',
                               'supra-domain-of': 'sub-domain-of',
                               'subtechnique-of': 'parent-technique-of',
                               'parent-technique-of': 'subtechnique-of',
                               'targeted-by': 'targets',
                               'targets': 'targeted-by',
                               'Types': 'Reverse',
                               'uploaded-to': 'hosts',
                               'used-by': 'uses',
                               'used-on': 'targeted-by',
                               'uses': 'used-by',
                               'variant-of': 'variant-of'}

        @staticmethod
        def is_valid(_type):
            """
            :type _type: ``str``
            :param _type: the data to be returned and will be set to context

            :return: Is the given type supported
            :rtype: ``bool``
            """
            return _type in EntityRelationship.Relationships.RELATIONSHIPS_NAMES.keys()

        @staticmethod
        def get_reverse(name):
            """
            :type name: ``str``
            :param name: Relationship name

            :return: Returns the reversed relationship name
            :rtype: ``str``
            """
            try:
                return EntityRelationship.Relationships.RELATIONSHIPS_NAMES[name]
            except KeyError:
                demisto.debug('Cannot find a reverse name for relationship name, using "related-to" instead.')
                return EntityRelationship.Relationships.RELATED_TO

    def __init__(self, name, entity_a, entity_a_type, entity_b, entity_b_type,
                 reverse_name='', relationship_type='IndicatorToIndicator', entity_a_family='Indicator',
                 entity_b_family='Indicator', source_reliability="", fields=None, brand=""):

        # Relationship
        if not EntityRelationship.Relationships.is_valid(name):
            demisto.debug("Unknown relationship name: " + name)
        self._name = name

        if reverse_name:
            if not EntityRelationship.Relationships.is_valid(reverse_name):
                demisto.debug("Unknown reverse relationship name: " + reverse_name)
            self._reverse_name = reverse_name
        else:
            self._reverse_name = EntityRelationship.Relationships.get_reverse(name)

        if not EntityRelationship.RelationshipsTypes.is_valid_type(relationship_type):
            raise ValueError("Invalid relationship type: " + relationship_type)
        self._relationship_type = relationship_type

        # Entity A - Source
        self._entity_a = entity_a

        self._entity_a_type = entity_a_type

        if not EntityRelationship.RelationshipsFamily.is_valid_type(entity_a_family):
            raise ValueError("Invalid entity A Family type: " + entity_a_family)
        self._entity_a_family = entity_a_family

        # Entity B - Destination
        if not entity_b:
            demisto.info(
                "WARNING: Invalid entity B - Relationships will not be created to entity A {} with relationship name {}".format(
                    str(entity_a), str(name)))
        self._entity_b = entity_b

        self._entity_b_type = entity_b_type

        if not EntityRelationship.RelationshipsFamily.is_valid_type(entity_b_family):
            raise ValueError("Invalid entity B Family type: " + entity_b_family)
        self._entity_b_family = entity_b_family

        # Custom fields
        if fields:
            self._fields = fields
        else:
            self._fields = {}

        # Source
        if brand:
            self._brand = brand
        else:
            self._brand = ''

        if source_reliability:
            if not DBotScoreReliability.is_valid_type(source_reliability):
                raise ValueError("Invalid source reliability value", source_reliability)
            self._source_reliability = source_reliability
        else:
            self._source_reliability = ''

    def to_entry(self):
        """ Convert object to XSOAR entry
        :return: XSOAR entry representation.
        :rtype: ``dict``
        """
        entry = {}

        if self._entity_b:
            entry = {
                "name": self._name,
                "reverseName": self._reverse_name,
                "type": self._relationship_type,
                "entityA": self._entity_a,
                "entityAFamily": self._entity_a_family,
                "entityAType": self._entity_a_type,
                "entityB": self._entity_b,
                "entityBFamily": self._entity_b_family,
                "entityBType": self._entity_b_type,
                "fields": self._fields,
            }
            if self._source_reliability:
                entry["reliability"] = self._source_reliability
            if self._brand:
                entry["brand"] = self._brand
        return entry

    def to_indicator(self):
        """ Convert object to XSOAR entry
        :return: XSOAR entry representation.
        :rtype: ``dict``
        """
        indicator_relationship = {}

        if self._entity_b:
            indicator_relationship = {
                "name": self._name,
                "reverseName": self._reverse_name,
                "type": self._relationship_type,
                "entityA": self._entity_a,
                "entityAFamily": self._entity_a_family,
                "entityAType": self._entity_a_type,
                "entityB": self._entity_b,
                "entityBFamily": self._entity_b_family,
                "entityBType": self._entity_b_type,
                "fields": self._fields,
            }
        return indicator_relationship

    def to_context(self):
        """ Convert object to XSOAR context
        :return: XSOAR context representation.
        :rtype: ``dict``
        """
        indicator_relationship_context = {}

        if self._entity_b:
            indicator_relationship_context = {
                "Relationship": self._name,
                "EntityA": self._entity_a,
                "EntityAType": self._entity_a_type,
                "EntityB": self._entity_b,
                "EntityBType": self._entity_b_type,
            }

        return indicator_relationship_context


class CommandResults:
    """
    CommandResults class - use to return results to warroom

    :type outputs_prefix: ``str``
    :param outputs_prefix: should be identical to the prefix in the yml contextPath in yml file. for example:
            CortexXDR.Incident

    :type outputs_key_field: ``str`` or ``list[str]``
    :param outputs_key_field: primary key field in the main object. If the command returns Incidents, and of the
            properties of Incident is incident_id, then outputs_key_field='incident_id'. If object has multiple
            unique keys, then list of strings is supported outputs_key_field=['id1', 'id2']

    :type outputs: ``list`` or ``dict``
    :param outputs: the data to be returned and will be set to context

    :type indicators: ``list``
    :param indicators: DEPRECATED: use 'indicator' instead.

    :type indicator: ``Common.Indicator``
    :param indicator: single indicator like Common.IP, Common.URL, Common.File, etc.

    :type readable_output: ``str``
    :param readable_output: (Optional) markdown string that will be presented in the warroom, should be human readable -
        (HumanReadable) - if not set, readable output will be generated

    :type raw_response: ``dict`` | ``list``
    :param raw_response: must be dictionary, if not provided then will be equal to outputs. usually must be the original
        raw response from the 3rd party service (originally Contents)

    :type indicators_timeline: ``IndicatorsTimeline``
    :param indicators_timeline: must be an IndicatorsTimeline. used by the server to populate an indicator's timeline.

    :type ignore_auto_extract: ``bool``
    :param ignore_auto_extract: must be a boolean, default value is False. Used to prevent AutoExtract on output.

    :type relationships: ``list of EntityRelationship``
    :param relationships: List of relationships of the indicator.

    :type mark_as_note: ``bool``
    :param mark_as_note: must be a boolean, default value is False. Used to mark entry as note.

    :type tags: ``list``
    :param tags:  must be a list, default value is None. Used to tag war room entries.

    :type entry_type: ``int`` code of EntryType
    :param entry_type: type of return value, see EntryType

    :type scheduled_command: ``ScheduledCommand``
    :param scheduled_command: manages the way the command should be polled.

    :type execution_metrics: ``ExecutionMetrics``
    :param execution_metrics: contains metric data about a command's execution

    :type replace_existing: ``bool``
    :param replace_existing: Replace the context value at outputs_prefix if it exists.
            Works only if outputs_prefix is a path to a nested value i.e., contains a period.
            For example, the "next token" result should always be overwritten. This response can be returned as follows:
            >>> CommandResults(
            >>>     readable_output=f'Next Token: {next_token}',
            >>>     outputs=next_token,
            >>>     outputs_prefix='Path.To.NextToken',
            >>>     replace_existing=True,
            >>> )

    :return: None
    :rtype: ``None``
    """

    def __init__(self, outputs_prefix=None,
                 outputs_key_field=None,
                 outputs=None,
                 indicators=None,
                 readable_output=None,
                 raw_response=None,
                 indicators_timeline=None,
                 indicator=None,
                 ignore_auto_extract=False,
                 mark_as_note=False,
                 tags=None,
                 scheduled_command=None,
                 relationships=None,
                 entry_type=None,
                 content_format=None,
                 execution_metrics=None,
                 replace_existing=False):
        # type: (str, object, object, list, str, object, IndicatorsTimeline, Common.Indicator, bool, bool, List[str], ScheduledCommand, list, int, str, List[Any], bool) -> None  # noqa: E501
        if raw_response is None:
            raw_response = outputs
        if outputs is not None:
            if not isinstance(outputs, dict) and not outputs_prefix:
                raise ValueError('outputs_prefix is missing')
            if outputs_prefix == '.':
                raise ValueError('outputs_prefix cannot be a period.')
        if indicators and indicator:
            raise ValueError('indicators is DEPRECATED, use only indicator')
        if entry_type is None:
            entry_type = EntryType.NOTE

        self.indicators = indicators  # type: Optional[List[Common.Indicator]]
        self.indicator = indicator  # type: Optional[Common.Indicator]
        self.entry_type = entry_type  # type: int

        self.outputs_prefix = outputs_prefix

        # this is public field, it is used by a lot of unit tests, so I don't change it
        self.outputs_key_field = outputs_key_field

        self._outputs_key_field = None  # type: Optional[List[str]]
        if not outputs_key_field:
            self._outputs_key_field = None
        elif isinstance(outputs_key_field, STRING_TYPES):
            self._outputs_key_field = [outputs_key_field]  # type: ignore[list-item]
        elif isinstance(outputs_key_field, list):
            self._outputs_key_field = outputs_key_field
        else:
            raise TypeError('outputs_key_field must be of type str or list')

        self.outputs = outputs
        self.raw_response = raw_response
        self.readable_output = readable_output
        self.indicators_timeline = indicators_timeline
        self.ignore_auto_extract = ignore_auto_extract
        self.mark_as_note = mark_as_note
        self.tags = tags
        self.scheduled_command = scheduled_command
        self.relationships = relationships
        self.execution_metrics = execution_metrics
        self.replace_existing = replace_existing

        if content_format is not None and not EntryFormat.is_valid_type(content_format):
            raise TypeError('content_format {} is invalid, see CommonServerPython.EntryFormat'.format(content_format))
        self.content_format = content_format

    def to_context(self):
        outputs = {}  # type: dict
        relationships = []  # type: list
        tags = []  # type: list
        if self.readable_output:
            human_readable = self.readable_output
        else:
            human_readable = None  # type: ignore[assignment]
        raw_response = self.raw_response  # type: ignore[assignment]
        indicators_timeline = []  # type: ignore[assignment]
        ignore_auto_extract = False  # type: bool
        mark_as_note = False  # type: bool
        exec_metrics = None  # type: ignore[assignment]

        indicators = [self.indicator] if self.indicator else self.indicators

        if indicators:
            for indicator in indicators:
                context_outputs = indicator.to_context()

                for key, value in context_outputs.items():
                    if key not in outputs:
                        outputs[key] = []

                    outputs[key].append(value)

        if self.tags:
            tags = self.tags  # type: ignore[assignment]

        if self.ignore_auto_extract:
            ignore_auto_extract = True

        if self.mark_as_note:
            mark_as_note = True

        if self.indicators_timeline:
            indicators_timeline = self.indicators_timeline.indicators_timeline

        if self.outputs is not None and self.outputs != []:
            if not self.readable_output:
                # if markdown is not provided then create table by default
                if isinstance(self.outputs, (dict, list)):
                    human_readable = tableToMarkdown('Results', self.outputs)
                else:
                    human_readable = self.outputs  # type: ignore[assignment]
            if self.outputs_prefix and self.replace_existing:
                next_token_path, _, next_token_key = self.outputs_prefix.rpartition('.')
                if not next_token_path:
                    raise DemistoException('outputs_prefix must be a nested path to replace an existing key.')
                outputs[next_token_path + '(true)'] = {next_token_key: self.outputs}
            elif self.outputs_prefix and self._outputs_key_field:
                # if both prefix and key field provided then create DT key
                formatted_outputs_key = ' && '.join(['val.{0} && val.{0} == obj.{0}'.format(key_field)
                                                     for key_field in self._outputs_key_field])
                outputs_key = '{0}({1})'.format(self.outputs_prefix, formatted_outputs_key)
                outputs[outputs_key] = self.outputs
            elif self.outputs_prefix:
                outputs[str(self.outputs_prefix)] = self.outputs
            else:
                outputs.update(self.outputs)  # type: ignore[call-overload]

        if self.relationships:
            relationships = [relationship.to_entry() for relationship in self.relationships if relationship.to_entry()]

        # using a local variable to avoid changing the object's attribute, see discussion on PR #18544.
        content_format = self.content_format
        if content_format is None:
            if isinstance(raw_response, STRING_TYPES + (int,)):
                content_format = EntryFormat.TEXT
            else:
                content_format = EntryFormat.JSON

        if self.execution_metrics:
            exec_metrics = self.execution_metrics
            self.entry_type = EntryType.EXECUTION_METRICS
            raw_response = 'Metrics reported successfully.'
            content_format = EntryFormat.TEXT
        return_entry = {
            'Type': self.entry_type,
            'ContentsFormat': content_format,
            'Contents': raw_response,
            'HumanReadable': human_readable,
            'EntryContext': outputs,
            'IndicatorTimeline': indicators_timeline,
            'IgnoreAutoExtract': bool(ignore_auto_extract),
            'Note': mark_as_note,
            'Relationships': relationships
        }
        if tags:
            # This is for backward compatibility reasons
            return_entry['Tags'] = tags
        if self.scheduled_command:
            return_entry.update(self.scheduled_command.to_results())

        if exec_metrics:
            return_entry.update({'APIExecutionMetrics': exec_metrics})

        return return_entry


def is_integration_command_execution():
    """
    This function determines whether the current execution a script execution or a integration command execution.

    :return: Is the current execution a script execution or a integration command execution.
    :rtype: ``bool``
    """

    try:
        return demisto.callingContext['context']['ExecutedCommands'][0]['moduleBrand'] != 'Scripts'
    except (KeyError, IndexError, TypeError):
        try:
            # In dynamic-section scripts ExecutedCommands is None and another way is needed to verify if we are in a Script.
            return demisto.callingContext['context']['ScriptName'] == ''
        except (KeyError, IndexError, TypeError):
            return True


EXECUTION_METRICS_SCRIPT_SKIP_MSG = "returning results with Type=EntryType.EXECUTION_METRICS isn't fully supported for scripts. dropping result."


def return_results(results):
    """
    This function wraps the demisto.results(), supports.

    :type results: ``CommandResults`` or ``PollResult`` or ``str`` or ``dict`` or ``BaseWidget`` or ``list`` or ``GetMappingFieldsResponse`` or ``GetModifiedRemoteDataResponse`` or ``GetRemoteDataResponse``
    :param results: A result object to return as a War-Room entry.

    :return: None
    :rtype: ``None``
    """
    is_integration = is_integration_command_execution()
    if results is None:
        # backward compatibility reasons
        demisto.results(None)
        return

    elif results and isinstance(results, list):
        result_list = []  # type: list
        for result in results:
            # Results of type dict or str are of the old results format and work with demisto.results()
            if isinstance(result, dict):
                if is_integration or result.get('Type') != EntryType.EXECUTION_METRICS:
                    result_list.append(result)
                else:
                    demisto.debug(EXECUTION_METRICS_SCRIPT_SKIP_MSG)
            elif isinstance(result, str):
                result_list.append(result)

            else:
                # The rest are of the new format and have a corresponding function (to_context, to_display, etc...)
                return_results(result)
        if result_list:
            demisto.results(result_list)

    elif isinstance(results, CommandResults):
        context = results.to_context()
        if is_integration or context.get('Type') != EntryType.EXECUTION_METRICS:
            demisto.results(context)
        else:
            demisto.debug(EXECUTION_METRICS_SCRIPT_SKIP_MSG)

    elif isinstance(results, BaseWidget):
        demisto.results(results.to_display())

    elif isinstance(results, GetMappingFieldsResponse):
        demisto.results(results.extract_mapping())

    elif isinstance(results, GetRemoteDataResponse):
        demisto.results(results.extract_for_local())

    elif isinstance(results, GetModifiedRemoteDataResponse):
        demisto.results(results.to_entry())

    elif hasattr(results, 'to_entry'):
        entry = results.to_entry()
        if is_integration or entry.get('Type') != EntryType.EXECUTION_METRICS:
            demisto.results(entry)
        else:
            demisto.debug(EXECUTION_METRICS_SCRIPT_SKIP_MSG)

    elif not is_integration and isinstance(results, dict) and results.get('Type') == EntryType.EXECUTION_METRICS:
        demisto.debug(EXECUTION_METRICS_SCRIPT_SKIP_MSG)
    else:
        demisto.results(results)


# deprecated
def return_outputs(readable_output, outputs=None, raw_response=None, timeline=None, ignore_auto_extract=False):
    """
    DEPRECATED: use return_results() instead

    :type readable_output: ``str`` | ``int``
    :param readable_output: markdown string
    :type outputs: ``dict``
    :param outputs: the outputs
    :type raw_response: ``dict`` | ``list`` | ``str``
    :param raw_response: must be dictionary
    :type timeline: ``dict`` | ``list``
    :param timeline: expects a list
    :type ignore_auto_extract: ``bool``
    :param ignore_auto_extract: expects a bool value
    :return: None
    :rtype: ``None``
    """
    timeline_list = [timeline] if isinstance(timeline, dict) else timeline
    if timeline_list:
        for tl_obj in timeline_list:
            if 'Category' not in tl_obj.keys():
                tl_obj['Category'] = 'Integration Update'

    return_entry = {
        "Type": entryTypes["note"],
        "HumanReadable": readable_output,
        "ContentsFormat": formats["text"] if isinstance(raw_response, STRING_TYPES) else formats['json'],
        "Contents": raw_response,
        "EntryContext": outputs,
        'IgnoreAutoExtract': ignore_auto_extract,
        "IndicatorTimeline": timeline_list
    }
    # Return 'readable_output' only if needed
    if readable_output and not outputs and not raw_response:
        return_entry["Contents"] = readable_output
        return_entry["ContentsFormat"] = formats["text"]
    elif outputs and raw_response is None:
        # if raw_response was not provided but outputs were provided then set Contents as outputs
        return_entry["Contents"] = outputs
    demisto.results(return_entry)


def return_error(message, error='', outputs=None):
    """
        Returns error entry with given message and exits the script

        :type message: ``str``
        :param message: The message to return to the entry (required)

        :type error: ``str`` or Exception
        :param error: The raw error message to log (optional)

        :type outputs: ``dict or None``
        :param outputs: the outputs that will be returned to playbook/investigation context (optional)

        :return: Error entry object
        :rtype: ``dict``
    """
    is_command = hasattr(demisto, 'command')
    try:
        is_server_handled = is_command and demisto.command() in ('fetch-incidents',
                                                                 'fetch-credentials',
                                                                 'long-running-execution',
                                                                 'fetch-indicators')
    except Exception:
        is_server_handled = False
    message = LOG(message)
    if error:
        LOG(str(error))
    if any(sys.exc_info()):  # Checking that an exception occurred
        fixed_traceback = fix_traceback_line_numbers(traceback.format_exc())
        LOG('\n{}'.format(fixed_traceback))
        if is_debug_mode():
            message = '{}\n\n{}'.format(message, fixed_traceback)

    LOG.print_log()
    if not isinstance(message, str):
        message = message.encode('utf8') if hasattr(message, 'encode') else str(message)

    if is_command and demisto.command() == 'get-modified-remote-data':
        if (error and not isinstance(error, NotImplementedError)) or sys.exc_info()[0] != NotImplementedError:
            message = 'skip update. error: ' + message

    if is_server_handled:
        raise Exception(message)
    else:
        if len(message) > MAX_ERROR_MESSAGE_LENGTH:
            half_length = MAX_ERROR_MESSAGE_LENGTH // 2
            message = message[:half_length] + "...This error body was truncated..." + message[half_length * (-1):]

        demisto.results({
            'Type': entryTypes['error'],
            'ContentsFormat': formats['text'],
            'Contents': message,
            'EntryContext': outputs,
        })
        sys.exit(0)


def return_warning(message, exit=False, warning='', outputs=None, ignore_auto_extract=False):
    """
        Returns a warning entry with the specified message, and exits the script.

        :type message: ``str``
        :param message: The message to return in the entry (required).

        :type exit: ``bool``
        :param exit: Determines if the program will terminate after the command is executed. Default is False.

        :type warning: ``str``
        :param warning: The warning message (raw) to log (optional).

        :type outputs: ``dict or None``
        :param outputs: The outputs that will be returned to playbook/investigation context (optional).

        :type ignore_auto_extract: ``bool``
        :param ignore_auto_extract: Determines if the War Room entry will be auto-enriched. Default is false.

        :return: Warning entry object
        :rtype: ``dict``
    """
    LOG(message)
    if warning:
        LOG(warning)
    LOG.print_log()

    demisto.results({
        'Type': entryTypes['warning'],
        'ContentsFormat': formats['text'],
        'IgnoreAutoExtract': ignore_auto_extract,
        'Contents': str(message),
        "EntryContext": outputs
    })
    if exit:
        sys.exit(0)


class ExecutionMetrics(object):
    """
        ExecutionMetrics is used to collect and format metric data to be reported to the XSOAR server.

        :return: None
        :rtype: ``None``
    """

    def __init__(self, success=0, quota_error=0, general_error=0, auth_error=0, service_error=0, connection_error=0,
                 proxy_error=0, ssl_error=0, timeout_error=0, retry_error=0):
        self._metrics = []
        self.metrics = None
        self.success = success
        self.quota_error = quota_error
        self.general_error = general_error
        self.auth_error = auth_error
        self.service_error = service_error
        self.connection_error = connection_error
        self.proxy_error = proxy_error
        self.ssl_error = ssl_error
        self.timeout_error = timeout_error
        self.retry_error = retry_error
        """
            Initializes an ExecutionMetrics object. Once initialized, you may increment each metric type according to the
            metric you'd like to report. Afterwards, pass the `metrics` value to CommandResults.

            :type success: ``int``
            :param success: Quantity of Successful metrics

            :type quota_error: ``int``
            :param quota_error: Quantity of Quota Error (Rate Limited) metrics

            :type general_error: ``int``
            :param general_error: Quantity of General Error metrics

            :type auth_error: ``int``
            :param auth_error: Quantity of Authentication Error metrics

            :type service_error: ``int``
            :param service_error: Quantity of Service Error metrics

            :type connection_error: ``int``
            :param connection_error: Quantity of Connection Error metrics

            :type proxy_error: ``int``
            :param proxy_error: Quantity of Proxy Error metrics

            :type ssl_error: ``int``
            :param ssl_error: Quantity of SSL Error metrics

            :type timeout_error: ``int``
            :param timeout_error: Quantity of Timeout Error metrics

            :type retry_error: ``int``
            :param retry_error: Quantity of Retry Error metrics

            :type metrics: ``CommandResults``
            :param metrics: Append this value to your CommandResults list to report the metrics to your server.
        """

    @staticmethod
    def is_supported():
        if is_demisto_version_ge('6.8.0'):
            return True
        return False

    @property
    def success(self):
        return self._success

    @success.setter
    def success(self, value):
        self._success = value
        self.update_metrics('Successful', self._success)

    @property
    def quota_error(self):
        return self._quota_error

    @quota_error.setter
    def quota_error(self, value):
        self._quota_error = value
        self.update_metrics(ErrorTypes.QUOTA_ERROR, self._quota_error)

    @property
    def general_error(self):
        return self._general_error

    @general_error.setter
    def general_error(self, value):
        self._general_error = value
        self.update_metrics(ErrorTypes.GENERAL_ERROR, self._general_error)

    @property
    def auth_error(self):
        return self._auth_error

    @auth_error.setter
    def auth_error(self, value):
        self._auth_error = value
        self.update_metrics(ErrorTypes.AUTH_ERROR, self._auth_error)

    @property
    def service_error(self):
        return self._service_error

    @service_error.setter
    def service_error(self, value):
        self._service_error = value
        self.update_metrics(ErrorTypes.SERVICE_ERROR, self._service_error)

    @property
    def connection_error(self):
        return self._connection_error

    @connection_error.setter
    def connection_error(self, value):
        self._connection_error = value
        self.update_metrics(ErrorTypes.CONNECTION_ERROR, self._connection_error)

    @property
    def proxy_error(self):
        return self._proxy_error

    @proxy_error.setter
    def proxy_error(self, value):
        self._proxy_error = value
        self.update_metrics(ErrorTypes.PROXY_ERROR, self._proxy_error)

    @property
    def ssl_error(self):
        return self._ssl_error

    @ssl_error.setter
    def ssl_error(self, value):
        self._ssl_error = value
        self.update_metrics(ErrorTypes.SSL_ERROR, self._ssl_error)

    @property
    def timeout_error(self):
        return self._timeout_error

    @timeout_error.setter
    def timeout_error(self, value):
        self._timeout_error = value
        self.update_metrics(ErrorTypes.TIMEOUT_ERROR, self._timeout_error)

    @property
    def retry_error(self):
        return self._retry_error

    @retry_error.setter
    def retry_error(self, value):
        self._retry_error = value
        self.update_metrics(ErrorTypes.RETRY_ERROR, self._retry_error)

    def get_metric_list(self):
        return self._metrics

    def update_metrics(self, metric_type, metric_value):
        if metric_value > 0:
            if len(self._metrics) == 0:
                self._metrics.append({'Type': metric_type, 'APICallsCount': metric_value})
            else:
                for metric in self._metrics:
                    if metric['Type'] == metric_type:
                        metric['APICallsCount'] = metric_value
                        break
                else:
                    self._metrics.append({'Type': metric_type, 'APICallsCount': metric_value})
            self.metrics = CommandResults(execution_metrics=self._metrics)


def append_metrics(execution_metrics, results):
    """
    Returns a 'CommandResults' list appended with metrics.

    :type execution_metrics: ``ExecutionMetrics``
    :param execution_metrics: Metrics object to be added to CommandResults list(optional).

    :type results: ``list``
    :param results: 'CommandResults' list to append metrics to (required).

    :return: results appended with the metrics if the server version is supported.
    :rtype: ``list``
    """
    if execution_metrics.metrics is not None and execution_metrics.is_supported():
        results.append(execution_metrics.metrics)
    return results


def convert_dict_values_bytes_to_str(input_dict):  # type: ignore
    """
    Converts byte dict values to str
    :type input_dict: ``dict``
    :param input_dict: dict to converts its values.

    :return: dict contains str instead of bytes.
    :rtype: ``dict``
    """
    output_dict = {}
    for key, value in input_dict.items():
        if isinstance(value, dict):
            output_dict[key] = convert_dict_values_bytes_to_str(value)
        elif isinstance(value, bytes):
            output_dict[key] = value.decode()
        elif isinstance(value, list):
            output_dict[key] = [
                convert_dict_values_bytes_to_str(item) if isinstance(item, dict)
                else item.decode() if isinstance(item, bytes) else item
                for item in value]
        else:
            output_dict[key] = value
    return output_dict


class CommandRunner:
    """
    Class for executing multiple commands and save the results of each command.

    :return: None
    :rtype: ``None``
    """

    class Command:
        """
        Data class with the data required to execute a command.

        :return: None
        :rtype: ``None``
        """

        def __init__(self, commands, args_lst, brand=None, instance=None):
            """

            :param commands: The commands list or a single command
            :type commands: str + List[str]
            :param args_lst: The args list or a single args
            :type args_lst: List[Dict] + Dict
            :param brand: The brand to use
            :type brand: str
            :param instance: The instance to use
            :type instance: str
            """
            if isinstance(commands, str) and isinstance(args_lst, dict):
                commands = [commands]
                args_lst = [args_lst]
            if isinstance(commands, str) and isinstance(args_lst, list):
                commands = [commands for _ in range(len(args_lst))]
            self._is_valid(commands, args_lst)
            self.commands = commands
            self.args_lst = args_lst
            if brand:
                for args in self.args_lst:
                    args.update({'using-brand': brand})
            if instance:
                for args in self.args_lst:
                    args.update({'using': instance})

        @staticmethod
        def _is_valid(commands, args_lst):
            """
            Error handling of the given arguments
            :param commands: list of commands
            :param args_lst: list of args
            :return:
            """
            if not isinstance(commands, list):
                raise DemistoException('Expected "commands" argument to be a list. received: {}'.format(type(commands)))
            if not isinstance(args_lst, list):
                raise DemistoException('Expected "args_lst" argument to be a list. received: {}'.format(type(args_lst)))
            if len(commands) != len(args_lst):
                raise DemistoException('"commands" and "args_lst" should be in the same size')

    class Result:
        """
        Class for the result of the command.

        :return: None
        :rtype: ``None``
        """

        def __init__(self, command, args, brand, instance, result):
            """
            :param command: command that was run.
            :type command ``str``
            :param args: args that was run.
            :type args: ``dict``
            :param brand: The brand that was used.
            :type brand: ``str``
            :param instance: The instance that was used.
            :type instance: ``str``
            :param result: The result of the command.
            :type result: ``object``
            """
            self.command = command
            self.args = args
            self.brand = brand
            self.instance = instance
            self.result = result

    @staticmethod
    def execute_commands(command, extract_contents=True):
        """
        Runs the `demisto.executeCommand()` and gets all the results, including the errors, returned from the command.

        :type command: ``Command``
        :param command: The commands to run. (required)

        :type extract_contents: ``bool``
        :param extract_contents: Whether to extract Contents part of the results. Default is True.

        :return: A tuple of two lists: the command results list and command errors list.
        :rtype: ``Tuple[List[ResultWrapper], List[ResultWrapper]]``
        """
        results, errors = [], []
        for command, args in zip(command.commands, command.args_lst):
            try:
                demisto.debug(' '.join(('calling', command, 'with args=', ','.join(args))))
                execute_command_results = demisto.executeCommand(command, args)
                for res in execute_command_results:
                    brand_name = res.get('Brand', 'Unknown') if isinstance(res, dict) else 'Unknown'
                    module_name = res.get('ModuleName', 'Unknown') if isinstance(res, dict) else 'Unknown'
                    if is_error(res):
                        error = get_error(res)
                        demisto.debug('error: ' + error)
                        errors.append(CommandRunner.Result(command, args, brand_name, module_name, error))
                    else:
                        if extract_contents:
                            res = res.get('Contents', {})
                        if res is None:
                            res = {}
                        results.append(CommandRunner.Result(command, args, brand_name, module_name, res))
            except ValueError as e:
                # We expect this error when the command is not supported.
                demisto.debug('demisto.executeCommand received an error because the command is not supported:'
                              ' {e}'.format(e=str(e)))
        return results, errors

    @staticmethod
    def run_commands_with_summary(commands):
        """
        Given a list of commands, return a list of results (to pass to return_results).
        In addition, it will create a `CommandResult` of the summary of the commands, which is a `readable_output`.

        :param commands: A list of commands.
        :type commands: ``List[Command]``
        :return: list of results
        """
        full_results, full_errors = [], []
        for command in commands:
            results, errors = CommandRunner.execute_commands(command, extract_contents=False)
            full_results.extend(results)
            full_errors.extend(errors)

        summary_md = CommandRunner.get_results_summary(full_results, full_errors)

        command_results = []
        for res in full_results:
            if isinstance(res.result, dict) and res.result.get('HumanReadable'):
                res.result['HumanReadable'] = "***{brand} ({instance})***\n{human_readable}".format(
                    brand=res.brand,
                    instance=res.instance,
                    human_readable=res.result.get('HumanReadable'))
            command_results.append(res.result)

        if not command_results:
            if full_errors:  # no results were given but there are errors
                errors = ["{instance}: {msg}".format(instance=err.instance, msg=err.result) for err in full_errors]
                error_msg = '\n'.join(['Script failed. The following errors were encountered: '] + errors)
            else:
                error_msg = 'The commands that run are not supported in this Instance. ' \
                            'Try to configure the integrations in XSOAR settings.'
            raise DemistoException(error_msg)

        command_results.append(CommandResults(readable_output=summary_md))
        return command_results

    @staticmethod
    def get_results_summary(results, errors):
        """
        Get a Human Readable result for all the results of the commands.
        :param results: list of returned results
        :param errors: list of returned errors
        :return: `CommandResults` of HumanReadable that summarizes the results and errors.
        """
        results_summary_table = []
        headers = ['Instance', 'Command', 'Result', 'Comment']
        for res in results:
            # don't care about using arg in command
            res.args.pop('using', None)
            res.args.pop('using-brand', None)
            command = {'command': res.command,
                       'args': res.args}
            comment = res.result.get('Contents', 'No contents found, see entry.') if isinstance(res.result, dict) else None
            results_summary_table.append({'Instance': '***{brand}***: {instance}'.format(brand=res.brand,
                                                                                         instance=res.instance),
                                          'Command': command,
                                          'Result': 'Success',
                                          'Comment': comment})

        for err in errors:
            # don't care about using arg in command
            err.args.pop('using', None)
            err.args.pop('using-brand', None)
            command = {'command': err.command,
                       'args': err.args}
            results_summary_table.append({'Instance': '***{brand}***: {instance}'.format(brand=err.brand,
                                                                                         instance=err.instance),
                                          'Command': command,
                                          'Result': 'Error',
                                          'Comment': err.result})
        summary_md = tableToMarkdown('Results Summary', results_summary_table, headers=headers, is_auto_json_transform=True)
        return summary_md


def execute_command(command, args, extract_contents=True, fail_on_error=True):
    """
    Runs the `demisto.executeCommand()` function and checks for errors.

    :type command: ``str``
    :param command: The command to run. (required)

    :type args: ``dict``
    :param args: The command arguments. (required)

    :type extract_contents: ``bool``
    :param extract_contents: Whether to return only the Contents part of the results. Default is True.

    :type fail_on_error: ``bool``
    :param fail_on_error: Whether to fail the command when receiving an error from the command. Default is True.

    :return: The command results.
    :rtype:
        - When `fail_on_error` is True - ``list`` or ``dict`` or ``str``.
        - When `fail_on_error` is False -``bool`` and ``str``.

    Note:
    For backward compatibility, only when `fail_on_error` is set to False, two values will be returned.
    """
    if not hasattr(demisto, 'executeCommand'):
        raise DemistoException('Cannot run demisto.executeCommand() from integrations.')

    res = demisto.executeCommand(command, args)
    if is_error(res):
        error_message = get_error(res)
        if fail_on_error:
            raise DemistoException('Failed to execute {}. Error details:\n{}'.format(command, error_message))
        else:
            return False, error_message

    if not extract_contents:
        if fail_on_error:
            return res
        else:
            return True, res
    contents = [entry.get('Contents', {}) for entry in res if entry['Type'] != entryTypes['debug']]
    contents = contents[0] if len(contents) == 1 else contents

    if fail_on_error:
        return contents

    return True, contents


def camelize(src, delim=' ', upper_camel=True):
    """
        Convert all keys of a dictionary (or list of dictionaries) to CamelCase (with capital first letter)

        :type src: ``dict`` or ``list``
        :param src: The dictionary (or list of dictionaries) to convert the keys for. (required)

        :type delim: ``str``
        :param delim: The delimiter between two words in the key (e.g. delim=' ' for "Start Date"). Default ' '.

        :type upper_camel: ``bool``
        :param upper_camel: When True then transforms dictionary keys to camel case with the first letter capitalised
                            (for example: demisto_content to DemistoContent), otherwise the first letter will not be capitalised
                            (for example: demisto_content to demistoContent).

        :return: The dictionary (or list of dictionaries) with the keys in CamelCase.
        :rtype: ``dict`` or ``list``
    """

    def camelize_str(src_str):
        if callable(getattr(src_str, "decode", None)):
            src_str = src_str.decode('utf-8')
        components = src_str.split(delim)
        camelize_without_first_char = ''.join(map(lambda x: x.title(), components[1:]))
        if upper_camel:
            return components[0].title() + camelize_without_first_char
        else:
            return components[0].lower() + camelize_without_first_char

    if isinstance(src, list):
        return [camelize(phrase, delim, upper_camel=upper_camel) for phrase in src]
    return {camelize_str(key): value for key, value in src.items()}


# Constants for common merge paths
outputPaths = {
    'file': 'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || '
            'val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || '
            'val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || '
            'val.SSDeep && val.SSDeep == obj.SSDeep)',
    'ip': 'IP(val.Address && val.Address == obj.Address)',
    'url': 'URL(val.Data && val.Data == obj.Data)',
    'domain': 'Domain(val.Name && val.Name == obj.Name)',
    'cve': 'CVE(val.ID && val.ID == obj.ID)',
    'email': 'Account.Email(val.Address && val.Address == obj.Address)',
    'dbotscore': 'DBotScore'
}


def replace_in_keys(src, existing='.', new='_'):
    """
        Replace a substring in all of the keys of a dictionary (or list of dictionaries)

        :type src: ``dict`` or ``list``
        :param src: The dictionary (or list of dictionaries) with keys that need replacement. (required)

        :type existing: ``str``
        :param existing: substring to replace.

        :type new: ``str``
        :param new: new substring that will replace the existing substring.

        :return: The dictionary (or list of dictionaries) with keys after substring replacement.
        :rtype: ``dict`` or ``list``
    """

    def replace_str(src_str):
        if callable(getattr(src_str, "decode", None)):
            src_str = src_str.decode('utf-8')
        return src_str.replace(existing, new)

    if isinstance(src, list):
        return [replace_in_keys(x, existing, new) for x in src]
    return {replace_str(k): v for k, v in src.items()}


# ############################## REGEX FORMATTING ###############################
regexFlags = re.M  # Multi line matching
# for the global(/g) flag use re.findall({regex_format},str)
# else, use re.match({regex_format},str)

ipv4Regex = r'^(?P<ipv4>(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))[:]?(?P<port>\d+)?$'  # noqa: E501
ipv4cidrRegex = r'^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))$'
ipv6Regex = r'^(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:(?:(:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$'  # noqa: E501
ipv6cidrRegex = r'^s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*(\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))$'  # noqa: E501
emailRegex = r'''(?i)(?:[a-z0-9!#$%&'*+/=?^_\x60{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_\x60{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])'''  # noqa: E501
urlRegex = r'(?i)(?:(?P<url_with_path>(?P<scheme>(?:https?|hxxps?|s?ftps?|meows?)\[?[:-]]?(?:\/\/|\\\\|3A__))?(?P<userinfo>[\w]+@)?(?P<host>(?P<simple_domain>(?:(?:[^\W_]|-)+\[?\.\]?)+[^\W\d_-]{2,})|(?P<ipv4>(?:(?:25[0-5]|2[0-4][\d]|[01]?[\d][\d]?)\[?[.]]?){3}(?:25[0-5]|2[0-4][\d]|[01]?[\d][\d]?))|(?P<HEXIPv4>0\[?x]?[\da-f]{8})|(?P<ipv6>\[?(?:(?:[\da-fA-F]{1,4}:){7,7}[\da-fA-F]{1,4}|(?:[\da-fA-F]{1,4}:){1,7}:|([\da-fA-F]{1,4}:){1,6}:[\da-fA-F]{1,4}|([\da-fA-F]{1,4}:){1,5}(:[\da-fA-F]{1,4}){1,2}|([\da-fA-F]{1,4}:){1,4}(:[\da-fA-F]{1,4}){1,3}|([\da-fA-F]{1,4}:){1,3}(:[\da-fA-F]{1,4}){1,4}|([\da-fA-F]{1,4}:){1,2}(:[\da-fA-F]{1,4}){1,5}|[\da-fA-F]{1,4}:(?:(:[\da-fA-F]{1,4}){1,6})|:(?:(:[\da-fA-F]{1,4}){1,7}|:)|fe80:(?::[\da-fA-F]{0,4}){0,4}%[\da-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[\d]){0,1}[\d])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[\d]){0,1}[\d])|([\da-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[\d]){0,1}[\d])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[\d]){0,1}[\d]))\]?))(?P<port>:(?:6[0-5][\d]{3}|[1-5][\d]{4}|[1-9][\d]{,3}))?/(?P<path>(?:[\w\/%-]+)(?P<extension>\[?[.]]?[^\W\d_-]+)?)?(?P<query>\?[^\s#]*)?(?P<fragment>#[\w\d]*)?)|(?P<no_path_url>(?:(?:https?|hxxps?|s?ftps?|meows?)\[?[:-]]?(?:\/\/|\\\\|3A__))(?:[\w]+@)?(?:(?:(?:[^\W_]+\[?\.\]?)+[^\W\d_-]{2,})[\/.]?)|(?:(?:(?:https?|hxxps?|s?ftps?|meows?)\[?[:-]]?(?:\/\/|\\\\|3A__))(?:(?:(?:(?:25[0-5]|2[0-4][\d]|[01]?[\d][\d]?)\[?[.]]?){3}(?:25[0-5]|2[0-4][\d]|[01]?[\d][\d]?))|(?:0\[?x]?[\da-f]{8})|(?:\[?(?:(?:[\da-fA-F]{1,4}:){7,7}[\da-fA-F]{1,4}|(?:[\da-fA-F]{1,4}:){1,7}:|([\da-fA-F]{1,4}:){1,6}:[\da-fA-F]{1,4}|([\da-fA-F]{1,4}:){1,5}(:[\da-fA-F]{1,4}){1,2}|([\da-fA-F]{1,4}:){1,4}(:[\da-fA-F]{1,4}){1,3}|([\da-fA-F]{1,4}:){1,3}(:[\da-fA-F]{1,4}){1,4}|([\da-fA-F]{1,4}:){1,2}(:[\da-fA-F]{1,4}){1,5}|[\da-fA-F]{1,4}:(?:(:[\da-fA-F]{1,4}){1,6})|:(?:(:[\da-fA-F]{1,4}){1,7}|:)|fe80:(?::[\da-fA-F]{0,4}){0,4}%[\da-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[\d]){0,1}[\d])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[\d]){0,1}[\d])|([\da-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[\d]){0,1}[\d])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[\d]){0,1}[\d]))\]?))))$|(?P<ip_port>(?:(?:https?|hxxps?|s?ftps?|meows?)\[?[:-]]?(?:\/\/|\\\\|3A__))?(?:(?:(?:(?:25[0-5]|2[0-4][\d]|[01]?[\d][\d]?)\[?[.]]?){3}(?:25[0-5]|2[0-4][\d]|[01]?[\d][\d]?))|(?:0\[?x]?[\da-f]{8})|(?:\[?(?:(?:[\da-fA-F]{1,4}:){7,7}[\da-fA-F]{1,4}|(?:[\da-fA-F]{1,4}:){1,7}:|([\da-fA-F]{1,4}:){1,6}:[\da-fA-F]{1,4}|([\da-fA-F]{1,4}:){1,5}(:[\da-fA-F]{1,4}){1,2}|([\da-fA-F]{1,4}:){1,4}(:[\da-fA-F]{1,4}){1,3}|([\da-fA-F]{1,4}:){1,3}(:[\da-fA-F]{1,4}){1,4}|([\da-fA-F]{1,4}:){1,2}(:[\da-fA-F]{1,4}){1,5}|[\da-fA-F]{1,4}:(?:(:[\da-fA-F]{1,4}){1,6})|:(?:(:[\da-fA-F]{1,4}){1,7}|:)|fe80:(?::[\da-fA-F]{0,4}){0,4}%[\da-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[\d]){0,1}[\d])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[\d]){0,1}[\d])|([\da-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[\d]){0,1}[\d])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[\d]){0,1}[\d]))\]?))(?::(?:6[0-5][\d]{3}|[1-5][\d]{4}|[1-9][\d]{,3})))$)'  # noqa: E501
cveRegex = r'(?i)^cve-\d{4}-([1-9]\d{4,}|\d{4})$'
domainRegex = r'(?i)(?P<scheme>(?:http|hxxp|s?ftp)s?(?::|%3A)(?:%2F%2F|//))?(?P<fqdn>(?:(?P<domain>(?:[^\W_]|-)+)\[?\.\]?)+(?P<tld>[^\W\d_-]{2,}))'
hashRegex = r'\b[0-9a-fA-F]+\b'
md5Regex = re.compile(r'\b[0-9a-fA-F]{32}\b', regexFlags)
sha1Regex = re.compile(r'\b[0-9a-fA-F]{40}\b', regexFlags)
sha256Regex = re.compile(r'\b[0-9a-fA-F]{64}\b', regexFlags)
sha512Regex = re.compile(r'\b[0-9a-fA-F]{128}\b', regexFlags)

pascalRegex = re.compile('([A-Z]?[a-z]+)')


# ############################## REGEX FORMATTING end ###############################


def is_filename_valid(filename):
    """
    Checking if the file name contains invalid characters.

    :param filename: The file name
    :type filename: ``str``

    :return: True if valid otherwise False.
    :rtype: ``bool``
    """
    if not re.match(r"^[^~)('\\!*<>:;,?\"*|/]+$", filename):
        return False
    return True


def underscoreToCamelCase(s, upper_camel=True):
    """
       Convert an underscore separated string to camel case

       :type s: ``str``
       :param s: The string to convert (e.g. hello_world) (required)

       :type upper_camel: ``bool``
       :param upper_camel: When True then transforms dictionarykeys to camel case with the first letter capitalised
                           (for example: demisto_content to DemistoContent), otherwise the first letter will not be capitalised
                           (for example: demisto_content to demistoContent).

       :return: The converted string (e.g. HelloWorld)
       :rtype: ``str``
    """
    if not isinstance(s, STRING_OBJ_TYPES):
        return s

    components = s.split('_')
    camel_without_first_char = ''.join(x.title() for x in components[1:])
    if upper_camel:
        return components[0].title() + camel_without_first_char
    else:
        return components[0].lower() + camel_without_first_char


def camel_case_to_underscore(s):
    """Converts a camelCase string to snake_case

   :type s: ``str``
   :param s: The string to convert (e.g. helloWorld) (required)

   :return: The converted string (e.g. hello_world)
   :rtype: ``str``
    """
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', s)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def snakify(src):
    """Convert all keys of a dictionary to snake_case (underscored separated)

    :type src: ``dict``
    :param src: The dictionary to convert the keys for. (required)

    :return: The dictionary (or list of dictionaries) with the keys in CamelCase.
    :rtype: ``dict``
    """
    return {camel_case_to_underscore(k): v for k, v in src.items()}


def pascalToSpace(s):
    """
       Converts pascal strings to human readable (e.g. "ThreatScore" -> "Threat Score",  "thisIsIPAddressName" ->
       "This Is IP Address Name"). Could be used as headerTransform

       :type s: ``str``
       :param s: The string to be converted (required)

       :return: The converted string
       :rtype: ``str``
    """

    if not isinstance(s, STRING_OBJ_TYPES):
        return s

    # double space to handle capital words like IP/URL/DNS that not included in the regex
    s = re.sub(pascalRegex, lambda match: r' {} '.format(match.group(1).title()), s)

    # split and join: to remove double spacing caused by previous workaround
    s = ' '.join(s.split())
    return s


def string_to_table_header(string):
    """
      Checks if string, change underscores to spaces, capitalize every word.
      Example: "one_two" to "One Two"

      :type string: ``str``
      :param string: The string to be converted (required)

      :return: The converted string
      :rtype: ``str``
    """
    if isinstance(string, STRING_OBJ_TYPES):
        return " ".join(word.capitalize() for word in string.replace("_", " ").split())
    else:
        raise Exception('The key is not a string: {}'.format(string))


def string_to_context_key(string):
    """
     Checks if string, removes underscores, capitalize every word.
     Example: "one_two" to "OneTwo"

     :type string: ``str``
     :param string: The string to be converted (required)

     :return: The converted string
     :rtype: ``str``
    """
    if isinstance(string, STRING_OBJ_TYPES):
        return "".join(word.capitalize() for word in string.split('_'))
    else:
        raise Exception('The key is not a string: {}'.format(string))


def response_to_context(reponse_obj, user_predefiend_keys=None):
    """
    Recursively creates a data dictionary where all key starts with capital letters.
    If a key include underscores,  removes underscores, capitalize every word.
    Example: "one_two" to "OneTwo

    :type reponse_obj: ``Any``
    :param reponse_obj: The response object to update.
    :type reponse_obj: ``dict``
    :user_predefiend_keys: An optional argument,
    a dict with predefined keys where the key is the key in the response and value is the key we want to turn the key into.

    :return: A response with all keys (if there're any) starts with a capital letter.
    :rtype: ``Any``
    """
    predefined_keys = {"id": "ID", "uuid": "UUID"}
    if user_predefiend_keys:
        predefined_keys.update(user_predefiend_keys)
    parsed_dict = {}
    key = ""
    if isinstance(reponse_obj, dict):
        for key, value in reponse_obj.items():
            if key in predefined_keys:
                key = predefined_keys.get(key, "")  # type: ignore
            else:
                key = string_to_context_key(key)
            if isinstance(value, dict):
                parsed_dict[key] = response_to_context(value)
            elif isinstance(value, list):
                parsed_dict[key] = [response_to_context(list_item) for list_item in value]
            else:
                parsed_dict[key] = value
        return parsed_dict
    elif isinstance(reponse_obj, list):
        return [response_to_context(list_item) for list_item in reponse_obj]
    else:
        return reponse_obj


def parse_date_range(date_range, date_format=None, to_timestamp=False, timezone=0, utc=True):
    """
        THIS FUNCTTION IS DEPRECATED - USE dateparser.parse instead

      Parses date_range string to a tuple date strings (start, end). Input must be in format 'number date_range_unit')
      Examples: (2 hours, 4 minutes, 6 month, 1 day, etc.)

      :type date_range: ``str``
      :param date_range: The date range to be parsed (required)

      :type date_format: ``str``
      :param date_format: Date format to convert the date_range to. (optional)

      :type to_timestamp: ``bool``
      :param to_timestamp: If set to True, then will return time stamp rather than a datetime.datetime. (optional)

      :type timezone: ``int``
      :param timezone: timezone should be passed in hours (e.g if +0300 then pass 3, if -0200 then pass -2).

      :type utc: ``bool``
      :param utc: If set to True, utc time will be used, otherwise local time.

      :return: The parsed date range.
      :rtype: ``(datetime.datetime, datetime.datetime)`` or ``(int, int)`` or ``(str, str)``
    """
    range_split = date_range.strip().split(' ')
    if len(range_split) != 2:
        return_error('date_range must be "number date_range_unit", examples: (2 hours, 4 minutes,6 months, 1 day, '
                     'etc.)')

    try:
        number = int(range_split[0])
    except ValueError:
        return_error('The time value is invalid. Must be an integer.')

    unit = range_split[1].lower()
    if unit not in ['minute', 'minutes',
                    'hour', 'hours',
                    'day', 'days',
                    'month', 'months',
                    'year', 'years',
                    ]:
        return_error('The unit of date_range is invalid. Must be minutes, hours, days, months or years.')

    if not isinstance(timezone, (int, float)):
        return_error('Invalid timezone "{}" - must be a number (of type int or float).'.format(timezone))

    if utc:
        utc_now = datetime.utcnow()
        end_time = utc_now + timedelta(hours=timezone)
        start_time = utc_now + timedelta(hours=timezone)
    else:
        now = datetime.now()
        end_time = now + timedelta(hours=timezone)
        start_time = now + timedelta(hours=timezone)

    if 'minute' in unit:
        start_time = end_time - timedelta(minutes=number)
    elif 'hour' in unit:
        start_time = end_time - timedelta(hours=number)
    elif 'day' in unit:
        start_time = end_time - timedelta(days=number)
    elif 'month' in unit:
        start_time = end_time - timedelta(days=number * 30)
    elif 'year' in unit:
        start_time = end_time - timedelta(days=number * 365)

    if to_timestamp:
        return date_to_timestamp(start_time), date_to_timestamp(end_time)

    if date_format:
        return datetime.strftime(start_time, date_format), datetime.strftime(end_time, date_format)

    return start_time, end_time


def timestamp_to_datestring(timestamp, date_format="%Y-%m-%dT%H:%M:%S.000Z", is_utc=False):
    """
      Parses timestamp (milliseconds) to a date string in the provided date format (by default: ISO 8601 format)
      Examples: (1541494441222, 1541495441000, etc.)

      :type timestamp: ``int`` or ``str``
      :param timestamp: The timestamp to be parsed (required)

      :type date_format: ``str``
      :param date_format: The date format the timestamp should be parsed to. (optional)

      :type is_utc: ``bool``
      :param is_utc: Should the string representation of the timestamp use UTC time or the local machine time

      :return: The parsed timestamp in the date_format
      :rtype: ``str``
    """
    use_utc_time = is_utc or date_format.endswith('Z')
    if use_utc_time:
        return datetime.utcfromtimestamp(int(timestamp) / 1000.0).strftime(date_format)
    return datetime.fromtimestamp(int(timestamp) / 1000.0).strftime(date_format)


def date_to_timestamp(date_str_or_dt, date_format='%Y-%m-%dT%H:%M:%S'):
    """
      Parses date_str_or_dt in the given format (default: %Y-%m-%dT%H:%M:%S) to milliseconds
      Examples: ('2018-11-06T08:56:41', '2018-11-06T08:56:41', etc.)

      :type date_str_or_dt: ``str`` or ``datetime.datetime``
      :param date_str_or_dt: The date to be parsed. (required)

      :type date_format: ``str``
      :param date_format: The date format of the date string (will be ignored if date_str_or_dt is of type
        datetime.datetime). (optional)

      :return: The parsed timestamp.
      :rtype: ``int``
    """
    if isinstance(date_str_or_dt, STRING_OBJ_TYPES):
        return int(time.mktime(time.strptime(date_str_or_dt, date_format)) * 1000)

    # otherwise datetime.datetime
    return int(time.mktime(date_str_or_dt.timetuple()) * 1000)


def remove_nulls_from_dictionary(data):
    """
        Remove Null values from a dictionary. (updating the given dictionary)

        :type data: ``dict``
        :param data: The data to be added to the context (required)

        :return: No data returned
        :rtype: ``None``
    """
    list_of_keys = list(data.keys())[:]
    for key in list_of_keys:
        if data[key] in ('', None, [], {}, ()):
            del data[key]


def assign_params(keys_to_ignore=None, values_to_ignore=None, **kwargs):
    """Creates a dictionary from given kwargs without empty values.
    empty values are: None, '', [], {}, ()
`   Examples:
        >>> assign_params(a='1', b=True, c=None, d='')
        {'a': '1', 'b': True}

        >>> since_time = 'timestamp'
        >>> assign_params(values_to_ignore=(15, ), sinceTime=since_time, b=15)
        {'sinceTime': 'timestamp'}

        >>> item_id = '1236654'
        >>> assign_params(keys_to_ignore=['rnd'], ID=item_id, rnd=15)
        {'ID': '1236654'}

    :type keys_to_ignore: ``tuple`` or ``list``
    :param keys_to_ignore: Keys to ignore if exists

    :type values_to_ignore: ``tuple`` or ``list``
    :param values_to_ignore: Values to ignore if exists

    :type kwargs: ``kwargs``
    :param kwargs: kwargs to filter

    :return: dict without empty values
    :rtype: ``dict``

    """
    if values_to_ignore is None:
        values_to_ignore = (None, '', [], {}, ())
    if keys_to_ignore is None:
        keys_to_ignore = tuple()
    return {
        key: value for key, value in kwargs.items()
        if value not in values_to_ignore and key not in keys_to_ignore
    }


class GetDemistoVersion:
    """
    Callable class to replace get_demisto_version function
    """

    def __init__(self):
        self._version = None

    def __call__(self):
        """Returns the Demisto version and build number.

        :return: Demisto version object if Demisto class has attribute demistoVersion, else raises AttributeError
        :rtype: ``dict``
        """
        if self._version is None:
            if hasattr(demisto, 'demistoVersion'):
                self._version = demisto.demistoVersion()
            else:
                raise AttributeError('demistoVersion attribute not found.')
        return self._version


get_demisto_version = GetDemistoVersion()


def get_demisto_version_as_str():
    """Get the Demisto Server version as a string `<version>-<build>`. If unknown will return: 'Unknown'.
    Meant to be use in places where we want to display the version. If you want to perform logic based upon vesrion
    use: is_demisto_version_ge.

    :return: Demisto version as string
    :rtype: ``dict``
    """
    try:
        ver_obj = get_demisto_version()
        return '{}-{}'.format(ver_obj.get('version', 'Unknown'),
                              ver_obj.get("buildNumber", 'Unknown'))
    except AttributeError:
        return "Unknown"


def is_demisto_version_ge(version, build_number=''):
    """Utility function to check if current running integration is at a server greater or equal to the passed version

    :type version: ``str``
    :param version: Version to check

    :type build_number: ``str``
    :param build_number: Build number to check

    :return: True if running within a Server version greater or equal than the passed version
    :rtype: ``bool``
    """

    def versionzfill(v):
        """ Split version on . and zfill. So we can compare 6.10 to 6.5 properly.

        :type v: ``srt``
        :param v: Version str to fill

        :return: Version with zfill
        :rtype: ``str``
        """
        vzfill = []
        for ver in v.split("."):
            vzfill.append(ver.zfill(8))
        return tuple(vzfill)

    server_version = {}
    try:
        server_version = get_demisto_version()
        server_zfill = versionzfill(server_version.get('version'))
        ver_zfill = versionzfill(version)
        if server_zfill > ver_zfill:
            return True
        elif server_zfill == ver_zfill:
            if build_number:
                return int(server_version.get('buildNumber')) >= int(build_number)  # type: ignore[arg-type]
            return True  # No build number
        else:
            return False
    except AttributeError:
        # demistoVersion was added in 5.0.0. We are currently running in 4.5.0 and below
        if version >= "5.0.0":
            return False
        raise
    except ValueError:
        # dev editions are not comparable
        demisto.log(  # pylint: disable=E9012
            'is_demisto_version_ge: ValueError. \n '
            'input: server version: {} build number: {}\n'
            'server version: {}'.format(version, build_number, server_version)
        )

        return True


def is_xsiam_or_xsoar_saas():
    """Determines whether or not the platform is XSIAM or XSOAR SAAS.

    :return: True iff the platform is XSIAM or XSOAR SAAS.
    :rtype: ``bool``
    """
    return is_demisto_version_ge('8.0.0')


def is_xsoar():
    """Determines whether or not the platform is XSOAR.

    :return: True iff the platform is XSOAR.
    :rtype: ``bool``
    """
    return "xsoar" in demisto.demistoVersion().get("platform")


def is_xsoar_on_prem():
    """Determines whether or not the platform is a XSOAR on-prem.

    :return: True iff the platform is XSOAR on-prem.
    :rtype: ``bool``
    """
    return demisto.demistoVersion().get("platform") == "xsoar" and not is_demisto_version_ge('8.0.0')


def is_xsoar_hosted():
    """Determines whether or not the platform is XSOAR hosted.

    :return: True iff the platform is XSOAR hosted.
    :rtype: ``bool``
    """
    return demisto.demistoVersion().get("platform") == "xsoar_hosted"


def is_xsoar_saas():
    """Determines whether or not the platform is XSOAR SAAS.

    :return: True iff the platform is XSOAR SAAS.
    :rtype: ``bool``
    """
    return demisto.demistoVersion().get("platform") == "xsoar" and is_xsiam_or_xsoar_saas()


def is_xsiam():
    """Determines whether or not the platform is XSIAM.

    :return: True iff the platform is XSIAM.
    :rtype: ``bool``
    """
    return demisto.demistoVersion().get("platform") == "x2"


def is_using_engine():
    """Determines whether or not the platform is using engine.
    NOTE: 
     - This method works only for system integrations (not custom).
     - On xsoar 8, this method works only for integrations that runs on the xsoar pod - not on the engine-0 (mainly long running
       integrations) such as:  EDL, Cortex Core - IOC, Cortex Core - IR, ExportIndicators, Generic Webhook, PingCastle,
       Publish List, Simple API Proxy, Syslog v2, TAXII Server, TAXII2 Server, Web File Repository, Workday_IAM_Event_Generator, 
       XSOAR-Web-Server, Microsoft Teams, AWS-SNS-Listener.

    :return: True iff the platform is using engine.
    :rtype: ``bool``
    """
    return demisto.demistoVersion().get("engine")


def is_integration_instance_running_on_engine():
    """Determines whether the current integration instance runs on an xsoar engine.
    If yes - returns the engine id.

    :return: The engine id iff the instance is running on an xsaor engine.
    :rtype: ``str``
    """
    engine_id = ''
    integrations_raw_response = demisto.internalHttpRequest(
        'POST', uri='/settings/integration/search', body='{\"size\":1000}'
    )
    integrations_body_raw_response = integrations_raw_response.get('body', '{}')
    try:
        integrations_body_response = json.loads(integrations_body_raw_response)  # type: ignore
    except json.JSONDecodeError:  # type: ignore[attr-defined]
        demisto.debug('Unable to load response {}'.format(integrations_body_raw_response))
        integrations_body_response = {}

    instances = integrations_body_response.get('instances', [])
    instance_name = demisto.integrationInstance()
    demisto.debug("Search for the data of the {} instance.".format(instance_name))
    for instance in instances:
        if instance_name == instance.get('name', ''):
            engine_id = instance.get('engine', '')
            break

    if engine_id:  # engine_id = '' for instances that don't run on engine
        demisto.debug("The {} instance runs on an xsoar engine, engine ID is: {}".format(instance_name, engine_id))
    else:
        demisto.debug("The {} instance does not run on an xsoar engine.".format(instance_name))

    return engine_id


def get_engine_base_url(engine_id):
    """Gets the xsoar engine id and returns it's base url. 
    For example: for engine_id = '4ccccccc-5aaa-4000-b666-dummy_id', base url = '11.180.111.111:1443'.

    :type engine_id: ``str``
    :param engine_id: The xsoar engine id.

    :return: The base URL of the engine.
    :rtype: ``str`
    """

    engines_raw_response = demisto.internalHttpRequest(
        'GET', uri='/engines', body=json.dumps({})
    )
    engines_body_raw_response = engines_raw_response.get('body', '{}')

    try:
        engines_body_response = json.loads(engines_body_raw_response)  # type: ignore
    except json.JSONDecodeError:  # type: ignore[attr-defined]
        demisto.debug('Unable to load response {}'.format(engines_body_raw_response))
        engines_body_response = {}

    engines = engines_body_response.get('engines', [])
    demisto.debug("Search for the data of engine ID {}.".format(engine_id))
    for engine in engines:
        if engine.get('id') == engine_id:
            engine_base_url = engine.get('baseUrl', '')
            demisto.debug("The base URL of engine ID {} is: {}.".format(engine_id, engine_base_url))
            return engine_base_url

    demisto.debug("Couldn't find a base url for engine ID {}.".format(engine_id))
    return ''


class DemistoHandler(logging.Handler):
    """
        Handler to route logging messages to an IntegrationLogger or demisto.debug if not supplied
    """

    def __init__(self, int_logger=None):
        logging.Handler.__init__(self)
        self.int_logger = int_logger

    def emit(self, record):
        msg = self.format(record)
        try:
            if self.int_logger:
                self.int_logger(msg)
            else:
                demisto.debug(msg)
        except Exception:  # noqa: disable=broad-except
            pass


def censor_request_logs(request_log):
    """
    Censors the request logs generated from the urllib library directly by replacing sensitive information such as tokens and cookies with a mask. 
    In most cases, the sensitive value is the first word after the keyword, but in some cases, it is the second one.
    :param request_log: The request log to censor
    :type request_log: ``str``

    :return: The censored request log
    :rtype: ``str``
    """
    keywords_to_censor = ['Authorization:', 'Cookie', "Token", "username",
                          "password", "Key", "identifier", "credential", "client"]
    lower_keywords_to_censor = [word.lower() for word in keywords_to_censor]

    trimed_request_log = request_log.lstrip(SEND_PREFIX)
    request_log_with_spaces = trimed_request_log.replace("\\r\\n", " \\r\\n")
    request_log_lst = request_log_with_spaces.split()

    for i, word in enumerate(request_log_lst):
        # Check if the word is a keyword or contains a keyword (e.g "Cookies" containes "Cookie")
        if any(keyword in word.lower() for keyword in lower_keywords_to_censor):
            next_word = request_log_lst[i + 1] if i + 1 < len(request_log_lst) else None
            if next_word:
                # If the next word is "Bearer", "JWT" or "Basic" then we replace the word after it since thats the token
                if next_word.lower() in ["bearer", "jwt", "basic"] and i + 2 < len(request_log_lst):
                    request_log_lst[i + 2] = MASK
                elif request_log_lst[i + 1].endswith("}'"):
                    request_log_lst[i + 1] = "\"{}\"}}'".format(MASK)
                else:
                    request_log_lst[i + 1] = MASK

    # Rebuild the request log so that the only change is the masked information.
    censored_string = SEND_PREFIX + \
        ' '.join(request_log_lst) if request_log.startswith(SEND_PREFIX) else ' '.join(request_log_lst)
    censored_string = censored_string.replace(" \\r\\n", "\\r\\n")
    return censored_string


class DebugLogger(object):
    """
        Wrapper to initiate logging at logging.DEBUG level.
        Is used when `debug-mode=True`.
    """

    def __init__(self):
        self.handler = None  # just in case our http_client code throws an exception. so we don't error in the __del__
        self.int_logger = IntegrationLogger()
        self.int_logger.set_buffering(False)
        self.http_client_print = None
        self.http_client = None
        if IS_PY3:
            # pylint: disable=import-error
            import http.client as http_client
            # pylint: enable=import-error
            self.http_client = http_client
            self.http_client.HTTPConnection.debuglevel = 1
            self.http_client_print = getattr(http_client, 'print', None)  # save in case someone else patched it already
            setattr(http_client, 'print', self.int_logger.print_override)
        self.handler = DemistoHandler(self.int_logger)
        demisto_formatter = logging.Formatter(fmt='python logging: %(levelname)s [%(name)s] - %(message)s', datefmt=None)
        self.handler.setFormatter(demisto_formatter)
        self.root_logger = logging.getLogger()
        self.prev_log_level = self.root_logger.getEffectiveLevel()
        self.root_logger.setLevel(logging.DEBUG)
        self.org_handlers = list()
        if self.root_logger.handlers:
            self.org_handlers.extend(self.root_logger.handlers)
            for h in self.org_handlers:
                self.root_logger.removeHandler(h)
        self.root_logger.addHandler(self.handler)

    def __del__(self):
        if self.handler:
            self.root_logger.setLevel(self.prev_log_level)
            self.root_logger.removeHandler(self.handler)
            self.handler.flush()
            self.handler.close()
        if self.org_handlers:
            for h in self.org_handlers:
                self.root_logger.addHandler(h)
        if self.http_client:
            self.http_client.HTTPConnection.debuglevel = 0
            if self.http_client_print:
                setattr(self.http_client, 'print', self.http_client_print)
            else:
                delattr(self.http_client, 'print')
            if self.int_logger.curl:
                for curl in self.int_logger.curl:
                    demisto.info('cURL:\n' + curl)

    def log_start_debug(self):
        """
        Utility function to log start of debug mode logging
        """
        msg = "debug-mode started.\n#### http client print found: {}.\n#### Env {}.".format(self.http_client_print is not None,
                                                                                            os.environ)
        if hasattr(demisto, 'params'):
            msg += "\n#### Params: {}.".format(json.dumps(demisto.params(), indent=2))
        calling_context = demisto.callingContext.get('context', {})
        msg += "\n#### Docker image: [{}]".format(calling_context.get('DockerImage'))
        brand = calling_context.get('IntegrationBrand')
        if brand:
            msg += "\n#### Integration: brand: [{}] instance: [{}]".format(brand, calling_context.get('IntegrationInstance'))
        sm = get_schedule_metadata(context=calling_context)
        if sm.get('is_polling'):
            msg += "\n#### Schedule Metadata: scheduled command: [{}] args: [{}] times ran: [{}] scheduled: [{}] end " \
                   "date: [{}]".format(sm.get('polling_command'),
                                       sm.get('polling_args'),
                                       sm.get('times_ran'),
                                       sm.get('start_date'),
                                       sm.get('end_date')
                                       )
        self.int_logger.write(msg)


_requests_logger = None
try:
    if is_debug_mode():
        _requests_logger = DebugLogger()
        _requests_logger.log_start_debug()
except Exception as ex:
    # Should fail silently so that if there is a problem with the logger it will
    # not affect the execution of commands and playbooks
    demisto.info('Failed initializing DebugLogger: {}'.format(ex))


def add_sensitive_log_strs(sensitive_str):
    """
    Adds the received string to both LOG and DebugLogger. The logger will mask the string each time he encounters it.

    :type sensitive_str: ``str``
    :param sensitive_str: The string to be replaced.

    :return: No data returned
    :rtype: ``None``
    """
    if _requests_logger:
        _requests_logger.int_logger.add_replace_strs(sensitive_str)
    LOG.add_replace_strs(sensitive_str)


def parse_date_string(date_string, date_format='%Y-%m-%dT%H:%M:%S'):
    """
        Parses the date_string function to the corresponding datetime object.
        Note: If possible (e.g. running Python 3), it is suggested to use
              dateutil.parser.parse or dateparser.parse functions instead.

        Examples:
        >>> parse_date_string('2019-09-17T06:16:39Z')
        datetime.datetime(2019, 9, 17, 6, 16, 39)
        >>> parse_date_string('2019-09-17T06:16:39.22Z')
        datetime.datetime(2019, 9, 17, 6, 16, 39, 220000)
        >>> parse_date_string('2019-09-17T06:16:39.4040+05:00', '%Y-%m-%dT%H:%M:%S+02:00')
        datetime.datetime(2019, 9, 17, 6, 16, 39, 404000)

        :type date_string: ``str``
        :param date_string: The date string to parse. (required)

        :type date_format: ``str``
        :param date_format:
            The date format of the date string. If the date format is known, it should be provided. (optional)

        :return: The parsed datetime.
        :rtype: ``(datetime.datetime, datetime.datetime)``
    """
    try:
        return datetime.strptime(date_string, date_format)
    except ValueError as e:
        error_message = str(e)

        date_format = '%Y-%m-%dT%H:%M:%S'
        time_data_regex = r'time data \'(.*?)\''
        time_data_match = re.findall(time_data_regex, error_message)
        sliced_time_data = ''

        if time_data_match:
            # found time date which does not match date format
            # example of caught error message:
            # "time data '2019-09-17T06:16:39Z' does not match format '%Y-%m-%dT%H:%M:%S.%fZ'"
            time_data = time_data_match[0]

            # removing YYYY-MM-DDThh:mm:ss from the time data to keep only milliseconds and time zone
            sliced_time_data = time_data[19:]
        else:
            unconverted_data_remains_regex = r'unconverted data remains: (.*)'
            unconverted_data_remains_match = re.findall(unconverted_data_remains_regex, error_message)

            if unconverted_data_remains_match:
                # found unconverted_data_remains
                # example of caught error message:
                # "unconverted data remains: 22Z"
                sliced_time_data = unconverted_data_remains_match[0]

        if not sliced_time_data:
            # did not catch expected error
            raise ValueError(e)

        if '.' in sliced_time_data:
            # found milliseconds - appending ".%f" to date format
            date_format += '.%f'

        timezone_regex = r'[Zz+-].*'
        time_zone = re.findall(timezone_regex, sliced_time_data)

        if time_zone:
            # found timezone - appending it to the date format
            date_format += time_zone[0]

        # Make the fractions shorter less than 6 charactors
        # e.g. '2022-01-23T12:34:56.123456789+09:00' to '2022-01-23T12:34:56.123456+09:00'
        #      '2022-01-23T12:34:56.123456789' to '2022-01-23T12:34:56.123456'
        date_string = re.sub(r'([0-9]+\.[0-9]{6})[0-9]*([Zz]|[+-]\S+?)?', '\\1\\2', date_string)

        return datetime.strptime(date_string, date_format)


def build_dbot_entry(indicator, indicator_type, vendor, score, description=None, build_malicious=True):
    """Build a dbot entry. if score is 3 adds malicious
    Examples:
        >>> build_dbot_entry('user@example.com', 'Email', 'Vendor', 1)
        {'DBotScore': {'Indicator': 'user@example.com', 'Type': 'email', 'Vendor': 'Vendor', 'Score': 1}}

        >>> build_dbot_entry('user@example.com', 'Email', 'Vendor', 3,  build_malicious=False)
        {'DBotScore': {'Indicator': 'user@example.com', 'Type': 'email', 'Vendor': 'Vendor', 'Score': 3}}

        >>> build_dbot_entry('user@example.com', 'email', 'Vendor', 3, 'Malicious email')
        {'DBotScore': {'Vendor': 'Vendor', 'Indicator': 'user@example.com', 'Score': 3, 'Type': 'email'}, \
'Account.Email(val.Address && val.Address == obj.Address)': {'Malicious': {'Vendor': 'Vendor', 'Description': \
'Malicious email'}, 'Address': 'user@example.com'}}

        >>> build_dbot_entry('md5hash', 'md5', 'Vendor', 1)
        {'DBotScore': {'Indicator': 'md5hash', 'Type': 'file', 'Vendor': 'Vendor', 'Score': 1}}

    :type indicator: ``str``
    :param indicator: indicator field. if using file hashes, can be dict

    :type indicator_type: ``str``
    :param indicator_type:
        type of indicator ('url, 'domain', 'ip', 'cve', 'email', 'md5', 'sha1', 'sha256', 'crc32', 'sha512', 'ctph')

    :type vendor: ``str``
    :param vendor: Integration ID

    :type score: ``int``
    :param score: DBot score (0-3)

    :type description: ``str`` or ``None``
    :param description: description (will be added to malicious if dbot_score is 3). can be None

    :type build_malicious: ``bool``
    :param build_malicious: if True, will add a malicious entry

    :return: dbot entry
    :rtype: ``dict``
    """
    if not 0 <= score <= 3:
        raise DemistoException('illegal DBot score, expected 0-3, got `{}`'.format(score))
    indicator_type_lower = indicator_type.lower()
    if indicator_type_lower not in INDICATOR_TYPE_TO_CONTEXT_KEY:
        raise DemistoException('illegal indicator type, expected one of {}, got `{}`'.format(
            INDICATOR_TYPE_TO_CONTEXT_KEY.keys(), indicator_type_lower
        ))
    # handle files
    if INDICATOR_TYPE_TO_CONTEXT_KEY[indicator_type_lower] == 'file':
        indicator_type_lower = 'file'
    dbot_entry = {
        outputPaths['dbotscore']: {
            'Indicator': indicator,
            'Type': indicator_type_lower,
            'Vendor': vendor,
            'Score': score
        }
    }
    if score == 3 and build_malicious:
        dbot_entry.update(build_malicious_dbot_entry(indicator, indicator_type, vendor, description))
    return dbot_entry


def build_malicious_dbot_entry(indicator, indicator_type, vendor, description=None):
    """ Build Malicious dbot entry
    Examples:
        >>> build_malicious_dbot_entry('8.8.8.8', 'ip', 'Vendor', 'Google DNS')
        {'IP(val.Address && val.Address == obj.Address)': {'Malicious': {'Vendor': 'Vendor', 'Description': 'Google DNS\
'}, 'Address': '8.8.8.8'}}

        >>> build_malicious_dbot_entry('md5hash', 'MD5', 'Vendor', 'Malicious File')
        {'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA\
256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTP\
H || val.SSDeep && val.SSDeep == obj.SSDeep)': {'Malicious': {'Vendor': 'Vendor', 'Description': 'Malicious File'}\
, 'MD5': 'md5hash'}}

    :type indicator: ``str``
    :param indicator: Value (e.g. 8.8.8.8)

    :type indicator_type: ``str``
    :param indicator_type: e.g. 'IP'

    :type vendor: ``str``
    :param vendor: Integration ID

    :type description: ``str``
    :param description: Why it's malicious

    :return: A malicious DBot entry
    :rtype: ``dict``
    """
    indicator_type_lower = indicator_type.lower()
    if indicator_type_lower in INDICATOR_TYPE_TO_CONTEXT_KEY:
        key = INDICATOR_TYPE_TO_CONTEXT_KEY[indicator_type_lower]
        # `file` indicator works a little different
        if key == 'file':
            entry = {
                indicator_type.upper(): indicator,
                'Malicious': {
                    'Vendor': vendor,
                    'Description': description
                }
            }
            return {outputPaths[key]: entry}
        else:
            entry = {
                key: indicator,
                'Malicious': {
                    'Vendor': vendor,
                    'Description': description
                }
            }
            return {outputPaths[indicator_type_lower]: entry}
    else:
        raise DemistoException('Wrong indicator type supplied: {}, expected {}'
                               .format(indicator_type, INDICATOR_TYPE_TO_CONTEXT_KEY.keys()))


# Will add only if 'requests' module imported
if 'requests' in sys.modules:
    if IS_PY3 and PY_VER_MINOR >= 10:
        from requests.packages.urllib3.util.ssl_ import create_urllib3_context

        # The ciphers string used to replace default cipher string

        CIPHERS_STRING = '@SECLEVEL=1:ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:ECDH+AESGCM:DH+AESGCM:' \
                         'ECDH+AES:DH+AES:RSA+ANESGCM:RSA+AES:!aNULL:!eNULL:!MD5:!DSS'

        class SSLAdapter(HTTPAdapter):
            """
                A wrapper used for https communication to enable ciphers that are commonly used
                and are not enabled by default
                :return: No data returned
                :rtype: ``None``
            """
            context = create_urllib3_context(ciphers=CIPHERS_STRING)

            def __init__(self, verify=True, **kwargs):
                # type: (bool, dict) -> None
                if not verify and IS_PY3:
                    self.context.check_hostname = False
                if not verify and ssl.OPENSSL_VERSION_INFO >= (3, 0, 0, 0):
                    self.context.options |= 0x4
                super().__init__(**kwargs)  # type: ignore[arg-type]

            def init_poolmanager(self, *args, **kwargs):
                kwargs['ssl_context'] = self.context
                return super(SSLAdapter, self).init_poolmanager(*args, **kwargs)

            def proxy_manager_for(self, *args, **kwargs):
                kwargs['ssl_context'] = self.context
                return super(SSLAdapter, self).proxy_manager_for(*args, **kwargs)

    class BaseClient(object):
        """Client to use in integrations with powerful _http_request
        :type base_url: ``str``
        :param base_url: Base server address with suffix, for example: https://example.com/api/v2/.

        :type verify: ``bool``
        :param verify: Whether the request should verify the SSL certificate.

        :type proxy: ``bool``
        :param proxy: Whether to run the integration using the system proxy.

        :type ok_codes: ``tuple`` or ``None``
        :param ok_codes:
            The request codes to accept as OK, for example: (200, 201, 204).
            Will use requests.Response.ok if set to None.

        :type headers: ``dict`` or ``None``
        :param headers:
            The request headers, for example: {'Accept`: `application/json`}.
            Can be None.

        :type auth: ``dict`` or ``tuple`` or ``None``
        :param auth:
            The request authorization, for example: (username, password).
            Can be None.

        :return: No data returned
        :rtype: ``None``
        """

        REQUESTS_TIMEOUT = 60

        def __init__(
            self,
            base_url,
            verify=True,
            proxy=False,
            ok_codes=tuple(),
            headers=None,
            auth=None,
            timeout=REQUESTS_TIMEOUT,
        ):
            self._base_url = base_url
            self._verify = verify
            self._ok_codes = ok_codes
            self._headers = headers
            self._auth = auth
            self._session = requests.Session()

            # the following condition was added to overcome the security hardening happened in Python 3.10.
            # https://github.com/python/cpython/pull/25778
            # https://bugs.python.org/issue43998

            if IS_PY3 and PY_VER_MINOR >= 10 and not verify:
                self._session.mount('https://', SSLAdapter(verify=verify))

            if proxy:
                ensure_proxy_has_http_prefix()
            else:
                skip_proxy()

            if not verify:
                skip_cert_verification()

            # removing trailing = char from env var value added by the server
            entity_timeout = os.getenv('REQUESTS_TIMEOUT.' + (get_integration_name() or get_script_name()), '')
            system_timeout = os.getenv('REQUESTS_TIMEOUT', '')
            self.timeout = float(entity_timeout or system_timeout or timeout)

            self.execution_metrics = ExecutionMetrics()

        def __del__(self):
            self._return_execution_metrics_results()
            try:
                self._session.close()
            except AttributeError:
                # we ignore exceptions raised due to session not used by the client and hence do not exist in __del__
                pass
            except Exception:  # noqa
                demisto.debug('failed to close BaseClient session with the following error:\n{}'.format(traceback.format_exc()))

        def _implement_retry(self, retries=0,
                             status_list_to_retry=None,
                             backoff_factor=5,
                             raise_on_redirect=False,
                             raise_on_status=False):
            """
            Implements the retry mechanism.
            In the default case where retries = 0 the request will fail on the first time

            :type retries: ``int``
            :param retries: How many retries should be made in case of a failure. when set to '0'- will fail on the first time

            :type status_list_to_retry: ``iterable``
            :param status_list_to_retry: A set of integer HTTP status codes that we should force a retry on.
                A retry is initiated if the request method is in ['GET', 'POST', 'PUT']
                and the response status code is in ``status_list_to_retry``.

            :type backoff_factor ``float``
            :param backoff_factor:
                A backoff factor to apply between attempts after the second try
                (most errors are resolved immediately by a second try without a
                delay). urllib3 will sleep for::

                    {backoff factor} * (2 ** ({number of total retries} - 1))

                seconds. If the backoff_factor is 0.1, then :func:`.sleep` will sleep
                for [0.0s, 0.2s, 0.4s, ...] between retries. It will never be longer
                than :attr:`Retry.BACKOFF_MAX`.

                By default, backoff_factor set to 5

            :type raise_on_redirect ``bool``
            :param raise_on_redirect: Whether, if the number of redirects is
                exhausted, to raise a MaxRetryError, or to return a response with a
                response code in the 3xx range.

            :type raise_on_status ``bool``
            :param raise_on_status: Similar meaning to ``raise_on_redirect``:
                whether we should raise an exception, or return a response,
                if status falls in ``status_forcelist`` range and retries have
                been exhausted.
            """
            try:
                method_whitelist = "allowed_methods" if hasattr(
                    Retry.DEFAULT, "allowed_methods") else "method_whitelist"  # type: ignore[attr-defined]
                whitelist_kawargs = {
                    method_whitelist: frozenset(['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
                }
                retry = Retry(
                    total=retries,
                    read=retries,
                    connect=retries,
                    backoff_factor=backoff_factor,
                    status=retries,
                    status_forcelist=status_list_to_retry,
                    raise_on_status=raise_on_status,
                    raise_on_redirect=raise_on_redirect,
                    **whitelist_kawargs  # type: ignore[arg-type]
                )
                http_adapter = HTTPAdapter(max_retries=retry)

                # the following condition was added to overcome the security hardening happened in Python 3.10.
                # https://github.com/python/cpython/pull/25778
                # https://bugs.python.org/issue43998

                if self._verify:
                    https_adapter = http_adapter
                elif IS_PY3 and PY_VER_MINOR >= 10:
                    https_adapter = SSLAdapter(max_retries=retry, verify=self._verify)  # type: ignore[arg-type]
                else:
                    https_adapter = http_adapter

                self._session.mount('https://', https_adapter)

            except NameError:
                pass

        def _http_request(self, method, url_suffix='', full_url=None, headers=None, auth=None, json_data=None,
                          params=None, data=None, files=None, timeout=None, resp_type='json', ok_codes=None,
                          return_empty_response=False, retries=0, status_list_to_retry=None,
                          backoff_factor=5, raise_on_redirect=False, raise_on_status=False,
                          error_handler=None, empty_valid_codes=None, params_parser=None, with_metrics=False, **kwargs):
            """A wrapper for requests lib to send our requests and handle requests and responses better.

            :type method: ``str``
            :param method: The HTTP method, for example: GET, POST, and so on.

            :type url_suffix: ``str``
            :param url_suffix: The API endpoint.

            :type full_url: ``str``
            :param full_url:
                Bypasses the use of self._base_url + url_suffix. This is useful if you need to
                make a request to an address outside of the scope of the integration
                API.

            :type headers: ``dict``
            :param headers: Headers to send in the request. If None, will use self._headers.

            :type auth: ``tuple``
            :param auth:
                The authorization tuple (usually username/password) to enable Basic/Digest/Custom HTTP Auth.
                if None, will use self._auth.

            :type params: ``dict``
            :param params: URL parameters to specify the query.

            :type data: ``dict``
            :param data: The data to send in a 'POST' request.

            :type json_data: ``dict``
            :param json_data: The dictionary to send in a 'POST' request.

            :type files: ``dict``
            :param files: The file data to send in a 'POST' request.

            :type timeout: ``float`` or ``tuple``
            :param timeout:
                The amount of time (in seconds) that a request will wait for a client to
                establish a connection to a remote machine before a timeout occurs.
                can be only float (Connection Timeout) or a tuple (Connection Timeout, Read Timeout).

            :type resp_type: ``str``
            :param resp_type:
                Determines which data format to return from the HTTP request. The default
                is 'json'. Other options are 'text', 'content', 'xml' or 'response'. Use 'response'
                 to return the full response object.

            :type ok_codes: ``tuple``
            :param ok_codes:
                The request codes to accept as OK, for example: (200, 201, 204). If you specify
                "None", will use self._ok_codes.

            :type retries: ``int``
            :param retries: How many retries should be made in case of a failure. when set to '0'- will fail on the first time

            :type status_list_to_retry: ``iterable``
            :param status_list_to_retry: A set of integer HTTP status codes that we should force a retry on.
                A retry is initiated if the request method is in ['GET', 'POST', 'PUT']
                and the response status code is in ``status_list_to_retry``.

            :type backoff_factor ``float``
            :param backoff_factor:
                A backoff factor to apply between attempts after the second try
                (most errors are resolved immediately by a second try without a
                delay). urllib3 will sleep for::

                    {backoff factor} * (2 ** ({number of total retries} - 1))

                seconds. If the backoff_factor is 0.1, then :func:`.sleep` will sleep
                for [0.0s, 0.2s, 0.4s, ...] between retries. It will never be longer
                than :attr:`Retry.BACKOFF_MAX`.

                By default, backoff_factor set to 5

            :type raise_on_redirect ``bool``
            :param raise_on_redirect: Whether, if the number of redirects is
                exhausted, to raise a MaxRetryError, or to return a response with a
                response code in the 3xx range.

            :type raise_on_status ``bool``
            :param raise_on_status: Similar meaning to ``raise_on_redirect``:
                whether we should raise an exception, or return a response,
                if status falls in ``status_forcelist`` range and retries have
                been exhausted.

            :type error_handler ``callable``
            :param error_handler: Given an error entry, the error handler outputs the
                new formatted error message.

            :type empty_valid_codes: ``list``
            :param empty_valid_codes: A list of all valid status codes of empty responses (usually only 204, but
                can vary)

            :type params_parser: ``callable``
            :param params_parser: How to quote the params. By default, spaces are replaced with `+` and `/` to `%2F`.
            see here for more info: https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlencode
            Note! supported only in python3.

            :type with_metrics ``bool``
            :param with_metrics: Whether or not to calculate execution metrics from the response

            :return: Depends on the resp_type parameter
            :rtype: ``dict`` or ``str`` or ``bytes`` or ``xml.etree.ElementTree.Element`` or ``requests.Response``
            """
            try:
                # Replace params if supplied
                address = full_url if full_url else urljoin(self._base_url, url_suffix)
                headers = headers if headers else self._headers
                auth = auth if auth else self._auth
                if retries:
                    self._implement_retry(retries, status_list_to_retry, backoff_factor, raise_on_redirect, raise_on_status)
                if not timeout:
                    timeout = self.timeout
                if IS_PY3 and params_parser:  # The `quote_via` parameter is supported only in python3.
                    params = urllib.parse.urlencode(params, quote_via=params_parser)

                # Execute
                res = self._session.request(
                    method,
                    address,
                    verify=self._verify,
                    params=params,
                    data=data,
                    json=json_data,
                    files=files,
                    headers=headers,
                    auth=auth,
                    timeout=timeout,
                    **kwargs
                )
                if not self._is_status_code_valid(res, ok_codes):
                    self._handle_error(error_handler, res, with_metrics)

                return self._handle_success(res, resp_type, empty_valid_codes, return_empty_response, with_metrics)

            except requests.exceptions.ConnectTimeout as exception:
                if with_metrics:
                    self.execution_metrics.timeout_error += 1
                err_msg = 'Connection Timeout Error - potential reasons might be that the Server URL parameter' \
                          ' is incorrect or that the Server is not accessible from your host.'
                raise DemistoException(err_msg, exception)
            except requests.exceptions.SSLError as exception:
                if with_metrics:
                    self.execution_metrics.ssl_error += 1
                # in case the "Trust any certificate" is already checked
                if not self._verify:
                    raise
                err_msg = 'SSL Certificate Verification Failed - try selecting \'Trust any certificate\' checkbox in' \
                          ' the integration configuration.'
                raise DemistoException(err_msg, exception)
            except requests.exceptions.ProxyError as exception:
                if with_metrics:
                    self.execution_metrics.proxy_error += 1
                err_msg = 'Proxy Error - if the \'Use system proxy\' checkbox in the integration configuration is' \
                          ' selected, try clearing the checkbox.'
                raise DemistoException(err_msg, exception)
            except requests.exceptions.ConnectionError as exception:
                if with_metrics:
                    self.execution_metrics.connection_error += 1
                # Get originating Exception in Exception chain
                error_class = str(exception.__class__)
                err_type = '<' + error_class[error_class.find('\'') + 1: error_class.rfind('\'')] + '>'

                err_msg = 'Verify that the server URL parameter' \
                          ' is correct and that you have access to the server from your host.' \
                          '\nError Type: {}'.format(err_type)
                if exception.errno and exception.strerror:
                    err_msg += '\nError Number: [{}]\nMessage: {}\n'.format(exception.errno, exception.strerror)
                else:
                    err_msg += '\n{}'.format(str(exception))
                raise DemistoException(err_msg, exception)

            except requests.exceptions.RetryError as exception:
                if with_metrics:
                    self.execution_metrics.retry_error += 1
                try:
                    reason = 'Reason: {}'.format(exception.args[0].reason.args[0])
                except Exception:  # noqa: disable=broad-except
                    reason = ''
                err_msg = 'Max Retries Error- Request attempts with {} retries failed. \n{}'.format(retries, reason)
                raise DemistoException(err_msg, exception)

        def _handle_error(self, error_handler, res, should_update_metrics):
            """ Handles error response by calling error handler or default handler.
            If an exception is raised, update metrics with failure. Otherwise, proceeds.

            :type res: ``requests.Response``
            :param res: Response from API after the request for which to check error type

            :type error_handler ``callable``
            :param error_handler: Given an error entry, the error handler outputs the
                new formatted error message.

            :type should_update_metrics ``bool``
            :param should_update_metrics: Whether or not to update execution metrics according to response
            """
            try:
                if error_handler:
                    error_handler(res)
                else:
                    self.client_error_handler(res)
            except Exception:
                if should_update_metrics:
                    self._update_metrics(res, success=False)
                raise

        def _handle_success(self, res, resp_type, empty_valid_codes, return_empty_response, should_update_metrics):
            """ Handles successful response

            :type res: ``requests.Response``
            :param res: Response from API after the request for which to check error type

            :type resp_type: ``str``
            :param resp_type:
                Determines which data format to return from the HTTP request. The default
                is 'json'. Other options are 'text', 'content', 'xml' or 'response'. Use 'response'
                 to return the full response object.

            :type empty_valid_codes: ``list``
            :param empty_valid_codes: A list of all valid status codes of empty responses (usually only 204, but
                can vary)

            :type return_empty_response: ``bool``
            :param response: Whether to return an empty response body if the response code is in empty_valid_codes

            :type should_update_metrics ``bool``
            :param should_update_metrics: Whether or not to update execution metrics according to response
            """
            if should_update_metrics:
                self._update_metrics(res, success=True)

            if not empty_valid_codes:
                empty_valid_codes = [204]
            is_response_empty_and_successful = (res.status_code in empty_valid_codes)
            if is_response_empty_and_successful and return_empty_response:
                return res

            return self.cast_response(res, resp_type)

        def cast_response(self, res, resp_type, raise_on_error=True):
            resp_type = resp_type.lower()
            try:
                if resp_type == 'json':
                    return res.json()
                if resp_type == 'text':
                    return res.text
                if resp_type == 'content':
                    return res.content
                if resp_type == 'xml':
                    ET.fromstring(res.text)
                if resp_type == 'response':
                    return res
                return res
            except ValueError as exception:
                if raise_on_error:
                    raise DemistoException('Failed to parse {} object from response: {}'  # type: ignore[str-bytes-safe]
                                           .format(resp_type, res.content), exception, res)

        def _update_metrics(self, res, success):
            """ Updates execution metrics based on response and success flag.

            :type response: ``requests.Response``
            :param response: Response from API after the request for which to check error type

            :type success: ``bool``
            :param success: Wheter the request succeeded or failed
            """
            if success:
                if not self.is_polling_in_progress(res):
                    self.execution_metrics.success += 1
            else:
                error_type = self.determine_error_type(res)
                if error_type == ErrorTypes.QUOTA_ERROR:
                    self.execution_metrics.quota_error += 1
                elif error_type == ErrorTypes.AUTH_ERROR:
                    self.execution_metrics.auth_error += 1
                elif error_type == ErrorTypes.SERVICE_ERROR:
                    self.execution_metrics.service_error += 1
                elif error_type == ErrorTypes.GENERAL_ERROR:
                    self.execution_metrics.general_error += 1

        def determine_error_type(self, response):
            """ Determines the type of error based on response status code and content.
            Note: this method can be overriden by subclass when implementing execution metrics.

            :type response: ``requests.Response``
            :param response: Response from API after the request for which to check error type

            :return: The error type if found, otherwise None
            :rtype: ``ErrorTypes``
            """
            if response.status_code == 401:
                return ErrorTypes.AUTH_ERROR
            elif response.status_code == 429:
                return ErrorTypes.QUOTA_ERROR
            elif response.status_code == 500:
                return ErrorTypes.SERVICE_ERROR
            return ErrorTypes.GENERAL_ERROR

        def is_polling_in_progress(self, response):
            """If thie response indicates polling operation in progress, return True.
            Note: this method should be overriden by subclass when implementing polling reputation commands
            with execution metrics.

            :type response: ``requests.Response``
            :param response: Response from API after the request for which to check the polling status

            :return: Whether the response indicates polling in progress
            :rtype: ``bool``
            """
            return False

        def _is_status_code_valid(self, response, ok_codes=None):
            """If the status code is OK, return 'True'.

            :type response: ``requests.Response``
            :param response: Response from API after the request for which to check the status.

            :type ok_codes: ``tuple`` or ``list``
            :param ok_codes:
                The request codes to accept as OK, for example: (200, 201, 204). If you specify
                "None", will use response.ok.

            :return: Whether the status of the response is valid.
            :rtype: ``bool``
            """
            # Get wanted ok codes
            status_codes = ok_codes if ok_codes else self._ok_codes
            if status_codes:
                return response.status_code in status_codes
            return response.ok

        def client_error_handler(self, res):
            """Generic handler for API call error
            Constructs and throws a proper error for the API call response.

            :type response: ``requests.Response``
            :param response: Response from API after the request for which to check the status.
            """
            err_msg = 'Error in API call [{}] - {}'.format(res.status_code, res.reason)
            try:
                # Try to parse json error response
                error_entry = res.json()
                err_msg += '\n{}'.format(json.dumps(error_entry))
                raise DemistoException(err_msg, res=res)
            except ValueError:
                err_msg += '\n{}'.format(res.text)
                raise DemistoException(err_msg, res=res)

        def _return_execution_metrics_results(self):
            """ Returns execution metrics results.
            Might raise an AttributeError exception if execution_metrics is not initialized.
            """
            try:
                if self.execution_metrics.metrics:
                    return_results(cast(CommandResults, self.execution_metrics.metrics))
            except AttributeError:
                pass


def generic_http_request(method,
                         server_url,
                         timeout=60,
                         verify=True,
                         proxy=False,
                         client_headers=None,
                         headers=None,
                         url_suffix=None,
                         data=None,
                         ok_codes=None,
                         auth=None,
                         error_handler=None,
                         files=None,
                         params=None,
                         retries=0,
                         resp_type='json',
                         status_list_to_retry=None,
                         json_data=None,
                         return_empty_response=False,
                         backoff_factor=5,
                         raise_on_redirect=False,
                         raise_on_status=False,
                         empty_valid_codes=None,
                         params_parser=None,
                         with_metrics=False,
                         **kwargs
                         ):
    """
        A wrapper for the BaseClient._http_request() method, that allows performing HTTP requests without initiating a BaseClient object.
        Note: Avoid using this method if unnecessary. It is more recommended to use the BaseClient class.

        Args:
            method (str): HTTP request method (e.g., GET, POST, PUT, DELETE).
            server_url (str): Base URL of the server.
            timeout (int, optional): Timeout in seconds for the request (defaults to 10).
            verify (bool, optional): Whether to verify SSL certificates (defaults to True).
            proxy (bool or str, optional): Use a proxy server. Can be a boolean (defaults to False)
                                           or a proxy URL string.
            client_headers (dict, optional): Additional headers to be included in all requests
                                             made by the client (overrides headers argument).
            headers (dict, optional): Additional headers for this specific request.
            url_suffix (str, optional): Path suffix to be appended to the server URL.
            data (object, optional): Data to be sent in the request body (e.g., dictionary for POST requests).
            ok_codes (list of int, optional): A list of HTTP status codes that are considered successful responses
                                               (defaults to [200]).
            auth (tuple, optional): Authentication credentials (username, password) for the request.
            error_handler (callable, optional): Function to handle request errors.
            files (dict, optional): Dictionary of files to be uploaded (for multipart/form-data requests).
            params (dict, optional): URL parameters to be included in the request.
            retries (int, optional): Number of times to retry the request on failure (defaults to 0).
            retries (int, optional): Number of times to retry the request on failure (defaults to 0).
            status_list_to_retry (int, optional): A set of integer HTTP status codes that we should force a retry on.
                A retry is initiated if the request method is in ['GET', 'POST', 'PUT']
                and the response status code is in ``status_list_to_retry``.
            resp_type (iterable, optional): Determines which data format to return from the HTTP request. The default
                is 'json'.
            json_data (dict, optional): The dictionary to send in a 'POST' request.
            backoff_factor (float, optional): A backoff factor to apply between attempts after the second try
                (most errors are resolved immediately by a second try without a
                delay). urllib3 will sleep for::

                    {backoff factor} * (2 ** ({number of total retries} - 1))

                seconds. If the backoff_factor is 0.1, then :func:`.sleep` will sleep
                for [0.0s, 0.2s, 0.4s, ...] between retries. It will never be longer
                than :attr:`Retry.BACKOFF_MAX`.

                By default, backoff_factor set to 5

            raise_on_redirect (bool, optional): Whether, if the number of redirects is
                exhausted, to raise a MaxRetryError, or to return a response with a
                response code in the 3xx range.

            raise_on_status (bool,optional): Similar meaning to ``raise_on_redirect``:
                whether we should raise an exception, or return a response,
                if status falls in ``status_forcelist`` range and retries have
                been exhausted.

            empty_valid_codes (list, optional): A list of all valid status codes of empty responses (usually only 204, but
                can vary)

            return_empty_response (bool, optional): Whether to return an empty response body if the response code is in empty_valid_codes

            params_parser (callable, optional): How to quote the params. By default, spaces are replaced with `+` and `/` to `%2F`.
            see here for more info: https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlencode
            Note! supported only in python3.

            with_metrics (bool, optional): Whether or not to calculate execution metrics from the response

        Returns:
            :return: Depends on the resp_type parameter
            :rtype: ``dict`` or ``str`` or ``bytes`` or ``xml.etree.ElementTree.Element`` or ``requests.Response``

        Raises:
            exceptions.RequestException: If an error occurs during the request.
    """
    client = BaseClient(base_url=server_url,
                        verify=verify,
                        proxy=proxy,
                        ok_codes=ok_codes,
                        headers=client_headers,
                        auth=auth,
                        timeout=timeout
                        )

    return client._http_request(method=method, url_suffix=url_suffix, data=data, ok_codes=ok_codes, error_handler=error_handler,
                                headers=headers, files=files, params=params, retries=retries, resp_type=resp_type,
                                status_list_to_retry=status_list_to_retry, json_data=json_data,
                                return_empty_response=return_empty_response, backoff_factor=backoff_factor,
                                raise_on_redirect=raise_on_redirect, raise_on_status=raise_on_status,
                                empty_valid_codes=empty_valid_codes, params_parser=params_parser, with_metrics=with_metrics,
                                **kwargs)


def batch(iterable, batch_size=1):
    """Gets an iterable and yields slices of it.

    :type iterable: ``list``
    :param iterable: list or other iterable object.

    :type batch_size: ``int``
    :param batch_size: the size of batches to fetch

    :rtype: ``list``
    :return:: Iterable slices of given
    """
    current_batch = iterable[:batch_size]
    not_batched = iterable[batch_size:]
    while current_batch:
        yield current_batch
        current_batch = not_batched[:batch_size]
        not_batched = not_batched[batch_size:]


def dict_safe_get(dict_object, keys, default_return_value=None, return_type=None, raise_return_type=True):
    """Recursive safe get query (for nested dicts and lists), If keys found return value otherwise return None or default value.
    Example:
    >>> data = {"something" : {"test": "A"}}
    >>> dict_safe_get(data, ['something', 'test'])
    >>> 'A'
    >>> dict_safe_get(data, ['something', 'else'], 'default value')
    >>> 'default value'

    :type dict_object: ``dict``
    :param dict_object: dictionary to query.

    :type keys: ``list``
    :param keys: keys for recursive get.

    :type default_return_value: ``object``
    :param default_return_value: Value to return when no key available.

    :type return_type: ``type``
    :param return_type: Excepted return type.

    :type raise_return_type: ``bool``
    :param raise_return_type: Whether to raise an error when the value didn't match the expected return type.

    :rtype: ``object``
    :return:: Value from nested query.
    """
    return_value = dict_object

    for key in keys:
        try:
            return_value = return_value[key]
        except (KeyError, TypeError, IndexError, AttributeError):
            return_value = default_return_value
            break

    if return_type and not isinstance(return_value, return_type):
        if raise_return_type:
            raise TypeError("Safe get Error:\nDetails: Return Type Error Excepted return type {0},"
                            " but actual type from nested dict/list is {1} with value {2}.\n"
                            "Query: {3}\nQueried object: {4}".format(return_type, type(return_value),
                                                                     return_value, keys, dict_object))
        return_value = default_return_value

    return return_value


CONTEXT_UPDATE_RETRY_TIMES = 3
MIN_VERSION_FOR_VERSIONED_CONTEXT = '6.0.0'


def merge_lists(original_list, updated_list, key):
    """
    Replace values in a list with those in an updated list.
    Example:
    >>> original = [{'id': '1', 'updated': 'n'}, {'id': '2', 'updated': 'n'}, {'id': '11', 'updated': 'n'}]
    >>> updated = [{'id': '1', 'updated': 'y'}, {'id': '3', 'updated': 'y'}, {'id': '11', 'updated': 'n',
    >>>                                                                                             'remove': True}]
    >>> result = [{'id': '1', 'updated': 'y'}, {'id': '2', 'updated': 'n'}, {'id': '3', 'updated': 'y'}]

    :type original_list: ``list``
    :param original_list: The original list.

    :type updated_list: ``list``
    :param updated_list: The updated list.

    :type key: ``str``
    :param key: The key to replace elements by.

    :rtype: ``list``
    :return: The merged list.

    """

    original_dict = {element[key]: element for element in original_list}
    updated_dict = {element[key]: element for element in updated_list}
    original_dict.update(updated_dict)

    removed = [obj for obj in original_dict.values() if obj.get('remove', False) is True]
    for r in removed:
        demisto.debug('Removing from integration context: {}'.format(str(r)))

    merged_list = [obj for obj in original_dict.values() if obj.get('remove', False) is False]

    return merged_list


def set_integration_context(context, sync=True, version=-1):
    """
    Sets the integration context.

    :type context: ``dict``
    :param context: The context to set.

    :type sync: ``bool``
    :param sync: Whether to save the context directly to the DB.

    :type version: ``Any``
    :param version: The version of the context to set.

    :rtype: ``dict``
    :return: The new integration context
    """
    demisto.debug('Setting integration context')
    if is_versioned_context_available():
        demisto.debug('Updating integration context with version {}. Sync: {}'.format(version, sync))
        return demisto.setIntegrationContextVersioned(context, version, sync)
    else:
        return demisto.setIntegrationContext(context)


def get_integration_context(sync=True, with_version=False):
    """
    Gets the integration context.

    :type sync: ``bool``
    :param sync: Whether to get the integration context directly from the DB.

    :type with_version: ``bool``
    :param with_version: Whether to return the version.

    :rtype: ``dict``
    :return: The integration context.
    """
    if is_versioned_context_available():
        integration_context = demisto.getIntegrationContextVersioned(sync)

        if with_version:
            return integration_context
        else:
            return integration_context.get('context', {})
    else:
        return demisto.getIntegrationContext()


def is_versioned_context_available():
    """
    Determines whether versioned integration context is available according to the server version.

    :rtype: ``bool``
    :return: Whether versioned integration context is available
    """
    return is_demisto_version_ge(MIN_VERSION_FOR_VERSIONED_CONTEXT)


def set_to_integration_context_with_retries(context, object_keys=None, sync=True,
                                            max_retry_times=CONTEXT_UPDATE_RETRY_TIMES):
    """
    Update the integration context with a dictionary of keys and values with multiple attempts.
    The function supports merging the context keys using the provided object_keys parameter.
    If the version is too old by the time the context is set,
    another attempt will be made until the limit after a random sleep.

    :type context: ``dict``
    :param context: A dictionary of keys and values to set.

    :type object_keys: ``dict``
    :param object_keys: A dictionary to map between context keys and their unique ID for merging them.

    :type sync: ``bool``
    :param sync: Whether to save the context directly to the DB.

    :type max_retry_times: ``int``
    :param max_retry_times: The maximum number of attempts to try.

    :rtype: ``None``
    :return: None
    """
    attempt = 0

    # do while...
    while True:
        if attempt == max_retry_times:
            raise Exception('Failed updating integration context. Max retry attempts exceeded.')

        # Update the latest context and get the new version
        integration_context, version = update_integration_context(context, object_keys, sync)

        demisto.debug('Attempting to update the integration context with version {}.'.format(version))

        # Attempt to update integration context with a version.
        # If we get a ValueError (DB Version), then the version was not updated and we need to try again.
        attempt += 1
        try:
            set_integration_context(integration_context, sync, version)
            demisto.debug('Successfully updated integration context with version {}.'
                          ''.format(version))
            break
        except ValueError as ve:
            demisto.debug('Failed updating integration context with version {}: {} Attempts left - {}'
                          ''.format(version, str(ve), CONTEXT_UPDATE_RETRY_TIMES - attempt))
            # Sleep for a random time
            time_to_sleep = randint(1, 100) / 1000
            time.sleep(time_to_sleep)  # pylint: disable=E9003


def get_integration_context_with_version(sync=True):
    """
    Get the latest integration context with version, if available.

    :type sync: ``bool``
    :param sync: Whether to get the context directly from the DB.

    :rtype: ``tuple``
    :return: The latest integration context with version.
    """
    latest_integration_context_versioned = get_integration_context(sync, with_version=True)
    version = -1
    if is_versioned_context_available():
        integration_context = latest_integration_context_versioned.get('context', {})
        if sync:
            version = latest_integration_context_versioned.get('version', 0)
    else:
        integration_context = latest_integration_context_versioned

    return integration_context, version


def update_integration_context(context, object_keys=None, sync=True):
    """
    Update the integration context with a given dictionary after merging it with the latest integration context.

    :type context: ``dict``
    :param context: The keys and values to update in the integration context.

    :type object_keys: ``dict``
    :param object_keys: A dictionary to map between context keys and their unique ID for merging them
    with the latest context.

    :type sync: ``bool``
    :param sync: Whether to use the context directly from the DB.

    :rtype: ``tuple``
    :return: The updated integration context along with the current version.

    """
    integration_context, version = get_integration_context_with_version(sync)
    if not object_keys:
        object_keys = {}

    for key, _ in context.items():
        latest_object = json.loads(integration_context.get(key, '[]'))
        updated_object = context[key]
        if key in object_keys:
            merged_list = merge_lists(latest_object, updated_object, object_keys[key])
            integration_context[key] = json.dumps(merged_list)
        else:
            integration_context[key] = json.dumps(updated_object)

    return integration_context, version


class DemistoException(Exception):
    def __init__(self, message, exception=None, res=None, error_type=None, *args):
        self.res = res
        self.message = message
        self.exception = exception
        self.error_type = error_type
        super(DemistoException, self).__init__(message, exception, error_type, *args)

    def __str__(self):
        return str(self.message)


class GetRemoteDataArgs:
    """get-remote-data args parser
    :type args: ``dict``
    :param args: arguments for the command.

    :return: No data returned
    :rtype: ``None``
    """

    def __init__(self, args):
        self.remote_incident_id = args['id']
        self.last_update = args['lastUpdate']


class GetModifiedRemoteDataArgs:
    """get-modified-remote-data args parser
    :type args: ``dict``
    :param args: arguments for the command.

    :return: No data returned
    :rtype: ``None``
    """

    def __init__(self, args):
        self.last_update = args['lastUpdate']


class UpdateRemoteSystemArgs:
    """update-remote-system args parser
    :type args: ``dict``
    :param args: arguments for the command of the command.

    :return: No data returned
    :rtype: ``None``
    """

    def __init__(self, args):
        self.data = args.get('data')  # type: ignore
        self.entries = args.get('entries')
        self.incident_changed = args.get('incidentChanged')
        self.remote_incident_id = args.get('remoteId')
        self.inc_status = args.get('status')
        self.delta = args.get('delta')


class GetRemoteDataResponse:
    """get-remote-data response parser
    :type mirrored_object: ``dict``
    :param mirrored_object: The object you are mirroring, in most cases the incident.

    :type entries: ``list``
    :param entries: The entries you want to add to the war room.

    :return: No data returned
    :rtype: ``None``
    """

    def __init__(self, mirrored_object, entries):
        self.mirrored_object = mirrored_object
        self.entries = entries

    def extract_for_local(self):
        """Extracts the response into the mirrored incident.

        :return: List of details regarding the mirrored incident.
        :rtype: ``list``
        """
        if self.mirrored_object:
            return [self.mirrored_object] + self.entries


class GetModifiedRemoteDataResponse:
    """get-modified-remote-data response parser
    :type modified_incident_ids: ``list``
    :param modified_incident_ids: The incidents that were modified since the last check.

    :return: No data returned
    :rtype: ``None``
    """

    def __init__(self, modified_incident_ids):
        self.modified_incident_ids = modified_incident_ids

    def to_entry(self):
        """Extracts the response

        :return: List of incidents to run the get-remote-data command on.
        :rtype: ``list``
        """
        demisto.info('Modified incidents: {}'.format(self.modified_incident_ids))
        return {'Contents': self.modified_incident_ids, 'Type': EntryType.NOTE, 'ContentsFormat': EntryFormat.JSON}


class SchemeTypeMapping:
    """Scheme type mappings builder.

    :type type_name: ``str``
    :param type_name: The name of the remote incident type.

    :type fields: ``dict``
    :param fields: The dict of fields to their description.

    :return: No data returned
    :rtype: ``None``
    """

    def __init__(self, type_name='', fields=None):
        self.type_name = type_name
        self.fields = fields if fields else {}

    def add_field(self, name, description=''):
        """Adds a field to the incident type mapping.

        :type name: ``str``
        :param name: The name of the field.

        :type description: ``str``
        :param description: The description for that field.a

        :return: No data returned
        :rtype: ``None``
        """
        self.fields.update({
            name: description
        })

    def extract_mapping(self):
        """Extracts the mapping into XSOAR mapping screen.

        :return: the mapping object for the current field.
        :rtype: ``dict``
        """
        return {
            self.type_name: self.fields
        }


class GetMappingFieldsResponse:
    """Handler for the mapping fields object.

    :type scheme_types_mapping: ``list``
    :param scheme_types_mapping: List of all the mappings in the remote system.

    :return: No data returned
    :rtype: ``None``
    """

    def __init__(self, scheme_types_mapping=None):
        self.scheme_types_mappings = scheme_types_mapping if scheme_types_mapping else []

    def add_scheme_type(self, scheme_type_mapping):
        """Add another incident type mapping.

        :type scheme_type_mapping: ``dict``
        :param scheme_type_mapping: mapping of a singular field.

        :return: No data returned
        :rtype: ``None``
        """
        self.scheme_types_mappings.append(scheme_type_mapping)

    def extract_mapping(self):
        """Extracts the mapping into XSOAR mapping screen.

        :return: the mapping object for the current field.
        :rtype: ``dict``
        """
        all_mappings = {}
        for scheme_types_mapping in self.scheme_types_mappings:
            all_mappings.update(scheme_types_mapping.extract_mapping())

        return all_mappings


def get_x_content_info_headers():
    """Get X-Content-* headers to send in outgoing requests to use when performing requests to
    external services such as oproxy.

    :return: headers dict
    :rtype: ``dict``
    """
    calling_context = demisto.callingContext.get('context', {})
    brand_name = calling_context.get('IntegrationBrand', '')
    instance_name = calling_context.get('IntegrationInstance', '')
    headers = {
        'X-Content-Version': CONTENT_RELEASE_VERSION,
        'X-Content-Name': brand_name or instance_name or 'Name not found',
        'X-Content-LicenseID': demisto.getLicenseID(),
        'X-Content-Branch': CONTENT_BRANCH_NAME,
        'X-Content-Server-Version': get_demisto_version_as_str(),
    }
    return headers


class BaseWidget:
    @abstractmethod
    def to_display(self):
        pass


class TextWidget(BaseWidget):
    """Text Widget representation

    :type text: ``str``
    :param text: The text for the widget to display

    :return: No data returned
    :rtype: ``None``
    """

    def __init__(self, text):
        # type: (str) -> None
        self.text = text

    def to_display(self):
        """Text Widget representation

        :type text: ``str``
        :param text: The text for the widget to display

        :return: No data returned
        :rtype: ``None``
        """
        return self.text


class TrendWidget(BaseWidget):
    """Trend Widget representation

    :type current_number: ``int``
    :param current_number: The Current number in the trend.

    :type previous_number: ``int``
    :param previous_number: The previous number in the trend.

    :return: No data returned
    :rtype: ``None``
    """

    def __init__(self, current_number, previous_number):
        # type: (int, int) -> None
        self.current_number = current_number
        self.previous_number = previous_number

    def to_display(self):
        return json.dumps({
            'currSum': self.current_number,
            'prevSum': self.previous_number
        })


class NumberWidget(BaseWidget):
    """Number Widget representation

    :type number: ``int``
    :param number: The number for the widget to display.

    :return: No data returned
    :rtype: ``None``
    """

    def __init__(self, number):
        # type: (int) -> None
        self.number = number

    def to_display(self):
        return self.number


class BarColumnPieWidget(BaseWidget):
    """Bar/Column/Pie Widget representation

    :type categories: ``list``
    :param categories: a list of categories to display(Better use the add_category function to populate the data.

    :return: No data returned
    :rtype: ``None``
    """

    def __init__(self, categories=None):
        # type: (list) -> None
        self.categories = categories if categories else []  # type: List[dict]

    def add_category(self, name, number):
        """Add a category to widget.

        :type name: ``str``
        :param name: the name of the category to add.

        :type number: ``int``
        :param number: the number value of the category.

        :return: No data returned.
        :rtype: ``None``
        """
        self.categories.append({
            'name': name,
            'data': [number]
        })

    def to_display(self):
        return json.dumps(self.categories)


class LineWidget(BaseWidget):
    """Line Widget representation

    :type categories: ``Any``
    :param categories: a list of categories to display(Better use the add_category function to populate the data.

    :return: No data returned
    :rtype: ``None``
    """

    def __init__(self, categories=None):
        # type: (list) -> None
        self.categories = categories if categories else []  # type: List[dict]

    def add_category(self, name, number, group):
        """Add a category to widget.

        :type name: ``str``
        :param name: the name of the category to add.

        :type number: ``int``
        :param number: the number value of the category.

        :type group: ``str``
        :param group: the name of the relevant group.

        :return: No data returned
        :rtype: ``None``
        """
        self.categories.append({
            'name': name,
            'data': [number],
            'groups': [
                {
                    'name': group,
                    'data': [number]
                },
            ]
        })

    def to_display(self):
        processed_names = []  # type: List[str]
        processed_categories = []  # type: List[dict]
        for cat in self.categories:
            if cat['name'] in processed_names:
                for processed_category in processed_categories:
                    if cat['name'] == processed_category['name']:
                        processed_category['data'] = [processed_category['data'][0] + cat['data'][0]]
                        processed_category['groups'].extend(cat['groups'])
                        break

            else:
                processed_categories.append(cat)
                processed_names.append(cat['name'])

        return json.dumps(processed_categories)


class TableOrListWidget(BaseWidget):
    """Table/List Widget representation

    :type data: ``Any``
    :param data: a list of data to display(Better use the add_category function to populate the data.

    :return: No data returned
    :rtype: ``None``
    """

    def __init__(self, data=None):
        # type: (Any) -> None
        self.data = data if data else []
        if not isinstance(self.data, list):
            self.data = [data]

    def add_row(self, data):
        """Add a row to the widget.

        :type data: ``Any``
        :param data: the data to add to the list/table.

        :return: No data returned
        :rtype: ``None``
        """
        self.data.append(data)

    def to_display(self):
        return json.dumps({
            'total': len(self.data),
            'data': self.data
        })


class IndicatorsSearcher:
    """Used in order to search indicators by the paging or serachAfter param
    :type page: ``int``
    :param page: the number of page from which we start search indicators from.

    :type filter_fields: ``Optional[str]``
    :param filter_fields: comma separated fields to filter (e.g. "value,type")

    :type from_date: ``Optional[str]``
    :param from_date: the start date to search from.

    :type query: ``Optional[str]``
    :param query: indicator search query

    :type to_date: ``Optional[str]``
    :param to_date: the end date to search until to.

    :type value: ``str``
    :param value: the indicator value to search.

    :type limit: ``Optional[int]``
    :param limit: the current upper limit of the search (can be updated after init)

    :type sort: ``List[Dict]``
    :param sort: An array of sort params ordered by importance. Item structure: {"field": string, "asc": boolean}

    :return: No data returned
    :rtype: ``None``
    """
    SEARCH_AFTER_TITLE = 'searchAfter'

    def __init__(self,
                 page=0,
                 filter_fields=None,
                 from_date=None,
                 query=None,
                 size=100,
                 to_date=None,
                 value='',
                 limit=None,
                 sort=None,
                 search_after=None
                 ):
        # searchAfter is available in searchIndicators from version 6.1.0
        self._can_use_search_after = True
        # populateFields merged in https://github.com/demisto/server/pull/18398
        self._can_use_filter_fields = True
        self._search_after_param = search_after
        self._page = page
        self._filter_fields = filter_fields
        self._total = None
        self._from_date = from_date
        self._query = query
        self._size = size
        self._to_date = to_date
        self._value = value
        self._limit = limit
        self._total_iocs_fetched = 0
        self._sort = sort

    def __iter__(self):
        return self

    # python2
    def next(self):
        return self.__next__()

    def __next__(self):
        if self.is_search_done():
            raise StopIteration
        res = self.search_indicators_by_version(from_date=self._from_date,
                                                query=self._query,
                                                size=self._size,
                                                to_date=self._to_date,
                                                value=self._value)
        fetched_len = len(res.get('iocs') or [])
        if fetched_len == 0:
            raise StopIteration
        self._total_iocs_fetched += fetched_len
        return res

    @property
    def page(self):
        return self._page

    @property
    def total(self):
        return self._total

    @property
    def limit(self):
        return self._limit

    @limit.setter
    def limit(self, value):
        self._limit = value

    def is_search_done(self):
        """
        Return True if one of these conditions is met (else False):
        1. self.limit is set, and it's updated to be less or equal to zero - return True
        2. for search_after if self.total was populated by a previous search, but no self._search_after_param
        3. for page if self.total was populated by a previous search, but page is too large
        """
        reached_limit = self.limit is not None and self.limit <= self._total_iocs_fetched
        if reached_limit:
            demisto.debug("IndicatorsSearcher has reached its limit: {}".format(self.limit))
            # update limit to match _total_iocs_fetched value
            if self._total_iocs_fetched > self.limit:
                self.limit = self._total_iocs_fetched
            return True
        else:
            if self.total is None:
                return False
            no_more_indicators = self.total and self._search_after_param is None
            if no_more_indicators:
                demisto.debug("IndicatorsSearcher can not fetch anymore indicators")
            return no_more_indicators

    def search_indicators_by_version(self, from_date=None, query='', size=100, to_date=None, value=''):
        """There are 2 cases depends on the sever version:
        1. Search indicators using paging, raise the page number in each call.
        2. Search indicators using searchAfter param, update the _search_after_param in each call.

        :type from_date: ``Optional[str]``
        :param from_date: the start date to search from.

        :type query: ``Optional[str]``
        :param query: indicator search query

        :type size: ``int``
        :param size: limit the number of returned results.

        :type to_date: ``Optional[str]``
        :param to_date: the end date to search until to.

        :type value: ``str``
        :param value: the indicator value to search.

        :return: object contains the search results
        :rtype: ``dict``
        """
        search_args = assign_params(
            fromDate=from_date,
            toDate=to_date,
            query=query,
            size=size,
            value=value,
            searchAfter=self._search_after_param,
            populateFields=self._filter_fields,
        )
        if is_demisto_version_ge('6.6.0'):
            search_args['sort'] = self._sort
        demisto.debug('IndicatorsSearcher: page {}, search_args: {}'.format(self._page, search_args))
        res = demisto.searchIndicators(**search_args)
        self._total = res.get('total')
        demisto.debug('IndicatorsSearcher: page {}, result size: {}'.format(self._page, self._total))
        # when total is None, there is a problem with the server for returning indicators, hence need to restart the container,
        # see XSUP-26699
        if self._total is None:
            raise SystemExit(
                "Encountered issue when trying to fetch indicators for integration in instance {integration}. "
                "Restarting container and trying again.".format(integration=get_integration_instance_name())
            )
        if isinstance(self._page, int):
            self._page += 1  # advance pages
        self._search_after_param = res.get(self.SEARCH_AFTER_TITLE)
        return res


class AutoFocusKeyRetriever:
    """AutoFocus API Key management class
    :type api_key: ``str``
    :param api_key: Auto Focus API key coming from the integration parameters
    :type override_default_credentials: ``bool``
    :param override_default_credentials: Whether to override the default credentials and use the
     Cortex XSOAR given AutoFocus API Key
    :return: No data returned
    :rtype: ``None``
    """

    def __init__(self, api_key):
        # demisto.getAutoFocusApiKey() is available from version 6.2.0
        if not api_key:
            try:
                api_key = demisto.getAutoFocusApiKey()  # is not available on tenants
            except ValueError as err:
                raise DemistoException('AutoFocus API Key is only available on the main account for TIM customers. ' + str(err))
        self.key = api_key


def get_feed_last_run():
    """
    This function gets the feed's last run: using `demisto.getLastRun()`.
    :rtype: ``dict``
    :return: All indicators from the feed's last run
    """
    feed_last_run = demisto.getLastRun() or {}
    if not feed_last_run:
        integration_ctx = demisto.getIntegrationContext()
        if integration_ctx:
            feed_last_run = integration_ctx
            demisto.setLastRun(feed_last_run)
            demisto.setIntegrationContext({})
    return feed_last_run


def set_feed_last_run(last_run_indicators):
    """
    This function sets the feed's last run: using `demisto.setLastRun()`.
    :type last_run_indicators: ``dict``
    :param last_run_indicators: Indicators to save in "lastRun" object.
    :rtype: ``None``
    :return: None
    """
    demisto.setLastRun(last_run_indicators)


def set_last_mirror_run(last_mirror_run):  # type: (Dict[Any, Any]) -> None
    """
    This function sets the last run of the mirror, from XSOAR version 6.6.0, by using `demisto.setLastMirrorRun()`.
    Before XSOAR version 6.6.0, we don't set the given data and an exception will be raised.
    :type last_mirror_run: ``dict``
    :param last_mirror_run: Data to save in the "LastMirrorRun" object.
    :rtype: ``None``
    :return: None
    """
    if is_demisto_version_ge('6.6.0'):
        try:
            demisto.setLastMirrorRun(last_mirror_run)
        except json.JSONDecodeError as e:
            # see XSUP-24343
            if not isinstance(last_mirror_run, dict):
                raise TypeError("non-dictionary passed to set_last_mirror_run")
            demisto.debug(
                "encountered JSONDecodeError from server during setLastMirrorRun. As long as the value passed can be converted to json, this error can be ignored.")
            demisto.debug(e)
    else:
        raise DemistoException("You cannot use setLastMirrorRun as your version is below 6.6.0")


def get_last_mirror_run():  # type: () -> Optional[Dict[Any, Any]]
    """
    This function gets the last run of the mirror, from XSOAR version 6.6.0, using `demisto.getLastMirrorRun()`.
    Before XSOAR version 6.6.0, the given data is not returned and an exception will be raised.
    :rtype: ``dict``
    :return: A dictionary representation of the data that was already set in the previous runs (or an empty dict if
     we did not set anything yet).
    """
    if is_demisto_version_ge('6.6.0'):
        return demisto.getLastMirrorRun() or {}
    raise DemistoException("You cannot use getLastMirrorRun as your version is below 6.6.0")


def support_multithreading():  # pragma: no cover
    """Adds lock on the calls to the Cortex XSOAR server from the Demisto object to support integration which use multithreading.

    :return: No data returned
    :rtype: ``None``
    """
    global HAVE_SUPPORT_MULTITHREADING_CALLED_ONCE
    if HAVE_SUPPORT_MULTITHREADING_CALLED_ONCE:
        return
    HAVE_SUPPORT_MULTITHREADING_CALLED_ONCE = True
    global demisto
    prev_do = demisto._Demisto__do  # type: ignore[attr-defined]
    demisto.lock = Lock()  # type: ignore[attr-defined]

    def locked_do(cmd):
        if demisto.lock.acquire(timeout=60):  # type: ignore[call-arg,attr-defined]
            try:
                return prev_do(cmd)  # type: ignore[call-arg]
            finally:
                demisto.lock.release()  # type: ignore[attr-defined]
        else:
            raise RuntimeError('Failed acquiring lock')

    demisto._Demisto__do = locked_do  # type: ignore[attr-defined]


def get_tenant_account_name():
    """Gets the tenant name from the server url.

    :return: The account name.
    :rtype: ``str``

    """
    urls = demisto.demistoUrls()
    server_url = urls.get('server', '')
    account_name = ''
    if '/acc_' in server_url:
        tenant_name = server_url.split('acc_')[-1]
        account_name = "acc_{}".format(tenant_name) if tenant_name != "" else ""

    return account_name


def indicators_value_to_clickable(indicators):
    """
    Function to get the indicator url link for indicators

    :type indicators: ``dict`` + List[dict]
    :param indicators: An indicator or a list of indicators

    :rtype: ``dict``
    :return: Key is the indicator, and the value is it's url in the server

    """
    if not isinstance(indicators, (list, dict)):
        return {}
    if not isinstance(indicators, list):
        indicators = [indicators]
    res = {}
    query = ' or '.join(['value:{indicator}'.format(indicator=indicator) for indicator in indicators])
    indicator_searcher = IndicatorsSearcher(query=query)
    for ioc_res in indicator_searcher:
        for inidicator_data in ioc_res.get('iocs', []):
            indicator = inidicator_data.get('value')
            indicator_id = inidicator_data.get('id')
            if not indicator or not indicator_id:
                raise DemistoException('The response of indicator searcher is invalid')
            indicator_url = os.path.join('#', 'indicator', indicator_id)
            res[indicator] = '[{indicator}]({indicator_url})'.format(indicator=indicator, indicator_url=indicator_url)
    return res


def get_message_threads_dump(_sig, _frame):
    """
    Listener function to dump the threads to log info

    :type _sig: ``int``
    :param _sig: The signal number

    :type _frame: ``Any``
    :param _frame: The current stack frame

    :return: Message to print.
    :rtype: ``str``
    """
    code = []
    for threadId, stack in sys._current_frames().items():
        code.append("\n# ThreadID: %s" % threadId)
        for filename, lineno, name, line in traceback.extract_stack(stack):
            code.append('File: "%s", line %d, in %s' % (filename, lineno, name))
            if line:
                code.append("  %s" % (line.strip()))

    ret_value = '\n\n--- Start Threads Dump ---\n' \
                + '\n'.join(code) \
                + '\n\n--- End Threads Dump ---\n'
    return ret_value


def get_message_memory_dump(_sig, _frame):
    """
    Listener function to dump the memory to log info

    :type _sig: ``int``
    :param _sig: The signal number

    :type _frame: ``Any``
    :param _frame: The current stack frame

    :return: Message to print.
    :rtype: ``str``
    """
    classes_dict = {}  # type: Dict[str, Dict]
    for obj in gc.get_objects():
        size = sys.getsizeof(obj, 0)
        if hasattr(obj, '__class__'):
            cls = str(obj.__class__)[8:-2]
            if cls in classes_dict:
                current_class = classes_dict.get(cls, {})  # type: Dict
                current_class['count'] += 1  # type: ignore
                current_class['size'] += size  # type: ignore
                classes_dict[cls] = current_class
            else:
                current_class = {
                    'name': cls,
                    'count': 1,
                    'size': size,
                }
                classes_dict[cls] = current_class

    classes_as_list = list(classes_dict.values())
    ret_value = '\n\n--- Start Variables Dump ---\n'
    ret_value += get_message_classes_dump(classes_as_list)
    ret_value += '\n--- End Variables Dump ---\n\n'

    ret_value = '\n\n--- Start Variables Dump ---\n'
    ret_value += get_message_local_vars()
    ret_value += get_message_global_vars()
    ret_value += '\n--- End Variables Dump ---\n\n'

    ret_value += get_message_modules_sizes()

    return ret_value


def get_message_classes_dump(classes_as_list):
    """
    A function that returns the printable message about classes dump

    :type classes_as_list: ``list``
    :param classes_as_list: The classes to print to the log

    :return: Message to print.
    :rtype: ``str``
    """

    ret_value = '\n\n--- Start Memory Dump ---\n'

    ret_value += '\n--- Start Top {} Classes by Count ---\n\n'.format(PROFILING_DUMP_ROWS_LIMIT)
    classes_sorted_by_count = sorted(classes_as_list, key=lambda d: d['count'], reverse=True)
    ret_value += 'Count\t\tSize\t\tName\n'
    for current_class in classes_sorted_by_count[:PROFILING_DUMP_ROWS_LIMIT]:
        ret_value += '{}\t\t{}\t\t{}\n'.format(current_class["count"], current_class["size"], current_class["name"])
    ret_value += '\n--- End Top {} Classes by Count ---\n'.format(PROFILING_DUMP_ROWS_LIMIT)

    ret_value += '\n--- Start Top {} Classes by Size ---\n'.format(PROFILING_DUMP_ROWS_LIMIT)
    classes_sorted_by_size = sorted(classes_as_list, key=lambda d: d['size'], reverse=True)
    ret_value += 'Size\t\tCount\t\tName\n'
    for current_class in classes_sorted_by_size[:PROFILING_DUMP_ROWS_LIMIT]:
        ret_value += '{}\t\t{}\t\t{}\n'.format(current_class["size"], current_class["count"], current_class["name"])
    ret_value += '\n--- End Top {} Classes by Size ---\n'.format(PROFILING_DUMP_ROWS_LIMIT)

    ret_value += '\n--- End Memory Dump ---\n\n'

    return ret_value


def get_message_local_vars():
    """
    A function that returns the printable message about local variables

    :return: Message to print.
    :rtype: ``str``
    """
    local_vars = list(locals().items())
    ret_value = '\n\n--- Start Local Vars ---\n\n'
    for current_local_var in local_vars:
        ret_value += shorten_string_for_printing(str(current_local_var)) + '\n'

    ret_value += '\n--- End Local Vars ---\n\n'

    return ret_value


def get_size_of_object(input_object):
    """
    A function that recursively iterate to sum size of object & members.

    :type input_object: ``Any``
    :param input_object: The object to calculate its memory footprint

    :return: Size of input_object in bytes, or -1 if cannot determine the size.
    :rtype: ``int``
    """
    if IS_PY3 and PY_VER_MINOR >= 10:
        from collections.abc import Mapping
    else:
        from collections import Mapping  # type: ignore[no-redef, attr-defined]

    from collections import deque
    from numbers import Number
    # IS_PY3:
    # ZERO_DEPTH_BASES = (str, bytes, Number, range, bytearray) if IS_PY3 else (str, bytes, Number, bytearray)
    ZERO_DEPTH_BASES = (str, bytes, Number, bytearray)
    MAX_LEVEL = 20
    _seen_ids = set()

    def inner(obj, level):
        """
        A recursion that goes deep into objects, to calculate their deep memory footprint.

        :type level: ``int``
        :param level: Current level of the recursion (object)

        :return: Size of obj in bytes, or -1 if cannot determine the size.
        :rtype: ``int``
        """
        if level == MAX_LEVEL:
            # Stop at MAX_LEVEL
            return sys.getsizeof(obj)
        obj_id = id(obj)
        if obj_id in _seen_ids:
            return 0
        _seen_ids.add(obj_id)
        size = sys.getsizeof(obj)
        if isinstance(obj, ZERO_DEPTH_BASES):
            pass
        elif isinstance(obj, (tuple, list, set, deque)):
            size += sum(inner(i, level + 1) for i in obj)
        elif isinstance(obj, Mapping):
            mapping_items_keys = list(getattr(obj, 'keys')())
            for current_key in mapping_items_keys:
                if current_key in obj:
                    size += (inner(current_key, level + 1) + inner(obj[current_key], level + 1))
        # Check for custom object instances - may subclass above too
        if hasattr(obj, '__dict__'):
            size += inner(vars(obj), level + 1)
        return size

    try:
        return inner(input_object, 0)
    except RuntimeError:
        # A RuntimeError can occur, for example, in flask apps: it's forbidden to perform
        # some functionality outside the flask app context, which is unreachable from the
        # signal handler. Therefore, we just skip calculating the size in this case.
        demisto.debug('Skipping flask app internal objects in size calculation')
        return -1


excluded_globals = ['__name__', '__doc__', '__package__', '__loader__',
                    '__spec__', '__annotations__', '__builtins__',
                    '__file__', '__cached__', '_Feature',
                    ]
excluded_types_names = ['MagicMock',  # When running tests locally
                        ]


def get_message_global_vars():
    """
    A function that returns the printable message about global variables

    :return: Message to print.
    :rtype: ``str``
    """
    excluded_types = [types.ModuleType, types.FunctionType,
                      ]

    globals_dict = dict(globals())
    globals_dict_full = {}
    for current_key in globals_dict.keys():
        current_value = globals_dict[current_key]
        if not type(current_value) in excluded_types \
                and current_key not in excluded_globals \
                and type(current_value).__name__ not in excluded_types_names:
            globals_dict_full[current_key] = {
                'name': current_key,
                'value': current_value,
                # Deep calculation. Better than sys.getsizeof(current_value)
                'size': get_size_of_object(current_value)
            }

    ret_value = '\n\n--- Start Top {} Globals by Size ---\n'.format(PROFILING_DUMP_ROWS_LIMIT)
    globals_sorted_by_size = sorted(globals_dict_full.values(), key=lambda d: d['size'], reverse=True)
    ret_value += 'Size\t\tName\t\tValue\n'
    for current_global in globals_sorted_by_size[:PROFILING_DUMP_ROWS_LIMIT]:
        ret_value += '{}\t\t{}\t\t{}\n'.format(current_global["size"], current_global["name"],
                                               shorten_string_for_printing(str(current_global["value"])))
    ret_value += '\n--- End Top {} Globals by Size ---\n'.format(PROFILING_DUMP_ROWS_LIMIT)

    return ret_value


def get_message_modules_sizes():
    """
    A function that returns the printable message about the loaded modules by size

    :return: Message to print.
    :rtype: ``str``
    """
    globals_dict = dict(globals())
    globals_dict_full = {}
    for current_key in globals_dict.keys():
        current_value = globals_dict[current_key]
        if isinstance(current_value, types.ModuleType) \
                and current_key not in excluded_globals \
                and type(current_value).__name__ not in excluded_types_names:
            globals_dict_full[current_key] = {
                'name': current_key,
                'value': current_value,
                # Deep calculation. Better than sys.getsizeof(current_value)
                'size': get_size_of_object(current_value)
            }

    ret_value = '\n\n--- Start Top {} Modules by Size ---\n'.format(PROFILING_DUMP_ROWS_LIMIT)
    globals_sorted_by_size = sorted(globals_dict_full.values(), key=lambda d: d['size'], reverse=True)
    ret_value += 'Size\t\tName\t\tValue\n'
    for current_global in globals_sorted_by_size[:PROFILING_DUMP_ROWS_LIMIT]:
        ret_value += '{}\t\t{}\t\t{}\n'.format(current_global["size"], current_global["name"],
                                               shorten_string_for_printing(str(current_global["value"])))
    ret_value += '\n--- End Top {} Modules by Size ---\n'.format(PROFILING_DUMP_ROWS_LIMIT)

    return ret_value


def signal_handler_profiling_dump(_sig, _frame):
    """
    Listener function to dump the threads and memory to log info

    :type _sig: ``int``
    :param _sig: The signal number

    :type _frame: ``Any``
    :param _frame: The current stack frame

    :return: No data returned
    :rtype: ``None``
    """
    msg = '\n\n--- Start Profiling Dump ---\n'
    msg += get_message_threads_dump(_sig, _frame)
    msg += get_message_memory_dump(_sig, _frame)
    msg += '\n--- End Profiling Dump ---\n\n'
    LOG(msg)
    LOG.print_log()


def register_signal_handler_profiling_dump(signal_type=None,
                                           profiling_dump_rows_limit=PROFILING_DUMP_ROWS_LIMIT):  # pragma: no cover
    """
    Function that registers the threads and memory dump signal listener

    :type profiling_dump_rows_limit: ``int``
    :param profiling_dump_rows_limit: The max number of profiling related rows to print to the log

    :type profiling_dump_rows_limit: ``int``
    :param profiling_dump_rows_limit: The max number of profiling related rows to print to the log

    :return: No data returned
    :rtype: ``None``
    """
    if OS_LINUX or OS_MAC:

        import signal

        globals_ = globals()
        globals_['PROFILING_DUMP_ROWS_LIMIT'] = profiling_dump_rows_limit

        requested_signal = signal_type if signal_type else signal.SIGUSR1
        signal.signal(requested_signal, signal_handler_profiling_dump)
    else:
        demisto.info('Not a Linux or Mac OS, profiling using a signal is not supported.')


def shorten_string_for_printing(source_string, max_length=64):
    """
    Function that removes the middle of a long str, for printint or logging.
    If needed, it will replace the middle with '...',
    Examples:
    >>> shorten_string_for_printing('123456789', 9)
    '123456789'
    >>> shorten_string_for_printing('1234567890', 9)
    'abc...890'
    >>> shorten_string_for_printing('123456789012', 10)
    '1234...012'

    :type source_string: ``str``
    :param source_string: A long str that needs shortening.

    :type max_length: ``int``
    :param max_length: Maximum length of the returned str, should be higher than 0. Default is 64.

    :return:: A string no longer than max_length.
    :rtype: ``str``
    """
    if not source_string or max_length < 1 or len(source_string) <= max_length:
        return source_string

    extremeties_length = int((max_length - 3) / 2)
    if max_length % 2 == 0:
        # even max_length. Start with one more char than at the beginning
        ret_value = source_string[:extremeties_length + 1] \
            + '...' \
            + source_string[-extremeties_length:]
        return ret_value
    else:
        # odd max_length
        ret_value = source_string[:extremeties_length] \
            + '...' \
            + source_string[-extremeties_length:]
        return ret_value


class PollResult:
    """The response object for polling functions. This object contains information about whether to run again, and what
    the CommandResults are in case of success, or failure.

    :return: PollResult
    :rtype: ``PollResult``

    """

    def __init__(self, response, continue_to_poll=False, args_for_next_run=None, partial_result=None):
        """
        Constructor for PollResult

        :type response: ``Any``
        :param response: The response of the command in the event of success,
        or in case of failure but Polling is false

        :type continue_to_poll: ``Union[bool, Callable]``
        :param continue_to_poll: An iterable of relevant keys list from the json. Notice we save it as a set in the class

        :type args_for_next_run: ``Dict``
        :param args_for_next_run: The arguments to use in the next iteration. Will use the input args in case of None

        :type partial_result: ``CommandResults``
        :param partial_result: CommandResults to return, even though we will poll again

        """
        self.response = response
        self.continue_to_poll = continue_to_poll
        self.args_for_next_run = args_for_next_run
        self.partial_result = partial_result


def polling_function(name, interval=30, timeout=600, poll_message='Fetching Results:', polling_arg_name="polling",
                     requires_polling_arg=True):  # pragma: no cover
    """
    To use on a function that should rerun itself
    Commands that use this decorator must have a Polling argument, polling: true in yaml,
    and a hidden hide_polling_output argument.
    Commands that use this decorator should return a PollResult.
    Will raise an DemistoException if the server version doesn't support Scheduled Commands (< 6.2.0)

    :type name: ``str``
    :param name: The name of the command

    :type interval: ``int``
    :param interval: How many seconds until the next run

    :type timeout: ``int``
    :param timeout: How long

    :type poll_message: ``str``
    :param poll_message: The message to display in the war room while polling

    :type requires_polling_arg: ``bool``
    :param requires_polling_arg: Whether a polling argument should be expected as one of the demisto args

    :return: Decorator for polling functions
    :rtype: ``Function``
    """

    def dec(func):
        def inner(args, *arguments, **kwargs):
            """
            Args:
                args (dict): command arguments (demisto.args()).
                *arguments: any additional arguments to the command function.
                **kwargs: additional keyword arguments to the command function.
            """
            if not requires_polling_arg or argToBoolean(args.get(polling_arg_name, False)):
                ScheduledCommand.raise_error_if_not_supported()
                poll_result = func(args, *arguments, **kwargs)

                should_poll = poll_result.continue_to_poll if isinstance(poll_result.continue_to_poll, bool) \
                    else poll_result.continue_to_poll()
                if not should_poll:
                    return poll_result.response

                readable_output = poll_message if not args.get('hide_polling_output') else None
                poll_args = poll_result.args_for_next_run or args
                poll_args['hide_polling_output'] = True

                poll_response = poll_result.partial_result or CommandResults(readable_output=readable_output)
                poll_response.scheduled_command = ScheduledCommand(command=name, next_run_in_seconds=interval,
                                                                   args=poll_args, timeout_in_seconds=timeout)
                return poll_response
            else:
                return func(args, *arguments, **kwargs).response

        return inner

    return dec


def get_pack_version(pack_name=''):
    """
    Get a pack version.
    The version can be retrieved either by a pack name or by the calling script/integration in which
    script/integration is part of.

    To get the version of the pack in which the calling script/integration is part of,
    just call the function without pack_name.

    :type pack_name: ``str``
    :param pack_name: the pack name as mentioned in the pack metadata file to query its version.
            use only if querying by a pack name.

    :return: The pack version in which the integration/script is part of / the version of the requested pack name in
        case provided. in case not found returns empty string.
    :rtype: ``str``
    """

    def _get_packs_by_query(_body_request):
        packs_body_response = demisto.internalHttpRequest(
            'POST', uri='/contentpacks/marketplace/search', body=json.dumps(body_request)
        )
        return _load_response(_response=packs_body_response.get('body')).get('packs') or []

    def _load_response(_response):
        try:
            return json.loads(_response)
        except json.JSONDecodeError:  # type: ignore[attr-defined]
            demisto.debug('Unable to load response {response}'.format(response=_response))
            return {}

    def _extract_current_pack_version(_packs, _query_type, _entity_name):
        # in case we have more than 1 pack returned from the search, need to make sure to retrieve the correct pack
        if query_type == 'automation' or query_type == 'integration':
            for pack in _packs:
                for content_entity in (pack.get('contentItems') or {}).get(_query_type) or []:
                    if (content_entity.get('name') or '') == _entity_name:
                        return pack.get('currentVersion') or ''
        else:
            for pack in _packs:
                if pack.get('name') == _entity_name:
                    return pack.get('currentVersion') or ''
        return ''

    def _extract_integration_display_name(_integration_brand):
        integrations_body_response = demisto.internalHttpRequest(
            'POST', uri='/settings/integration/search', body=json.dumps({})
        )
        integrations_body_response = _load_response(_response=integrations_body_response.get('body'))
        integrations = integrations_body_response.get('configurations') or []

        for integration in integrations:
            integration_display_name = integration.get('display')
            if integration.get('id') == _integration_brand and integration_display_name:
                return integration_display_name
        return ''

    # query by pack name
    if pack_name:
        entity_name = pack_name
        body_request = {'packsQuery': entity_name}
        query_type = 'pack'
    # query by integration name
    elif demisto.callingContext.get('integration'):  # True means its integration, False means its script/automation.
        entity_name = (demisto.callingContext.get('context') or {}).get('IntegrationBrand') or ''
        body_request = {'integrationsQuery': entity_name}
        query_type = 'integration'
    # query by script/automation name
    else:
        entity_name = (demisto.callingContext.get('context') or {}).get('ScriptName') or ''
        body_request = {'automationQuery': entity_name}
        query_type = 'automation'

    pack_version = _extract_current_pack_version(
        _packs=_get_packs_by_query(_body_request=body_request),
        _query_type=query_type,
        _entity_name=entity_name
    )
    if not pack_version and query_type == 'integration':
        # handle the case where the display name of the integration is not the same as the integration brand
        integration_display = _extract_integration_display_name(_integration_brand=entity_name)
        if integration_display and integration_display != entity_name:
            body_request['integrationsQuery'] = integration_display

            return _extract_current_pack_version(
                _packs=_get_packs_by_query(_body_request=body_request),
                _query_type=query_type,
                _entity_name=integration_display
            )
        return ''
    return pack_version


def create_indicator_result_with_dbotscore_unknown(indicator, indicator_type, reliability=None,
                                                   context_prefix=None, address_type=None, relationships=None):
    '''
    Used for cases where the api response to an indicator is not found,
    returns CommandResults with readable_output generic in this case, and indicator with DBotScore unknown

    :type indicator: ``str``
    :param indicator: The value of the indicator

    :type indicator_type: ``DBotScoreType``
    :param indicator_type: use DBotScoreType class [Unsupport in types CVE and ATTACKPATTERN]

    :type reliability: ``DBotScoreReliability``
    :param reliability: use DBotScoreReliability class

    :type context_prefix: ``str``
    :param context_prefix: Use only in case that the indicator is CustomIndicator

    :type address_type: ``str``
    :param address_type: Use only in case that the indicator is Cryptocurrency

    :type relationships: ``list of EntityRelationship``
    :param relationships: List of relationships of the indicator.

    :rtype: ``CommandResults``
    :return: CommandResults
    '''
    if not context_prefix and (indicator_type is DBotScoreType.CUSTOM or not DBotScoreType.is_valid_type(indicator_type)):
        raise ValueError('Indicator type is invalid')

    if indicator_type in [DBotScoreType.CVE, DBotScoreType.ATTACKPATTERN]:
        #  not supportted, because they have a fixed dbotscore
        msg_error = 'DBotScoreType.{} is unsupported'.format(indicator_type.upper())
        raise ValueError(msg_error)

    dbot_score = Common.DBotScore(indicator=indicator,
                                  indicator_type=indicator_type
                                  if DBotScoreType.is_valid_type(indicator_type) else DBotScoreType.CUSTOM,
                                  score=Common.DBotScore.NONE,
                                  reliability=reliability,
                                  message='No results found.')

    integration_name = dbot_score.integration_name or 'Results'
    indicator_ = None  # type: Any
    if indicator_type is DBotScoreType.FILE:
        if sha1Regex.match(indicator):
            indicator_ = Common.File(dbot_score=dbot_score, sha1=indicator)
            indicator_type = 'sha1'
        elif sha256Regex.match(indicator):
            indicator_ = Common.File(dbot_score=dbot_score, sha256=indicator)
            indicator_type = 'sha256'
        elif sha512Regex.match(indicator):
            indicator_ = Common.File(dbot_score=dbot_score, sha512=indicator)
            indicator_type = 'sha512'
        elif md5Regex.match(indicator):
            indicator_ = Common.File(dbot_score=dbot_score, md5=indicator)
            indicator_type = 'md5'
        else:
            raise ValueError('This indicator -> {} is incorrect'.format(indicator))

    elif indicator_type is DBotScoreType.IP:
        indicator_ = Common.IP(ip=indicator, dbot_score=dbot_score)

    elif indicator_type is DBotScoreType.URL:
        indicator_ = Common.URL(url=indicator, dbot_score=dbot_score)

    elif indicator_type is DBotScoreType.DOMAIN:
        indicator_ = Common.Domain(domain=indicator, dbot_score=dbot_score)

    elif indicator_type is DBotScoreType.EMAIL:
        indicator_ = Common.EMAIL(address=indicator, dbot_score=dbot_score)

    elif indicator_type is DBotScoreType.CERTIFICATE:
        indicator_ = Common.Certificate(subject_dn=indicator, dbot_score=dbot_score)

    elif indicator_type is DBotScoreType.ACCOUNT:
        indicator_ = Common.Account(id=indicator, dbot_score=dbot_score)

    elif indicator_type is DBotScoreType.CRYPTOCURRENCY:
        if not address_type:
            raise ValueError('Missing address_type parameter')
        indicator_ = Common.Cryptocurrency(address=indicator, address_type=address_type, dbot_score=dbot_score)
        indicator_type = address_type

    else:
        indicator_ = Common.CustomIndicator(indicator_type=indicator_type,
                                            value=indicator,
                                            dbot_score=dbot_score,
                                            data={},
                                            context_prefix=context_prefix,
                                            relationships=relationships,
                                            )

    indicator_type = indicator_type.upper()
    readable_output = tableToMarkdown(name='{}:'.format(integration_name),
                                      t={indicator_type: indicator, 'Result': 'Not found'},
                                      headers=[indicator_type, 'Result'])

    return CommandResults(readable_output=readable_output, indicator=indicator_)


def get_fetch_run_time_range(last_run, first_fetch, look_back=0, timezone=0, date_format='%Y-%m-%dT%H:%M:%S'):
    """
    Calculates the time range for fetch depending the look_back argument and the previous fetch start time
    given from the last_run object.

    :type last_run: ``dict``
    :param last_run: The LastRun object

    :type first_fetch: ``str``
    :param first_fetch: The first time to fetch, used in the first fetch of an instance

    :type look_back: ``int``
    :param look_back: The time to look back in fetch in minutes

    :type timezone: ``int``
    :param timezone: The time zone offset in hours

    :type date_format: ``str``
    :param date_format: The date format

    :return: The time range (start_time, end_time) of the creation date for the incidents to fetch in the current run.
    :rtype: ``Tuple``
    """
    last_run_time = last_run and 'time' in last_run and last_run['time']
    now = get_current_time(timezone)
    if not last_run_time:
        last_run_time = dateparser.parse(first_fetch, settings={'TIMEZONE': 'UTC', 'RETURN_AS_TIMEZONE_AWARE': True})
        if last_run_time:
            last_run_time += timedelta(hours=timezone)
    else:
        last_run_time = dateparser.parse(last_run_time, settings={'TIMEZONE': 'UTC', 'RETURN_AS_TIMEZONE_AWARE': True})

    if look_back and look_back > 0:
        if now - last_run_time < timedelta(minutes=look_back):
            last_run_time = now - timedelta(minutes=look_back)

    demisto.debug("lb: fetch start time: {}, fetch end time: {}".format(
        last_run_time.strftime(date_format), now.strftime(date_format)))
    return last_run_time.strftime(date_format), now.strftime(date_format)


def get_current_time(time_zone=0):
    """
    Gets the current time in a given timezone, as time awared datetime.

    :type time_zone: ``int``
    :param time_zone: The time zone offset in hours.

    :return: The current time.
    :rtype: ``datetime``
    """
    now = datetime.utcnow() + timedelta(hours=time_zone)
    try:
        import pytz
        return now.replace(tzinfo=pytz.UTC)
    except ImportError:
        demisto.debug('pytz is missing, will not return timeaware object.')
        return now


def calculate_new_offset(old_offset, num_incidents, total_incidents):
    """ This calculates the new offset based on the response

    :type old_offset: ``int``
    :param old_offset: The offset from the previous run

    :type num_incidents: ``int``
    :param num_incidents: The number of incidents returned by the API.

    :type total_incidents: ``int``
    :param total_incidents: The total number of incidents returned by the API.

    :return: The new offset for the next run.
    :rtype: ``int``
    """
    if not num_incidents:
        return 0
    if total_incidents and num_incidents + old_offset >= total_incidents:
        return 0
    return old_offset + num_incidents


def filter_incidents_by_duplicates_and_limit(incidents_res, last_run, fetch_limit, id_field):
    """
    Removes duplicate incidents from response and returns the incidents till limit.
    The function should be called after getting the get-incidents API response,
    and by passing the id_field it will filter out the incidents that were already fetched
    by checking the incident IDs that are saved from the previous fetch in the last run object

    :type incidents_res: ``list``
    :param incidents_res: The incidents from the API response

    :type last_run: ``dict``
    :param last_run: The LastRun object

    :type fetch_limit: ``int``
    :param fetch_limit: The incidents limit to return

    :type id_field: ``str``
    :param id_field: The incident id field

    :return: List of incidents after filtering duplicates when len(incidents) <= limit
    :rtype: ``list``
    """
    demisto.debug('lb: Filtering incidents by duplicates and limit')
    found_incidents = last_run.get('found_incident_ids', {})

    incidents = []

    demisto.debug('lb: Number of incidents before filtering: {}, their ids: {}'.format(len(incidents_res),
                                                                                       [incident_res[id_field] for incident_res in
                                                                                        incidents_res]))
    for incident in incidents_res:
        if incident[id_field] not in found_incidents:
            incidents.append(incident)

    demisto.debug('lb: Number of incidents after filtering: {}, their ids: {}'.format(len(incidents),
                                                                                      [incident[id_field] for incident in
                                                                                       incidents]))
    return incidents[:fetch_limit]


def get_latest_incident_created_time(incidents, created_time_field, date_format='%Y-%m-%dT%H:%M:%S',
                                     increase_last_run_time=False):
    """
    Gets the latest incident created time

    :type incidents: ``list``
    :param incidents: List of incidents

    :type created_time_field: ``str``
    :param created_time_field: The incident created time field

    :type date_format: ``str``
    :param date_format: The date format

    :type increase_last_run_time: ``bool``
    :param increase_last_run_time: Whether to increase the last run time with one millisecond

    :return: The latest incident time
    :rtype: ``str``
    """
    demisto.debug('lb: Getting latest incident created time')
    latest_incident_time = datetime.strptime(incidents[0][created_time_field], date_format)

    for incident in incidents:
        incident_time = datetime.strptime(incident[created_time_field], date_format)
        if incident_time > latest_incident_time:
            latest_incident_time = incident_time

    if increase_last_run_time:
        latest_incident_time = latest_incident_time + timedelta(milliseconds=1)

    demisto.debug("lb: latest_incident_time is {}".format(latest_incident_time))
    return latest_incident_time.strftime(date_format)


def remove_old_incidents_ids(found_incidents_ids, current_time, look_back):
    """
    Removes old incident ids from the last run object to avoid overloading.

    :type found_incidents_ids: ``dict``
    :param found_incidents_ids: Dict of incidents ids

    :type current_time: ``int``
    :param current_time: The current epoch time to compare with the existing IDs added time

    :type look_back: ``int``
    :param look_back: The look back time in minutes

    :return: The new incidents ids
    :rtype: ``dict``
    """
    demisto.debug('lb: Remove old incidents ids, current time is {}'.format(current_time))
    look_back_in_seconds = look_back * 60
    deletion_threshold_in_seconds = look_back_in_seconds * 2

    new_found_incidents_ids = {}
    for inc_id, addition_time in found_incidents_ids.items():

        if current_time - addition_time <= deletion_threshold_in_seconds:
            new_found_incidents_ids[inc_id] = addition_time
            demisto.debug('lb: Adding incident id: {}, its addition time: {}, deletion_threshold_in_seconds: {}'.format(
                inc_id, addition_time, deletion_threshold_in_seconds))
        else:
            demisto.debug('lb: Removing incident id: {}, its addition time: {}, deletion_threshold_in_seconds: {}'.format(
                inc_id, addition_time, deletion_threshold_in_seconds))
    demisto.debug('lb: Number of new found ids: {}, their ids: {}'.format(
        len(new_found_incidents_ids), new_found_incidents_ids.keys()))
    return new_found_incidents_ids


def get_found_incident_ids(last_run, incidents, look_back, id_field, remove_incident_ids):
    """
    Gets the found incident ids from the last run object and adds the new fetched incident IDs.

    :type last_run: ``dict``
    :param last_run: The LastRun object

    :type incidents: ``list``
    :param incidents: List of incidents to add

    :type look_back: ``int``
    :param look_back: The look back time in minutes

    :type id_field: ``str``
    :param id_field: The incident id field

    :return: The new incident ids.
    :rtype: ``dict``
    """

    demisto.debug('lb: Get found incident ids')
    found_incidents = last_run.get('found_incident_ids', {})
    current_time = int(time.time())

    for incident in incidents:
        found_incidents[incident[id_field]] = current_time
    if remove_incident_ids:
        found_incidents = remove_old_incidents_ids(found_incidents, current_time, look_back)

    return found_incidents


def create_updated_last_run_object(last_run, incidents, fetch_limit, look_back, start_fetch_time, end_fetch_time,
                                   created_time_field, date_format='%Y-%m-%dT%H:%M:%S', increase_last_run_time=False,
                                   new_offset=None):
    """
    Calculates the next fetch time and limit depending the incidents result and creates an updated LastRun object
    with the new time and limit.

    :type last_run: ``dict``
    :param last_run: The LastRun object

    :type incidents: ``list``
    :param incidents: List of the incidents result

    :type fetch_limit: ``int``
    :param fetch_limit: The fetch limit

    :type look_back: ``int``
    :param look_back: The time to look back in fetch in minutes

    :type start_fetch_time: ``str``
    :param start_fetch_time: The time the fetch started to fetch from

    :type end_fetch_time: ``str``
    :param end_fetch_time: The end time in which the fetch incidents ended

    :type created_time_field: ``str``
    :param created_time_field: The incident created time field

    :type date_format: ``str``
    :param date_format: The date format

    :type increase_last_run_time: ``bool``
    :param increase_last_run_time: Whether to increase the last run time with one millisecond

    :type new_offset: ``int | None``
    :param new_offset: The new offset to set in the last run

    :return: The new LastRun object
    :rtype: ``Dict``
    """
    demisto.debug("lb: Create updated last run object, len(incidents) is {},"
                  "look_back is {}, fetch_limit is {}, new_offset is {}".format(len(incidents), look_back, fetch_limit,
                                                                                new_offset))
    remove_incident_ids = True
    new_limit = len(last_run.get('found_incident_ids', [])) + len(incidents) + fetch_limit
    if new_offset:
        # if we need to update the offset, we need to keep the old time and just update the offset
        new_last_run = {
            'time': last_run.get("time"),
        }
    elif len(incidents) == 0:
        new_last_run = {
            'time': end_fetch_time,
            'limit': fetch_limit,
        }
    else:
        latest_incident_fetched_time = get_latest_incident_created_time(incidents, created_time_field, date_format,
                                                                        increase_last_run_time)
        new_last_run = {
            'time': latest_incident_fetched_time,
            'limit': new_limit if look_back > 0 else fetch_limit
        }
        if latest_incident_fetched_time == start_fetch_time:
            # we are still on the same time, no need to remove old incident ids
            remove_incident_ids = False

    if new_offset is not None:
        new_last_run['offset'] = new_offset
        new_last_run['limit'] = fetch_limit
    demisto.debug("lb: The new_last_run is: {}, the remove_incident_ids is: {}".format(new_last_run,
                                                                                       remove_incident_ids))

    return new_last_run, remove_incident_ids


def update_last_run_object(last_run, incidents, fetch_limit, start_fetch_time, end_fetch_time, look_back,
                           created_time_field, id_field, date_format='%Y-%m-%dT%H:%M:%S', increase_last_run_time=False,
                           new_offset=None):
    """
    Updates the LastRun object with the next fetch time and limit and with the new fetched incident IDs.

    :type last_run: ``dict``
    :param last_run: The LastRun object

    :type incidents: ``list``
    :param incidents: List of the incidents result

    :type fetch_limit: ``int``
    :param fetch_limit: The fetch limit

    :type start_fetch_time: ``str``
    :param start_fetch_time: The time the fetch started to fetch from

    :type end_fetch_time: ``str``
    :param end_fetch_time: The end time in which the fetch incidents ended

    :type look_back: ``int``
    :param look_back: The time to look back in fetch in minutes

    :type created_time_field: ``str``
    :param created_time_field: The incident created time field

    :type id_field: ``str``
    :param id_field: The incident id field

    :type date_format: ``str``
    :param date_format: The date format

    :type increase_last_run_time: ``bool``
    :param increase_last_run_time: Whether to increase the last run time with one millisecond

    :type new_offset: ``int | None``
    :param new_offset: The new offset to set in the last run


    :return: The updated LastRun object
    :rtype: ``Dict``
    """
    if not look_back:
        look_back = 0

    updated_last_run, remove_incident_ids = create_updated_last_run_object(last_run,
                                                                           incidents,
                                                                           fetch_limit,
                                                                           look_back,
                                                                           start_fetch_time,
                                                                           end_fetch_time,
                                                                           created_time_field,
                                                                           date_format,
                                                                           increase_last_run_time,
                                                                           new_offset
                                                                           )

    found_incidents = get_found_incident_ids(last_run, incidents, look_back, id_field, remove_incident_ids)

    updated_last_run['found_incident_ids'] = found_incidents
    last_run.update(updated_last_run)

    return last_run


# YML metadata collector mocked classes.
class ParameterTypes:
    """YML ConfKey key_type type.

    This is an empty class, used for code autocompletion when using
    demisto-sdk generate_yml_from_python command syntax. For more information,
    visit the command's README.md.

    :return: The ParameterTypes enum
    :rtype: ``ParameterTypes``
    """
    STRING = 0
    NUMBER = 1
    ENCRYPTED = 4
    BOOLEAN = 8
    AUTH = 9
    DOWNLOAD_LINK = 11
    TEXT_AREA = 12
    INCIDENT_TYPE = 13
    TEXT_AREA_ENCRYPTED = 14
    SINGLE_SELECT = 15
    MULTI_SELECT = 16


class OutputArgument:
    """YML output argument.

    This is an empty class, used for code autocompletion when using
    demisto-sdk generate_yml_from_python command syntax. For more information,
    visit the command's README.md.

    :return: The OutputArgument object
    :rtype: ``OutputArgument``
    """

    def __init__(self,
                 name,
                 output_type=dict,
                 description=None,
                 prefix=None):
        pass


class InputArgument:
    """YML input argument for a command.

    This is an empty class, used for code autocompletion when using
    demisto-sdk generate_yml_from_python command syntax. For more information,
    visit the command's README.md.

    :return: The InputArgument object
    :rtype: ``InputArgument``
    """

    def __init__(self,
                 name=None,
                 description=None,
                 required=False,
                 default=None,
                 is_array=False,
                 secret=False,
                 execution=False,
                 options=None,
                 input_type=None):
        pass


class ConfKey:
    """YML configuration key fields.

    This is an empty class, used for code autocompletion when using
    demisto-sdk generate_yml_from_python command syntax. For more information,
    visit the command's README.md.

    :return: The ConfKey object
    :rtype: ``ConfKey``
    """

    def __init__(self,
                 name,
                 display=None,
                 default_value=None,
                 key_type=0,  # Expects ParameterType
                 required=False,
                 additional_info=None,
                 options=None,
                 input_type=None):
        pass


class YMLMetadataCollector:
    """The YMLMetadataCollector class provides decorators for integration
    functions which contain details relevant to yml generation.

    This is an empty class, used for code autocompletion when using
    demisto-sdk generate_yml_from_python command syntax. For more information,
    visit the command's README.md.

    :return: The YMLMetadataCollector object
    :rtype: ``YMLMetadataCollector``
    """

    def __init__(self, integration_name, docker_image="demisto/python3:latest",
                 description=None, category="Utilities", conf=None,
                 is_feed=False, is_fetch=False, is_runonce=False,
                 detailed_description=None, image=None, display=None,
                 tests=["No tests"], fromversion="6.0.0",
                 long_running=False, long_running_port=False, integration_type="python",
                 integration_subtype="python3", deprecated=None, systemd=None,
                 timeout=None, default_classifier=None,
                 default_mapper_in=None, integration_name_x2=None, default_enabled_x2=None,
                 default_enabled=None, verbose=False):
        pass

    def command(self, command_name, outputs_prefix=None,
                outputs_list=None, inputs_list=None,
                execution=None, file_output=False,
                multiple_output_prefixes=False, deprecated=False, restore=False,
                description=None):
        def command_wrapper(func):
            def get_out_info(*args, **kwargs):
                if restore:
                    kwargs['command_name'] = command_name
                    kwargs['outputs_prefix'] = outputs_prefix
                    kwargs['execution'] = execution
                return func(*args, **kwargs)

            return get_out_info

        return command_wrapper


def xsiam_api_call_with_retries(
    client,
    xsiam_url,
    zipped_data,
    headers,
    num_of_attempts,
    events_error_handler=None,
    error_msg='',
    is_json_response=False,
    data_type=EVENTS
):  # pragma: no cover
    """
    Send the fetched events or assests into the XDR data-collector private api.

    :type client: ``BaseClient``
    :param client: base client containing the XSIAM url.

    :type xsiam_url: ``str``
    :param xsiam_url: The URL of XSIAM to send the api request.

    :type zipped_data: ``bytes``
    :param zipped_data: encoded events

    :type headers: ``dict``
    :param headers: headers for the request

    :type error_msg: ``str``
    :param error_msg: The error message prefix in case of an error.

    :type num_of_attempts: ``int``
    :param num_of_attempts: The num of attempts to do in case there is an api limit (429 error codes).

    :type events_error_handler: ``callable``
    :param events_error_handler: error handler function

    :type data_type: ``str``
    :param data_type: events or assets

    :return: Response object or DemistoException
    :rtype: ``requests.Response`` or ``DemistoException``
    """
    # retry mechanism in case there is a rate limit (429) from xsiam.
    status_code = None
    attempt_num = 1
    response = None

    while status_code != 200 and attempt_num < num_of_attempts + 1:
        demisto.debug('Sending {data_type} into xsiam, attempt number {attempt_num}'.format(
            data_type=data_type, attempt_num=attempt_num))
        # in the last try we should raise an exception if any error occurred, including 429
        ok_codes = (200, 429) if attempt_num < num_of_attempts else None
        response = client._http_request(
            method='POST',
            full_url=urljoin(xsiam_url, '/logs/v1/xsiam'),
            data=zipped_data,
            headers=headers,
            error_handler=events_error_handler,
            ok_codes=ok_codes,
            resp_type='response'
        )
        status_code = response.status_code
        demisto.debug('received status code: {status_code}'.format(status_code=status_code))
        if status_code == 429:
            time.sleep(1)
        attempt_num += 1
    if is_json_response and response:
        response = response.json()
        if response.get('error', '').lower() != 'false':
            raise DemistoException(error_msg + response.get('error'))
    return response


def split_data_to_chunks(data, target_chunk_size):
    """
    Splits a string of data into chunks of an approximately specified size.
    The actual size can be lower.

    :type data: ``list`` or a ``string``
    :param data: A list of data or a string delimited with \n  to split to chunks.
    :type target_chunk_size: ``int``
    :param target_chunk_size: The maximum size of each chunk. The maximal size allowed is 9MB.

    :return: An iterable of lists where each list contains events with approx size of chunk size.
    :rtype: ``collections.Iterable[list]``
    """
    target_chunk_size = min(target_chunk_size, XSIAM_EVENT_CHUNK_SIZE_LIMIT)
    chunk = []  # type: ignore[var-annotated]
    chunk_size = 0
    if isinstance(data, str):
        data = data.split('\n')
    for data_part in data:
        if chunk_size >= target_chunk_size:
            demisto.debug("reached max chunk size, sending chunk with size: {size}".format(size=chunk_size))
            yield chunk
            chunk = []
            chunk_size = 0
        data_part_size = sys.getsizeof(data_part)
        if data_part_size >= MAX_ALLOWED_ENTRY_SIZE:
            demisto.error(
                "entry size {} is larger than the maximum allowed entry size {}, skipping this entry".format(data_part_size,
                                                                                                             MAX_ALLOWED_ENTRY_SIZE))
            continue
        chunk.append(data_part)
        chunk_size += data_part_size
    if chunk_size != 0:
        demisto.debug("sending the remaining chunk with size: {size}".format(size=chunk_size))
        yield chunk


def send_events_to_xsiam(events, vendor, product, data_format=None, url_key='url', num_of_attempts=3,
                         chunk_size=XSIAM_EVENT_CHUNK_SIZE, should_update_health_module=True,
                         add_proxy_to_request=False, multiple_threads=False):
    """
    Send the fetched events into the XDR data-collector private api.

    :type events: ``Union[str, list]``
    :param events: The events to send to XSIAM server. Should be of the following:
        1. List of strings or dicts where each string or dict represents an event.
        2. String containing raw events separated by a new line.

    :type vendor: ``str``
    :param vendor: The vendor corresponding to the integration that originated the events.

    :type product: ``str``
    :param product: The product corresponding to the integration that originated the events.

    :type data_format: ``str``
    :param data_format: Should only be filled in case the 'events' parameter contains a string of raw
        events in the format of 'leef' or 'cef'. In other cases the data_format will be set automatically.

    :type url_key: ``str``
    :param url_key: The param dict key where the integration url is located at. the default is 'url'.

    :type num_of_attempts: ``int``
    :param num_of_attempts: The num of attempts to do in case there is an api limit (429 error codes)

    :type chunk_size: ``int``
    :param chunk_size: Advanced - The maximal size of each chunk size we send to API. Limit of 9 MB will be inforced.

    :type should_update_health_module: ``bool``
    :param should_update_health_module: whether to trigger the health module showing how many events were sent to xsiam

    :type add_proxy_to_request :``bool``
    :param add_proxy_to_request: whether to add proxy to the send evnets request.

    :type multiple_threads: ``bool``
    :param multiple_threads: whether to use multiple threads to send the events to xsiam or not.

    :return: Either None if running in a single thread or a list of future objects if running in multiple threads.
    In case of running with multiple threads, the list of futures will hold the number of events sent and can be accessed by:
    for future in concurrent.futures.as_completed(futures):
        data_size += future.result()
    :rtype: ``List[Future]`` or ``None``
    """
    return send_data_to_xsiam(
        events,
        vendor,
        product,
        data_format,
        url_key,
        num_of_attempts,
        chunk_size,
        data_type="events",
        should_update_health_module=should_update_health_module,
        add_proxy_to_request=add_proxy_to_request,
        multiple_threads=multiple_threads
    )


def is_scheduled_command_retry():
    """
    Determines if the current command is a polling retry command. This is useful if some actions should not be performed
    when a command is polling for a response such as submitting data for processing.

    :returns: True if the command is part of a polling retry, otherwise false
    :rtype: ``Bool``

    """
    calling_context = demisto.callingContext.get('context', {})
    sm = get_schedule_metadata(context=calling_context)
    return True if sm.get('is_polling', False) else False


def retry(
    times=3,
    delay=1,
    exceptions=Exception,
):
    """
    retries to execute a function until an exception isn't raised anymore.

    :type times: ``int``
    :param times: The number of times to trigger the retry mechanism.

    :type delay: ``int``
    :param delay: The time in seconds to sleep between each time

    :type exceptions: ``Exception``
    :param exceptions: The exceptions that should be caught when executing
        the function (Union[tuple[type[Exception], ...], type[Exception]])

    :return: Any
    :rtype: ``Any``
    """

    def _retry(func):
        func_name = func.__name__

        @wraps(func)
        def wrapper(*args, **kwargs):
            for i in range(1, times + 1):
                demisto.debug("Running func {func_name} for the {time} time".format(func_name=func_name, time=i))
                try:
                    return func(*args, **kwargs)
                except exceptions as error:
                    demisto.debug(
                        "Error when executing func {func_name}, error: {error}, time {time}".format(
                            func_name=func_name, error=error, time=i
                        )
                    )
                    if i == times:
                        raise
                    time.sleep(delay)  # pylint: disable=sleep-exists

        return wrapper

    return _retry


def replace_spaces_in_credential(credential):
    """
    This function is used in case of credential from type: 9 is in the wrong format
    of one line with spaces instead of multiple lines.

    :type credential: ``str`` or ``None``
    :param credential: the credential to replace spaces in.

    :return: the credential with spaces replaced with new lines if the credential is in the correct format,
             otherwise the credential will be returned as is.
    :rtype: ``str`` or ``None``
    """
    if not credential:
        return credential

    match_begin = re.search("-----BEGIN(.*?)-----", credential)
    match_end = re.search("-----END(.*?)-----", credential)

    if match_begin and match_end:
        return re.sub("(?<={0})(.*?)(?={1})".format(match_begin.group(0), match_end.group(0)),
                      lambda match: match.group(0).replace(' ', '\n'), credential)
    return credential


def has_passed_time_threshold(timestamp_str, seconds_threshold):
    """
    Checks if the time difference between the current time and the timestamp is greater than the threshold.

    :type timestamp_str: ``str``
    :param timestamp_str: The timestamp to compare the current time to.
    :type seconds_threshold: ``int``
    :param seconds_threshold: The threshold in seconds.

    :return: True if the time difference is greater than the threshold, otherwise False.
    :rtype: ``bool``
    """
    import pytz
    to_utc_timestamp = dateparser.parse(timestamp_str, settings={'TIMEZONE': 'UTC'})
    # using astimezone since utcnow() returns a naive datetime object when unitesting
    current_time = datetime.now().astimezone(pytz.utc)
    if to_utc_timestamp:
        time_difference = current_time - to_utc_timestamp
        return time_difference.total_seconds() > seconds_threshold
    else:
        raise ValueError("Failed to parse timestamp: {timestamp_str}".format(timestamp_str=timestamp_str))


def send_data_to_xsiam(data, vendor, product, data_format=None, url_key='url', num_of_attempts=3,
                       chunk_size=XSIAM_EVENT_CHUNK_SIZE, data_type=EVENTS, should_update_health_module=True,
                       add_proxy_to_request=False, snapshot_id='', items_count=None, multiple_threads=False):
    """
    Send the supported fetched data types into the XDR data-collector private api.

    :type data: ``Union[str, list]``
    :param data: The data to send to XSIAM server. Should be of the following:
        1. List of strings or dicts where each string or dict represents an event or asset.
        2. String containing raw events separated by a new line.

    :type vendor: ``str``
    :param vendor: The vendor corresponding to the integration that originated the data.

    :type product: ``str``
    :param product: The product corresponding to the integration that originated the data.

    :type data_format: ``str``
    :param data_format: Should only be filled in case the 'events' parameter contains a string of raw
        events in the format of 'leef' or 'cef'. In other cases the data_format will be set automatically.

    :type url_key: ``str``
    :param url_key: The param dict key where the integration url is located at. the default is 'url'.

    :type num_of_attempts: ``int``
    :param num_of_attempts: The num of attempts to do in case there is an api limit (429 error codes)

    :type chunk_size: ``int``
    :param chunk_size: Advanced - The maximal size of each chunk size we send to API. Limit of 9 MB will be inforced.

    :type data_type: ``str``
    :param data_type: Type of data to send to Xsiam, events or assets.

    :type should_update_health_module: ``bool``
    :param should_update_health_module: whether to trigger the health module showing how many events were sent to xsiam
        This can be useful when using send_data_to_xsiam in batches for the same fetch.

    :type add_proxy_to_request: ``bool``
    :param add_proxy_to_request: whether to add proxy to the send evnets request.

    :type snapshot_id: ``str``
    :param snapshot_id: the snapshot id.

    :type items_count: ``str``
    :param items_count: the asset snapshot items count.

    :type multiple_threads: ``bool``
    :param multiple_threads: whether to use multiple threads to send the events to xsiam or not.
    Note that when set to True, the updateModuleHealth should be done from the itnegration itself.

    :return: Either None if running in a single thread or a list of future objects if running in multiple threads.
    In case of running with multiple threads, the list of futures will hold the number of events sent and can be accessed by:
    for future in concurrent.futures.as_completed(futures):
        data_size += future.result()
    :rtype: ``List[Future]`` or ``None```
    """
    data_size = 0
    params = demisto.params()
    url = params.get(url_key)
    calling_context = demisto.callingContext.get('context', {})
    instance_name = calling_context.get('IntegrationInstance', '')
    collector_name = calling_context.get('IntegrationBrand', '')
    if not items_count:
        items_count = len(data) if isinstance(data, list) else 1
    if data_type not in DATA_TYPES:
        demisto.debug("data type must be one of these values: {types}".format(types=DATA_TYPES))
        return

    if not data:
        demisto.debug('send_data_to_xsiam function received no {data_type}, '
                      'skipping the API call to send {data} to XSIAM'.format(data_type=data_type, data=data_type))
        demisto.updateModuleHealth({'{data_type}Pulled'.format(data_type=data_type): data_size})
        return

    # only in case we have data to send to XSIAM we continue with this flow.
    # Correspond to case 1: List of strings or dicts where each string or dict represents an one event or asset or snapshot.
    if isinstance(data, list):
        # In case we have list of dicts we set the data_format to json and parse each dict to a stringify each dict.
        demisto.debug("Sending {size} {data_type} to XSIAM".format(size=len(data), data_type=data_type))
        if isinstance(data[0], dict):
            data = [json.dumps(item) for item in data]
            data_format = 'json'
        # Separating each event with a new line
        data = '\n'.join(data)
    elif not isinstance(data, str):
        raise DemistoException('Unsupported type: {data} for the {data_type} parameter.'
                               ' Should be a string or list.'.format(data=type(data), data_type=data_type))
    if not data_format:
        data_format = 'text'

    xsiam_api_token = demisto.getLicenseCustomField('Http_Connector.token')
    xsiam_domain = demisto.getLicenseCustomField('Http_Connector.url')
    xsiam_url = 'https://api-{xsiam_domain}'.format(xsiam_domain=xsiam_domain)
    headers = {
        'authorization': xsiam_api_token,
        'format': data_format,
        'product': product,
        'vendor': vendor,
        'content-encoding': 'gzip',
        'collector-name': collector_name,
        'instance-name': instance_name,
        'final-reporting-device': url,
        'collector-type': ASSETS if data_type == ASSETS else EVENTS
    }
    if data_type == ASSETS:
        if not snapshot_id:
            snapshot_id = str(round(time.time() * 1000))

        # We are setting a time stamp ahead of the instance name since snapshot-ids must be configured in ascending
        # alphabetical order such that first_snapshot < second_snapshot etc.
        headers['snapshot-id'] = snapshot_id + instance_name
        headers['total-items-count'] = str(items_count)

    header_msg = 'Error sending new {data_type} into XSIAM.\n'.format(data_type=data_type)

    def data_error_handler(res):
        """
        Internal function to parse the XSIAM API errors
        """
        try:
            response = res.json()
            error = res.reason
            if response.get('error').lower() == 'false':
                xsiam_server_err_msg = response.get('error')
                error += ": " + xsiam_server_err_msg

        except ValueError:
            if res.text:
                error = '\n{}'.format(res.text)
            else:
                error = "Received empty response from the server"

        api_call_info = (
            'Parameters used:\n'
            '\tURL: {xsiam_url}\n'
            '\tHeaders: {headers}\n\n'
            'Response status code: {status_code}\n'
            'Error received:\n\t{error}'
        ).format(xsiam_url=xsiam_url, headers=json.dumps(headers, indent=8), status_code=res.status_code, error=error)

        demisto.error(header_msg + api_call_info)
        raise DemistoException(header_msg + error, DemistoException)

    client = BaseClient(base_url=xsiam_url, proxy=add_proxy_to_request)
    data_chunks = split_data_to_chunks(data, chunk_size)

    def send_events(data_chunk):
        chunk_size = len(data_chunk)
        data_chunk = '\n'.join(data_chunk)
        zipped_data = gzip.compress(data_chunk.encode('utf-8'))  # type: ignore[AttributeError,attr-defined]
        xsiam_api_call_with_retries(client=client, events_error_handler=data_error_handler,
                                    error_msg=header_msg, headers=headers,
                                    num_of_attempts=num_of_attempts, xsiam_url=xsiam_url,
                                    zipped_data=zipped_data, is_json_response=True, data_type=data_type)
        return chunk_size

    if multiple_threads:
        demisto.info("Sending events to xsiam with multiple threads.")
        all_chunks = [chunk for chunk in data_chunks]
        demisto.info("Finished appending all data_chunks to a list.")
        support_multithreading()
        futures = []
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=NUM_OF_WORKERS)
        for chunk in all_chunks:
            future = executor.submit(send_events, chunk)
            futures.append(future)

        demisto.info('Finished submiting {} Futures.'.format(len(futures)))
        return futures
    else:
        demisto.info("Sending events to xsiam with a single thread.")
        for chunk in data_chunks:
            data_size += send_events(chunk)

        if should_update_health_module:
            demisto.updateModuleHealth({'{data_type}Pulled'.format(data_type=data_type): data_size})
    return


def comma_separated_mapping_to_dict(raw_text):
    """
     Transforming a textual comma-separated mapping into a dictionary object.

    :type raw_text: ``str``
    :param raw_text: Comma-separated mapping e.g ('key1=value1', 'key2=value2', ...)

    :rtype: ``dict``
    :return: Validated dictionary of the raw mapping e.g {'key1': 'value1', 'key2': 'value2', ...}
    """
    demisto.debug("comma_separated_mapping_to_dict "
                  ">> Resolving comma-separated input mapping: {raw_text}".format(raw_text=raw_text))

    mapping_dict = {}  # type: Dict[str, str]
    # If a proper mapping was not provided, return an empty dict.
    if not raw_text:
        return mapping_dict

    key_value_pairs = raw_text.split(',')

    for pair in key_value_pairs:
        # Trimming trailing whitespace
        pair = pair.strip()

        try:
            key, value = pair.split('=')
        except ValueError:
            demisto.error("Error: Invalid mapping was provided. "
                          "Expected comma-separated mapping of format `key1=value1, key2=value2, ...`")
            key = value = ''

        if key in mapping_dict:
            demisto.debug(
                "comma_separated_mapping_to_dict "
                "Warning: duplicate key provided for {key}: using latter value: {value}".format(key=key, value=value)
            )
        mapping_dict[key] = value
    demisto.debug("comma_separated_mapping_to_dict << Resolved mapping: {mapping_dict}".format(mapping_dict=mapping_dict))
    return mapping_dict


def safe_sleep(duration_seconds):
    """
    Sleeps for the given duration, but raises an error if it would exceed the TTL.

        :type duration_seconds: ``float``
        :param duration_seconds: The desired sleep duration in seconds.

        :return: None
        :rtype: ``None``
    """
    context = demisto.callingContext.get('context', {})
    if 'runDuration' in context:
        run_duration = int(context.get('runDuration')) * 60
        time_left = run_duration - (datetime.now() - SAFE_SLEEP_START_TIME).total_seconds()
        if duration_seconds > time_left:
            raise ValueError("Requested a sleep of {} seconds, but time left until docker timeout is {} seconds."
                             .format(duration_seconds, run_duration))
    else:
        demisto.info('Safe sleep is not supported in this server version, sleeping for the requested time.')
    time.sleep(duration_seconds)  # pylint: disable=E9003


def is_time_sensitive():
    """
    Checks if the command reputation (auto-enrichment) is called as auto-extract=inline.
    This function checks if the 'isTimeSensitive' attribute exists in the 'demisto' object and if it's set to True.

        :return: bool
        :rtype: ``bool``
    """
    return hasattr(demisto, 'isTimeSensitive') and demisto.isTimeSensitive()


def parse_json_string(json_string):
    """
    Parse a JSON string into a Python dictionary.

    :type json_string: ``str``
    :param json_string: The JSON string to be parsed.

    :rtype: ``dict``
    :return: A Python dictionary representing the parsed JSON data.
    """
    try:
        data = json.loads(json_string)
        return data
    except json.JSONDecodeError as error:  # type: ignore[attr-defined]
        demisto.error("Error decoding JSON: {error}".format(error=error))
        return {}


def get_server_config():
    """
    Retrieves XSOAR server configuration.

    :rtype: ``dict``
    :return: The XSOAR server configuration.
    """
    response = demisto.internalHttpRequest(method='GET', uri='/system/config')
    body = parse_json_string(response.get('body'))
    server_config = body.get('sysConf', {})
    return server_config


def content_profiler(func):
    """
    A decorator that profiles a function's execution time and performance. It reports total runtime,
    call count, and average time per call, helping you identify bottlenecks and optimize your code.
    Simply decorate the function with @content_profiler.

    Analyze the Profiling Data with SnakeViz:
        Download the {automation_name}.prof from the war room and run:
            pip install snakeviz; snakveiz <automation_name>.prof

    **Tested with Python 3.10**

    :type func: ``function``
    :param func: The function to be profiled.
    :return: The profiled function.
    :rtype: ``any``
    """
    import cProfile
    import threading

    def profiler_wrapper(*args, **kwargs):
        """
        A wrapper function that profiles the execution of the decorated function.
        :param args: The positional arguments to be passed to the decorated function.
        :param kwargs: The keyword arguments to be passed to the decorated function.
        :return: The result of the decorated function.
        """

        def profiler_function(signal_event, profiler):
            """
            A helper function that runs the profiled function. When the profiled function is finished
             a signal is received and the profiling data is dumped to a temporary file.
             Otherwise, the function will stop when reaching to timeout.
            :param signal_event: A signal that will be set when the profiled function is finished.
            :param profiler: The Profile object to use for profiling.
            """

            def dump_result():
                """
                Helper function to dump the profiling results to a file and return the file.
                """
                import tempfile
                # Create a temporary file to store profiling data
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    profiler.dump_stats(temp_file.name)
                    temp_file_path = temp_file.name

                # Read the profiling data from the temporary file
                with open(temp_file_path, 'rb') as f:
                    profiling_results = f.read()

                # Delete the temporary file
                os.remove(temp_file_path)
                context = demisto.callingContext
                executed_commands = context.get("context", {}).get("ExecutedCommands", {})
                automation_name = context.get("command") or executed_commands[0].get("name",
                                                                                     "stats") if executed_commands else "stats"
                # Use Demisto's fileResult to create a file from the profiling stats
                demisto.results(fileResult('{}.prof'.format(automation_name), profiling_results))

            # 5 minutes in nanoseconds
            default_timeout = 60 * 5 * 1e9

            # The system timeout configuration.
            timeout_nanoseconds = demisto.callingContext["context"].get("TimeoutDuration") or default_timeout
            timeout_seconds = timeout_nanoseconds / 1e9
            event_set = signal_event.wait(timeout_seconds - 5)
            profiler.disable()
            dump_result()
            demisto.debug("Profiler finished.")
            if not event_set:
                return_error("The profiled function '{}' failed due to a timeout.".format(func.__name__))

        def function_runner(func, profiler, signal_event,
                            results, *args, **kwargs):
            """
            A wrapper function that runs the targeted profiled function and captures the results in the results list.
            :param func: The function to be profiled.
            :param profiler: The Profile object to use for profiling.
            :param signal_event: The event to signal when profiling is complete.
            :param results: A shared object to store the results of the profiled function.
            :param args: The positional arguments to be passed to the profiled function.
            :param kwargs: The keyword arguments
            """
            profiler.enable()
            demisto.debug("Profiler started.")
            try:
                results["function_results"] = func(*args, **kwargs)
            finally:
                # Signal the profiling thread that the command has completed.
                signal_event.set()

        support_multithreading()
        results = {}
        profiler = cProfile.Profile()
        signal_event = threading.Event()
        function_thread = threading.Thread(target=function_runner, args=(func, profiler, signal_event, results) + args,
                                           kwargs=kwargs)
        function_thread.start()
        profiler_function(signal_event, profiler)
        return results.get("function_results")

    return profiler_wrapper


from DemistoClassApiModule import *  # type:ignore [no-redef]  # noqa:E402

###########################################
#     DO NOT ADD LINES AFTER THIS ONE     #
###########################################
register_module_line('CommonServerPython', 'end', __line__())
register_module_line('CustomScriptIntegration', 'start', __line__())
