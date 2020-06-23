"""Common functions script
This script will be appended to each server script before being executed.
Please notice that to add custom common code, add it to the CommonServerUserPython script.
Note that adding code to CommonServerUserPython can override functions in CommonServerPython
"""
from __future__ import print_function

import base64
import json
import logging
import os
import re
import socket
import sys
import time
import traceback
import xml.etree.cElementTree as ET
from collections import OrderedDict
from datetime import datetime, timedelta
from abc import abstractmethod

import demistomock as demisto

# imports something that can be missed from docker image
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util import Retry
except Exception:
    pass


CONTENT_RELEASE_VERSION = '0.0.0'
CONTENT_BRANCH_NAME = 'master'
IS_PY3 = sys.version_info[0] == 3

# pylint: disable=undefined-variable
if IS_PY3:
    STRING_TYPES = (str, bytes)  # type: ignore
    STRING_OBJ_TYPES = (str,)
else:
    STRING_TYPES = (str, unicode)  # type: ignore
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
    'widget': 17
}


class EntryType(object):
    """
    Enum: contains all the entry types (e.g. NOTE, ERROR, WARNING, FILE, etc.)
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
    WARNING = 11
    MAP_ENTRY_TYPE = 15
    WIDGET = 17


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
    :return: None
    :rtype: ``None``
    """
    IP = 'ip'
    FILE = 'file'
    DOMAIN = 'domain'
    URL = 'url'
    CVE = 'cve'

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
            DBotScoreType.CVE
        )


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
            FeedIndicatorType.URL
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

        :rtype: ``str``
        :return:: Indicator type from FeedIndicatorType, or None if invalid IP address.
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

    if re.match(ipv4cidrRegex, indicator_value):
        return FeedIndicatorType.CIDR

    if re.match(ipv6cidrRegex, indicator_value):
        return FeedIndicatorType.IPv6CIDR

    if re.match(ipv4Regex, indicator_value):
        return FeedIndicatorType.IP

    if re.match(ipv6Regex, indicator_value):
        return FeedIndicatorType.IPv6

    if re.match(sha256Regex, indicator_value):
        return FeedIndicatorType.File

    if re.match(urlRegex, indicator_value):
        return FeedIndicatorType.URL

    if re.match(md5Regex, indicator_value):
        return FeedIndicatorType.File

    if re.match(sha1Regex, indicator_value):
        return FeedIndicatorType.File

    if re.match(emailRegex, indicator_value):
        return FeedIndicatorType.Email

    if re.match(cveRegex, indicator_value):
        return FeedIndicatorType.CVE

    try:
        no_cache_extract = tldextract.TLDExtract(cache_file=False,suffix_list_urls=None)
        if no_cache_extract(indicator_value).suffix:
            if '*' in indicator_value:
                return FeedIndicatorType.DomainGlob
            return FeedIndicatorType.Domain

    except Exception:
        pass

    return None


# ===== Fix fetching credentials from vault instances =====
# ====================================================================================
try:
    for k, v in demisto.params().items():
        if isinstance(v, dict):
            if 'credentials' in v:
                vault = v['credentials'].get('vaultInstanceId')
                if vault:
                    v['identifier'] = v['credentials'].get('user')
                break

except Exception:
    pass


# ====================================================================================


def handle_proxy(proxy_param_name='proxy', checkbox_default_value=False, handle_insecure=True, insecure_param_name=None):
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

        :rtype: ``dict``
        :return: proxies dict for the 'proxies' parameter of 'requests' functions
    """
    proxies = {}  # type: dict
    if demisto.params().get(proxy_param_name, checkbox_default_value):
        proxies = {
            'http': os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy', ''),
            'https': os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy', '')
        }
    else:
        for k in ('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy'):
            if k in os.environ:
                del os.environ[k]
    if handle_insecure:
        if insecure_param_name is None:
            param_names = ('insecure', 'unsecure')
        else:
            param_names = (insecure_param_name, )
        for p in param_names:
            if demisto.params().get(p, False):
                for k in ('REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE'):
                    if k in os.environ:
                        del os.environ[k]
    return proxies


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

        :rtype: ``string``
        :return: Full joined url
    """
    if url[-1:] != "/":
        url = url + "/"

    if suffix.startswith("/"):
        suffix = suffix[1:]
        return url + suffix

    return url + suffix


def positiveUrl(entry):
    """
       Checks if the given entry from a URL reputation query is positive (known bad) (deprecated)

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


def positiveFile(entry):
    """
       Checks if the given entry from a file reputation query is positive (known bad) (deprecated)

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


def positiveIp(entry):
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


def shortCrowdStrike(entry):
    """
       Display CrowdStrike Intel results in Markdown (deprecated)

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


def shortUrl(entry):
    """
       Formats a URL reputation entry into a short table (deprecated)

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


def shortFile(entry):
    """
       Formats a file reputation entry into a short table (deprecated)

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
       Formats an ip reputation entry into a short table (deprecated)

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
       Formats a domain reputation entry into a short table (deprecated)

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
    except UnicodeEncodeError as exception:
        return text.encode("utf8", "replace")


def safe_load_json(json_object):
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
    if (json_object.startswith('{') and json_object.endswith('}')) or (json_object.startswith('[') and json_object.endswith(']')):
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
                    if isinstance(list_response[0], str):
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


class IntegrationLogger(object):
    """
      a logger for python integrations:
      use LOG(<message>) to add a record to the logger (message can be any object with __str__)
      use LOG.print_log(verbose=True/False) to display all records in War-Room (if verbose) and server log.
      use add_replace_strs to add sensitive strings that should be replaced before going to the log.

      :type message: ``str``
      :param message: The message to be logged

      :return: No data returned
      :rtype: ``None``
    """

    def __init__(self):
        self.messages = []  # type: list
        self.write_buf = []  # type: list
        self.replace_strs = []  # type: list
        self.buffering = True
        # if for some reason you don't want to auto add credentials.password to replace strings
        # set the os env COMMON_SERVER_NO_AUTO_REPLACE_STRS. Either in CommonServerUserPython, or docker env
        if (not os.getenv('COMMON_SERVER_NO_AUTO_REPLACE_STRS') and hasattr(demisto, 'getParam')):
            # add common params
            sensitive_params = ('key', 'private', 'password', 'secret', 'token', 'credentials')
            if demisto.params():
                self._iter_sensistive_dict_obj(demisto.params(), sensitive_params)

    def _iter_sensistive_dict_obj(self, dict_obj, sensitive_params):
        for (k, v) in dict_obj.items():
            if isinstance(v, dict):  # credentials object case. recurse into the object
                self._iter_sensistive_dict_obj(v, sensitive_params)
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
            res = res.replace(s, '<XX_REPLACED>')
        return res

    def __call__(self, message):
        text = self.encode(message)
        if self.buffering:
            self.messages.append(text)
        else:
            demisto.info(text)

    def add_replace_strs(self, *args):
        '''
            Add strings which will be replaced when logging.
            Meant for avoiding passwords and so forth in the log.
        '''
        to_add = [self.encode(a) for a in args if a]
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
                demisto.log(text)
            demisto.info(text)
            self.messages = []

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
use LOG(<message>) to add a record to the logger (message can be any object with __str__)
use LOG.print_log() to display all records in War-Room and server log.
"""
LOG = IntegrationLogger()


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
        return func(*args, **kwargs)

    return func_wrapper


def formatCell(data, is_pretty=True):
    """
       Convert a given object to md while decending multiple levels

       :type data: ``str`` or ``list``
       :param data: The cell content (required)

       :type is_pretty: ``bool``
       :param is_pretty: Should cell content be prettified (default is True)

       :return: The formatted cell content as a string
       :rtype: ``str``
    """
    if isinstance(data, STRING_TYPES):
        return data
    elif isinstance(data, dict):
        return '\n'.join([u'{}: {}'.format(k, flattenCell(v, is_pretty)) for k, v in data.items()])
    else:
        return flattenCell(data, is_pretty)


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
        return json.dumps(data, indent=indent, ensure_ascii=False)


def FormatIso8601(t):
    """
       Convert a time expressed in seconds to ISO 8601 time format string

       :type t: ``int``
       :param t: Time expressed in seconds (required)

       :return: An ISO 8601 time format string
       :rtype: ``str``
    """
    return t.strftime("%Y-%m-%dT%H:%M:%S")


def argToList(arg, separator=','):
    """
       Converts a string representation of args to a python list

       :type arg: ``str`` or ``list``
       :param arg: Args to be converted (required)

       :type separator: ``str``
       :param separator: A string separator to separate the strings, the default is a comma.

       :return: A python list of args
       :rtype: ``list``
    """
    if not arg:
        return []
    if isinstance(arg, list):
        return arg
    if isinstance(arg, STRING_TYPES):
        if arg[0] == '[' and arg[-1] == ']':
            return json.loads(arg)
        return [s.strip() for s in arg.split(separator)]
    return [arg]


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
                new_val = data + ',' + existing
            else:
                new_val = data + existing  # will raise a self explanatory TypeError

        elif isinstance(existing, dict):
            if isinstance(data, dict):
                new_val = [existing, data]
            else:
                new_val = data + existing  # will raise a self explanatory TypeError

        elif isinstance(existing, list):
            if isinstance(data, list):
                existing.extend(data)
            else:
                existing.append(data)
            new_val = existing

        else:
            new_val = [existing, data]

        if dedup and isinstance(new_val, list):
            new_val = list(set(new_val))

        demisto.setContext(key, new_val)
    else:
        demisto.setContext(key, data)


def tableToMarkdown(name, t, headers=None, headerTransform=None, removeNull=False, metadata=None):
    """
       Converts a demisto table in JSON form to a Markdown table

       :type name: ``str``
       :param name: The name of the table (required)

       :type t: ``dict`` or ``list``
       :param t: The JSON table - List of dictionaries with the same keys or a single dictionary (required)

       :type headers: ``list`` or ``string``
       :keyword headers: A list of headers to be presented in the output table (by order). If string will be passed
            then table will have single header. Default will include all available headers.

       :type headerTransform: ``function``
       :keyword headerTransform: A function that formats the original data headers (optional)

       :type removeNull: ``bool``
       :keyword removeNull: Remove empty columns from the table. Default is False

       :type metadata: ``str``
       :param metadata: Metadata about the table contents

       :return: A string representation of the markdown table
       :rtype: ``str``
    """

    mdResult = ''
    if name:
        mdResult = '### ' + name + '\n'

    if metadata:
        mdResult += metadata + '\n'

    if not t or len(t) == 0:
        mdResult += '**No entries.**\n'
        return mdResult

    if not isinstance(t, list):
        t = [t]

    if headers and isinstance(headers, STRING_TYPES):
        headers = [headers]

    if not isinstance(t[0], dict):
        # the table cotains only simple objects (strings, numbers)
        # should be only one header
        if headers and len(headers) > 0:
            header = headers[0]
            t = map(lambda item: dict((h, item) for h in [header]), t)
        else:
            raise Exception("Missing headers param for tableToMarkdown. Example: headers=['Some Header']")

    # in case of headers was not provided (backward compatibility)
    if not headers:
        headers = list(t[0].keys())
        headers.sort()

    if removeNull:
        headers_aux = headers[:]
        for header in headers_aux:
            if all(obj.get(header) in ('', None, [], {}) for obj in t):
                headers.remove(header)

    if t and len(headers) > 0:
        newHeaders = []
        if headerTransform is None:  # noqa
            headerTransform = lambda s: s  # noqa
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
            vals = [stringEscapeMD((formatCell(entry.get(h, ''), False) if entry.get(h) is not None else ''),
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


def createContextSingle(obj, id=None, keyTransform=None, removeNull=False):
    """Receives a dict with flattened key values, and converts them into nested dicts

    :type obj: ``dict`` or ``list``
    :param obj: The data to be added to the context (required)

    :type id: ``str``
    :keyword id: The ID of the context entry

    :type keyTransform: ``function``
    :keyword keyTransform: A formatting function for the markdown table headers

    :type removeNull: ``bool``
    :keyword removeNull: True if empty columns should be removed, false otherwise

    :return: The converted context list
    :rtype: ``list``
    """
    res = {}  # type: dict
    if keyTransform is None:
        keyTransform = lambda s: s  # noqa
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
        :keyword id: The ID of the context entry

        :type keyTransform: ``function``
        :keyword keyTransform: A formatting function for the markdown table headers

        :type removeNull: ``bool``
        :keyword removeNull: True if empty columns should be removed, false otherwise

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
    if (IS_PY3 and isinstance(data, str)) or (not IS_PY3 and isinstance(data, unicode)):  # type: ignore
        data = data.encode('utf-8')
    # pylint: enable=undefined-variable
    with open(demisto.investigation()['id'] + '_' + temp, 'wb') as f:
        f.write(data)
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


MARKDOWN_CHARS = r"\`*_{}[]()#+-!"


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
        for c in '|':
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
    strip_ns_tag = tag
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
    return demisto.callingContext.get('IntegrationBrand')


class Common(object):
    class Indicator(object):
        """
        interface class
        """
        @abstractmethod
        def to_context(self):
            pass

    class DBotScore(object):
        """
        DBotScore class

        :type indicator: ``str``
        :param indicator: indicator value, ip, hash, domain, url, etc

        :type indicator_type: ``DBotScoreType``
        :param indicator_type: use DBotScoreType class

        :type integration_name: ``str``
        :param integration_name: integration name

        :type score: ``DBotScore``
        :param score: DBotScore.NONE, DBotScore.GOOD, DBotScore.SUSPICIOUS, DBotScore.BAD

        :type malicious_description: ``str``
        :param malicious_description: if the indicator is malicious and have explanation for it then set it to this field

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

        def __init__(self, indicator, indicator_type, integration_name, score, malicious_description=None):

            if not DBotScoreType.is_valid_type(indicator_type):
                raise TypeError('indicator_type must be of type DBotScoreType enum')

            if not Common.DBotScore.is_valid_score(score):
                raise TypeError('indicator_type must be of type DBotScore enum')

            self.indicator = indicator
            self.indicator_type = indicator_type
            self.integration_name = integration_name or get_integration_name()
            self.score = score
            self.malicious_description = malicious_description

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
            if is_demisto_version_ge('5.5.0'):
                return Common.DBotScore.CONTEXT_PATH
            else:
                return Common.DBotScore.CONTEXT_PATH_PRIOR_V5_5

        def to_context(self):
            return {
                Common.DBotScore.get_context_path(): {
                    'Indicator': self.indicator,
                    'Type': self.indicator_type,
                    'Vendor': self.integration_name,
                    'Score': self.score
                }
            }

    class IP(Indicator):
        """
        IP indicator class - https://xsoar.pan.dev/docs/context-standards#ip

        :type ip: ``str``
        :param ip: IP address

        :type asn: ``str``
        :param asn: The autonomous system name for the IP address, for example: "AS8948".

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

        :type dbot_score: ``DBotScore``
        :param dbot_score:

        :return: None
        :rtype: ``None``
        """
        CONTEXT_PATH = 'IP(val.Address && val.Address == obj.Address)'

        def __init__(self, ip, dbot_score, asn=None, hostname=None, geo_latitude=None, geo_longitude=None,
                     geo_country=None, geo_description=None, detection_engines=None, positive_engines=None):
            self.ip = ip
            self.asn = asn
            self.hostname = hostname
            self.geo_latitude = geo_latitude
            self.geo_longitude = geo_longitude
            self.geo_country = geo_country
            self.geo_description = geo_description
            self.detection_engines = detection_engines
            self.positive_engines = positive_engines

            if not isinstance(dbot_score, Common.DBotScore):
                raise ValueError('dbot_score must be of type DBotScore')

            self.dbot_score = dbot_score

        def to_context(self):
            ip_context = {
                'Address': self.ip
            }

            if self.asn:
                ip_context['ASN'] = self.asn

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

            if self.detection_engines:
                ip_context['DetectionEngines'] = self.detection_engines

            if self.positive_engines:
                ip_context['PositiveDetections'] = self.positive_engines

            if self.dbot_score and self.dbot_score.score == Common.DBotScore.BAD:
                ip_context['Malicious'] = {
                    'Vendor': self.dbot_score.integration_name,
                    'Description': self.dbot_score.malicious_description
                }

            ret_value = {
                Common.IP.CONTEXT_PATH: ip_context
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

    class File(Indicator):
        """
        File indicator class - https://xsoar.pan.dev/docs/context-standards#file
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

        :type dbot_score: ``DBotScore``
        :param dbot_score: If file has a score then create and set a DBotScore object

        :rtype: ``None``
        :return: None
        """
        CONTEXT_PATH = 'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || ' \
                       'val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || ' \
                       'val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || ' \
                       'val.SSDeep && val.SSDeep == obj.SSDeep)'

        def __init__(self, dbot_score, name=None, entry_id=None, size=None, md5=None, sha1=None, sha256=None,
                     sha512=None, ssdeep=None, extension=None, file_type=None, hostname=None, path=None, company=None,
                     product_name=None, digital_signature__publisher=None, signature=None, actor=None, tags=None):

            self.name = name
            self.entry_id = entry_id
            self.size = size
            self.md5 = md5
            self.sha1 = sha1
            self.sha256 = sha256
            self.sha512 = sha512
            self.ssdeep = ssdeep
            self.extension = extension
            self.file_type = file_type
            self.hostname = hostname
            self.path = path
            self.company = company
            self.product_name = product_name
            self.digital_signature__publisher = digital_signature__publisher
            self.signature = signature
            self.actor = actor
            self.tags = tags

            self.dbot_score = dbot_score

        def to_context(self):
            file_context = {}

            if self.name:
                file_context['Name'] = self.name
            if self.entry_id:
                file_context['EntryID'] = self.entry_id
            if self.size:
                file_context['Size'] = self.size
            if self.md5:
                file_context['MD5'] = self.md5
            if self.sha1:
                file_context['SHA1'] = self.sha1
            if self.sha256:
                file_context['SHA256'] = self.sha256
            if self.sha512:
                file_context['SHA512'] = self.sha512
            if self.ssdeep:
                file_context['SSDeep'] = self.ssdeep
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

            if self.dbot_score and self.dbot_score.score == Common.DBotScore.BAD:
                file_context['Malicious'] = {
                    'Vendor': self.dbot_score.integration_name,
                    'Description': self.dbot_score.malicious_description
                }

            ret_value = {
                Common.File.CONTEXT_PATH: file_context
            }

            if self.dbot_score:
                ret_value.update(self.dbot_score.to_context())

            return ret_value

    class CVE(Indicator):
        """
        CVE indicator class - https://xsoar.pan.dev/docs/context-standards#cve
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
        :return: None
        :rtype: ``None``
        """
        CONTEXT_PATH = 'CVE(val.ID && val.ID == obj.ID)'

        def __init__(self, id, cvss, published, modified, description):
            # type (str, str, str, str, str) -> None

            self.id = id
            self.cvss = cvss
            self.published = published
            self.modified = modified
            self.description = description
            self.dbot_score = Common.DBotScore(
                indicator=id,
                indicator_type=DBotScoreType.CVE,
                integration_name=None,
                score=Common.DBotScore.NONE
            )

        def to_context(self):
            cve_context = {
                'ID': self.id
            }

            if self.cvss:
                cve_context['CVSS'] = self.cvss

            if self.published:
                cve_context['Published'] = self.published

            if self.modified:
                cve_context['Modified'] = self.modified

            if self.description:
                cve_context['Description'] = self.description

            ret_value = {
                Common.CVE.CONTEXT_PATH: cve_context
            }

            if self.dbot_score:
                ret_value.update(self.dbot_score.to_context())

            return ret_value

    class URL(Indicator):
        """
        URL indicator - https://xsoar.pan.dev/docs/context-standards#url
        :type url: ``str``
        :param url: The URL

        :type detection_engines: ``int``
        :param detection_engines: The total number of engines that checked the indicator.

        :type positive_detections: ``int``
        :param positive_detections: The number of engines that positively detected the indicator as malicious.

        :type dbot_score: ``DBotScore``
        :param dbot_score: If URL has reputation then create DBotScore object

        :return: None
        :rtype: ``None``
        """
        CONTEXT_PATH = 'URL(val.Data && val.Data == obj.Data)'

        def __init__(self, url, dbot_score, detection_engines=None, positive_detections=None):
            self.url = url
            self.detection_engines = detection_engines
            self.positive_detections = positive_detections

            self.dbot_score = dbot_score

        def to_context(self):
            url_context = {
                'Data': self.url
            }

            if self.detection_engines:
                url_context['DetectionEngines'] = self.detection_engines

            if self.positive_detections:
                url_context['PositiveDetections'] = self.positive_detections

            if self.dbot_score and self.dbot_score.score == Common.DBotScore.BAD:
                url_context['Malicious'] = {
                    'Vendor': self.dbot_score.integration_name,
                    'Description': self.dbot_score.malicious_description
                }

            ret_value = {
                Common.URL.CONTEXT_PATH: url_context
            }

            if self.dbot_score:
                ret_value.update(self.dbot_score.to_context())

            return ret_value


    class Domain(Indicator):
        """ ignore docstring
        Domain indicator - https://xsoar.pan.dev/docs/context-standards#domain
        """
        CONTEXT_PATH = 'Domain(val.Name && val.Name == obj.Name)'

        def __init__(self, domain, dbot_score, dns=None, detection_engines=None, positive_detections=None,
                     organization=None, sub_domains=None, creation_date=None, updated_date=None, expiration_date=None,
                     domain_status=None, name_servers=None,
                     registrar_name=None, registrar_abuse_email=None, registrar_abuse_phone=None,
                     registrant_name=None, registrant_email=None, registrant_phone=None, registrant_country=None,
                     admin_name=None, admin_email=None, admin_phone=None, admin_country=None):
            self.domain = domain
            self.dns = dns
            self.detection_engines = detection_engines
            self.positive_detections = positive_detections
            self.organization = organization
            self.sub_domains = sub_domains
            self.creation_date = creation_date
            self.updated_date = updated_date
            self.expiration_date = expiration_date

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


            self.domain_status = domain_status
            self.name_servers = name_servers

            self.dbot_score = dbot_score

        def to_context(self):
            domain_context = {
                'Name': self.domain
            }
            whois_context = {}

            if self.dns:
                domain_context['DNS'] = self.dns

            if self.detection_engines:
                domain_context['DetectionEngines'] = self.detection_engines

            if self.positive_detections:
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

            if self.dbot_score and self.dbot_score.score == Common.DBotScore.BAD:
                domain_context['Malicious'] = {
                    'Vendor': self.dbot_score.integration_name,
                    'Description': self.dbot_score.malicious_description
                }

            if whois_context:
                domain_context['WHOIS'] = whois_context

            ret_value = {
                Common.Domain.CONTEXT_PATH: domain_context
            }

            if self.dbot_score:
                ret_value.update(self.dbot_score.to_context())

            return ret_value

    class Endpoint(Indicator):
        """ ignore docstring
        Endpoint indicator - https://xsoar.pan.dev/docs/integrations/context-standards#endpoint
        """
        CONTEXT_PATH = 'Endpoint(val.ID && val.ID == obj.ID)'

        def __init__(self, id, hostname=None, ip_address=None, domain=None, mac_address=None,
                     os=None, os_version=None, dhcp_server=None, bios_version=None, model=None,
                     memory=None, processors=None, processor=None):
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

            ret_value = {
                Common.Endpoint.CONTEXT_PATH: endpoint_context
            }

            return ret_value


class CommandResults:
    """
    CommandResults class - use to return results to warroom

    :type outputs_prefix: ``str``
    :param outputs_prefix: should be identical to the prefix in the yml contextPath in yml file. for example:
            CortexXDR.Incident

    :type outputs_key_field: ``str``
    :param outputs_key_field: primary key field in the main object. If the command returns Incidents, and of the
            properties of Incident is incident_id, then outputs_key_field='incident_id'

    :type outputs: ``list`` or ``dict``
    :param outputs: the data to be returned and will be set to context

    :type indicators: ``list``
    :param indicators: must be list of Indicator types, like Common.IP, Common.URL, Common.File, etc.

    :type readable_output: ``str``
    :param readable_output: (Optional) markdown string that will be presented in the warroom, should be human readable -
        (HumanReadable) - if not set, readable output will be generated

    :type raw_response: ``dict`` | ``list``
    :param raw_response: must be dictionary, if not provided then will be equal to outputs. usually must be the original
        raw response from the 3rd party service (originally Contents)

    :return: None
    :rtype: ``None``
    """
    def __init__(self, outputs_prefix, outputs_key_field, outputs, indicators=None, readable_output=None,
                 raw_response=None):

        # type: (str, str, object, list, str, object) -> None
        self.indicators = indicators

        self.outputs_prefix = outputs_prefix
        self.outputs_key_field = outputs_key_field
        self.outputs = outputs

        self.raw_response = raw_response
        self.readable_output = readable_output

    def to_context(self):
        outputs = {}  # type: dict
        human_readable = None
        raw_response = None

        if self.indicators:
            for indicator in self.indicators:
                context_outputs = indicator.to_context()

                for key, value in context_outputs.items():
                    if key not in outputs:
                        outputs[key] = []

                    outputs[key].append(value)

        if self.raw_response:
            raw_response = self.raw_response

        if self.outputs:
            if not self.readable_output:
                # if markdown is not provided then create table by default
                human_readable = tableToMarkdown('Results', self.outputs)
            else:
                human_readable = self.readable_output

            if not self.raw_response:
                raw_response = self.outputs

            if self.outputs_prefix and self.outputs_key_field:
                # if both prefix and key field provided then create DT key
                outputs_key = '{0}(val.{1} == obj.{1})'.format(self.outputs_prefix, self.outputs_key_field)
                outputs[outputs_key] = self.outputs
            elif self.outputs_prefix:
                outputs_key = '{}'.format(self.outputs_prefix)
                outputs[outputs_key] = self.outputs
            else:
                outputs = self.outputs
                human_readable = self.readable_output  # prefix and key field not provided, human readable should

        return_entry = {
            'Type': EntryType.NOTE,
            'ContentsFormat': EntryFormat.JSON,
            'Contents': raw_response,
            'HumanReadable': human_readable,
            'EntryContext': outputs
        }

        return return_entry


def return_results(results):
    """
    This function wraps the demisto.results(), supports.

    :type results: ``CommandResults`` or ``str`` or ``dict``
    :param results:

    :return: None
    :rtype: ``None``
    """
    if results is None:
        # backward compatibility reasons
        demisto.results(None)
        return

    if isinstance(results, CommandResults):
        demisto.results(results.to_context())
        return

    demisto.results(results)


# deprecated
def return_outputs(readable_output, outputs=None, raw_response=None, timeline=None, ignore_auto_extract=False):
    """
    DEPRECATED: use return_results() instead

    This function wraps the demisto.results(), makes the usage of returning results to the user more intuitively.

    :type readable_output: ``str``
    :param readable_output: markdown string that will be presented in the warroom, should be human readable -
        (HumanReadable)

    :type outputs: ``dict``
    :param outputs: the outputs that will be returned to playbook/investigation context (originally EntryContext)

    :type raw_response: ``dict`` | ``list``
    :param raw_response: must be dictionary, if not provided then will be equal to outputs. usually must be the original
        raw response from the 3rd party service (originally Contents)

    :type timeline: ``dict`` | ``list``
    :param timeline: expects a list, if a dict is passed it will be put into a list. used by server to populate an
        indicator's timeline. if the 'Category' field is not present in the timeline dict(s), it will automatically
        be be added to the dict(s) with its value set to 'Integration Update'.

    :type ignore_auto_extract: ``bool``
    :param ignore_auto_extract: expects a bool value. if true then the warroom entry readable_output will not be auto enriched.

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
        "ContentsFormat": formats["json"],
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
        :param message: The message to return in the entry (required)

        :type error: ``str`` or Exception
        :param error: The raw error message to log (optional)

        :type outputs: ``dict or None``
        :param outputs: the outputs that will be returned to playbook/investigation context (optional)

        :return: Error entry object
        :rtype: ``dict``
    """
    is_server_handled = hasattr(demisto, 'command') and demisto.command() in ('fetch-incidents',
                                                                              'long-running-execution',
                                                                              'fetch-indicators')
    if is_debug_mode() and not is_server_handled and any(sys.exc_info()):  # Checking that an exception occurred
        message = "{}\n\n{}".format(message, traceback.format_exc())

    LOG(message)
    if error:
        LOG(str(error))

    LOG.print_log()
    if not isinstance(message, str):
        message = message.encode('utf8') if hasattr(message, 'encode') else str(message)

    if is_server_handled:
        raise Exception(message)
    else:
        demisto.results({
            'Type': entryTypes['error'],
            'ContentsFormat': formats['text'],
            'Contents': message,
            'EntryContext': outputs
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


def camelize(src, delim=' '):
    """
        Convert all keys of a dictionary (or list of dictionaries) to CamelCase (with capital first letter)

        :type src: ``dict`` or ``list``
        :param src: The dictionary (or list of dictionaries) to convert the keys for. (required)

        :type delim: ``str``
        :param delim: The delimiter between two words in the key (e.g. delim=' ' for "Start Date"). Default ' '.

        :return: The dictionary (or list of dictionaries) with the keys in CamelCase.
        :rtype: ``dict`` or ``list``
    """

    def camelize_str(src_str):
        if callable(getattr(src_str, "decode", None)):
            src_str = src_str.decode('utf-8')
        components = src_str.split(delim)
        return ''.join(map(lambda x: x.title(), components))

    if isinstance(src, list):
        return [camelize(phrase, delim) for phrase in src]
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

ipv4Regex = r'\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b([^\/]|$)'
ipv4cidrRegex = r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\[\.\]|\.)){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\/([0-9]|[1-2][0-9]|3[0-2]))\b'
ipv6Regex = r'\b(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:(?:(:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\b'
ipv6cidrRegex = r'\b(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(\/(12[0-8]|1[0-1][0-9]|[1-9][0-9]|[0-9]))\b'
emailRegex = r'\b[^@]+@[^@]+\.[^@]+\b'
hashRegex = r'\b[0-9a-fA-F]+\b'
urlRegex = r'(?:(?:https?|ftp|hxxps?):\/\/|www\[?\.\]?|ftp\[?\.\]?)(?:[-\w\d]+\[?\.\]?)+[-\w\d]+(?::\d+)?' \
           r'(?:(?:\/|\?)[-\w\d+&@#\/%=~_$?!\-:,.\(\);]*[\w\d+&@#\/%=~_$\(\);])?'
cveRegex = r'(?i)^cve-\d{4}-([1-9]\d{4,}|\d{4})$'
md5Regex = re.compile(r'\b[0-9a-fA-F]{32}\b', regexFlags)
sha1Regex = re.compile(r'\b[0-9a-fA-F]{40}\b', regexFlags)
sha256Regex = re.compile(r'\b[0-9a-fA-F]{64}\b', regexFlags)

pascalRegex = re.compile('([A-Z]?[a-z]+)')


# ############################## REGEX FORMATTING end ###############################


def underscoreToCamelCase(s):
    """
       Convert an underscore separated string to camel case

       :type s: ``str``
       :param s: The string to convert (e.g. hello_world) (required)

       :return: The converted string (e.g. HelloWorld)
       :rtype: ``str``
    """
    if not isinstance(s, STRING_OBJ_TYPES):
        return s

    components = s.split('_')
    return ''.join(x.title() for x in components)


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

    tokens = pascalRegex.findall(s)
    for t in tokens:
        # double space to handle capital words like IP/URL/DNS that not included in the regex
        s = s.replace(t, ' {} '.format(t.title()))

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


def parse_date_range(date_range, date_format=None, to_timestamp=False, timezone=0, utc=True):
    """
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
    range_split = date_range.split(' ')
    if len(range_split) != 2:
        return_error('date_range must be "number date_range_unit", examples: (2 hours, 4 minutes,6 months, 1 day, '
                     'etc.)')

    number = int(range_split[0])
    if not range_split[1] in ['minute', 'minutes', 'hour', 'hours', 'day', 'days', 'month', 'months', 'year', 'years']:
        return_error('The unit of date_range is invalid. Must be minutes, hours, days, months or years')

    if not isinstance(timezone, (int, float)):
        return_error('Invalid timezone "{}" - must be a number (of type int or float).'.format(timezone))

    if utc:
        end_time = datetime.utcnow() + timedelta(hours=timezone)
        start_time = datetime.utcnow() + timedelta(hours=timezone)
    else:
        end_time = datetime.now() + timedelta(hours=timezone)
        start_time = datetime.now() + timedelta(hours=timezone)

    unit = range_split[1]
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


def get_demisto_version():
    """Returns the Demisto version and build number.

    :return: Demisto version object if Demisto class has attribute demistoVersion, else raises AttributeError
    :rtype: ``dict``
    """
    if getattr(get_demisto_version, '_version', None):
        return get_demisto_version._version
    if hasattr(demisto, 'demistoVersion'):
        version = demisto.demistoVersion()
        get_demisto_version._version = version
        return version
    else:
        raise AttributeError('demistoVersion attribute not found.')


def is_demisto_version_ge(version):
    """Utility function to check if current running integration is at a server greater or equal to the passed version

    :type version: ``str``
    :param version: Version to check

    :return: True if running within a Server version greater or equal than the passed version
    :rtype: ``bool``
    """
    try:
        server_version = get_demisto_version()
        return server_version.get('version') >= version
    except AttributeError:
        # demistoVersion was added in 5.0.0. We are currently running in 4.5.0 and below
        if version >= "5.0.0":
            return False
        raise


def is_debug_mode():
    """Return if this script/command was passed debug-mode=true option

    :return: true if debug-mode is enabled
    :rtype: ``bool``
    """
    # use `hasattr(demisto, 'is_debug')` to ensure compatibility with server version <= 4.5
    return hasattr(demisto, 'is_debug') and demisto.is_debug


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
                self.int_logger.write(msg)
            else:
                demisto.debug(msg)
        except Exception:
            pass


class DebugLogger(object):
    """
        Wrapper to initiate logging at logging.DEBUG level.
        Is used when `debug-mode=True`.
    """

    def __init__(self):
        logging.raiseExceptions = False
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
        self.handler = DemistoHandler()
        demisto_formatter = logging.Formatter(fmt='%(asctime)s - %(message)s', datefmt=None)
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

    def log_start_debug(self):
        """
        Utility function to log start of debug mode logging
        """
        msg = "debug-mode started.\nhttp client print found: {}.\nEnv {}.".format(self.http_client_print is not None, os.environ)
        if hasattr(demisto, 'params'):
            msg += "\nParams: {}.".format(demisto.params())
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
    class BaseClient(object):
        """Client to use in integrations with powerful _http_request
        :type base_url: ``str``
        :param base_url: Base server address with suffix, for example: https://example.com/api/v2/.

        :type verify: ``bool``
        :param verify: Whether the request should verify the SSL certificate.

        :type proxy: ``bool``
        :param proxy: Whether to run the integration using the system proxy.

        :type ok_codes: ``tuple``
        :param ok_codes:
            The request codes to accept as OK, for example: (200, 201, 204).
            If you specify "None", will use requests.Response.ok

        :type headers: ``dict``
        :param headers:
            The request headers, for example: {'Accept`: `application/json`}.
            Can be None.

        :type auth: ``dict`` or ``tuple``
        :param auth:
            The request authorization, for example: (username, password).
            Can be None.

        :return: No data returned
        :rtype: ``None``
        """

        def __init__(self, base_url, verify=True, proxy=False, ok_codes=tuple(), headers=None, auth=None):
            self._base_url = base_url
            self._verify = verify
            self._ok_codes = ok_codes
            self._headers = headers
            self._auth = auth
            self._session = requests.Session()
            if not proxy:
                self._session.trust_env = False

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
                retry = Retry(
                    total=retries,
                    read=retries,
                    connect=retries,
                    backoff_factor=backoff_factor,
                    status=retries,
                    status_forcelist=status_list_to_retry,
                    method_whitelist=frozenset(['GET', 'POST', 'PUT']),
                    raise_on_status=raise_on_status,
                    raise_on_redirect=raise_on_redirect
                )
                adapter = HTTPAdapter(max_retries=retry)
                self._session.mount('http://', adapter)
                self._session.mount('https://', adapter)
            except NameError:
                pass

        def _http_request(self, method, url_suffix, full_url=None, headers=None, auth=None, json_data=None,
                          params=None, data=None, files=None, timeout=10, resp_type='json', ok_codes=None,
                          return_empty_response = False, retries=0, status_list_to_retry=None,
                          backoff_factor=5, raise_on_redirect=False, raise_on_status=False, **kwargs):
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

            :return: Depends on the resp_type parameter
            :rtype: ``dict`` or ``str`` or ``requests.Response``

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
                # Replace params if supplied
                address = full_url if full_url else urljoin(self._base_url, url_suffix)
                headers = headers if headers else self._headers
                auth = auth if auth else self._auth
                self._implement_retry(retries, status_list_to_retry, backoff_factor, raise_on_redirect, raise_on_status)
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
                # Handle error responses gracefully
                if not self._is_status_code_valid(res, ok_codes):
                    err_msg = 'Error in API call [{}] - {}' \
                        .format(res.status_code, res.reason)
                    try:
                        # Try to parse json error response
                        error_entry = res.json()
                        err_msg += '\n{}'.format(json.dumps(error_entry))
                        raise DemistoException(err_msg)
                    except ValueError:
                        err_msg += '\n{}'.format(res.text)
                        raise DemistoException(err_msg)

                is_response_empty_and_successful = (res.status_code == 204)
                if is_response_empty_and_successful and return_empty_response:
                    return res

                resp_type = resp_type.lower()
                try:
                    if resp_type == 'json':
                        return res.json()
                    if resp_type == 'text':
                        return res.text
                    if resp_type == 'content':
                        return res.content
                    if resp_type == 'xml':
                        ET.parse(res.text)
                    return res
                except ValueError as exception:
                    raise DemistoException('Failed to parse json object from response: {}'
                                           .format(res.content), exception)
            except requests.exceptions.ConnectTimeout as exception:
                err_msg = 'Connection Timeout Error - potential reasons might be that the Server URL parameter' \
                          ' is incorrect or that the Server is not accessible from your host.'
                raise DemistoException(err_msg, exception)
            except requests.exceptions.SSLError as exception:
                err_msg = 'SSL Certificate Verification Failed - try selecting \'Trust any certificate\' checkbox in' \
                          ' the integration configuration.'
                raise DemistoException(err_msg, exception)
            except requests.exceptions.ProxyError as exception:
                err_msg = 'Proxy Error - if the \'Use system proxy\' checkbox in the integration configuration is' \
                          ' selected, try clearing the checkbox.'
                raise DemistoException(err_msg, exception)
            except requests.exceptions.ConnectionError as exception:
                # Get originating Exception in Exception chain
                error_class = str(exception.__class__)
                err_type = '<' + error_class[error_class.find('\'') + 1: error_class.rfind('\'')] + '>'
                err_msg = '\nError Type: {}\nError Number: [{}]\nMessage: {}\n' \
                          'Verify that the server URL parameter' \
                          ' is correct and that you have access to the server from your host.' \
                    .format(err_type, exception.errno, exception.strerror)
                raise DemistoException(err_msg, exception)
            except requests.exceptions.RetryError as exception:
                try:
                    reason = 'Reason: {}'.format(exception.args[0].reason.args[0])
                except:
                    reason = ''
                err_msg = 'Max Retries Error- Request attempts with {} retries failed. \n{}'.format(retries, reason)
                raise DemistoException(err_msg, exception)


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

def dict_safe_get(dict_object, keys, default_return_value = None):
    """Recursive safe get query, If keys found return value othewise return None or default value.

    :type dict_object: ``dict``
    :param dict_object: dictionary to query.

    :type keys: ``list``
    :param keys: keys for recursive get.

    :type default_return_value: ``object``
    :param default_return_value: Value to return when no key availble.

    :rtype: ``object``
    :return:: Value found.
    """
    for key in keys:
        try:
            dict_object = dict_object[key]
        except (KeyError, TypeError):
            return default_return_value

    return dict_object


class DemistoException(Exception):
    pass
