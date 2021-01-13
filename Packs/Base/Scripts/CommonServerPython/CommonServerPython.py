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
from random import randint
import xml.etree.cElementTree as ET
from collections import OrderedDict
from datetime import datetime, timedelta
from abc import abstractmethod

import demistomock as demisto
import warnings


class WarningsHandler(object):
    #    Wrapper to handle warnings. We use a class to cleanup after execution

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
    from typing import Optional, Dict, List, Any, Union, Set

    import dateparser
    from datetime import timezone  # type: ignore
except Exception:
    if sys.version_info[0] < 3:
        # in python 2 an exception in the imports might still be raised even though it is caught.
        # for more info see https://cosmicpercolator.com/2016/01/13/exception-leaks-in-python-2-and-3/
        sys.exc_clear()

CONTENT_RELEASE_VERSION = '0.0.0'
CONTENT_BRANCH_NAME = 'master'
IS_PY3 = sys.version_info[0] == 3

# pylint: disable=undefined-variable

ZERO = timedelta(0)
HOUR = timedelta(hours=1)


if IS_PY3:
    STRING_TYPES = (str, bytes)  # type: ignore
    STRING_OBJ_TYPES = (str,)

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
    'widget': 17
}


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
    WARNING = 11
    MAP_ENTRY_TYPE = 15
    WIDGET = 17


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
        )

class DBotScoreReliability(object):
    """
    Enum: Source reliability levels
    Values are case sensitive

    :return: None
    :rtype: ``None``
    """
    COMPLETELY = 'A: Completely reliable'
    USUALLY = 'B: Usually reliable'
    FAIRLY = 'C: Fairly reliable'
    NOT_USUALLY = 'D: Not usually reliable'
    UNRELIABLE = 'E: Unreliable'
    CANNOT_BE_JUDGED = 'F: Reliability cannot be judged'
    def __init__(self):
        # required to create __init__ for create_server_docs.py purpose
        pass

    @classmethod
    def is_valid_type(cls, _type):
        # type: (str) -> bool

        return _type in (
            DBotScoreReliability.COMPLETELY,
            DBotScoreReliability.USUALLY,
            DBotScoreReliability.FAIRLY,
            DBotScoreReliability.NOT_USUALLY,
            DBotScoreReliability.UNRELIABLE,
            DBotScoreReliability.CANNOT_BE_JUDGED,
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


def is_debug_mode():
    """Return if this script/command was passed debug-mode=true option

    :return: true if debug-mode is enabled
    :rtype: ``bool``
    """
    # use `hasattr(demisto, 'is_debug')` to ensure compatibility with server version <= 4.5
    return hasattr(demisto, 'is_debug') and demisto.is_debug


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

    if re.match(sha512Regex, indicator_value):
        return FeedIndicatorType.File

    try:
        no_cache_extract = tldextract.TLDExtract(cache_file=False, suffix_list_urls=None)
        if no_cache_extract(indicator_value).suffix:
            if '*' in indicator_value:
                return FeedIndicatorType.DomainGlob
            return FeedIndicatorType.Domain

    except Exception:
        pass

    return None


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
            param_names = (insecure_param_name,)  # type: ignore[assignment]
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
    except UnicodeEncodeError:
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
      use LOG(<message>) to add a record to the logger (message can be any object with __str__)
      use LOG.print_log(verbose=True/False) to display all records in War-Room (if verbose) and server log.
      use add_replace_strs to add sensitive strings that should be replaced before going to the log.

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
        data = text.split("send: b'")[1]
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
                demisto.info(text)
                if is_debug_mode() and text.startswith('send:'):
                    try:
                        self.build_curl(text)
                    except Exception as e:  # should fail silently
                        demisto.debug('Failed generating curl - {}'.format(str(e)))
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
                new_val = [existing, data]  # type: ignore[assignment]
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


def create_clickable_url(url):
    """
    Make the given url clickable when in markdown format by concatenating itself, with the proper brackets

    :type url: ``Union[List[str], str]``
    :param url: the url of interest or a list of urls

    :return: markdown format for clickable url
    :rtype: ``str``

    """
    if not url:
        return None
    elif isinstance(url, list):
        return ['[{}]({})'.format(item, item) for item in url]
    return '[{}]({})'.format(url, url)


def tableToMarkdown(name, t, headers=None, headerTransform=None, removeNull=False, metadata=None, url_keys=None):
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

       :type url_keys: ``list``
       :param url_keys: a list of keys in the given JSON table that should be turned in to clickable

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

    if not isinstance(t, list):
        t = [t]

    if headers and isinstance(headers, STRING_TYPES):
        headers = [headers]

    if not isinstance(t[0], dict):
        # the table contains only simple objects (strings, numbers)
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
    if (IS_PY3 and isinstance(data, str)) or (not IS_PY3 and isinstance(data, unicode)):  # type: ignore # noqa: F821
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

        :type reliability: ``DBotScoreReliability``
        :param reliability: use DBotScoreReliability class

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

        def __init__(self, indicator, indicator_type, integration_name, score, malicious_description=None,
                     reliability=None):

            if not DBotScoreType.is_valid_type(indicator_type):
                raise TypeError('indicator_type must be of type DBotScoreType enum')

            if not Common.DBotScore.is_valid_score(score):
                raise TypeError('indicator_type must be of type DBotScore enum')

            if reliability and not DBotScoreReliability.is_valid_type(reliability):
                raise TypeError('reliability must be of type DBotScoreReliability enum')

            self.indicator = indicator
            self.indicator_type = indicator_type
            self.integration_name = integration_name or get_integration_name()
            self.score = score
            self.malicious_description = malicious_description
            self.reliability = reliability

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
            dbot_context = {
                'Indicator': self.indicator,
                'Type': self.indicator_type,
                'Vendor': self.integration_name,
                'Score': self.score
            }

            if self.reliability:
                dbot_context['Reliability'] = self.reliability

            ret_value = {
                Common.DBotScore.get_context_path(): dbot_context
            }
            return ret_value

    class IP(Indicator):
        """
        IP indicator class - https://xsoar.pan.dev/docs/integrations/context-standards-mandatory#ip

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
        :param dbot_score: If IP has a score then create and set a DBotScore object.

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
        URL indicator - https://xsoar.pan.dev/docs/integrations/context-standards-mandatory#url
        :type url: ``str``
        :param url: The URL

        :type detection_engines: ``int``
        :param detection_engines: The total number of engines that checked the indicator.

        :type positive_detections: ``int``
        :param positive_detections: The number of engines that positively detected the indicator as malicious.

        :type category: ``str``
        :param category: The category associated with the indicator.

        :type dbot_score: ``DBotScore``
        :param dbot_score: If URL has reputation then create DBotScore object

        :return: None
        :rtype: ``None``
        """
        CONTEXT_PATH = 'URL(val.Data && val.Data == obj.Data)'

        def __init__(self, url, dbot_score, detection_engines=None, positive_detections=None, category=None):
            self.url = url
            self.detection_engines = detection_engines
            self.positive_detections = positive_detections
            self.category = category

            self.dbot_score = dbot_score

        def to_context(self):
            url_context = {
                'Data': self.url
            }

            if self.detection_engines:
                url_context['DetectionEngines'] = self.detection_engines

            if self.positive_detections:
                url_context['PositiveDetections'] = self.positive_detections

            if self.category:
                url_context['Category'] = self.category

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
        Domain indicator - https://xsoar.pan.dev/docs/integrations/context-standards-mandatory#domain
        """
        CONTEXT_PATH = 'Domain(val.Name && val.Name == obj.Name)'

        def __init__(self, domain, dbot_score, dns=None, detection_engines=None, positive_detections=None,
                     organization=None, sub_domains=None, creation_date=None, updated_date=None, expiration_date=None,
                     domain_status=None, name_servers=None,
                     registrar_name=None, registrar_abuse_email=None, registrar_abuse_phone=None,
                     registrant_name=None, registrant_email=None, registrant_phone=None, registrant_country=None,
                     admin_name=None, admin_email=None, admin_phone=None, admin_country=None, tags=None):
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
            self.tags = tags

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

            if self.tags:
                domain_context['Tags'] = self.tags

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
        Endpoint indicator - https://xsoar.pan.dev/docs/integrations/context-standards-mandatory#endpoint
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

    class Account(Indicator):
        """
        Account indicator - https://xsoar.pan.dev/docs/integrations/context-standards-recommended#account

        :type dbot_score: ``DBotScore``
        :param dbot_score: If account has reputation then create DBotScore object

        :return: None
        :rtype: ``None``
        """
        CONTEXT_PATH = 'Account(val.id && val.id == obj.id)'

        def __init__(self, id, type=None, username=None, display_name=None, groups=None,
                     domain=None, email_address=None, telephone_number=None, office=None, job_title=None,
                     department=None, country=None, state=None, city=None, street=None, is_enabled=None,
                     dbot_score=None):
            self.id = id
            self.type = type
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

            if not isinstance(dbot_score, Common.DBotScore):
                raise ValueError('dbot_score must be of type DBotScore')

            self.dbot_score = dbot_score

        def to_context(self):
            account_context = {
                'Id': self.id
            }

            if self.type:
                account_context['Type'] = self.type

            irrelevent = ['CONTEXT_PATH', 'to_context', 'dbot_score', 'Id']
            details = [detail for detail in dir(self) if not detail.startswith('__') and detail not in irrelevent]
            for detail in details:
                if self.__getattribute__(detail):
                    if detail == 'email_address':
                        account_context['Email'] = {
                            'Address': self.email_address
                        }
                    else:
                        Detail = camelize_string(detail, '_')
                        account_context[Detail] = self.__getattribute__(detail)

            if self.dbot_score and self.dbot_score.score == Common.DBotScore.BAD:
                account_context['Malicious'] = {
                    'Vendor': self.dbot_score.integration_name,
                    'Description': self.dbot_score.malicious_description
                }

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
                and any(isinstance(e, Common.CertificateExtension) for e in extensions)
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
                    elif(isinstance(san, Common.CertificateExtension.SubjectAlternativeName)):
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


def camelize_string(src_str, delim='_'):
    """
    Transform snake_case to CamelCase

    :type src_str: ``str``
    :param src_str: snake_case string to convert.

    :type delim: ``str``
    :param delim: indicator category.

    :return: A CammelCase string.
    :rtype: ``str``
    """
    components = src_str.split(delim)
    return ''.join(map(lambda x: x.title(), components))


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
            return datetime.utcfromtimestamp(ms).replace(tzinfo=timezone.utc)
        else:
            return datetime.fromtimestamp(ms)
    if isinstance(arg, str):
        # we use dateparser to handle strings either in ISO8601 format, or
        # relative time stamps.
        # For example: format 2019-10-23T00:00:00 or "3 days", etc
        if settings:
            date = dateparser.parse(arg, settings=settings)
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

    :return: None
    :rtype: ``None``
    """

    def __init__(self, outputs_prefix=None, outputs_key_field=None, outputs=None, indicators=None, readable_output=None,
                 raw_response=None, indicators_timeline=None, indicator=None, ignore_auto_extract=False):
        # type: (str, object, object, list, str, object, IndicatorsTimeline, Common.Indicator, bool) -> None
        if raw_response is None:
            raw_response = outputs

        if indicators and indicator:
            raise ValueError('indicators is DEPRECATED, use only indicator')
        self.indicators = indicators  # type: Optional[List[Common.Indicator]]
        self.indicator = indicator  # type: Optional[Common.Indicator]

        self.outputs_prefix = outputs_prefix

        # this is public field, it is used by a lot of unit tests, so I don't change it
        self.outputs_key_field = outputs_key_field

        self._outputs_key_field = None  # type: Optional[List[str]]
        if not outputs_key_field:
            self._outputs_key_field = None
        elif isinstance(outputs_key_field, STRING_TYPES):
            self._outputs_key_field = [outputs_key_field]
        elif isinstance(outputs_key_field, list):
            self._outputs_key_field = outputs_key_field
        else:
            raise TypeError('outputs_key_field must be of type str or list')

        self.outputs = outputs

        self.raw_response = raw_response
        self.readable_output = readable_output
        self.indicators_timeline = indicators_timeline
        self.ignore_auto_extract = ignore_auto_extract

    def to_context(self):
        outputs = {}  # type: dict
        if self.readable_output:
            human_readable = self.readable_output
        else:
            human_readable = None  # type: ignore[assignment]
        raw_response = None  # type: ignore[assignment]
        indicators_timeline = []  # type: ignore[assignment]
        ignore_auto_extract = False  # type: bool

        indicators = [self.indicator] if self.indicator else self.indicators

        if indicators:
            for indicator in indicators:
                context_outputs = indicator.to_context()

                for key, value in context_outputs.items():
                    if key not in outputs:
                        outputs[key] = []

                    outputs[key].append(value)

        if self.raw_response:
            raw_response = self.raw_response

        if self.ignore_auto_extract:
            ignore_auto_extract = True

        if self.indicators_timeline:
            indicators_timeline = self.indicators_timeline.indicators_timeline

        if self.outputs is not None and self.outputs != []:
            if not self.readable_output:
                # if markdown is not provided then create table by default
                human_readable = tableToMarkdown('Results', self.outputs)
            if self.outputs_prefix and self._outputs_key_field:
                # if both prefix and key field provided then create DT key
                formatted_outputs_key = ' && '.join(['val.{0} == obj.{0}'.format(key_field)
                                                     for key_field in self._outputs_key_field])
                outputs_key = '{0}({1})'.format(self.outputs_prefix, formatted_outputs_key)
                outputs[outputs_key] = self.outputs
            elif self.outputs_prefix:
                outputs_key = '{}'.format(self.outputs_prefix)
                outputs[outputs_key] = self.outputs
            else:
                outputs = self.outputs  # type: ignore[assignment]

        content_format = EntryFormat.JSON
        if isinstance(raw_response, STRING_TYPES) or isinstance(raw_response, int):
            content_format = EntryFormat.TEXT

        return_entry = {
            'Type': EntryType.NOTE,
            'ContentsFormat': content_format,
            'Contents': raw_response,
            'HumanReadable': human_readable,
            'EntryContext': outputs,
            'IndicatorTimeline': indicators_timeline,
            'IgnoreAutoExtract': True if ignore_auto_extract else False
        }

        return return_entry


def return_results(results):
    """
    This function wraps the demisto.results(), supports.

    :type results: ``CommandResults`` or ``str`` or ``dict`` or ``BaseWidget`` or ``IAMUserProfile`` or ``list``
    :param results: A result object to return as a War-Room entry.

    :return: None
    :rtype: ``None``
    """
    if results is None:
        # backward compatibility reasons
        demisto.results(None)
        return

    if results and isinstance(results, list) and len(results) > 0 and isinstance(results[0], CommandResults):
        for result in results:
            demisto.results(result.to_context())
        return

    if isinstance(results, CommandResults):
        demisto.results(results.to_context())
        return

    if isinstance(results, BaseWidget):
        demisto.results(results.to_display())
        return

    if isinstance(results, GetMappingFieldsResponse):
        demisto.results(results.extract_mapping())
        return

    if isinstance(results, GetRemoteDataResponse):
        demisto.results(results.extract_for_local())
        return

    if isinstance(results, IAMUserProfile):
        demisto.results(results.to_entry())
        return

    if isinstance(results, GetModifiedRemoteDataResponse):
        demisto.results(results.to_entry())
        return

    demisto.results(results)


# deprecated
def return_outputs(readable_output, outputs=None, raw_response=None, timeline=None, ignore_auto_extract=False):
    """
    DEPRECATED: use return_results() instead

    This function wraps the demisto.results(), makes the usage of returning results to the user more intuitively.

    :type readable_output: ``str`` | ``int``
    :param readable_output: markdown string that will be presented in the warroom, should be human readable -
        (HumanReadable)

    :type outputs: ``dict``
    :param outputs: the outputs that will be returned to playbook/investigation context (originally EntryContext)

    :type raw_response: ``dict`` | ``list`` | ``str``
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

    message = LOG(message)
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
ipv4cidrRegex = r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\[\.\]|\.)){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\/([0-9]|[1-2][0-9]|3[0-2]))\b'  # noqa: E501
ipv6Regex = r'\b(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:(?:(:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\b'  # noqa: E501
ipv6cidrRegex = r'\b(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(\/(12[0-8]|1[0-1][0-9]|[1-9][0-9]|[0-9]))\b'  # noqa: E501
emailRegex = r'\b[^@]+@[^@]+\.[^@]+\b'
hashRegex = r'\b[0-9a-fA-F]+\b'
urlRegex = r'(?:(?:https?|ftp|hxxps?):\/\/|www\[?\.\]?|ftp\[?\.\]?)(?:[-\w\d]+\[?\.\]?)+[-\w\d]+(?::\d+)?' \
           r'(?:(?:\/|\?)[-\w\d+&@#\/%=~_$?!\-:,.\(\);]*[\w\d+&@#\/%=~_$\(\);])?'
cveRegex = r'(?i)^cve-\d{4}-([1-9]\d{4,}|\d{4})$'
md5Regex = re.compile(r'\b[0-9a-fA-F]{32}\b', regexFlags)
sha1Regex = re.compile(r'\b[0-9a-fA-F]{40}\b', regexFlags)
sha256Regex = re.compile(r'\b[0-9a-fA-F]{64}\b', regexFlags)
sha512Regex = re.compile(r'\b[0-9a-fA-F]{128}\b', regexFlags)

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
        end_time = datetime.utcnow() + timedelta(hours=timezone)
        start_time = datetime.utcnow() + timedelta(hours=timezone)
    else:
        end_time = datetime.now() + timedelta(hours=timezone)
        start_time = datetime.now() + timedelta(hours=timezone)

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
    """Get the Demisto Server version as a string <version>-<build>. If unknown will return: 'Unknown'.
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
    try:
        server_version = get_demisto_version()
        return \
            server_version.get('version') >= version and \
            (not build_number or server_version.get('buildNumber') >= build_number)
    except AttributeError:
        # demistoVersion was added in 5.0.0. We are currently running in 4.5.0 and below
        if version >= "5.0.0":
            return False
        raise


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
        except Exception:
            pass


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
        callingContext = demisto.callingContext.get('context', {})
        msg += "\n#### Docker image: [{}]".format(callingContext.get('DockerImage'))
        brand = callingContext.get('IntegrationBrand')
        if brand:
            msg += "\n#### Integration: brand: [{}] instance: [{}]".format(brand, callingContext.get('IntegrationInstance'))
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

        def _http_request(self, method, url_suffix='', full_url=None, headers=None, auth=None, json_data=None,
                          params=None, data=None, files=None, timeout=10, resp_type='json', ok_codes=None,
                          return_empty_response=False, retries=0, status_list_to_retry=None,
                          backoff_factor=5, raise_on_redirect=False, raise_on_status=False,
                          error_handler=None, empty_valid_codes=None, **kwargs):
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

            :type error_handler ``callable``
            :param error_handler: Given an error entery, the error handler outputs the
                new formatted error message.

            :type empty_valid_codes: ``list``
            :param empty_valid_codes: A list of all valid status codes of empty responses (usually only 204, but
                can vary)

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
                    if error_handler:
                        error_handler(res)
                    else:
                        err_msg = 'Error in API call [{}] - {}' \
                            .format(res.status_code, res.reason)
                        try:
                            # Try to parse json error response
                            error_entry = res.json()
                            err_msg += '\n{}'.format(json.dumps(error_entry))
                            raise DemistoException(err_msg, res=res)
                        except ValueError:
                            err_msg += '\n{}'.format(res.text)
                            raise DemistoException(err_msg, res=res)

                if not empty_valid_codes:
                    empty_valid_codes = [204]
                is_response_empty_and_successful = (res.status_code in empty_valid_codes)
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
                err_msg = 'Verify that the server URL parameter' \
                          ' is correct and that you have access to the server from your host.' \
                          '\nError Type: {}\nError Number: [{}]\nMessage: {}\n' \
                    .format(err_type, exception.errno, exception.strerror)
                raise DemistoException(err_msg, exception)
            except requests.exceptions.RetryError as exception:
                try:
                    reason = 'Reason: {}'.format(exception.args[0].reason.args[0])
                except Exception:
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


def dict_safe_get(dict_object, keys, default_return_value=None, return_type=None, raise_return_type=True):
    """Recursive safe get query (for nested dicts and lists), If keys found return value otherwise return None or default value.
    Example:
    >>> dict = {"something" : {"test": "A"}}
    >>> dict_safe_get(dict,['something', 'test'])
    >>> 'A'
    >>> dict_safe_get(dict,['something', 'else'],'default value')
    >>> 'default value'

    :type dict_object: ``dict``
    :param dict_object: dictionary to query.

    :type keys: ``list``
    :param keys: keys for recursive get.

    :type default_return_value: ``object``
    :param default_return_value: Value to return when no key available.

    :type return_type: ``object``
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
            time.sleep(time_to_sleep)


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
    def __init__(self, message, exception=None, res=None, *args):
        self.res = res
        self.message = message
        self.exception = exception
        super(DemistoException, self).__init__(message, exception, *args)

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
            demisto.info('Updating object {}'.format(self.mirrored_object["id"]))
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
        all_mappings = []
        for scheme_types_mapping in self.scheme_types_mappings:
            all_mappings.append(scheme_types_mapping.extract_mapping())

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


class IAMErrors(object):
    """
    An enum class to manually handle errors in IAM integrations
    :return: None
    :rtype: ``None``
    """
    USER_DOES_NOT_EXIST = 404, 'User does not exist'
    USER_ALREADY_EXISTS = 409, 'User already exists'


class IAMActions(object):
    """
    Enum: contains all the IAM actions (e.g. get, update, create, etc.)
    :return: None
    :rtype: ``None``
    """
    GET_USER = 'get'
    UPDATE_USER = 'update'
    CREATE_USER = 'create'
    DISABLE_USER = 'disable'
    ENABLE_USER = 'enable'


class IAMVendorActionResult:
    """ This class is used in IAMUserProfile class to represent actions data.
    :return: None
    :rtype: ``None``
    """

    def __init__(self, success=True, active=None, iden=None, username=None, email=None, error_code=None,
                 error_message=None, details=None, skip=False, skip_reason=None, action=None, return_error=False):
        """ Sets the outputs and readable outputs attributes according to the given arguments.

        :param success: (bool) whether or not the command succeeded.
        :param active:  (bool) whether or not the user status is active.
        :param iden: (str) the user ID.
        :param username: (str) the username of the user.
        :param email:  (str) the email of the user.
        :param error_code: (str or int) the error code of the response, if exists.
        :param error_message: (str) the error details of the response, if exists.
        :param details: (dict) the full response.
        :param skip: (bool) whether or not the command is skipped.
        :param skip_reason: (str) If the command is skipped, describes the reason.
        :param action: (IAMActions) An enum object represents the action taken (get, update, create, etc).
        :param return_error: (bool) Whether or not to return an error entry.
        """
        self._brand = demisto.callingContext.get('context', {}).get('IntegrationBrand')
        self._instance_name = demisto.callingContext.get('context', {}).get('IntegrationInstance')
        self._success = success
        self._active = active
        self._iden = iden
        self._username = username
        self._email = email
        self._error_code = error_code
        self._error_message = error_message
        self._details = details
        self._skip = skip
        self._skip_reason = skip_reason
        self._action = action
        self._return_error = return_error

    def should_return_error(self):
        return self._return_error

    def create_outputs(self):
        """ Sets the outputs in `_outputs` attribute.
        """
        outputs = {
            'brand': self._brand,
            'instanceName': self._instance_name,
            'action': self._action,
            'success': self._success,
            'active': self._active,
            'id': self._iden,
            'username': self._username,
            'email': self._email,
            'errorCode': self._error_code,
            'errorMessage': self._error_message,
            'details': self._details,
            'skipped': self._skip,
            'reason': self._skip_reason
        }
        return outputs

    def create_readable_outputs(self, outputs):
        """ Sets the human readable output in `_readable_output` attribute.

        :param outputs: (dict) the command outputs.
        """
        title = self._action.title() + ' User Results ({})'.format(self._brand)

        if not self._skip:
            headers = ["brand", "instanceName", "success", "active", "id", "username",
                       "email", "errorCode", "errorMessage", "details"]
        else:
            headers = ["brand", "instanceName", "skipped", "reason"]

        readable_output = tableToMarkdown(
            name=title,
            t=outputs,
            headers=headers,
            removeNull=True
        )

        return readable_output


class IAMUserProfile:
    """ A User Profile object class for IAM integrations.

    :type _user_profile: ``str``
    :param _user_profile: The user profile information.

    :type _user_profile_delta: ``str``
    :param _user_profile_delta: The user profile delta.

    :type _vendor_action_results: ``list``
    :param _vendor_action_results: A List of data returned from the vendor.

    :return: None
    :rtype: ``None``
    """

    INDICATOR_TYPE = 'User Profile'

    def __init__(self, user_profile, user_profile_delta=None):
        self._user_profile = safe_load_json(user_profile)
        self._user_profile_delta = safe_load_json(user_profile_delta) if user_profile_delta else {}
        self._vendor_action_results = []

    def get_attribute(self, item):
        return self._user_profile.get(item)

    def to_entry(self):
        """ Generates a XSOAR IAM entry from the data in _vendor_action_results.
        Note: Currently we are using only the first element of the list, in the future we will support multiple results.

        :return: A XSOAR entry.
        :rtype: ``dict``
        """

        outputs = self._vendor_action_results[0].create_outputs()
        readable_output = self._vendor_action_results[0].create_readable_outputs(outputs)

        entry_context = {
            'IAM.UserProfile(val.email && val.email == obj.email)': self._user_profile,
            'IAM.Vendor(val.instanceName && val.instanceName == obj.instanceName && '
            'val.email && val.email == obj.email)': outputs
        }

        return_entry = {
            'ContentsFormat': EntryFormat.JSON,
            'Contents': outputs,
            'EntryContext': entry_context
        }

        if self._vendor_action_results[0].should_return_error():
            return_entry['Type'] = EntryType.ERROR
        else:
            return_entry['Type'] = EntryType.NOTE
            return_entry['HumanReadable'] = readable_output

        return return_entry

    def set_result(self, success=True, active=None, iden=None, username=None, email=None, error_code=None,
                   error_message=None, details=None, skip=False, skip_reason=None, action=None, return_error=False):
        """ Sets the outputs and readable outputs attributes according to the given arguments.

        :param success: (bool) whether or not the command succeeded.
        :param active:  (bool) whether or not the user status is active.
        :param iden: (str) the user ID.
        :param username: (str) the username of the user.
        :param email:  (str) the email of the user.
        :param error_code: (str or int) the error code of the response, if exists.
        :param error_message: (str) the error details of the response, if exists.
        :param details: (dict) the full response.
        :param skip: (bool) whether or not the command is skipped.
        :param skip_reason: (str) If the command is skipped, describes the reason.
        :param action: (IAMActions) An enum object represents the action taken (get, update, create, etc).
        :param return_error: (bool) Whether or not to return an error entry.
        """
        if not email:
            email = self.get_attribute('email')

        vendor_action_result = IAMVendorActionResult(
            success=success,
            active=active,
            iden=iden,
            username=username,
            email=email,
            error_code=error_code,
            error_message=error_message if error_message else '',
            details=details,
            skip=skip,
            skip_reason=skip_reason if skip_reason else '',
            action=action,
            return_error=return_error
        )

        self._vendor_action_results.append(vendor_action_result)

    def map_object(self, mapper_name, mapping_type=None):
        """ Returns the user data, in an application data format.

        :type mapper_name: ``str``
        :param mapper_name: The outgoing mapper from XSOAR to the application.

        :type mapping_type: ``str``
        :param mapping_type: The mapping type of the mapper (optional).

        :return: the user data, in the app data format.
        :rtype: ``dict``
        """
        if not mapping_type:
            mapping_type = IAMUserProfile.INDICATOR_TYPE
        if not self._user_profile:
            raise DemistoException('You must provide the user profile data.')
        app_data = demisto.mapObject(self._user_profile, mapper_name, mapping_type)
        return app_data

    def update_with_app_data(self, app_data, mapper_name, mapping_type=None):
        """ updates the user_profile attribute according to the given app_data

        :type app_data: ``dict``
        :param app_data: The user data in app

        :type mapper_name: ``str``
        :param mapper_name: Incoming mapper name

        :type mapping_type: ``str``
        :param mapping_type: Optional - mapping type
        """
        if not mapping_type:
            mapping_type = IAMUserProfile.INDICATOR_TYPE
        if not isinstance(app_data, dict):
            app_data = safe_load_json(app_data)
        self._user_profile = demisto.mapObject(app_data, mapper_name, mapping_type)


class IAMUserAppData:
    """ Holds user attributes retrieved from an application.

    :type id: ``str``
    :param id: The ID of the user.

    :type username: ``str``
    :param username: The username of the user.

    :type is_active: ``bool``
    :param is_active: Whether or not the user is active in the application.

    :type full_data: ``dict``
    :param full_data: The full data of the user in the application.

    :return: None
    :rtype: ``None``
    """
    def __init__(self, user_id, username, is_active, app_data):
        self.id = user_id
        self.username = username
        self.is_active = is_active
        self.full_data = app_data


class IAMCommand:
    """ A class that implements the IAM CRUD commands - should bbe used.

    :type id: ``str``
    :param id: The ID of the user.

    :type username: ``str``
    :param username: The username of the user.

    :type is_active: ``bool``
    :param is_active: Whether or not the user is active in the application.

    :type full_data: ``dict``
    :param full_data: The full data of the user in the application.

    :return: None
    :rtype: ``None``
    """
    def __init__(self, is_create_enabled=True, is_disable_enabled=True, is_update_enabled=True,
                 create_if_not_exists=True, mapper_in=None, mapper_out=None):
        """ The IAMCommand c'tor

        :param is_create_enabled: (bool) Whether or not the `iam-create-user` command is enabled in the instance
        :param is_disable_enabled: (bool) Whether or not the `iam-disable-user` command is enabled in the instance
        :param is_update_enabled: (bool) Whether or not the `iam-update-user` command is enabled in the instance
        :param create_if_not_exists: (bool) Whether or not to create a user if does not exist in the application
        :param mapper_in: (str) Incoming mapper from the application to Cortex XSOAR
        :param mapper_out: (str) Outgoing mapper from the Cortex XSOAR to the application
        """
        self.is_create_enabled = is_create_enabled
        self.is_disable_enabled = is_disable_enabled
        self.is_update_enabled = is_update_enabled
        self.create_if_not_exists = create_if_not_exists
        self.mapper_in = mapper_in
        self.mapper_out = mapper_out

    def get_user(self, client, args):
        """ Searches a user in the application and updates the user profile object with the data.
            If not found, the error details will be resulted instead.

        :param client: (Client) The integration Client object that implements a get_user() method
        :param args: (dict) The `iam-get-user` command arguments
        :return: (IAMUserProfile) The user profile object.
        """
        user_profile = IAMUserProfile(user_profile=args.get('user-profile'))
        try:
            email = user_profile.get_attribute('email')
            user_app_data = client.get_user(email)
            if not user_app_data:
                error_code, error_message = IAMErrors.USER_DOES_NOT_EXIST
                user_profile.set_result(action=IAMActions.GET_USER,
                                        success=False,
                                        error_code=error_code,
                                        error_message=error_message)
            else:
                user_profile.update_with_app_data(user_app_data.full_data, self.mapper_in)
                user_profile.set_result(
                    action=IAMActions.GET_USER,
                    active=user_app_data.is_active,
                    iden=user_app_data.id,
                    email=email,
                    username=user_app_data.username,
                    details=user_app_data.full_data
                )

        except Exception as e:
            client.handle_exception(user_profile, e, IAMActions.GET_USER)

        return user_profile

    def disable_user(self, client, args):
        """ Disables a user in the application and updates the user profile object with the updated data.
            If not found, the command will be skipped.

        :param client: (Client) The integration Client object that implements get_user() and disable_user() methods
        :param args: (dict) The `iam-disable-user` command arguments
        :return: (IAMUserProfile) The user profile object.
        """

        user_profile = IAMUserProfile(user_profile=args.get('user-profile'))
        if not self.is_disable_enabled:
            user_profile.set_result(action=IAMActions.DISABLE_USER,
                                    skip=True,
                                    skip_reason='Command is disabled.')
        else:
            try:
                email = user_profile.get_attribute('email')
                user_app_data = client.get_user(email)
                if not user_app_data:
                    _, error_message = IAMErrors.USER_DOES_NOT_EXIST
                    user_profile.set_result(action=IAMActions.DISABLE_USER,
                                            skip=True,
                                            skip_reason=error_message)
                else:
                    if user_app_data.is_active:
                        user_app_data = client.disable_user(user_app_data.id)
                    user_profile.set_result(
                        action=IAMActions.DISABLE_USER,
                        active=False,
                        iden=user_app_data.id,
                        email=email,
                        username=user_app_data.username,
                        details=user_app_data.full_data
                    )

            except Exception as e:
                client.handle_exception(user_profile, e, IAMActions.DISABLE_USER)

        return user_profile

    def create_user(self, client, args):
        """ Creates a user in the application and updates the user profile object with the data.
            If a user in the app already holds the email in the given user profile, updates
            its data with the given data.

        :param client: (Client) A Client object that implements get_user(), create_user() and update_user() methods
        :param args: (dict) The `iam-create-user` command arguments
        :return: (IAMUserProfile) The user profile object.
        """

        user_profile = IAMUserProfile(user_profile=args.get('user-profile'))

        if not self.is_create_enabled:
            user_profile.set_result(action=IAMActions.CREATE_USER,
                                    skip=True,
                                    skip_reason='Command is disabled.')
        else:
            try:
                email = user_profile.get_attribute('email')
                user_app_data = client.get_user(email)
                if user_app_data:
                    # if user exists, update it
                    user_profile = self.update_user(client, args)

                else:
                    app_profile = user_profile.map_object(self.mapper_out)
                    created_user = client.create_user(app_profile)
                    user_profile.set_result(
                        action=IAMActions.CREATE_USER,
                        active=created_user.is_active,
                        iden=created_user.id,
                        email=email,
                        username=created_user.username,
                        details=created_user.full_data
                    )

            except Exception as e:
                client.handle_exception(user_profile, e, IAMActions.CREATE_USER)

        return user_profile

    def update_user(self, client, args):
        """ Creates a user in the application and updates the user profile object with the data.
            If the user is disabled and `allow-enable` argument is `true`, also enables the user.
            If the user does not exist in the app and the `create-if-not-exist` parameter is checked, creates the user.

        :param client: (Client) A Client object that implements get_user(), create_user() and update_user() methods
        :param args: (dict) The `iam-update-user` command arguments
        :return: (IAMUserProfile) The user profile object.
        """

        user_profile = IAMUserProfile(user_profile=args.get('user-profile'))
        allow_enable = args.get('allow-enable') == 'true'
        if not self.is_update_enabled:
            user_profile.set_result(action=IAMActions.UPDATE_USER,
                                    skip=True,
                                    skip_reason='Command is disabled.')
        else:
            try:
                email = user_profile.get_attribute('email')
                user_app_data = client.get_user(email)
                if user_app_data:
                    app_profile = user_profile.map_object(self.mapper_out)

                    if allow_enable and not user_app_data.is_active:
                        client.enable_user(user_app_data.id)

                    updated_user = client.update_user(user_app_data.id, app_profile)
                    user_profile.set_result(
                        action=IAMActions.UPDATE_USER,
                        active=updated_user.is_active,
                        iden=updated_user.id,
                        email=email,
                        username=updated_user.username,
                        details=updated_user.full_data
                    )
                else:
                    if self.create_if_not_exists:
                        user_profile = self.create_user(client, args)
                    else:
                        _, error_message = IAMErrors.USER_DOES_NOT_EXIST
                        user_profile.set_result(action=IAMActions.UPDATE_USER,
                                                skip=True,
                                                skip_reason=error_message)

            except Exception as e:
                client.handle_exception(user_profile, e, IAMActions.UPDATE_USER)

        return user_profile
