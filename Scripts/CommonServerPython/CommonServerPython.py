"""Common functions script
This script will be appended to each server script before being executed.
Please notice that to add custom common code, add it to the CommonServerUserPython script.
Note that adding code to CommonServerUserPython can override functions in CommonServerPython
"""
from __future__ import print_function
import socket
import time
import json
import sys
import os
import re
import base64
import logging
from collections import OrderedDict
import xml.etree.cElementTree as ET
from datetime import datetime, timedelta

import demistomock as demisto

# imports something that can be missed from docker image
try:
    import requests
except Exception:
    pass

IS_PY3 = sys.version_info[0] == 3
# pylint: disable=undefined-variable
if IS_PY3:
    STRING_TYPES = (str, bytes)  # type: ignore
    STRING_OBJ_TYPES = (str,)
else:
    STRING_TYPES = (str, unicode)  # type: ignore
    STRING_OBJ_TYPES = STRING_TYPES  # type: ignore
# pylint: enable=undefined-variable

entryTypes = {
    'note': 1,
    'downloadAgent': 2,
    'file': 3,
    'error': 4,
    'pinned': 5,
    'userManagement': 6,
    'image': 7,
    'plagroundError': 8,
    'playgroundError': 8,
    'entryInfoFile': 9,
    'warning': 11,
    'map': 15,
    'widget': 17
}
formats = {
    'html': 'html',
    'table': 'table',
    'json': 'json',
    'text': 'text',
    'dbotResponse': 'dbotCommandResponse',
    'markdown': 'markdown'
}
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
dbotscores = {
    'Critical': 4,
    'High': 3,
    'Medium': 2,
    'Low': 1,
    'Unknown': 0,
    'Informational': 0.5
}

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


def handle_proxy(proxy_param_name='proxy', checkbox_default_value=False):
    """
        Handle logic for routing traffic through the system proxy.
        Should usually be called at the beginning of the integration, depending on proxy checkbox state.

        :type proxy_param_name: ``string``
        :param proxy_param_name: name of the "use system proxy" integration parameter

        :type checkbox_default_value: ``bool``
        :param checkbox_default_value: Default value of the proxy param checkbox

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
    to_encode = text
    if IS_PY3:
        to_encode = text.encode('utf-8', 'ignore')
    res = base64.b64encode(to_encode)
    if IS_PY3:
        res = res.decode('utf-8')  # type: ignore
    return res


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
                for (k, v) in demisto.params().items():
                    k_lower = k.lower()
                    for p in sensitive_params:
                        if p in k_lower:
                            if isinstance(v, STRING_OBJ_TYPES):
                                self.add_replace_strs(v, b64_encode(v))
                            if isinstance(v, dict) and v.get('password'):  # credentials object case
                                pswrd = v.get('password')
                                self.add_replace_strs(pswrd, b64_encode(pswrd))

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
    return arg


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
        strBased = isinstance(data, STRING_TYPES) and isinstance(existing, STRING_TYPES)
        if strBased:
            data = data.split(',')
            existing = existing.split(',')
        newVal = data + existing
        if dedup:
            newVal = list(set(newVal))
        if strBased:
            newVal = ','.join(newVal)
        demisto.setContext(key, newVal)
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


def return_outputs(readable_output, outputs=None, raw_response=None):
    """
    This function wraps the demisto.results(), makes the usage of returning results to the user more intuitively.

    :type readable_output: ``str``
    :param readable_output: markdown string that will be presented in the warroom, should be human readable -
        (HumanReadable)

    :type outputs: ``dict``
    :param outputs: the outputs that will be returned to playbook/investigation context (originally EntryContext)

    :type raw_response: ``dict`` | ``list``
    :param raw_response: must be dictionary, if not provided then will be equal to outputs. usually must be the original
    raw response from the 3rd party service (originally Contents)

    :return: None
    :rtype: ``None``
    """
    return_entry = {
        "Type": entryTypes["note"],
        "HumanReadable": readable_output,
        "ContentsFormat": formats["json"],
        "Contents": raw_response,
        "EntryContext": outputs
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
    LOG(message)
    if error:
        LOG(str(error))
    LOG.print_log()
    if not isinstance(message, str):
        message = message.encode('utf8') if hasattr(message, 'encode') else str(message)

    if hasattr(demisto, 'command') and demisto.command() in ('fetch-incidents', 'long-running-execution'):
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

ipv4Regex = r'\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
emailRegex = r'\b[^@]+@[^@]+\.[^@]+\b'
hashRegex = r'\b[0-9a-fA-F]+\b'
urlRegex = r'(?:(?:https?|ftp|hxxps?):\/\/|www\[?\.\]?|ftp\[?\.\]?)(?:[-\w\d]+\[?\.\]?)+[-\w\d]+(?::\d+)?' \
           r'(?:(?:\/|\?)[-\w\d+&@#\/%=~_$?!\-:,.\(\);]*[\w\d+&@#\/%=~_$\(\);])?'

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


def timestamp_to_datestring(timestamp, date_format="%Y-%m-%dT%H:%M:%S.000Z"):
    """
      Parses timestamp (milliseconds) to a date string in the provided date format (by default: ISO 8601 format)
      Examples: (1541494441222, 1541495441000, etc.)

      :type timestamp: ``int`` or ``str``
      :param timestamp: The timestamp to be parsed (required)

      :type date_format: ``str``
      :param date_format: The date format the timestamp should be parsed to. (optional)

      :return: The parsed timestamp in the date_format
      :rtype: ``str``
    """
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
    if hasattr(demisto, 'demistoVersion'):
        return demisto.demistoVersion()
    else:
        raise AttributeError('demistoVersion attribute not found.')


def is_debug_mode():
    """Return if this script/command was passed debug-mode=true option

    :return: true if debug-mode is enabled
    :rtype: ``bool``
    """
    # use `hasattr(demisto, 'is_debug')` to ensure compatibility with server version <= 4.5
    return hasattr(demisto, 'is_debug') and demisto.is_debug


class DemistoHandler(logging.Handler):
    """
        Handler to route logging messages to demisto.debug
    """

    def __init__(self):
        logging.Handler.__init__(self)

    def emit(self, record):
        msg = self.format(record)
        try:
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
        self.handler = None  # just incase our http_client code throws an exception. so we don't error in the __del__
        if IS_PY3:
            # pylint: disable=import-error
            import http.client as http_client
            # pylint: enable=import-error
            self.http_client = http_client
            self.http_client.HTTPConnection.debuglevel = 1
            self.http_client_print = getattr(http_client, 'print', None)  # save in case someone else patched it alread
            self.int_logger = IntegrationLogger()
            self.int_logger.set_buffering(False)
            setattr(http_client, 'print', self.int_logger.print_override)
        else:
            self.http_client = None
        self.handler = DemistoHandler()
        demisto_formatter = logging.Formatter(fmt='%(asctime)s - %(message)s', datefmt=None)
        self.handler.setFormatter(demisto_formatter)
        self.root_logger = logging.getLogger()
        self.prev_log_level = self.root_logger.getEffectiveLevel()
        self.root_logger.setLevel(logging.DEBUG)
        self.root_logger.addHandler(self.handler)

    def __del__(self):
        if self.handler:
            self.root_logger.setLevel(self.prev_log_level)
            self.root_logger.removeHandler(self.handler)
            self.handler.flush()
            self.handler.close()
        if self.http_client:
            self.http_client.HTTPConnection.debuglevel = 0
            if self.http_client_print:
                setattr(self.http_client, 'print', self.http_client_print)
            else:
                delattr(self.http_client, 'print')


_requests_logger = None
try:
    if is_debug_mode():
        _requests_logger = DebugLogger()
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
            if proxy:
                self._proxies = handle_proxy()
            else:
                self._proxies = None

        def _http_request(self, method, url_suffix, full_url=None, headers=None,
                          auth=None, json_data=None, params=None, data=None, files=None,
                          timeout=10, resp_type='json', ok_codes=None, **kwargs):
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

            :type timeout: ``float``
            :param timeout:
                The amount of time (in seconds) that a request will wait for a client to
                establish a connection to a remote machine before a timeout occurs.

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
            """
            try:
                # Replace params if supplied
                address = full_url if full_url else self._base_url + url_suffix
                headers = headers if headers else self._headers
                auth = auth if auth else self._auth
                # Execute
                res = requests.request(
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
                    proxies=self._proxies,
                    **kwargs
                )
                # Handle error responses gracefully
                if not self._is_status_code_valid(res, ok_codes):
                    err_msg = 'Error in API call [{}] - {}' \
                        .format(res.status_code, res.reason)
                    try:
                        # Try to parse json error response
                        error_entry = res.json()
                        err_msg += '\n{}'.format(error_entry)
                        raise DemistoException(err_msg)
                    except ValueError as exception:
                        raise DemistoException(err_msg, exception)

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


class DemistoException(Exception):
    pass
