import demistomock as demisto
from CommonServerPython import *
''' IMPORTS '''
import requests
import json
from collections import defaultdict
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


'''GLOBAL VARS'''
API_URL = demisto.params().get('url')
USE_SSL = not demisto.params().get('insecure')
PROXY = demisto.params().get('proxy')


'''HELPER FUNCTIONS'''


def http_request(data):
    api_key = demisto.params().get('credentials_api_key', {}).get('password') or demisto.params().get('api_key')
    if not api_key:
        raise DemistoException('API key must be provided.')
    headers = {
        'X-API-KEY': api_key,
    }
    r = requests.request(
        'POST',
        API_URL,
        data=data,
        headers=headers,
        verify=USE_SSL
    )
    if r.status_code != 200:
        return_error('Error in API call to WhatIsMyBrowser [%d] - %s' % (r.status_code, r.reason))
    return r.content


'''MAIN FUNCTIONS'''


def ua_parse(user_agent):
    post_data = {
        "user_agent": user_agent
    }
    post_json = json.dumps(post_data)
    r = http_request(post_json)
    return r


def ua_parse_command():
    user_agent = demisto.args().get('UserAgent')
    raw = ua_parse(user_agent)
    r = json.loads(raw)
    dbot_score = {}
    demisto.debug("Initializing dbot_score")
    if 'success' in r['result']['code']:
        parsed = r['parse']
        hr = defaultdict()  # type: dict
        ua_ec = defaultdict(lambda: defaultdict(int))  # type: dict
        if 'software' in parsed:
            hr['Software'] = parsed['software']
            ua_ec['Software'] = parsed['software']
        if 'software_name' in parsed:
            hr['Software Name'] = parsed['software_name']
            ua_ec['SoftwareName'] = parsed['software_name']
        if 'operating_system' in parsed and parsed['operating_system'] is not None:
            hr['Operating System'] = parsed['operating_system']
            ua_ec['OperatingSystem'] = parsed['operating_system']
        if 'is_abusive' in parsed:
            hr['Abusive'] = parsed['is_abusive']
            ua_ec['Abusive'] = parsed['is_abusive']
            if parsed['is_abusive'] is True:
                dbot_score = {
                    'Score': 3,
                    'Type': 'UserAgent',
                    'Vendor': 'WhatIsMyBrowser',  # disable-secrets-detection
                    'Indicator': parsed['user_agent']
                }
            else:
                dbot_score = {
                    'Score': 1,
                    'Type': 'UserAgent',
                    'Vendor': 'WhatIsMyBrowser',  # disable-secrets-detection
                    'Indicator': parsed['user_agent']
                }
        if 'operating_system_name' in parsed and parsed['operating_system_name'] is not None:
            hr['Operating System Name'] = parsed['operating_system_name']
            ua_ec['OperatingSystemName'] = parsed['operating_system_name']
        if 'user_agent' in parsed:
            hr['User Agent'] = parsed['user_agent']
            ua_ec['UserAgent'] = parsed['user_agent']
        if 'hardware_type' in parsed and parsed['hardware_type'] is not None:
            hr['Hardware Type'] = parsed['hardware_type']
            ua_ec['HardwareType'] = parsed['hardware_type']
        if 'hardware_sub_type' in parsed and parsed['hardware_sub_type'] is not None:
            hr['Hardware Sub Type'] = parsed['hardware_sub_type']
            ua_ec['HardwareSubType'] = parsed['hardware_sub_type']
        ec = {
            'UA.Parse(val.UserAgent && val.UserAgent == obj.UserAgent)': ua_ec,
            'DBotScore': dbot_score
        }
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': r,
            'HumanReadable': tableToMarkdown(f'Parsed result for {user_agent}', hr),
            'EntryContext': ec
        })
    if r['result']['code'] == 'error':
        error_msg = r['result']['message']
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': r,
            'HumanReadable': f'{error_msg}'
        })


def test_command():
    post_data = {
        # disable-secrets-detection
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/64.0.3282.140 Safari/537.36"
    }
    post_json = json.dumps(post_data)
    http_request(post_json)
    demisto.results('ok')


'''EXECUTION BLOCK'''
try:
    handle_proxy()
    if demisto.command() == 'ua-parse':
        ua_parse_command()
    if demisto.command() == 'test-module':
        test_command()
except Exception as e:
    return_error(str(e))
