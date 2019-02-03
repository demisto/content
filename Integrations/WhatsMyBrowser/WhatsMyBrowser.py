import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import requests
import json
from collections import defaultdict

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

'''GLOBAL VARS'''
API_URL = demisto.params().get('API_URL')
API_KEY = demisto.params().get('API_KEY')
INSECURE = demisto.params().get('insecure')
PROXY = demisto.params().get('proxy')
if not demisto.params().get('proxy', False) or demisto.params()['proxy'] == 'false':
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

UA_TEST_STRING = ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5)'
                  'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/'
                  '64.0.3282.140 Safari/537.36')

'''HELPER FUNCTIONS'''


def http_request(json):
    headers = {
        'X-API-KEY': API_KEY,
    }
    r = requests.request(
        'POST',
        API_URL,
        data=json,
        headers=headers,
        verify=INSECURE
    )
    if r.status_code != 200:
        return_error('Error in API call to WhatsMyBrowser [%d] - %s' % (r.status_code, r.reason))
    return r.content


'''MAIN FUNCTIONS'''


def ua_parse(user_agent):
    post_data = {
        "user_agent": "{}".format(user_agent)
    }
    post_json = json.dumps(post_data)
    r = http_request(post_json)
    return r


def ua_parse_command():
    user_agent = demisto.args().get('UserAgent')
    raw = ua_parse(user_agent)
    r = json.loads(raw)
    if 'success' in r['result']['code']:
        parsed = r['parse']
        hr = defaultdict()
        ua_ec = defaultdict(lambda: defaultdict(int))
        if 'software' in parsed:
            hr['Software'] = parsed['software']
            ua_ec['Software'] = parsed['software']
        if 'software_name' in parsed:
            hr['Software Name'] = parsed['software_name']
            ua_ec['SoftwareName'] = parsed['software_name']
        if 'operating_system' in parsed:
            hr['Operating System'] = parsed['operating_system']
            ua_ec['OperatingSystem'] = parsed['operating_system']
        if 'is_abusive' in parsed:
            hr['Abusive'] = parsed['is_abusive']
            ua_ec['Abusive'] = parsed['is_abusive']
            if parsed['is_abusive'] == 'true':
                dbot_score = {
                    'Score': 3,
                    'Type': 'UserAgent',
                    'Vendor': 'WhatsMyBrowser',
                    'Indicator': parsed['user_agent']
                }
            else:
                dbot_score = {
                    'Score': 1,
                    'Type': 'UserAgent',
                    'Vendor': 'WhatsMyBrowser',
                    'Indicator': parsed['user_agent']
                }
        if 'operating_system_name' in parsed:
            hr['Operating System Name'] = parsed['operating_system_name']
            ua_ec['OperatingSystemName'] = parsed['operating_system_name']
        if 'user_agent' in parsed:
            hr['User Agent'] = parsed['user_agent']
            ua_ec['UserAgent'] = parsed['user_agent']
        if 'hardware_type' in parsed:
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
            'ContentsFormat': formats['markdown'],
            'Contents': r,
            'HumanReadable': tableToMarkdown('Parsed result for {}'.format(user_agent), hr),
            'EntryContext': ec
        })
    if r['result']['code'] == 'error':
        error_msg = r['result']['message']
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': r,
            'HumanReadable': '{}'.format(error_msg)
        })


def test_command():
    post_data = {
        "user_agent": UA_TEST_STRING
    }
    post_json = json.dumps(post_data)
    http_request(post_json)
    demisto.results('ok')


if demisto.command() == 'ua-parse':
    ua_parse_command()
if demisto.command() == 'test-module':
    test_command()
    sys.exit(0)
