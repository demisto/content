import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
import os
import urllib3
import requests

if not demisto.params()['proxy']:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBAL VARS '''
ACCOUNT = demisto.params()['account']
USERNAME = demisto.params()['credentials']['identifier']
PASSWORD = demisto.params()['credentials']['password']
SERVER = demisto.params()['server'][:-1] if demisto.params()['server'].endswith('/') else demisto.params()['server']
BASE_URL = f'{SERVER}/api/v1/{ACCOUNT}/'
USE_SSL = not demisto.params().get('insecure', False)

''' HELPER FUNCTIONS '''


def http_request(method, url_suffix):
    demisto.debug(f'running request with url={BASE_URL}{url_suffix}')
    try:
        res = requests.request(
            method,
            BASE_URL + url_suffix,
            verify=USE_SSL,
            auth=requests.auth.HTTPBasicAuth(USERNAME, PASSWORD)
        )
        if res.status_code != 200:
            raise Exception(f'Your request failed with the following error: {str(res.content)}{str(res.status_code)}')
    except Exception as e:
        demisto.debug(f'{e}')
        raise
    return res.json()


def dict_to_str(obj):
    """
    Input - dictionary :
    {
        key1_keya: "valuea",
        key1_keyb: "valueb",
        HREF: "http://link"
    }

    Output - string:
    Key1Keya: Valuea
    Key1Keyb: Valueb
    """
    string_result = ''
    context_result = {}
    for key, value in obj.items():
        if key != 'HREF':
            string_result = f'{string_result}{underscoreToCamelCase(key)}:{value}<br>'
            context_result[underscoreToCamelCase(key)] = value
    return string_result, context_result


''' FUNCTIONS '''


def search_command():
    request = demisto.args().get('request')
    if request:
        response = search(request=request)
    else:
        asset = demisto.args().get('asset')
        attribute = demisto.args().get('attribute')
        value = demisto.args().get('value')
        if asset and attribute and value:
            response = search(asset, attribute, value)
        else:
            return 'Not enough arguments given'
    records = []
    context = []
    for record in response:
        string_record: dict = {}
        context_record = {}
        for header in record:
            current_context = {}
            if isinstance(record[header], dict):
                current_string, current_context = dict_to_str(record[header])
                if len(current_string) == 0:
                    string_record[header] = None
                else:
                    string_record[header] = current_string
                context_record[underscoreToCamelCase(header)] = current_context
        records.append(string_record)
        context.append(context_record)
    if records:
        title = 'EasyVista Search Results'
        demisto.results({
            'Type': entryTypes['note'],
            'Contents': records,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, records, headerTransform=underscoreToCamelCase, removeNull=True),
            'EntryContext': {
                'EasyVista.Records': context
            }
        })
    else:
        demisto.results('No records found')


def search(asset=None, attribute=None, value=None, request=None):
    cmd_url = 'requests?search='
    if request:
        cmd_url += request
    else:
        cmd_url = f'{cmd_url}{asset}.{attribute}:"{value}"'
    records = http_request('GET', cmd_url)['records']
    return records


''' EXECUTION CODE '''
demisto.debug(f'command is {demisto.command()}')

try:
    if demisto.command() == 'test-module':
        http_request('GET', 'assets')
        demisto.results('ok')

    elif demisto.command() == 'easy-vista-search':
        search_command()

except Exception as e:
    demisto.debug(f'{e}')
    raise e
