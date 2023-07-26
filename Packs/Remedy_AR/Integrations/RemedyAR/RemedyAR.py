import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from urllib.parse import quote_plus

from CommonServerUserPython import *  # noqa

''' IMPORTS '''
import json
import os
import urllib3

import requests

# disable insecure warnings
urllib3.disable_warnings()

if not demisto.params()['proxy']:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, data, headers):
    data = {} if data is None else data
    LOG.print_log(f'running request with url={BASE_URL}{url_suffix}\tdata={data}\theaders={headers}')
    try:
        res = requests.request(method,
                               BASE_URL + url_suffix,
                               verify=USE_SSL,
                               data=data,
                               headers=headers
                               )
        if res.status_code not in (200, 204):
            raise Exception(f'Your request failed with the following error: {res.reason}')
    except Exception as ex:
        raise Exception(ex)
    return res


''' GLOBAL VARS '''
SERVER_URL = demisto.params()['server']
USERNAME = demisto.params()['credentials']['identifier']
PASSWORD = demisto.params()['credentials']['password']
BASE_URL = SERVER_URL + '/api'
USE_SSL = not demisto.params().get('insecure', False)
DEFAULT_HEADERS = {
    'Content-Type': 'application/json'
}

''' FUNCTIONS '''


def login():
    cmd_url = '/jwt/login'
    data = {
        'username': USERNAME,
        'password': PASSWORD
    }
    login_headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    result = http_request('POST', cmd_url, data, login_headers)
    return result


def logout():
    cmd_url = '/jwt/logout'
    http_request('POST', cmd_url, None, DEFAULT_HEADERS)


def get_server_details(qualification, fields):

    # Adds fields to filter by
    if isinstance(fields, list):
        fields = ','.join(fields)
    fields = f'fields=values({fields})'

    # URL Encodes qualification
    qualification = quote_plus(qualification)

    cmd_url = f'/arsys/v1/entry/AST:ComputerSystem/?q={qualification}&{fields}'
    result = http_request('GET', cmd_url, None, DEFAULT_HEADERS).json()

    entries = result['entries']
    server_details = []
    for entry in entries:
        # Context Standard
        current_entry = entry['values']
        if current_entry['NC_IOPs'] is None:
            current_entry.pop('NC_IOPs', None)
        else:
            current_entry['IPAddress'] = current_entry.pop('NC_IOPs')
        current_entry['Hostname'] = current_entry.pop('Name')

        server_details.append(current_entry)

    context = {
        'Endpoint': server_details
    }

    entry = {
        'Type': entryTypes['note'],
        'Contents': json.dumps(server_details),
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Remedy AR Server Details', server_details),
        'EntryContext': context
    }

    return entry


''' EXECUTION CODE '''
auth = login()
token = auth.content
DEFAULT_HEADERS['Authorization'] = f'AR-JWT {token}'

LOG('command is %s' % (demisto.command(), ))
try:
    if demisto.command() == 'test-module':
        # Login is made and tests connectivity and credentials
        demisto.results('ok')
    elif demisto.command() == 'remedy-get-server-details':
        if 'qualification' in demisto.args():
            qualification = demisto.args()['qualification']
        else:
            qualification = ''
        demisto.results(get_server_details(qualification, demisto.args()['fields']))
except Exception as e:
    LOG(e)
    LOG.print_log()
    raise
finally:
    logout()
