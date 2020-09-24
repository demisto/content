import base64
import json
# imports, diable where possible
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta

import demistomock as demisto
import requests
from CommonServerPython import *  # noqa: F401

## Global ##

if not demisto.params().get("proxy", False):
    del os.environ["HTTP_PROXY"]
    del os.environ["HTTPS_PROXY"]
    del os.environ["http_proxy"]
    del os.environ["https_proxy"]

requests.packages.urllib3.disable_warnings()

USE_SSL = not demisto.params().get('unsecure', False)
SERVER = demisto.params()['server'][:-1] if demisto.params()['server'].endswith('/') else demisto.params()['server']
# Does server have base Path e.g. "/api/v1/"
BASE_URL = SERVER + ''

# For integrations that fetch incidents/alerts

# Headers to be sent in GET requests
HEADERS = {
    'Content-Type': 'application/json',
    'Connection': 'close',
    'Accept': 'application/json'
}

# Headers to be used when making a request to POST a multi-part encoded file
MULTIPART_HEADERS = {
    'Accept': 'application/json'
}

## Helper functions ##


def http_request(method, url_suffix, params=None, data=None, files=None, headers=HEADERS):

    res = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        params=params,
        data=data,
        headers=headers,
        files=files
    )

    # Handle error responses gracefully
    if res.status_code not in {200, 201, 202, 204}:
        LOG(res.json())
        LOG(res.text)
        LOG.print_log()
        err_msg = 'Error in API call [{}] - {}'.format(res.status_code, res.reason)
        err = json.loads(res.content)
        if err.get('errors'):
            for error in err.get('errors'):
                err_msg += '\n' + json.dumps(error, indent=2)
        else:
            for key, value in res.json().iteritems():
                err_msg += '\n{}: {}'.format(key, value)
        return_error(err_msg)
    # Handle response with no content
    elif res.status_code == 204:
        return res

    return res.json()


## Integration specific functions ##

def ad_search(thisFilter):

    response = http_request('GET', '/ad-search.php?filter=' + thisFilter, headers=HEADERS)

    # Example POST
    # response = http_request('GET', 'path/file?param='+input1, headers=MULTIPART_HEADERS).json()

    if response:
        entry = {
            'Type': entryTypes['note'],
            'Contents': response,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': "The output was " + response['fullname'],
            'EntryContext': {
                'ActiveDirectory': {
                    'Search': response['fullname']
                }
            }
        }
        return entry

    else:
        return 'No events were found'


##

LOG('Command being called is %s' % (demisto.command()))

try:
    if demisto.command() == 'test-module':
        # Tests connectivity and authentication
        # http_request only returns if HTTP 20x, so we've already tested for permissions and auth, e.g. 30x, 40x, 50x
        response = http_request('GET', 'path/file?param=test').json()
        demisto.results("ok")
        sys.exit(0)

    elif demisto.command() == 'ad-search':
        # commands specific to the integration, these are defined in the 'Commands' section of the Integration
        # we can also fetch arguments here, these are defined in the 'arguments' section per specific command
        thisFilter = demisto.args().get('filter')
        demisto.results(ad_search(thisFilter))


except Exception as e:
    LOG(e)
    LOG.print_log()
    return_error(e)
