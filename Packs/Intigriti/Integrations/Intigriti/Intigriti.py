import json
import os
import urllib

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401
from requests.exceptions import ConnectionError, HTTPError

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''
TOKEN_URL = 'https://login.intigriti.com/connect/token'
LOOKUP_URL = 'https://api.intigriti.com/external/iplookup'
CLIENT_ID = demisto.params().get('client_id')
CLIENT_SECRET = demisto.params().get('client_secret')
USE_SSL = not demisto.params().get('insecure', False)
DATA = {
    'client_id': CLIENT_ID,
    'client_secret': CLIENT_SECRET,
    'grant_type': 'client_credentials'}


access_token_response = requests.post(TOKEN_URL, data=DATA, verify=False, allow_redirects=False)
token = json.loads(access_token_response.text)


def get_ip_status(ip):
    """
        Send request with no error handling, so the error handling can be done via wrapper function
    """
    api_call_headers = {'Authorization': 'Bearer ' + token['access_token']}
    params = {'ipAddress': ip}
    api_call_response = requests.get(LOOKUP_URL, params=params, headers=api_call_headers, verify=False)
    return api_call_response.text


if demisto.command() == 'IntigritiIPStatus':
    ip = demisto.args().get('ip')
    # Check status of IP with Intrigriti usage API
    result = get_ip_status(ip)
    results = CommandResults(
        outputs_prefix='IntigritiResult',
        outputs_key_field='result',
        outputs={'result': result}
    )
    return_results(results)
