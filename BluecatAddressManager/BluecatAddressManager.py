import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import requests


# error class for token errors
class TokenException(Exception):
    pass


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

USERNAME = demisto.params().get('credentials').get('identifier')
PASSWORD = demisto.params().get('credentials').get('password')
TOKEN = demisto.params().get('token')
# Remove trailing slash to prevent wrong URL path to service
SERVER = demisto.params()['url'][:-1] \
    if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)
# How many time before the first fetch to retrieve incidents
# Service base URL
BASE_URL = SERVER + '/Services/REST/v1'

# Headers to be sent in requests
HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}
TOKEN_LIFE_TIME_MINS = 5

''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, data=None, headers=HEADERS, safe=False):
    """
        A wrapper for requests lib to send our requests and handle requests and responses better.

        :type method: ``str``
        :param method: HTTP method for the request.

        :type url_suffix: ``str``
        :param url_suffix: The suffix of the URL (endpoint)

        :type params: ``dict``
        :param params: The URL params to be passed.

        :type data: ``str``
        :param data: The body data of the request.

        :type headers: ``dict``
        :param headers: Request headers

        :type safe: ``bool``
        :param safe: If set to true will return None in case of http error

        :type get_token_flag: ``bool``
        :param get_token_flag: If set to True will call get_token()

        :return: Returns the http request response json
        :rtype: ``dict``
    """
    headers['Authorization'] = get_token()
    url = SERVER + url_suffix
    try:
        res = requests.request(method, url, verify=USE_SSL, params=params, data=data, headers=headers)
        # Try to create a new token
        if res.status_code == 401:
            headers['Authorization'] = get_token(new_token=True)
            res = requests.request(method, url, verify=USE_SSL, params=params, data=data, headers=headers)
    except requests.exceptions.RequestException:
        return_error('Error in connection to the server. Please make sure you entered the URL correctly.')
    # Handle error responses gracefully
    if res.status_code not in {200, 201, 202}:
        err_msg = 'Error in API call. code:{code}; reason: {reason}'.format(code=res.status_code, reason=res.reason)
        if safe:
            return None
        return_error(err_msg)
    return res.json()


def get_token(new_token=False):
    """
        Retrieves the token from the server if it's expired and updates the global HEADERS to include it

        :param new_token: If set to True will generate a new token regardless of time passed

        :rtype: ``str``
        :return: Token
    """
    now = datetime.now()
    ctx = demisto.getIntegrationContext()
    if ctx and not new_token:
        passed_mins = get_passed_mins(now, ctx.get('time'))
        if passed_mins >= TOKEN_LIFE_TIME_MINS:
            # token expired
            auth_token = get_token_request()
            demisto.setIntegrationContext({'auth_token': auth_token, 'time': date_to_timestamp(now) / 1000})
        else:
            # token hasn't expired
            auth_token = ctx.get('auth_token')
    else:
        # generating new token
        auth_token = get_token_request()
        demisto.setIntegrationContext({'auth_token': auth_token, 'time': date_to_timestamp(now) / 1000})
    return auth_token


def get_passed_mins(start_time, end_time_str):
    """
        Returns the time passed in mins
        :param start_time: Start time in datetime
        :param end_time_str: End time in str
        :return: The passed mins in int
    """
    time_delta = start_time - datetime.fromtimestamp(end_time_str)
    return time_delta.seconds / 60


''' COMMANDS + REQUESTS FUNCTIONS '''


def get_token_request():
    url_args = {
        'username': USERNAME,
        'password': PASSWORD
    }
    start_idx = 16
    end_delim = ' <-'
    url = BASE_URL + '/login'
    res = requests.request('GET', url, verify=USE_SSL, params=url_args)
    if res.status_code != 200:
        raise TokenException('Error: Failed to create a new token, please try again')
    res_json = res.json()
    demisto.info(f'\n#### Res: {res_json}')
    end_idx = res_json.index(end_delim)
    return res_json[start_idx:end_idx]


def test_module():
    """
    Performs basic get request to get item samples
    """
    get_token(new_token=True)
    demisto.results('ok')


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    handle_proxy()
    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        if command == 'test-module':
            test_module()

    # Log exceptions
    except Exception as e:
        return_error(str(e))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
