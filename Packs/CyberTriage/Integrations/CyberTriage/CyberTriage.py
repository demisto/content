import os
import traceback

import demistomock as demisto  # noqa: F401
import requests
import urllib3
from CommonServerPython import *  # noqa: F401

# Disable warning for insecure requests when cert validation is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Get dict of CT instance parameters and command args
CT_PARAMS = demisto.params()
CMD_ARGS = demisto.args()

SCAN_OPTIONS = ['pr', 'nw', 'nc', 'st', 'sc', 'ru', 'co', 'lo', 'ns', 'wb', 'fs']
CT_SERVER = CT_PARAMS['server']
REST_PORT = CT_PARAMS['rest_port']
API_KEY = CT_PARAMS['api_key']
USER = CT_PARAMS['credentials']['identifier']
PASSWORD = CT_PARAMS['credentials']['password']
VERIFY_SERVER_CERT = False
REQ_HEADERS = {'restApiKey': API_KEY}
USE_PROXY = CT_PARAMS['use_proxy']
def IS_2XX(x): return (x / 100) == 2  # Returns true if status code (int) is 2xx


# Delete request proxy environment variables if user does not want to use proxy
if not USE_PROXY:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

# Dict of Cyber Triage REST APIs currently used
REST_APIS = {
    'check_creds': 'https://{0}:{1}/api/correlation/checkcredentials'.format(CT_SERVER, REST_PORT),
    'start_collection': 'https://{0}:{1}/api/livesessions'.format(CT_SERVER, REST_PORT)
}

# Method to make rest calls (using requests) and handle error scenarios.
#
# Args: rest_api    - a string that represents a url to a rest api
#       method      - a string that represents an http methods supported by requests (get, put, post, ...)
#       json_data   - same as requests json arg
#       headers     - same as requests headers arg
#       verify_cert - same as requests verify arg
#
# Return: Dictionary with response, status_code, and exception keys. status_code will be -1 or status code returned in
# response object. Exception will be empty unless an exception occurred. Response will contain the json response from CT if a 2xx response
# occurred, otherwise it will represent an error message string.


def make_rest_call(rest_api, method, json_data=None, headers=REQ_HEADERS, verify_cert=VERIFY_SERVER_CERT):
    ret_msg = ''
    http_status_code = -1
    e_str = ''
    e = None

    # Get the request function associate with the type of http request we want to make (ex. GET or POST)
    try:
        request_func = getattr(requests, method)
    except AttributeError:
        ret_msg = 'Invalid requests method: {0}'.format(method)
        return_error(ret_msg)
        sys.exit(1)

    # Attempt to make the rest API call and get data from response
    try:
        response = request_func(rest_api, json=json_data, headers=headers, verify=verify_cert)
        http_status_code = response.status_code

        # Raises ValueError exception if response cannot be converted to json
        resp_json = response.json()

        # Raises HTTPError exception if we get a non successful http status code (4xx/5xx)
        response.raise_for_status()

        ret_msg = resp_json

    except ValueError as e:
        ret_msg = 'Response did not contain valid json data. Response: {}'.format(response.text)
        demisto.error(traceback.format_exc())

    except requests.exceptions.SSLError as e:
        ret_msg = 'Unable to verify the Cyber Triage server certificate'
        demisto.error(traceback.format_exc())

    except requests.exceptions.HTTPError as e:
        # Format error message based on error response in json
        ret_msg = 'No Error Message found'

        if 'Error' in resp_json:
            ret_msg = resp_json['Error']
        elif 'message' in resp_json:
            ret_msg = resp_json['message']

        demisto.error(resp_json)
        demisto.error(traceback.format_exc())

    except requests.exceptions.ConnectionError as e:
        ret_msg = 'Error while connecting to ({})'.format(rest_api)
        demisto.error(traceback.format_exc())

    except requests.exceptions.RequestException as e:
        ret_msg = 'An unexpected error has occurred'
        demisto.error(traceback.format_exc())

    # If an exception occurred then update the exception string
    if (e):
        e_str = '{}: {}'.format(type(e).__name__, e)

    return {
        'response': ret_msg,
        'status_code': http_status_code,
        'exception': e_str
    }

# Format non 2xx responses from make_rest_call(). These are cases where an error has occurred.


def format_err_resp(json_resp):
    return 'Error message: {0}\nHTTP Status code: {1}\nExceptions: {2}'.format(json_resp['response'],
                                                                               json_resp['status_code'],
                                                                               json_resp['exception'])


def test_connection():
    response = make_rest_call(REST_APIS['check_creds'], 'get')

    if IS_2XX(response['status_code']):
        demisto.results('ok')
    else:
        return_error(format_err_resp(response))


def triage_endpoint():
    def is_true(x): return x == 'yes'
    is_hash_upload_on = is_true(CMD_ARGS['malware_hash_upload'])  # arg value = 'yes' or 'no'
    is_file_upload_on = is_true(CMD_ARGS['malware_file_upload'])  # arg value = 'yes' or 'no'
    endpoint = CMD_ARGS['endpoint']
    scan_options = CMD_ARGS['scan_options']
    incident_name = CMD_ARGS['incident_name']

    # Validate scan options
    invalid_options = [opt for opt in scan_options.split(',') if opt not in SCAN_OPTIONS]
    if invalid_options:
        return_error('The following are not valid scan options: {0}'.format(','.join(invalid_options)))

    # Make data dict for rest call
    api_data = {'incidentName': incident_name}
    api_data.update({'hostName': endpoint})
    api_data.update({'userId': USER})
    api_data.update({'password': PASSWORD})
    api_data.update({'scanOptions': scan_options})
    api_data.update({'malwareScanRequested': is_hash_upload_on})
    api_data.update({'sendContent': is_file_upload_on})
    api_data.update({'sendIpAddress': False})
    response = make_rest_call(REST_APIS['start_collection'], 'post', api_data)

    if is_ip_valid(endpoint):
        endpoint_context = {'IPAddress': endpoint}
    else:
        endpoint_context = {'Hostname': endpoint}

    ec = {
        'CyberTriage': response['response'],
        'Endpoint': endpoint_context
    }

    if IS_2XX(response['status_code']):
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': response,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': 'A collection has been scheduled for {0}'.format(endpoint),
            'EntryContext': ec
        })
    else:
        return_error(format_err_resp(response))


# This is the call made when running the ct-triage-endpoint command.
if demisto.command() == 'ct-triage-endpoint':
    triage_endpoint()

# This is the call made when pressing the integration test button.
elif demisto.command() == 'test-module':
    test_connection()
