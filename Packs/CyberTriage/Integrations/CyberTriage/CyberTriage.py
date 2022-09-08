import traceback
from typing import Any

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
CT_SERVER = CT_PARAMS.get('server', '')
REST_PORT = CT_PARAMS.get('rest_port', '')
API_KEY = CT_PARAMS.get('api_key', {}).get('password', '')
USER = CT_PARAMS.get('credentials', {}).get('identifier', '')
PASSWORD = CT_PARAMS.get('credentials', {}).get('password', '')
VERIFY_SERVER_CERT = False
REQ_HEADERS = {'restApiKey': API_KEY}
PROXIES = handle_proxy(proxy_param_name='use_proxy')


def IS_2XX(x):
    return (x / 100) == 2  # Returns true if status code (int) is 2xx


# Dict of Cyber Triage REST APIs currently used
REST_APIS = {
    'check_creds': f'https://{CT_SERVER}:{REST_PORT}/api/correlation/checkcredentials',
    'start_collection': f'https://{CT_SERVER}:{REST_PORT}/api/livesessions'
}


def make_rest_call(rest_api, method, json_data=None, headers=REQ_HEADERS, verify_cert=VERIFY_SERVER_CERT):
    """Method to make rest calls (using requests) and handle error scenarios.

    Args:
        rest_api (str): a string that represents a url to a rest api
        method (str): a string that represents an http methods supported by requests (get, put, post, ...)
        json_data (dict, optional): same as requests json arg. Defaults to None.
        headers (dict, optional): same as requests headers arg. Defaults to REQ_HEADERS.
        verify_cert (bool, optional): same as requests verify arg. Defaults to VERIFY_SERVER_CERT.

    Returns:
        dict: Dictionary with response, status_code, and exception keys. status_code will be -1 or status code
              returned in response object. Exception will be empty unless an exception occurred. Response will
              contain the json response from CT if a 2xx response occurred, otherwise it will represent an error
              message string.
    """
    ret_msg: str | dict[str, Any] = ''
    http_status_code = -1
    err = None

    # Get the request function associate with the type of http request we want to make (ex. GET or POST)
    try:
        request_func = getattr(requests, method)
    except AttributeError:
        ret_msg = f'Invalid requests method: {method}'
        return_error(ret_msg)
    else:
        resp_json = {}
        response: requests.Response = requests.Response()
        # Attempt to make the rest API call and get data from response
        try:
            response = request_func(rest_api, json=json_data, headers=headers, proxies=PROXIES, verify=verify_cert)
            http_status_code = response.status_code

            # Raises ValueError exception if response cannot be converted to json
            resp_json = response.json()

            # Raises HTTPError exception if we get a non successful http status code (4xx/5xx)
            response.raise_for_status()

            ret_msg = resp_json

        except ValueError as e:
            ret_msg = f'Response did not contain valid json data. Response: {response.text}'
            err = e
            demisto.error(traceback.format_exc())

        except requests.exceptions.SSLError as e:
            ret_msg = 'Unable to verify the Cyber Triage server certificate'
            err = e
            demisto.error(traceback.format_exc())

        except requests.exceptions.HTTPError as e:
            # Format error message based on error response in json
            ret_msg = 'No Error Message found'

            if 'Error' in resp_json:
                ret_msg = resp_json['Error']
            elif 'message' in resp_json:
                ret_msg = resp_json['message']

            err = e
            demisto.error(resp_json)
            demisto.error(traceback.format_exc())

        except requests.exceptions.ConnectionError as e:
            ret_msg = f'Error while connecting to ({rest_api})'
            err = e
            demisto.error(traceback.format_exc())

        except requests.exceptions.RequestException as e:
            ret_msg = 'An unexpected error has occurred'
            err = e
            demisto.error(traceback.format_exc())

        result = {
            'response': ret_msg,
            'status_code': http_status_code
        }
        if err:
            result['exception'] = str(err)
        return result

# Format non 2xx responses from make_rest_call(). These are cases where an error has occurred.


def format_err_resp(json_resp):
    return (
        f'Error message: {json_resp["response"]}\nHTTP Status '
        f'code: {json_resp["status_code"]}\nExceptions: {json_resp["exception"]}'
    )


def test_connection():
    response = make_rest_call(REST_APIS['check_creds'], 'get')

    if IS_2XX(response['status_code']):
        demisto.results('ok')
    else:
        return_error(format_err_resp(response))


def triage_endpoint():
    def is_true(x):
        return x == 'yes'
    is_hash_upload_on = is_true(CMD_ARGS['malware_hash_upload'])  # arg value = 'yes' or 'no'
    is_file_upload_on = is_true(CMD_ARGS['malware_file_upload'])  # arg value = 'yes' or 'no'
    endpoint = CMD_ARGS['endpoint']
    scan_options = CMD_ARGS['scan_options']
    incident_name = CMD_ARGS['incident_name']

    # Validate scan options
    invalid_options = [opt for opt in scan_options.split(',') if opt not in SCAN_OPTIONS]
    if invalid_options:
        return_error('The following are not valid scan options: {}'.format(','.join(invalid_options)))

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
            'HumanReadable': f'A collection has been scheduled for {endpoint}',
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
