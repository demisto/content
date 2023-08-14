import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''

import json

import requests

# Disable insecure warnings
import urllib3
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

USER_NAME = demisto.params().get('credentials').get('identifier')
PASSWORD = demisto.params().get('credentials').get('password')
SERVER = demisto.params()['server'][:-1] if (demisto.params()['server'] and demisto.params()
                                             ['server'].endswith('/')) else demisto.params()['server']
USE_SSL = not demisto.params().get('unsecure', False)
BASE_URL = SERVER + '/api/v1/'

# remove proxy if not set to true in params
if not demisto.params().get('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


''' COMMANDS + REQUESTS FUNCTIONS '''


@logger
def test_module():
    """
    Perform basic login and logout operation, validate connection.
    """
    r = requests.get(BASE_URL, auth=(USER_NAME, PASSWORD), verify=USE_SSL)
    if r.status_code == 200:
        return True
    else:
        return False


@logger
def get_user_command():
    user_context = []
    userType = demisto.args().get('user_type')
    userItems = get_user_request(userType)

    if userItems:

        user_context.append({
            'id': userItems["objects"][0]["id"],
            'username': userItems["objects"][0]["username"],
            'email': userItems["objects"][0]["email"],
            'active': userItems["objects"][0]["active"],
            'token_auth': userItems["objects"][0]["token_auth"],
            'token_type': userItems["objects"][0]["token_type"],
            'token_serial': userItems["objects"][0]["token_serial"]
        })

        markdown = 'FortiAuthenticator\n'
        markdown += tableToMarkdown('FortiAuthenticator User Info', user_context,
                                    headers=['id', 'username', 'email', 'active', 'token_auth', 'token_type', 'token_serial'])
        results = CommandResults(
            readable_output=markdown,
            outputs_prefix='FortiAuthenticator.user',
            outputs_key_field='id',
            outputs=user_context
        )
        return_results(results)
    else:
        markdown = 'No such user.\n'
        results = CommandResults(readable_output=markdown)
        return_results(results)


@logger
def get_user_request(userType):
    email = demisto.args().get('email')
    username = demisto.args().get('username')
    token_serial = demisto.args().get('token_serial')

    if email:
        params = {
            'format': 'json',
            'email': email
        }
    elif username:
        params = {
            'format': 'json',
            'username': username
        }
    elif token_serial:
        params = {
            'format': 'json',
            'token_serial': token_serial
        }
    else:
        return False

    res = requests.get(BASE_URL + userType, params=params, auth=(USER_NAME, PASSWORD), verify=USE_SSL)
    tmp = res.json()
    if tmp['meta']['total_count'] == 0:
        return False
    else:
        return res.json()


@logger
def update_user_command():
    user_context = []
    active = demisto.args().get('active')
    userType = demisto.args().get('user_type')
    userItems = get_user_request(userType)

    if userItems:
        userURI = str(userItems["objects"][0]["resource_uri"])
        if active == "true":
            userDict = {
                "active": True
            }
        else:
            userDict = {
                "active": False
            }

        jsonData = json.dumps(userDict)

        res = requests.patch(SERVER + userURI, data=jsonData, auth=(USER_NAME, PASSWORD), verify=USE_SSL)

        if res.status_code == 202:
            user_context.append({
                'id': userItems["objects"][0]["id"],
                'username': userItems["objects"][0]["username"],
                'email': userItems["objects"][0]["email"],
                'active': active,
                'token_auth': userItems["objects"][0]["token_auth"],
                'token_type': userItems["objects"][0]["token_type"],
                'token_serial': userItems["objects"][0]["token_serial"]
            })

            markdown = 'FortiAuthenticator\n'
            markdown += tableToMarkdown('Updated FortiAuthenticator User Info', user_context,
                                        headers=['id', 'username', 'email', 'active', 'token_auth', 'token_type', 'token_serial'])
            results = CommandResults(
                readable_output=markdown,
                outputs_prefix='FortiAuthenticator.user',
                outputs_key_field='id',
                outputs=user_context
            )
        else:
            results = CommandResults(readable_output='Fail to update user.\n')
    else:
        results = CommandResults(readable_output='No such user for update.\n')
    return_results(results)


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('command is %s' % (demisto.command(), ))

try:
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_module()
        demisto.results('ok')
    elif demisto.command() == 'fortiauthenticator-get-user':
        get_user_command()
    elif demisto.command() == 'fortiauthenticator-update-user':
        update_user_command()

# Log exceptions and return errors
except Exception:
    demisto.error(traceback.format_exc())  # print the traceback
    return_error(f'Failed to execute {demisto.command()} command.\nError:\n{traceback.format_exc()}')
