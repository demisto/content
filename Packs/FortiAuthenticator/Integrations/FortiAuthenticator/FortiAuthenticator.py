import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''

import json

import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

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
    email = demisto.args().get('email')
    userType = demisto.args().get('user_type')
    userItems = get_addresses_request(email, userType)

    if userItems:
        user_context.append({
            'username': userItems["objects"][0]["username"],
            'email': userItems["objects"][0]["email"],
            'active': userItems["objects"][0]["active"],
            'id': userItems["objects"][0]["id"]
        })

        markdown = 'FortiAuthenticator\n'
        markdown += tableToMarkdown('FortiAuthenticator User Info', user_context, headers=['id', 'username', 'email', 'active'])
        results = CommandResults(
            readable_output=markdown,
            outputs_prefix='FortiAuthenticator.user',
            outputs_key_field='id',
            outputs=user_context
        )
        return_results(results)
    else:
        markdown = 'No such user.\n'
        results = CommandResults(
            readable_output=markdown
        )
        return_results(results)


@logger
def get_addresses_request(email, userType):
    params = {
        'format': 'json',
        'email': email
    }
    res = requests.get(BASE_URL + userType, params=params, auth=(USER_NAME, PASSWORD), verify=USE_SSL)
    tmp = res.json()
    if tmp['meta']['total_count'] == 0:
        return False
    else:
        return res.json()


@logger
def update_user_command():
    user_context = []
    email = demisto.args().get('email')
    active = demisto.args().get('active')
    userType = demisto.args().get('user_type')
    userItems = get_addresses_request(email, userType)

    if userItems:
        userID = str(userItems["objects"][0]["id"])

        userDict = {
            "active": active
        }
        jsonData = json.dumps(userDict)

        res = requests.patch(BASE_URL + 'localusers/' + userID + '/', data=jsonData, auth=(USER_NAME, PASSWORD), verify=USE_SSL)

        if res.status_code == 202:
            user_context.append({
                'username': userItems["objects"][0]["username"],
                'email': userItems["objects"][0]["email"],
                'active': active,
                'id': userItems["objects"][0]["id"]
            })

            markdown = 'FortiAuthenticator\n'
            markdown += tableToMarkdown('Updated FortiAuthenticator User Info', user_context,
                                        headers=['id', 'username', 'email', 'active'])
            results = CommandResults(
                readable_output=markdown,
                outputs_prefix='FortiAuthenticator.user',
                outputs_key_field='id',
                outputs=user_context
            )
        else:
            results = CommandResults(
                readable_output='Fail to update user.\n'
            )
    else:
        results = CommandResults(
            readable_output='No such user for update.\n'
        )
    return_results(results)


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('command is %s' % (demisto.command(), ))

try:
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_module()
        demisto.results('ok')
    elif demisto.command() == 'FortiAuthenticator-get-user':
        get_user_command()
    elif demisto.command() == 'FortiAuthenticator-update-user':
        update_user_command()

# Log exceptions and return errors
except Exception:
    demisto.error(traceback.format_exc())  # print the traceback
    return_error(f'Failed to execute {demisto.command()} command.\nError:\n{traceback.format_exc()}')
