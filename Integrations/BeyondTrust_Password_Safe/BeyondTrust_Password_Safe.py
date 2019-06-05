import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
from requests import Request, Session


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

USERNAME = demisto.params().get('credentials').get('identifier')
PASSWORD = demisto.params().get('credentials').get('password')
API_KEY = demisto.params().get('key')
# Remove trailing slash to prevent wrong URL path to service
SERVER = demisto.params()['url'][:-1] \
    if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)
# Service base URL
BASE_URL = SERVER + '/BeyondTrust/api/public/v3'
# Headers to be sent in requests
HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': 'PS-Auth key=' + API_KEY + '; ' + 'runas=' + USERNAME + '; ' + 'pwd=[' + PASSWORD + '];'
}

SESSION = requests.session()
# Remove proxy if not set to true in params
if not demisto.params().get('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


''' HELPER FUNCTIONS '''


def http_request(method, suffix_url, params=None, data=None):

    url = BASE_URL + suffix_url

    res = SESSION.request(
        method,
        url,
        verify=USE_SSL,
        params=params,
        data=data,
        headers=HEADERS
    )
    # Handle error responses gracefully
    if res.status_code not in {200, 201, 204}:
        return_error('Error in API call to BeyondSafe Integration [%d] - %s' % (res.status_code, res.content))

    try:
        return res.json()
    except ValueError:
        return None


def signin():

    suffix_url = '/Auth/SignAppin'
    header = {'Authorization': 'PS-Auth key=' + API_KEY + '; ' + 'runas=' + USERNAME + '; ' + 'pwd=[' + PASSWORD + '];'}
    SESSION.headers.update(header)
    response = SESSION.post(BASE_URL + suffix_url,verify=USE_SSL)


def signout():

    suffix_url = '/auth/signout'
    response = SESSION.post(BASE_URL + suffix_url)


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Singing in the execution code
    """
    pass


def get_managed_accounts_request():

    suffix_url = '/managedaccounts'
    response = http_request('GET', suffix_url)

    return response


def get_managed_accounts():
    """
    Returns a list of Managed Accounts that can be requested by the current user.
    """
    data = []
    managed_accounts = get_managed_accounts_request()
    for account in managed_accounts:
        data.append({
            'PlatformID': account.get('PlatformID'),
            'SystemId': account.get('SystemId'),
            'SystemName': account.get('SystemName'),
            'DomainName': account.get('DomainName'),
            'AccountId': account.get('AccountId'),
            'AccountName': account.get('AccountName')
        })

    ec = {'BeyondTrust.Account(val.AccountId === obj.AccountId)': managed_accounts}

    return_outputs(tableToMarkdown('BeyondTrust Managed Accounts', data, removeNull=True), ec, managed_accounts)


def get_managed_systems_request():

    suffix_url = '/managedsystems'
    response = http_request('GET', suffix_url)

    return response


def get_managed_systems():
    """
    Returns a list of Managed Systems.
    """
    data = []
    managed_systems = get_managed_systems_request()
    for managed_system in managed_systems:
        data.append({
            'ManagedSystemID': managed_system.get('ManagedSystemID'),
            'ChangeFrequencyDays': managed_system.get('ChangeFrequencyDays'),
            'AssetID': managed_system.get('AssetID'),
            'DatabaseID': managed_system.get('DatabaseID'),
            'DirectoryID': managed_system.get('DirectoryID'),
            'SystemName': managed_system.get('SystemName'),
            'PlatformID': managed_system.get('PlatformID'),
            'Port': managed_system.get('Port')
        })

    ec = {'BeyondTrust.System(val.ManagedSystemID === obj.ManagedSystemID)': managed_systems}

    return_outputs(tableToMarkdown('BeyondTrust Managed Systems', data, removeNull=True), ec, managed_systems)


def create_release_request(data):

    suffix_url = '/requests'
    response = http_request('POST', suffix_url, data=data)

    return response


def create_release():
    """
    Creates a new release request.
    Retrieves the credentials for an approved and active (not expired) credentials release request.
    """
    access_type = demisto.args().get('access_type')
    system_id = demisto.args().get('system_id').encode('utf-8')
    account_id = demisto.args().get('account_id').encode('utf-8')
    duration_minutes = demisto.args().get('duration_minutes').encode('utf-8')
    reason = demisto.args().get('reason')
    access_policy_schedule_id = demisto.args().get('access_policy_schedule_id')
    conflict_option = demisto.args().get('conflict_option')

    data = {
        'SystemId': system_id,
        'AccountId': account_id,
        'DurationMinutes': duration_minutes
    }

    if access_type:
        data['AccessType'] = access_type

    if reason:
        data['Reason'] = reason

    if access_policy_schedule_id:
        data['AccessPolicyScheduleID'] = access_policy_schedule_id

    if conflict_option:
        data['ConflictOption'] = conflict_option

    request = create_release_request(str(data))
    request_id = str(request)

    credentials = get_credentials_request(request_id)

    response = {
        'RequestID': request_id,
        'Credentials': credentials
    }

    ec = {'BeyondTrust.Request(val.AccountId === obj.AccountId)':createContext(response)}
    return_outputs(tableToMarkdown('The request has been Successful', response), ec, response)


def get_credentials_request(request_id):

    suffix_url = '/credentials/' + request_id
    response = http_request('GET', suffix_url)

    return response


# def get_credentials():
#     """
#     Retrieves the credentials for an approved and active (not expired) credentials release request.
#     """

#     request_id = demisto.args().get('request_id')
#     response = get_credentials_request(request_id)

#     ec = {'BeyondTrust.Request(val.request_id === obj.request_id)': response}

#     return_outputs(tableToMarkdown('BeyondTrust Release Request', response, removeNull=True), ec, response)


def check_in_credentials_request(request_id, data):

    suffix_url = '/Requests/' + request_id + '/Checkin'
    response = http_request('PUT', suffix_url, data=json.dumps(data))

    return response


def check_in_credentials():
    """
    Checks-in/releases a request before it has expired.
    """
    request_id = demisto.args().get('request_id')
    reason = demisto.args().get('reason')

    data = {'Reason': reason if reason else ''}

    check_in = check_in_credentials_request(request_id, data)

    demisto.results('The request has been Successful')


def change_credentials_request(account_id, data):

    suffix_url = '/ManagedAccounts/' + account_id + '/Credentials'
    response = http_request('PUT', suffix_url, data=json.dumps(data))

    return response


def change_credentials():
    """
    Updates the credentials for a Managed Account, optionally applying the change to the Managed System.
    """
    account_id = demisto.args().get('account_id')
    password = demisto.args().get('password')
    public_key = demisto.args().get('public_key')
    private_key = demisto.args().get('private_key')
    pass_phrase = demisto.args().get('pass_phrase')
    update_system = demisto.args().get('update_system')

    data = {
        'AccountId': account_id
    }

    if password:
        data['Password'] = password

    if private_key:
        if public_key and update_system == True:
            data['PrivateKey'] = private_key
            data['PublicKey'] = public_key
        else:
            demisto.results('Please provide public key')

    if pass_phrase:
        data['Passphrase'] = pass_phrase
    change_request = change_credentials_request(account_id, data)

    demisto.results('The password has been changed')


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

try:
    signin()
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_module()
        demisto.results('ok')
    elif demisto.command() == 'beyondtrust-get-managed-accounts':
        get_managed_accounts()
    elif demisto.command() == 'beyondtrust-get-managed-systems':
        get_managed_systems()
    elif demisto.command() == 'beyondtrust-create-release-request':
        create_release()
    elif demisto.command() == 'beyondtrust-check-in-credentials':
        check_in_credentials()
    elif demisto.command() == 'beyondtrust-change-credentials':
        change_credentials()

# Log exceptions
except Exception, e:
    LOG(e.message)
    LOG.print_log()
    raise
finally:
    signout()