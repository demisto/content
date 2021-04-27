import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *

''' IMPORTS '''

import json
import requests
from typing import List, Dict
from string import Template

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

USERNAME = demisto.params().get('credentials', {}).get('identifier')
PASSWORD = demisto.params().get('credentials', {}).get('password')
API_KEY = demisto.params().get('key')
SYSTEM_NAME = demisto.params().get('system_name')
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
}

SESSION = requests.session()
ERR_DICT = {
    '4031': 'User does not have permission.',
    '4034': 'Request is not yet approved.',
    '4091': 'Conflicting request exists. This user or another user has already requested a password for the'
            'specified account'
}


''' HELPER FUNCTIONS '''


def http_request(method: str, suffix_url: str, data=None):
    """
    A wrapper for requests lib to send our requests and handle requests
    and responses better

    Parameters
    ----------
    method : str
        HTTP method, e.g. 'GET', 'POST' ... etc.
    suffix_url : str
        API endpoint.
    data: str
        Data to be sent in a 'POST' request.

    Returns
    -------
    Response from having made the request.
    """
    url = BASE_URL + suffix_url
    try:
        res = SESSION.request(
            method,
            url,
            verify=USE_SSL,
            data=data,  # type: ignore
            headers=HEADERS
        )
    except requests.exceptions.SSLError:
        ssl_error = 'Could not connect to BeyondTrust: Could not verify certificate.'
        return return_error(ssl_error)
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout,
            requests.exceptions.TooManyRedirects, requests.exceptions.RequestException) as e:
        connection_error = f'Could not connect to BeyondTrust: {e}'
        return return_error(connection_error)

    # Handle error responses gracefully
    if res.status_code not in {200, 201, 204}:
        txt = res.text
        if txt in ERR_DICT:
            txt = ERR_DICT[txt]
        elif res.status_code in ERR_DICT:
            txt = ERR_DICT[txt]
        elif res.status_code == 401:
            txt = 'Wrong credentials.'
        return_error(f'Error in API call to BeyondSafe Integration [{res.status_code}] - {txt})')
    try:
        return res.json()
    except ValueError:
        return None


def signin():
    """
    Starts a session in BeyondTrust
    """
    suffix_url = '/Auth/SignAppin'
    header = {'Authorization': f'PS-Auth key={API_KEY}; runas={USERNAME}; pwd=[{PASSWORD}];'}
    SESSION.headers.update(header)
    http_request('POST', suffix_url)


def signout():
    """
    Ends a session
    """

    suffix_url = '/auth/signout'
    http_request('POST', suffix_url)


''' COMMANDS + REQUESTS FUNCTIONS '''


def get_managed_accounts_request():
    """
    Request for all managed accounts
    """
    suffix_url = '/managedaccounts'
    response = http_request('GET', suffix_url)

    return response


def get_managed_accounts():
    """
    Returns a list of Managed Accounts that can be requested by the current user.
    """
    data = []
    headers = ['AccountName', 'AccountID', 'AssetName', 'AssetID', 'DomainName', 'LastChangeDate', 'NextChangeDate']
    managed_accounts = get_managed_accounts_request()
    for account in managed_accounts:
        data.append({
            'LastChangeDate': account.get('LastChangeDate'),
            'NextChangeDate': account.get('NextChangeDate'),
            'AssetID': account.get('SystemId'),
            'AssetName': account.get('SystemName'),
            'DomainName': account.get('DomainName'),
            'AccountID': account.get('AccountId'),
            'AccountName': account.get('AccountName')

        })

    entry_context = {'BeyondTrust.Account(val.AccountID === obj.AccountID)': managed_accounts}

    return_outputs(tableToMarkdown('BeyondTrust Managed Accounts', data, headers, removeNull=True), entry_context,
                   managed_accounts)


def get_managed_systems_request() -> List[Dict]:
    """
    Request for all managed systems
    """
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
            'ManagedAssetID': managed_system.get('ManagedSystemID'),
            'ChangeFrequencyDays': managed_system.get('ChangeFrequencyDays'),
            'AssetID': managed_system.get('AssetID'),
            'DatabaseID': managed_system.get('DatabaseID'),
            'DirectoryID': managed_system.get('DirectoryID'),
            'AssetName': managed_system.get('SystemName'),
            'PlatformID': managed_system.get('PlatformID'),
            'Port': managed_system.get('Port')
        })

    entry_context = {'BeyondTrust.System(val.ManagedAssetID === obj.ManagedAssetID)': managed_systems}

    return_outputs(tableToMarkdown('BeyondTrust Managed Systems', data, removeNull=True), entry_context,
                   managed_systems)


def create_release_request(data: str):
    """
    Request for credentials release
    """
    suffix_url = '/requests'
    response = http_request('POST', suffix_url, data=data)

    return response


def create_release():
    """
    Creates a new release request.
    Retrieves the credentials for an approved and active (not expired) credentials release request.

    demisto parameter: (string) access_type
        The type of access requested (View, RDP, SSH). Defualt is "View".

    demisto parameter: (int) system_id
        ID of the Managed System to request.

    demisto parameter: (int) account_id
        ID of the Managed Account to request.

    demisto parameter: (int) duration_minutes
        The request duration (in minutes).

    demisto parameter: (string) reason
        The reason for the request.

    demisto parameter: (int) access_policy_schedule_id
        The Schedule ID of an Access Policy to use for the request. If omitted, automatically selects the best schedule.

    demisto parameter: (bool) conflict_option
        The conflict resolution option to use if an existing request is found for the same user,
        system, and account ("reuse" or "renew").
    """
    access_type = demisto.args().get('access_type')
    system_id = demisto.args().get('system_id')
    account_id = demisto.args().get('account_id')
    duration_minutes = demisto.args().get('duration_minutes')
    reason = demisto.args().get('reason')
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

    if conflict_option:
        data['ConflictOption'] = conflict_option

    request = create_release_request(str(data))
    request_id = str(request)

    credentials = get_credentials_request(request_id)

    response = {
        'RequestID': request_id,
        'Password': credentials
    }

    entry_context = {'BeyondTrust.Request(val.AccountID === obj.AccountID)': createContext(response)}
    return_outputs(tableToMarkdown('The new release was created successfully.', response), entry_context, response)


def get_credentials_request(request_id: str):
    """
    Request for specific credentials
    """

    suffix_url = '/credentials/' + request_id
    response = http_request('GET', suffix_url)

    return response


def get_credentials():
    """
    Retrieves the credentials for an approved and active (not expired) credentials release request.

    demisto parameter: (int) request_id
        ID of the Request for which to retrieve the credentials
    """

    request_id = demisto.args().get('request_id')
    request = str(request_id)
    response = get_credentials_request(request)

    demisto.results('The credentials for BeyondTrust request: ' + response)


def check_in_credentials_request(request_id: str, data: dict):
    """
    Request for check-in credentials

    """
    suffix_url = f'/Requests/{request_id}/Checkin'
    response = http_request('PUT', suffix_url, data=json.dumps(data))

    return response


def check_in_credentials():
    """
    Checks-in/releases a request before it has expired.

    demisto parameter: (int) request_id
        ID of the request to release.

    demisto parameter: (string) reason
        A reason or comment why the request is being released.

    """
    request_id = demisto.args().get('request_id')
    reason = str(demisto.args().get('reason'))

    data = {'Reason': reason if reason else ''}

    check_in_credentials_request(request_id, data)

    demisto.results('The release was successfully checked-in/released')


def change_credentials_request(account_id: str, data: dict):
    """
    Request to change credentials
    """
    suffix_url = f'/ManagedAccounts/{account_id}/Credentials'
    response = http_request('PUT', suffix_url, data=json.dumps(data))

    return response


def change_credentials():
    """
    Updates the credentials for a Managed Account, optionally applying the change to the Managed System.

    demisto parameter: (int) account_id
        ID of the account for which to set the credentials.

    demisto parameter: (string) password
        The new password to set. If not given, generates a new, random password.

    demisto parameter: (string) public_key
        The new public key to set on the host. This is required if PrivateKey is given and updateSystem=true.

    demisto parameter: (string) private_key
        The private key to set (provide Passphrase if encrypted).

    demisto parameter: (string) pass_phrase
        The passphrase to use for an encrypted private key.

    demisto parameter: (bool) update_system
        Whether to update the credentials on the referenced system.

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
        if public_key and update_system is True:
            data['PrivateKey'] = private_key
            data['PublicKey'] = public_key
        else:
            return_error('Missing public key')

    if pass_phrase:
        data['Passphrase'] = pass_phrase

    change_credentials_request(account_id, data)

    demisto.results('The password has been changed')


def match_cred_name(config_name, name_value, matcher_regex, default_result):
    if matcher_regex is None:
        return default_result
    for r in matcher_regex:
        try:
            if re.search(r, name_value):
                return True
        except Exception as e:
            demisto.debug(
                "BeyondTrust_PGE: Invalid regular expression found in configuration [{0}] with value[{1}]".format(config_name, r))
    return default_result


def fetch_credentials_build_credential(integration_config, requested_identifier, account_name, system_name, password):

    matchedConditionalNameConfig = None
    if integration_config and 'conditional_names_workaround' in integration_config and len(integration_config['conditional_names_workaround']) > 0:
        for conditionalNameConfig in integration_config['conditional_names_workaround']:
            if 'identifier' in conditionalNameConfig and 'name' in conditionalNameConfig and 'new_name' in conditionalNameConfig and \
                    requested_identifier == conditionalNameConfig['identifier'] and account_name == conditionalNameConfig['name']:
                matchedConditionalNameConfig = (conditionalNameConfig['name'], conditionalNameConfig['new_name'])

    if 'fetch_format_templates' in integration_config and len(integration_config['fetch_format_templates']) > 0:
        formatTemplates = integration_config['fetch_format_templates']
    else:
        formatTemplates = None

    credentials = []
    if (formatTemplates):
        for t in formatTemplates:

            s = Template(t)
            template_name_result = s.substitute(name=account_name, system=system_name, requested_identifier=SYSTEM_NAME)
            demisto.debug("PgeBeyondTrust: added credential [{0}] from template string[{1}] for account={2}".format(
                template_name_result, t, account_name))
            if matchedConditionalNameConfig and template_name_result == matchedConditionalNameConfig[0]:
                credentials.append({
                    'user': template_name_result,
                    'password': password,
                    'name': matchedConditionalNameConfig[1]
                })
            else:
                credentials.append({
                    'user': template_name_result,
                    'password': password,
                    'name': template_name_result
                })

    else:

        demisto.debug("PgeBeyondTrust: no templates specified while processing so adding account [{0}]".format(account_name))

        if matchedConditionalNameConfig and account_name == matchedConditionalNameConfig[0]:
            credentials.append({
                'user': account_name,
                'password': password,
                'name': matchedConditionalNameConfig[1]
            })
        else:
            credentials.append({
                'user': account_name,
                'password': password,
                'name': account_name
            })

    return credentials


def fetch_credentials_impl():
    """
    Returns: Account's credentials
    """

    credential_names = []
    credentials = []
    identifier = demisto.args().get('identifier')
    duration_minutes = 1
    account_info = get_managed_accounts_request()

    # read the configuration data from the integration configuration data
    try:
        if 'integration_config' in demisto.params():
            integration_config = json.loads(demisto.params().get('integration_config', {}))
        else:
            integration_config = {}
    except Exception as e:
        demisto.debug("PgeBeyondTrust: Unhandled exception while reading the configuration, ex={}".format(str(e)))
        integration_config = {}

    includeMatchesConfigName = "include_regex"
    excludeMatchesConfigName = "exclude_regex"
    demisto.debug("PgeBeyondTrust: Starting fetch with account size={0}, identifier={1}, config={2}".format(
        str(len(account_info)), identifier, str(integration_config)))

    if includeMatchesConfigName in integration_config and len(integration_config[includeMatchesConfigName]) > 0:
        includeMatches = integration_config[includeMatchesConfigName]
    else:
        includeMatches = None

    if excludeMatchesConfigName in integration_config and len(integration_config[excludeMatchesConfigName]) > 0:
        excludeMatches = integration_config[excludeMatchesConfigName]
    else:
        excludeMatches = None

    return_credentials = []
    for account in account_info:

        account_name = account.get('AccountName')
        system_name = account.get('SystemName')

        doesNameMatch = False
        if includeMatches is None and excludeMatches is None:
            doesNameMatch = True
        elif includeMatches is not None and excludeMatches is None:
            if match_cred_name(includeMatchesConfigName, account_name, includeMatches, False):
                doesNameMatch = True
            else:
                doesNameMatch = False
        elif includeMatches is None and excludeMatches is not None:
            if match_cred_name(excludeMatchesConfigName, account_name, excludeMatches, False):
                doesNameMatch = False
            else:
                doesNameMatch = True
        elif includeMatches is not None and excludeMatches is not None:

            if match_cred_name(includeMatchesConfigName, account_name, includeMatches, False):
                if match_cred_name(excludeMatchesConfigName, account_name, excludeMatches, False):
                    doesNameMatch = False
                else:
                    doesNameMatch = True
            else:
                doesNameMatch = False

        else:
            doesNameMatch = False

        if not doesNameMatch:
            continue

        if SYSTEM_NAME and system_name != SYSTEM_NAME:
            continue

        if 'ignore_system_names' in integration_config and system_name in integration_config["ignore_system_names"]:
            continue

        item = {
            'SystemId': account.get('SystemId'),
            'AccountId': account.get('AccountId'),
            'DurationMinutes': duration_minutes,
            'ConflictOption': 'reuse'
        }

        release_id = create_release_request(str(item))
        password = get_credentials_request(str(release_id))

        demisto.debug("PgeBeyondTrust: processing beyondtrust account record, account={0}, system={1}".format(
            account_name, system_name))

        credentials_from_request = fetch_credentials_build_credential(
            integration_config=integration_config, requested_identifier=identifier, account_name=account_name, system_name=system_name, password=password)
        if credentials_from_request:
            for cred in credentials_from_request:
                if cred["name"] not in credential_names:
                    if identifier and identifier != "" and cred["name"] == identifier:
                        return_credentials.append(cred)
                    elif not identifier or identifier == "":
                        return_credentials.append(cred)
                    credential_names.append(cred["name"])

    demisto.debug("PgeBeyondTrust: built a list of [{0}] credentials for identifier={1}".format(
        str(len(return_credentials)), identifier))

    return return_credentials


def fetch_credentials_command():
    demisto.credentials(fetch_credentials_impl())


def fetch_credentials_test_command():
    current_credentials = fetch_credentials_impl()
    return_credentials = []
    headers = ['user', 'password', 'name']
    for cred in current_credentials:
        if 'password' in cred or not cred['password']:
            current_password = cred['password'][:2] + "..."
        else:
            current_password = "<Empty>"
        return_credentials.append({
            'user': cred['user'],
            'name': cred['name'],
            'password': current_password
        })

    return_outputs(tableToMarkdown('BeyondTrust Current Fetch Accounts', return_credentials, headers, removeNull=True))


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))
demisto.debug('PgeBeyondTrust: %s called' % (demisto.command()))

try:
    handle_proxy()
    signin()
    if demisto.command() == 'test-module':
        demisto.debug("PgeBeyondTrust: test-module called")
        # This is the call made when pressing the integration test button.
        get_managed_accounts_request()
        demisto.results('ok')
    elif demisto.command() == 'beyondtrust-test-fetch-credentials':
        fetch_credentials_test_command()
    elif demisto.command() == 'beyondtrust-get-managed-accounts':
        get_managed_accounts()
    elif demisto.command() == 'beyondtrust-get-managed-systems':
        get_managed_systems()
    elif demisto.command() == 'beyondtrust-create-release-request':
        create_release()
    elif demisto.command() == 'beyondtrust-get-credentials':
        get_credentials()
    elif demisto.command() == 'beyondtrust-check-in-credentials':
        check_in_credentials()
    elif demisto.command() == 'beyondtrust-change-credentials':
        change_credentials()
    elif demisto.command() == 'fetch-credentials':
        fetch_credentials_command()

# Log exceptions
except Exception as e:
    LOG(str(e))
    LOG.print_log()
    raise
finally:
    signout()
