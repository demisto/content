import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
from typing import Dict, Tuple, List, AnyStr, Union
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

"""GLOBALS/PARAMS
Attributes:
    INTEGRATION_NAME:
        Name of the integration as shown in the integration UI, for example: Microsoft Graph User.

    INTEGRATION_COMMAND_NAME:
        Command names should be written in all lower-case letters,
        and each word separated with a hyphen, for example: msgraph-user.

    INTEGRATION_CONTEXT_NAME:
        Context output names should be written in camel case, for example: MSGraphUser.
"""
INTEGRATION_NAME = 'Infoblox Integration'
INTEGRATION_COMMAND_NAME = 'infoblox'
INTEGRATION_CONTEXT_NAME = 'Infoblox'
REQUEST_PARAM_EXTRA_ATTRIBUTES = {'_return_fields+': 'extattrs'}
REQUEST_PARAM_PAGING_FLAG = {'_paging': '1'}

RESPONSE_TRANSLATION_DICTIONARY = {
    '_ref': 'ReferenceID'
}


class Client(BaseClient):
    def __init__(self, base_url, verify=True, proxy=False, ok_codes=tuple(), headers=None, auth=None, params=None):
        super(Client, self).__init__(base_url, verify, proxy, ok_codes, headers, auth)
        self.params = params

    def _http_request(self, method, url_suffix, full_url=None, headers=None, auth=None, json_data=None, params=None,
                      data=None, files=None, timeout=10, resp_type='json', ok_codes=None, **kwargs):
        if params:
            self.params.update(params)
        try:
            return super()._http_request(method, url_suffix, full_url, headers, auth, json_data, self.params, data,
                                         files, timeout, resp_type, ok_codes, **kwargs)
        except DemistoException as error:
            print(parse_demisto_exception(error, 'text'))

    def test_module(self) -> Dict:
        """Performs basic GET request to check if the API is reachable and authentication is successful.

        Returns:
            Response JSON
        """
        return self.get_response_policy_zones()

    def get_response_policy_zones(self) -> Dict:
        """Uses to fetch credentials into Demisto
        Documentation: https://github.com/demisto/content/tree/master/docs/fetching_credentials

        Returns:
            Response JSON
        """
        suffix = 'zone_rp'
        # return self._http_request('GET', suffix, headers={'Authorization': "Basic cGFuOnBhbl8xMjM0NTY="})
        return self._http_request('GET', suffix)

    def get_ip(self, ip: str) -> Dict:
        """Get ip information.
        Args:
            ip: ip to retrieve.

        Returns:
            Response JSON
        """
        suffix = 'ipv4address'

        request_params = assign_params(ip_address=ip)
        request_params.update(REQUEST_PARAM_EXTRA_ATTRIBUTES)
        return self._http_request('GET', suffix, params=request_params)

    def search_related_objects_by_ip(self, ip: str, max_results: str) -> Dict:
        """Get ip information.
        Args:
            ip: ip to retrieve.
            max_results: maximum number of results

        Returns:
            Response JSON
        """
        suffix = 'search'

        request_params = assign_params(address=ip, _max_results=max_results)
        return self._http_request('GET', suffix, params=request_params)

    def list_response_policy_zone_rules(self, zone: str, max_results: str, next_page_id: str) -> Dict:
        """Locks an account by the account ID.

        Args:
            zone: response policy zone name.
            max_results: maximum number of results.
            next_page_id: ID of the next page to retrieve, if given all other arguments are ignored.

        Returns:
            Response JSON
        """
        # The service endpoint to request from
        suffix = 'allrpzrecords'
        # Dictionary of params for the request
        request_params = assign_params(zone=zone, _max_results=max_results, _page_id=next_page_id)
        request_params.update(REQUEST_PARAM_PAGING_FLAG)
        return self._http_request('GET', suffix, params=request_params)

    def unlock_account(self, account_id: AnyStr) -> Dict:
        """Returns events by the account ID.

        Args:
            account_id: Account ID to unlock.

        Returns:
            Response JSON
        """
        # The service endpoint to request from
        suffix = 'account/unlock'
        # Dictionary of params for the request
        params = {'account': account_id}
        # Send a request using our http_request wrapper
        return self._http_request('POST', suffix, params=params)

    def reset_account(self, account_id: str):
        """Resets an account by account ID.

        Args:
            account_id: Account ID to reset.

        Returns:
            Response JSON
        """
        # The service endpoint to request from
        suffix = 'account/reset'
        # Dictionary of params for the request
        params = {'account': account_id}
        # Send a request using our http_request wrapper
        return self._http_request('POST', suffix, params=params)

    def unlock_vault(self, vault_to_lock: AnyStr) -> Dict:
        """Unlocks a vault by vault ID.

        Args:
            vault_to_lock: Vault ID to lock

        Returns:
            Response JSON
        """
        suffix = 'vault/unlock'
        params = {'vaultId': vault_to_lock}
        return self._http_request('POST', suffix, params=params)

    def lock_vault(self, vault_to_lock: AnyStr) -> Dict:
        """Locks vault by vault ID.

        Args:
            vault_to_lock: Vault ID to lock.

        Returns:
            Response JSON
        """
        suffix = 'vault/lock'
        params = {'vaultId': vault_to_lock}
        return self._http_request('POST', suffix, params=params)

    def list_vaults(self, max_results: int) -> Dict:
        """Return all vaults from API.

        Args:
            max_results: Maximum results to fetch.

        Returns:
            Response JSON
        """
        suffix = 'vault'
        values_to_ignore = [0]
        params = assign_params(limit=max_results, values_to_ignore=values_to_ignore)
        return self._http_request('GET', suffix, params=params)


''' HELPER FUNCTIONS '''


def parse_demisto_exception(self, error: DemistoException, field_in_error: str):
    infoblox_err = error.args[0].split('\n')[1].replace('\\', '')
    infoblox_json = json.loads(infoblox_err)
    return infoblox_json.get(field_in_error, 'text')


def account_response_to_context(credentials: Union[Dict, List]) -> Union[Dict, List]:
    """Formats the API response to Demisto context.

    Args:
        credentials: The raw response from the API call. Can be a List or Dict.

    Returns:
        The formatted Dict or List.

    Examples:
        >>> account_response_to_context([{'username': 'user', 'name': 'demisto', 'isLocked': False}])
        [{'Username': 'user', 'Name': 'demisto', 'IsLocked': False}]
    """
    if isinstance(credentials, list):
        return [account_response_to_context(credential) for credential in credentials]
    return {
        'Username': credentials.get('username'),
        'Name': credentials.get('name'),
        'IsLocked': credentials.get('isLocked')
    }


def build_credentials_fetch(credentials: Union[Dict, List]) -> Union[Dict, List]:
    """Formats the API response to Demisto context.

    Args:
        credentials: The raw response from the API call. Can be a List or Dict.

    Returns:
        The formatted Dict or List.

    Examples:
        >>> build_credentials_fetch([{'username': 'user1', 'name': 'name1', 'password': 'password'}])
        [{'user': 'user1', 'name': 'name1', 'password': 'password'}]
    """
    if isinstance(credentials, list):
        return [build_credentials_fetch(credential) for credential in credentials]
    return {
        'user': credentials.get('username'),
        'name': credentials.get('name'),
        'password': credentials.get('password')
    }


def build_vaults_context(vaults: Union[List, Dict]) -> Union[List[Dict], Dict]:
    if isinstance(vaults, list):
        return [build_vaults_context(vault_entry) for vault_entry in vaults]
    return {
        'ID': vaults.get('vaultId'),
        'IsLocked': vaults.get('isLocked')
    }


''' COMMANDS '''


def test_module_command(client: Client, *_) -> str:
    """Performs a basic GET request to check if the API is reachable and authentication is successful.
    """
    try:
        _ = client.test_module()
        return ['ok']
    except Exception as e:
        raise DemistoException('Test module failed, {}'.format(e))


#
# def fetch_credentials(client: Client) -> list:
#     """Uses to fetch credentials into Demisto
#     Documentation: https://github.com/demisto/content/tree/master/docs/fetching_credentials
#
#     Args:
#         client: Client object
#
#     Returns:
#         Outputs
#     """
#     # Get credentials from api
#     raw_response = client.list_credentials()
#     raw_credentials = raw_response.get('credential', [])
#     if raw_credentials:
#         # Creates credentials entry
#         credentials = build_credentials_fetch(raw_credentials)
#         return credentials
#     else:
#         raise DemistoException(f'`fetch-incidents` failed in `{INTEGRATION_NAME}`, no keyword `credentials` in'
#                                f' response. Check API')
#
#
# def lock_account_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
#     """Locks an account by account ID.
#     Args:
#         client: Client object
#         args: Usually demisto.args()
#
#     Returns:
#         Outputs
#     """
#     # Get arguments from user
#     username = args.get('username', '')
#     # Make request and get raw response
#     raw_response = client.lock_account(username)
#     # Get account from raw_response
#     accounts = raw_response.get('account')
#     # Parse response into context & content entries
#     if accounts and accounts[0].get('username') == username and accounts[0].get('isLocked') is True:
#         user_object = accounts[0]
#         title: str = f'{INTEGRATION_NAME} - Account `{username}` has been locked.'
#         context_entry = account_response_to_context(user_object)
#         context = {
#             f'{INTEGRATION_CONTEXT_NAME}.Account(val.Username && val.Username === obj.Username)': context_entry
#         }
#         # Creating human readable for War room
#         human_readable: str = tableToMarkdown(title, context_entry)
#         # Return data to Demisto
#         return human_readable, context, raw_response
#     else:
#         raise DemistoException(f'{INTEGRATION_NAME} - Could not lock account `{username}`')
#
#
# def unlock_account_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
#     """Unlocks an account by account ID.
#     Args:
#         client: Client object
#         args: Usually demisto.args()
#
#     Returns:
#         Outputs
#     """
#     # Get arguments from user
#     username = args.get('username', '')
#     # Make request and get raw response
#     raw_response = client.unlock_account(username)
#     # Get account from raw_response
#     accounts = raw_response.get('account')
#     # Parse response into context & content entries
#     if accounts and accounts[0].get('username') == username and accounts[0].get('isLocked') is False:
#         user_object = accounts[0]
#         title = f'{INTEGRATION_NAME} - Account `{username}` has been unlocked.'
#         context_entry = account_response_to_context(user_object)
#         context = {
#             f'{INTEGRATION_CONTEXT_NAME}.Account(val.Username && val.Username === obj.Username)': context_entry}
#         # Creating human readable for War room
#         human_readable = tableToMarkdown(title, context_entry)
#         # Return data
#         return human_readable, context, raw_response
#     else:
#         raise DemistoException(f'{INTEGRATION_NAME} - Could not unlock account `{username}`')
#
#
# def reset_account_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
#     """Resets an account by account ID.
#     Args:
#         client: Client object
#         args: Usually demisto.args()
#
#     Returns:
#         Outputs
#     """
#     # Get arguments from user
#     username = args.get('username', '')
#     # Make request and get raw response
#     raw_response = client.reset_account(username)
#     # Get account from raw_response
#     accounts = raw_response.get('account')
#     # Parse response into context & content entries
#     if accounts and accounts[0].get('username') == username and accounts[0].get('isLocked') is False:
#         user_object = accounts[0]
#         title = f'{INTEGRATION_NAME} - Account `{username}` has been returned to default.'
#         context_entry = account_response_to_context(user_object)
#         context = {
#             f'{INTEGRATION_CONTEXT_NAME}.Account(val.Username && val.Username === obj.Username)': context_entry}
#         # Creating human readable for War room
#         human_readable = tableToMarkdown(title, context_entry)
#         # Return data to Demisto
#         return human_readable, context, raw_response
#     else:
#         raise DemistoException(f'{INTEGRATION_NAME} - Could not reset account `{username}`')


def get_ip_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Returns credentials to user without passwords.
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    ip = args.get('ip')
    raw_response = client.get_ip(ip)
    ip_list = raw_response['result']

    # If no IP object was returned
    if not ip_list:
        return f'{INTEGRATION_NAME} - Could not find any data corresponds to: {ip}', {}, {}
    fixed_keys_obj = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                      ip_list[0].items()}
    title = f'{INTEGRATION_NAME} - IP: {ip} info.'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.IP(val.ReferenceID && val.ReferenceID ==== obj.ReferenceID)': fixed_keys_obj}
    human_readable = tableToMarkdown(title, fixed_keys_obj, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def search_related_objects_by_ip_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Locks a vault by vault ID.
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    ip = args.get('ip')
    max_results = args.get('max_results')
    raw_response = client.search_related_objects_by_ip(ip, max_results)
    obj_list = raw_response['result']
    if not obj_list:
        return f'{INTEGRATION_NAME} - No objects associated to ip: {ip} were found', {}, {}
    fixed_keys_obg_list = []
    for obj in obj_list:
        fixed_keys_obj = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                          obj.items()}
        fixed_keys_obg_list.append(fixed_keys_obj)

    title = f'{INTEGRATION_NAME} - IP: {ip} search results.'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.IPSearchObjects(val.ReferenceID && val.ReferenceID ==== obj.ReferenceID)':
            fixed_keys_obg_list}
    human_readable = tableToMarkdown(title, fixed_keys_obg_list, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def list_response_policy_zone_rules_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Unlocks a vault by vault ID.
    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    zone = args.get('response_policy_zone_name')
    max_results = args.get('page_size', 50)
    next_page_id = args.get('next_page_id')
    if not zone and not next_page_id:
        raise DemistoException('To run this command either a zone or a next page ID must be given')
    raw_response = client.list_response_policy_zone_rules(zone, max_results, next_page_id)
    rules_list = raw_response['result']
    if not rules_list:
        return f'{INTEGRATION_NAME} - No rules associated to zone: {zone} were found', {}, {}
    fixed_keys_rule_list = []
    for rule in rules_list:
        fixed_keys_rule = {RESPONSE_TRANSLATION_DICTIONARY.get(key, string_to_context_key(key)): val for key, val in
                           rule.items()}
        fixed_keys_rule_list.append(fixed_keys_rule)
    zone_name = {zone.capitalize()}
    title = f'{INTEGRATION_NAME} - Zone: {zone_name} rule list.'
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.PolicyZoneRules(val.Name && val.Name ==== obj.Name)':
            {'Name': zone_name, 'Rules': fixed_keys_rule_list}}
    human_readable = tableToMarkdown(title, fixed_keys_rule_list, headerTransform=pascalToSpace)
    return human_readable, context, raw_response


def list_vaults_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Lists all vaults.
    """
    max_results = int(args.get('max_results', 0))
    raw_response = client.list_vaults(max_results)
    vaults = raw_response.get('vault')
    if vaults:
        title = f'{INTEGRATION_NAME} - Total of {len(vaults)} has been found.'
        context_entry = build_vaults_context(vaults)
        context = {f'{INTEGRATION_CONTEXT_NAME}.Vault(val.ID && val.ID === obj.ID)': context_entry}
        human_readable = tableToMarkdown(title, context_entry)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - No vaults found.', {}, {}


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():  # pragma: no cover
    params = demisto.params()
    base_url = f"{params.get('url', '').rstrip('/')}/wapi/v2.7/"
    verify = not params.get('insecure', False)
    proxy = params.get('proxy') == 'true'
    user = demisto.get(params, 'credentials.identifier')
    password = demisto.get(params, 'credentials.password')
    default_request_params = {
        '_return_as_object': '1'
    }
    client = Client(base_url, verify=verify, proxy=proxy, auth=(user, password), params=default_request_params)

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    # Switch case
    commands = {
        'test-module': test_module_command,
        f'{INTEGRATION_COMMAND_NAME}-get-ip': get_ip_command,
        f'{INTEGRATION_COMMAND_NAME}-search-related-objects-by-ip': search_related_objects_by_ip_command,
        f'{INTEGRATION_COMMAND_NAME}-list-response-policy-zone-rules': list_response_policy_zone_rules_command,
    }
    try:
        if command in commands:
            return_outputs(*commands[command](client, demisto.args()))
    # Log exceptions
    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} - [{e}]'
        return_error(err_msg, error=e)


if __name__ in ["__builtin__", "builtins", '__main__']:  # pragma: no cover
    main()
