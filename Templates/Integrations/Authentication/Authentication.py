import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
from typing import Any, Dict, Tuple, List, AnyStr, Union
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''


class Client(BaseHTTPClient):
    def test_module_request(self) -> Dict:
        """Performs basic GET request to check if the API is reachable and authentication is successful.

        Returns:
            Response JSON
        """
        return self._http_request('GET', 'version')

    def list_credentials_request(self) -> Dict:
        """Uses to fetch incidents into Demisto
        Documentation:https://github.com/demisto/content/tree/master/docs/fetching_incidents
        Returns:
            Response JSON
        """
        suffix = 'credentials'
        return self._http_request('GET', suffix)

    def lock_account_request(self, account_id: AnyStr) -> Dict:
        """Locks an account by the account ID.

        Args:
            account_id: Account ID to lock.

        Returns:
            Response JSON
        """
        # The service endpoint to request from
        suffix = 'account/lock'
        # Dictionary of params for the request
        params = {'account': account_id}
        return self._http_request('POST', suffix, params=params)

    def unlock_account_request(self, account_id: AnyStr) -> Dict:
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

    def reset_account_request(self, account_id: str):
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

    def unlock_vault_request(self, vault_to_lock: AnyStr) -> Dict:
        """Unlocks a vault by vault ID.

        Args:
            vault_to_lock: Vault ID to lock

        Returns:
            Response JSON
        """
        suffix = 'vault/unlock'
        params = {'vault_id': vault_to_lock}
        return self._http_request('POST', suffix, params=params)

    def lock_vault_request(self, vault_to_lock: AnyStr) -> Dict:
        """Locks vault by vault ID.

        Args:
            vault_to_lock: Vault ID to lock.

        Returns:
            Response JSON
        """
        suffix = 'vault/lock'
        params = {'vault_id': vault_to_lock}
        return self._http_request('POST', suffix, params=params)


''' HELPER FUNCTIONS '''


def build_credentials_context(credentials: Union[Dict, List]) -> Union[Dict, List]:
    """Formats the API response to Demisto context.

    Args:
        credentials: The raw response from the API call. Can be a List or Dict.

    Returns:
        The formatted Dict or List.

    Examples:
        >>> build_credentials_context()
    """

    def build_dict(credential: Dict) -> Dict:
        """Builds a Dict formatted for Demisto.

        Args:
            credential: A single event from the API call.

        Returns:
            A Dict formatted for Demisto context.
        """
        return assign_params(
            User=credential.get('username'),
            Name=credential.get('title'),
            IsLocked=credential.get('isLocked')
        )

    if isinstance(credentials, list):
        return [build_dict(credential) for credential in credentials]
    return build_dict(credentials)


def build_credentials_fetch(credentials: Union[Dict, List]) -> Union[Dict, List]:
    """Formats the API response to Demisto context.

    Args:
        credentials: The raw response from the API call. Can be a List or Dict.

    Returns:
        The formatted Dict or List.

    Examples:
        >>> build_credentials_context()
    """

    def build_dict(credential: Dict) -> Dict:
        """Builds a Dict formatted for Demisto.

        Args:
            credential: A single event from the API call.

        Returns:
            A Dict formatted for Demisto context.
        """
        return {
            'user': credential.get('username'),
            'name': credential.get('name'),
            'password': credential.get('password'),
        }

    if isinstance(credentials, list):
        return [build_dict(credential) for credential in credentials]
    return build_dict(credentials)


def remove_password_key(raw: Any) -> Any:
    """Filtering out `password` key from dict, if not dict returns self.

    Args:
        raw: Any input that may contain dict with `password` key

    Returns:
        raw, if dict - will return without `password` key

    Examples:
        >>> remove_password_key({'password': 'oyvey'})
        {}

        >>> remove_password_key([{'password': 'oyvey'}])
        [{}]

        >>> remove_password_key('oyvey')
        'oyvey'
    """
    if isinstance(raw, dict):
        if 'password' in raw:
            raw.pop('password')
        return {key: remove_password_key(value) for key, value in raw.items()}
    if isinstance(raw, list):
        return [remove_password_key(value) for value in raw]
    return raw


''' COMMANDS '''


def test_module(client: Client, *_) -> Tuple[str, Dict, Dict]:
    """Performs a basic GET request to check if the API is reachable and authentication is successful.
    """
    results = client.test_module_request()
    if 'version' in results:
        return 'ok', {}, {}
    raise DemistoException('Test module failed, {}'.format(results))


def fetch_credentials(client: Client, *_):
    """Uses to fetch credentials into Demisto
    Documentation: https://github.com/demisto/content/tree/master/docs/fetching_credentials
    """
    # Get credentials from api
    raw_response = client.list_credentials_request()
    raw_credentials = raw_response.get('credentials', [])
    # Creates credentials entry
    credentials = build_credentials_fetch(raw_credentials)
    demisto.credentials(credentials)


def lock_account(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Locks an account by account ID.
    """
    # Get arguments from user
    account_id = args.get('account_id', '')
    # Make request and get raw response
    raw_response = client.lock_account_request(account_id)
    # Parse response into context & content entries
    if raw_response.get('locked_account') == account_id:
        title: str = f'{client.integration_name} - Account `{account_id}` has been locked.'
        context_entry = {
            'IsLocked': True,
            'ID': account_id
        }
        context = {f'{client.integration_context_name}.Account(val.ID && val.ID === obj.ID)': context_entry}
        # Creating human readable for War room
        human_readable: str = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        raise DemistoException(f'{client.integration_name} - Could not lock account `{account_id}`')


def unlock_account(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Unlocks an account by account ID.
    """
    # Get arguments from user
    account_id = args.get('account_id', '')
    # Make request and get raw response
    raw_response = client.unlock_account_request(account_id)
    unlocked_account = raw_response.get('account')
    # Parse response into context & content entries
    if unlocked_account == account_id:
        title = f'{client.integration_name} - Account `{unlocked_account}` has been unlocked.'
        context_entry = {
            'IsLocked': False,
            'ID': account_id
        }
        context = {f'{client.integration_context_name}.Account(val.ID && val.ID === obj.ID)': context_entry}
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry)
        # Return data
        return human_readable, context, raw_response
    else:
        raise DemistoException(f'{client.integration_name} - Could not unlock account `{account_id}`')


def lock_vault(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Locks a vault by vault ID.
    """
    vault_to_lock = args.get('vault', '')
    raw_response = client.lock_vault_request(vault_to_lock)
    if raw_response.get('is_locked') is True:
        title = f'{client.integration_name} - Vault {vault_to_lock} has been locked'
        context_entry = {
            'ID': vault_to_lock,
            'IsLocked': True
        }
        context = {f'{client.integration_context_name}.Vault(val.ID && val.ID === obj.ID)': context_entry}
        human_readable = tableToMarkdown(title, context_entry)
        return human_readable, context, raw_response
    else:
        raise DemistoException(f'{client.integration_name} - Could not lock vault ID: {vault_to_lock}')


def unlock_vault(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Unlocks a vault by vault ID.
    """
    vault_to_lock = args.get('vault', '')
    raw_response = client.unlock_vault_request(vault_to_lock)
    if raw_response.get('is_locked') is False:
        title = f'{client.integration_name} - Vault {vault_to_lock} has been unlocked'
        context_entry = {
            'ID': vault_to_lock,
            'IsLocked': True
        }
        context = {f'{client.integration_context_name}.Vault(val.ID && val.ID === obj.ID)': context_entry}
        human_readable = tableToMarkdown(title, context_entry)
        return human_readable, context, raw_response
    else:
        raise DemistoException(f'{client.integration_name} - Could not lock vault ID: {vault_to_lock}')


def reset_account_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Resets an account by account ID
    """
    # Get arguments from user
    account_id = args.get('account_id', '')
    # Make request and get raw response
    raw_response = client.reset_account_request(account_id)
    # Parse response into context & content entries
    if raw_response.get('account') == account_id:
        title = f'{client.integration_name} - Account `{account_id}` has been returned to default.'
        context_entry = {
            'IsLocked': False,
            'ID': account_id
        }
        context = {f'{client.integration_context_name}.Account(val.ID && val.ID === obj.ID)': context_entry}
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        raise DemistoException(f'{client.integration_name} - Could not reset account `{account_id}`')


def list_credentials(client: Client, *_) -> Tuple[str, Dict, Dict]:
    """Returns credentials to user without passwords.
    """
    raw_response = client.list_credentials_request()
    # Filtering out passwords for list_credentials, so it won't get back to the user
    raw_response = assign_params(keys_to_ignore=['password'], **raw_response)
    credentials: List[Dict] = raw_response.get('credentials', [])
    if credentials:
        title = f'{client.integration_name} - Credentials list.'
        context_entry = build_credentials_context(credentials)
        context = {f'{client.integration_context_name}.Credential(val.ID && val.ID ==== obj.ID)': context_entry}
        human_readable = tableToMarkdown(title, context_entry)
        return human_readable, context, raw_response
    else:
        return f'{client.integration_name} - Could not find any credentials.', {}, {}


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    integration_name = 'Authentication Integration'
    # lowercase with `-` dividers
    integration_command_name = 'authentication'
    # No dividers
    integration_context_name = 'AuthenticationIntegration'
    params = demisto.params()
    server = params.get('url')
    base_suffix = '/api/v1'
    verify = not params.get('insecure', False)
    proxy = params.get('proxy') == 'true'
    client = Client(integration_name, integration_command_name, integration_context_name, server,
                    base_suffix, verify=verify, proxy=proxy)
    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    # Switch case
    commands = {
        'test-module': test_module,
        'fetch-credentials': fetch_credentials,
        f'{integration_command_name}-list-accounts': list_credentials,
        f'{integration_command_name}-lock-account': lock_account,
        f'{integration_command_name}-unlock-account': unlock_account,
        f'{integration_command_name}-reset-account': reset_account_command,
        f'{integration_command_name}-lock-vault': lock_vault,
        f'{integration_command_name}-unlock-vault': unlock_vault
    }
    try:
        if command == 'fetch-credentials':
            # Fetch credentials is handled, no return statement.
            commands[command](client, demisto.args())
        if command in commands:
            return_outputs(*commands[command](client, demisto.args()))
    # Log exceptions
    except Exception as e:
        err_msg = f'Error in AuthenticationExample Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ == '__builtin__':
    main()
