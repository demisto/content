import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
from typing import cast, Any, Dict, Tuple, List, AnyStr, Optional
from xml.etree import ElementTree

import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
INTEGRATION_NAME: str = 'Case Management Integration'
# lowercase with `-` dividers
INTEGRATION_NAME_COMMAND: str = 'case-management'
# No dividers
INTEGRATION_CONTEXT_NAME: str = 'CaseManagement'


class Client(BaseClient):
    def __init__(self, base_url, limit=50, *args, **kwargs):
        self._limit = limit
        super().__init__(base_url, *args, **kwargs)

    def test_module(self) -> Dict:
        """Performs basic get request to get item samples

        Returns:
            True if request succeeded
        """
        return self._http_request('GET', 'version')

    def list_tickets(self, limit: Optional[AnyStr]) -> dict:
        """Gets all credentials from API.

        Returns:
            credentials
        """
        suffix = 'ticket'
        params = dict()
        if limit:
            params['limit'] = limit
        elif self._limit:
            params['limit'] = limit
        return self._http_request('GET', suffix, params=params)

    def close_ticket(self, ticket_id: AnyStr) -> dict:
        """Gets events from given IDS

        Args:
            ticket_id: account to lock

        Returns:
            locked account
        """
        # The service endpoint to request from
        suffix: str = 'ticket/close'
        # Dictionary of params for the request
        params = {
            'ticketId': ticket_id
        }
        return self._http_request('POST', suffix, params=params)

    def reopen_ticket(self, ticket_id: AnyStr) -> dict:
        """Gets events from given IDS

        Args:
            ticket_id: account to unlock

        Returns:
            response json
        """
        # The service endpoint to request from
        suffix = 'ticket/open'
        # Dictionary of params for the request
        params = {
            'ticketId': ticket_id
        }
        # Send a request using our http_request wrapper
        return self._http_request('POST', suffix, params=params)

    def reset_ticket(self, ticket_id: str) -> dict:
        """Gets events from given IDS

        Args:
            ticket_id: ticket to reset

        Returns:
            response json
        """
        # The service endpoint to request from
        suffix = 'ticket/reset'
        # Dictionary of params for the request
        params = {
            'ticketId': ticket_id
        }
        # Send a request using our http_request wrapper
        return self._http_request('POST', suffix, params=params)

    def unlock_vault(self, vault_id) -> Dict:
        """Unlocks vault

        Args:
            vault_id: vault to lock

        Returns:
            locked state
        """
        suffix = 'vault/unlock'
        params = {'vaultId': vault_id}
        return self._http_request('POST', suffix, params=params)

    def lock_vault(self, vault_id: AnyStr) -> Dict:
        """Locks vault

        Args:
            vault_id: vault to lock

        Returns:
            locked state
        """
        suffix = 'vault/lock'
        params = {'vaultId': vault_id}
        return self._http_request('POST', suffix, params=params)


''' HELPER FUNCTIONS '''

''' COMMANDS '''


def test_module(client: Client) -> str:
    """
    Performs basic get request to get item samples
    """
    raw_response = client.test_module()
    if raw_response:
        return 'ok'


def get_ticket_command(client: Client, args: dict) -> Tuple[str, dict, dict]:
    """
    Gets details about a raw_response using IDs or some other filters
    """
    # Initialize main vars
    context: Dict = dict()
    # Get arguments from user
    ticket_to_get = args.get('ticket_id')
    # Make request and get raw response
    raw_response = client.close_ticket(ticket_to_get)
    # Parse response into context & content entries
    ticket_obj = raw_response.get('ticket', [{}])[0]
    ticket_id = ticket_obj.get('ticketId')
    if ticket_id == ticket_to_get:
        title = f'{INTEGRATION_NAME} - Account `{ticket_to_get}` has been locked.'
        context_entry = {
            'IsLocked': True,
            'ID': ticket_to_get
        }
        context[f'{INTEGRATION_CONTEXT_NAME}.Account(val.ID && val.ID === obj.ID)'] = context_entry
        # Creating human readable for War room
        human_readable: str = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return_error(f'{INTEGRATION_NAME} - Could not lock account `{ticket_to_get}`')


def create_ticket(client: Client, args: dict) -> Tuple[str, dict, dict]:
    """
    Gets details about a raw_response using IDs or some other filters
    """
    # Initialize main vars
    context: Dict = dict()
    # Get arguments from user
    account_to_unlock = args.get('account_id', '')
    # Make request and get raw response
    unlocked_account: str = client.reopen_ticket(account_to_unlock)
    # Parse response into context & content entries
    if unlocked_account == account_to_unlock:
        title: str = f'{INTEGRATION_NAME} - Account `{unlocked_account}` has been unlocked.'
        context_entry = {
            'IsLocked': False,
            'ID': account_to_unlock
        }

        context[f'{INTEGRATION_CONTEXT_NAME}.Account(val.ID && val.ID === obj.ID)'] = context_entry
        # Creating human readable for War room
        human_readable: str = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return_error(f'{INTEGRATION_NAME} - Could not unlock account `{account_to_unlock}`')


def assign_ticket(client: Client, args: dict) -> Tuple[str, dict, dict]:
    vault_to_lock: str = demisto.args().get('vault', '')
    raw_response = client.lock_vault(vault_to_lock)
    if 'is_locked' in raw_response and raw_response['is_locked'] is True:
        title: str = f'{INTEGRATION_NAME} - Vault {vault_to_lock} has been locked'
        context_entry = {
            'ID': vault_to_lock,
            'IsLocked': True
        }
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Vault(val.ID && val.ID === obj.ID)': context_entry
        }
        human_readable = tableToMarkdown(title, context_entry)
        return human_readable, context, raw_response
    else:
        return_error(f'{INTEGRATION_NAME} - Could not lock vault ID: {vault_to_lock}')


def list_users(client: Client, args: dict) -> Tuple[str, dict, dict]:
    vault_to_lock: str = demisto.args().get('vault', '')
    raw_response = client.unlock_vault(vault_to_lock)
    if 'is_locked' in raw_response and raw_response['is_locked'] is True:
        title: str = f'{INTEGRATION_NAME} - Vault {vault_to_lock} has been unlocked'
        context_entry = {
            'ID': vault_to_lock,
            'IsLocked': True
        }
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Vault(val.ID && val.ID === obj.ID)': context_entry
        }
        human_readable = tableToMarkdown(title, context_entry)
        return human_readable, context, raw_response
    else:
        return_error(f'{INTEGRATION_NAME} - Could not lock vault ID: {vault_to_lock}')


def close_ticket(client: Client, args: dict) -> Tuple[str, dict, dict]:
    """
    Gets details about a raw_response using IDs or some other filters
    """
    # Initialize main vars
    context = dict()
    # Get arguments from user
    ticket_to_lock = args.get('ticket_id', '')
    # Make request and get raw response
    raw_response = client.reset_ticket(ticket_to_lock)
    # Parse response into context & content entries
    ticket_obj = raw_response.get('ticket', [{}])[0]
    ticket_id = ticket_obj.get('ticketId')
    closed_status = ticket_obj.get('isClosed')
    if ticket_id == ticket_to_lock and closed_status:
        title: str = f'{INTEGRATION_NAME} - Ticket `{ticket_id}` has been closed.'
        context_entry = {
            'IsClosed': True,
            'ID': ticket_to_lock
        }

        context[f'{INTEGRATION_CONTEXT_NAME}.Ticket(val.ID && val.ID === obj.ID)'] = context_entry
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return_error(f'{INTEGRATION_NAME} - Could not reset ticket `{ticket_to_lock}`')


def list_tickets_command(client: Client, args: dict) -> Tuple[str, dict, dict]:
    limit: Optional[str] = demisto.args().get('limit')
    raw_response: Dict = client.list_tickets(limit)
    tickets: List[Dict] = raw_response.get('tickets', [])
    if tickets:
        title: str = f'{INTEGRATION_NAME} - Tickets list'
        context_entry = [
            {
                'ID': ticket.get('id'),
                'Name': ticket.get('name'),
                'Category': ticket.get('category'),
                'Assignee': [
                    {
                        'ID': assignee.get('id'),
                        'Name': assignee.get('name')
                    } for assignee in ticket.get('assignee', [])
                ]
            } for ticket in tickets
        ]
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Ticket(val.ID && val.Name ==== obj.ID)': context_entry
        }
        human_readable = tableToMarkdown(title, context_entry)
        return human_readable, context, raw_response
    else:
        return_warning(f'{INTEGRATION_NAME} - Could not find any tickets.')


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    server: str = demisto.params().get('url')
    use_ssl: bool = not demisto.params().get('insecure', False)
    proxy: Optional[bool] = demisto.params().get('proxy')
    client: Client = Client(server, use_ssl=use_ssl, proxy=proxy)
    command: str = demisto.command()
    demisto.info(f'Command being called is {command}')
    commands: Dict = {
        'test-module': test_module,
        f'{INTEGRATION_NAME_COMMAND}-list-tickets': list_tickets_command,
        f'{INTEGRATION_NAME_COMMAND}-get-ticket': get_ticket_command,
        f'{INTEGRATION_NAME_COMMAND}-create-ticket': create_ticket,
        f'{INTEGRATION_NAME_COMMAND}-close-ticket': close_ticket,
        f'{INTEGRATION_NAME_COMMAND}-assign-ticket': assign_ticket,
        f'{INTEGRATION_NAME_COMMAND}-list-users': list_users
    }
    try:
        if command in commands:
            return_outputs(*commands[command](client, demisto.args()))
    # Log exceptions
    except Exception as e:
        err_msg = f'Error in AuthenticationExample Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ == '__builtin__':
    main()
