from CommonServerPython import *

''' IMPORTS '''
from typing import Dict, Tuple, List, AnyStr, Optional, Union

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
INTEGRATION_NAME: str = 'Case Management Integration'
# lowercase with `-` dividers
INTEGRATION_NAME_COMMAND: str = 'case-management'
# No dividers
INTEGRATION_CONTEXT_NAME: str = 'CaseManagement'


def build_raw_tickets_to_context(tickets: Union[dict, list]):
    if isinstance(tickets, list):
        return [build_raw_tickets_to_context(ticket) for ticket in tickets]
    return {
        'ID': tickets.get('id'),
        'Name': tickets.get('name'),
        'Category': tickets.get('category'),
        'Description': tickets.get('description'),
        'Timestamp': tickets.get('timestamp'),
        'IsOpen': tickets.get('isOpen'),
        'Assignee': [
            {
                'ID': assignee.get('id'),
                'Name': assignee.get('name')
            } for assignee in tickets.get('assignee', [])
        ]
    }


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

    def list_tickets(self, ticket_id: Optional[AnyStr] = None, limit: Optional[AnyStr] = None) -> dict:
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
        if ticket_id:
            params['id'] = ticket_id
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
            'id': ticket_id
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
            'id': ticket_id
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
            'id': ticket_id
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

    def create_ticket(
            self, name: str = None, category: str = None, description: str = None,
            assignee: list = None, timestamp: str = None, is_open: bool = None
    ):
        suffix = 'ticket'
        params = assign_params(
            name=name,
            category=category,
            description=description,
            assignee=assignee,
            timestamp=timestamp if timestamp else datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ'),
            isOpen=is_open
        )
        return self._http_request('POST', suffix, params=params)


''' HELPER FUNCTIONS '''

''' COMMANDS '''


@logger
def test_module_command(client: Client, *_) -> str:
    """Performs basic get request to get item samples.
    """
    raw_response = client.test_module()
    if raw_response:
        return 'ok'
    raise DemistoException(f'{INTEGRATION_NAME} - Unexpected response from service: {raw_response}')


@logger
def get_ticket_command(client: Client, args: dict) -> Tuple[str, dict, dict]:
    """Gets details about a raw_response using IDs or some other filters.

    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    # Initialize main vars
    context = dict()
    # Get arguments from user
    ticket_to_get = args.get('ticket_id')
    # Make request and get raw response
    raw_response = client.list_tickets(ticket_id=ticket_to_get)
    # Parse response into context & content entries
    tickets = raw_response.get('ticket')
    if tickets:
        title = f'{INTEGRATION_NAME} - Ticket ID: `{ticket_to_get}`.'
        context_entry = build_raw_tickets_to_context(tickets)
        context[f'{INTEGRATION_CONTEXT_NAME}.Ticket(val.ID && val.ID === obj.ID)'] = context_entry
        # Creating human readable for War room
        human_readable = tableToMarkdown(
            title, context_entry, headers=['ID', 'Name', 'Timestamp', 'Description', 'Assignee']
        )
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find ticket ID: `{ticket_to_get}`', {}, {}


@logger
def create_ticket_command(client: Client, args: dict) -> Tuple[str, dict, dict]:
    """Gets details about a raw_response using IDs or some other filters.

    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    # Initialize main vars
    context = dict()
    # Get arguments from user
    name = args.get('name')
    description = args.get('description')
    assignee = argToList(args.get('assignee'))
    category = args.get('category')
    timestamp = args.get('timestamp')
    # Make request and get raw response
    raw_response = client.create_ticket(
        name=name, category=category, description=description, assignee=assignee, timestamp=timestamp
    )
    tickets = raw_response.get('ticket')
    # Parse response into context & content entries
    if tickets:
        title: str = f'{INTEGRATION_NAME} - Ticket has been successfully created.'
        context_entry = build_raw_tickets_to_context(tickets)

        context[f'{INTEGRATION_CONTEXT_NAME}.Ticket(val.ID && val.ID === obj.ID)'] = context_entry
        # Creating human readable for War room
        human_readable = tableToMarkdown(
            title, context_entry, headers=['ID', 'Name', 'Timestamp', 'Description', 'Assignee']
        )
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        raise DemistoException(f'{INTEGRATION_NAME} - Could not create new ticket!\n Response: {raw_response}')


@logger
def assign_ticket_command(client: Client, args: dict) -> Tuple[str, dict, dict]:
    """

    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs

    """
    vault_to_lock = args.get('vault', '')
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
        human_readable = tableToMarkdown(
            title, context_entry, headers=['ID', 'Name', 'Timestamp', 'Description', 'Assignee']
        )
        return human_readable, context, raw_response
    else:
        return_error(f'{INTEGRATION_NAME} - Could not lock vault ID: {vault_to_lock}')


@logger
def list_users_command(client: Client, args: dict) -> Tuple[str, dict, dict]:
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


@logger
def close_ticket_command(client: Client, args: dict) -> Tuple[str, dict, dict]:
    """
    Gets details about a raw_response using IDs or some other filters
    """
    # Initialize main vars
    context = dict()
    # Get arguments from user
    ticket_to_lock = args.get('ticket_id', '')
    # Make request and get raw response
    raw_response = client.close_ticket(ticket_to_lock)
    # Parse response into context & content entries
    tickets = raw_response.get('ticket')
    if tickets and tickets[0].get('id') == ticket_to_lock and not tickets[0].get('isOpen'):
        ticket_obj = tickets[0]
        ticket_id = ticket_obj.get('id')
        title: str = f'{INTEGRATION_NAME} - Ticket `{ticket_id}` has been closed.'
        context_entry = build_raw_tickets_to_context(tickets[0])
        context[f'{INTEGRATION_CONTEXT_NAME}.Ticket(val.ID && val.ID === obj.ID)'] = context_entry
        # Creating human readable for War room
        human_readable = tableToMarkdown(
            title, context_entry, headers=['ID', 'Name', 'Timestamp', 'Description', 'Assignee']
        )
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        raise DemistoException(f'{INTEGRATION_NAME} - Could not close'
                               f' ticket `{ticket_to_lock}`.\nResponse: {raw_response}')


@logger
def list_tickets_command(client: Client, args: dict) -> Tuple[str, dict, dict]:
    limit = args.get('limit')
    raw_response = client.list_tickets(limit=limit)
    tickets = raw_response.get('ticket')
    if tickets:
        title = f'{INTEGRATION_NAME} - Tickets list:'
        context_entry = build_raw_tickets_to_context(tickets)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Ticket(val.ID && val.Name ==== obj.ID)': context_entry
        }
        human_readable = tableToMarkdown(title, context_entry)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any tickets.', {}, raw_response


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    params = demisto.params()
    server = params.get('url')
    use_ssl = not params.get('insecure', False)
    proxy = params.get('proxy') == 'true'
    client = Client(server, use_ssl=use_ssl, proxy=proxy)
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    commands = {
        'test-module': test_module_command,
        f'{INTEGRATION_NAME_COMMAND}-list-tickets': list_tickets_command,
        f'{INTEGRATION_NAME_COMMAND}-get-ticket': get_ticket_command,
        f'{INTEGRATION_NAME_COMMAND}-create-ticket': create_ticket_command,
        f'{INTEGRATION_NAME_COMMAND}-close-ticket': close_ticket_command,
        f'{INTEGRATION_NAME_COMMAND}-assign-ticket': assign_ticket_command,
        f'{INTEGRATION_NAME_COMMAND}-list-users': list_users_command
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
