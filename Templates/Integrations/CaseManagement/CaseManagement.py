from CommonServerPython import *

''' IMPORTS '''
from typing import Dict, Tuple, List, AnyStr, Optional, Union
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
INTEGRATION_NAME = 'Case Management Integration'
INTEGRATION_NAME_COMMAND = 'case-management'
INTEGRATION_CONTEXT_NAME = 'CaseManagement'

TIME_FORMAT = '%Y-%m-%dT%H:%M:%S'
DEFAULT_FETCH_TIME = '3 days'

"""Helper function"""


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


def build_raw_users_to_context(users: Union[list, dict]):
    if isinstance(users, list):
        return [build_raw_users_to_context(user) for user in users]
    return {
        'ID': users.get('id'),
        'Username': users.get('username')
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

    def list_tickets(self, ticket_id: Optional[AnyStr] = None,
                     limit: Optional[AnyStr] = None, from_time: Optional[datetime] = None
                     ) -> dict:
        """Gets all credentials from API.

        Returns:
            credentials
        """
        suffix = 'ticket'
        params = dict()
        if limit:
            params['limit'] = limit
        elif self._limit:
            params['limit'] = limit  # type: ignore # [assignment]
        params.update(
            assign_params(
                id=ticket_id,
                fromTime=from_time.strftime(TIME_FORMAT) if from_time else None
            ))
        return self._http_request('GET', suffix, params=params)

    def close_ticket(self, ticket_id: AnyStr) -> dict:
        """Gets events from given IDS

        Args:
            ticket_id:  to lock

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

    def assign_ticket(self, ticket_id: str, users: List[str]) -> dict:
        """Locks vault

        Args:
            ticket_id: vault to lock
            users: A list of users' id

        Returns:
            Response JSON
        """
        suffix = 'ticket/assign'
        params = {'id': ticket_id}
        body = {'users': users}
        return self._http_request('POST', suffix, params=params, json_data=body)

    def create_ticket(
            self, name: str = None, category: str = None, description: str = None,
            assignee: list = None, timestamp: str = None, is_open: bool = None
    ):
        suffix = 'ticket'
        body = {'ticket': assign_params(
            name=name,
            category=category,
            description=description,
            assignee=assignee,
            timestamp=timestamp if timestamp else datetime.now().strftime(TIME_FORMAT),
            isOpen=is_open
        )}
        return self._http_request('POST', suffix, json_data=body)

    def list_users(self):
        suffix = 'user'
        return self._http_request('GET', suffix)


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
    # Get arguments from user
    ticket_to_get = args.get('ticket_id')
    # Make request and get raw response
    raw_response = client.list_tickets(ticket_id=ticket_to_get)
    # Parse response into context & content entries
    tickets = raw_response.get('ticket')
    if tickets:
        context = dict()
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
def assign_users_command(client: Client, args: dict) -> Tuple[str, dict, dict]:
    """

    Args:
        client: Client object
        args: Usually demisto.args()

    Returns:
        Outputs

    """
    ticket_id = args.get('ticket_id')
    users = argToList(args.get('users'))
    raw_response = client.assign_ticket(ticket_id, users)  # type: ignore # [assignment]
    tickets = raw_response.get('ticket')
    if tickets:
        title = f'{INTEGRATION_NAME} - Users has been assigned to {ticket_id}.'
        context_entry = build_raw_tickets_to_context(tickets)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Ticket(val.ID && val.ID === obj.ID)': context_entry
        }
        human_readable = tableToMarkdown(
            title, context_entry, headers=['ID', 'Name', 'Timestamp', 'Description', 'Assignee']
        )
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not assign users to ticket ID: {ticket_id}', {}, raw_response


@logger
def list_users_command(client: Client, *_) -> Tuple[str, dict, dict]:
    raw_response = client.list_users()
    if raw_response:
        title = f'{INTEGRATION_NAME} - Users list:'
        context_entry = build_raw_users_to_context(raw_response.get('user', []))
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.User(val.ID && val.ID === obj.ID)': context_entry
        }
        human_readable = tableToMarkdown(title, context_entry, headers=['Username', 'ID'])
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any users.', {}, {}


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


@logger
def fetch_incidents_command(client: Client, last_fetch: dict, fetch_time: str) -> Tuple[list, dict]:
    if last_fetch:
        last_fetch_datetime = datetime.strptime(last_fetch.get('timestamp', ''), TIME_FORMAT)
    else:
        last_fetch_datetime, _ = parse_date_range(fetch_time if fetch_time else DEFAULT_FETCH_TIME)
    raw_response = client.list_tickets(from_time=last_fetch_datetime)
    tickets = raw_response.get('ticket')
    incidents = list()
    if tickets:
        for ticket in tickets:
            incidents.append({
                'name': f'{INTEGRATION_NAME} - ticket number: {ticket.get("id")}',
                'rawJSON': json.dumps(ticket)
            })
            new_time = datetime.strptime(ticket.get('timestamp'), TIME_FORMAT)
            if last_fetch_datetime < new_time:
                last_fetch_datetime = new_time
    return incidents, {'timestamp': last_fetch_datetime.strftime(TIME_FORMAT)}


def main():
    params = demisto.params()
    server = params.get('url')
    use_ssl = not params.get('insecure', False)
    use_proxy = params.get('proxy')
    client = Client(server, use_ssl=use_ssl, proxy=use_proxy)
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    commands = {
        'test-module': test_module_command,
        f'{INTEGRATION_NAME_COMMAND}-list-tickets': list_tickets_command,
        f'{INTEGRATION_NAME_COMMAND}-get-ticket': get_ticket_command,
        f'{INTEGRATION_NAME_COMMAND}-create-ticket': create_ticket_command,
        f'{INTEGRATION_NAME_COMMAND}-close-ticket': close_ticket_command,
        f'{INTEGRATION_NAME_COMMAND}-assign-user': assign_users_command,
        f'{INTEGRATION_NAME_COMMAND}-list-users': list_users_command,
        'fetch-incidents': fetch_incidents_command,
    }
    try:
        if command == 'fetch-incidents':
            incidents, last_run = fetch_incidents_command(client, demisto.getLastRun(), params.get('fetch_time'))
            demisto.incidents(incidents)
            demisto.setLastRun(last_run)
        if command in commands:
            return_outputs(*commands[command](client, demisto.args()))
    # Log exceptions
    except Exception as e:
        err_msg = f'Error in AuthenticationExample Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ == 'builtins':
    main()
