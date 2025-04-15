import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests
from datetime import datetime

# disable insecure warnings
import urllib3
urllib3.disable_warnings()


class Client:
    """
    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this implementation, no special attributes defined
    """

    def __init__(self, base_url, token_url, client_id, client_secret, verify=True, proxy=False):
        self.base_url = base_url
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.verify = verify
        self.proxy = proxy
        self.access_token = None

    def get_access_token(self):

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        payload = f'grant_type=client_credentials&client_id={self.client_id}&client_secret={self.client_secret}'

        response = requests.post(self.token_url, headers=headers, data=payload, verify=self.verify, proxies=self.proxy)
        response.raise_for_status()
        token_data = response.json()
        self.access_token = token_data.get('access_token')
        return self.access_token

    def make_api_request(self, endpoint, method='GET', headers=None, params=None, data=None):
        access_token = self.get_access_token()
        if headers is None:
            headers = {}
        headers['Authorization'] = f'Bearer {access_token}'

        url = f"{self.base_url}{endpoint}"
        response = requests.request(method, url, headers=headers, params=params,
                                    json=data, verify=self.verify, proxies=self.proxy)
        response.raise_for_status()
        data = {}
        data["status_code"] = response.status_code
        if response.content:
            data["content"] = response.json()
        return data


def test_module(client):
    try:
        client.get_access_token()
        return 'ok'
    except Exception as e:
        return f'Test failed: {str(e)}'


def get_ticket_data(client: Client):
    """Retrieves data of a given ticket
    Args: Client

    Returns:
        Raw Ticket Data
        """
    sys_id = demisto.args().get("sys_id")
    endpoint = f"/AuthorizationRequest/{sys_id}"
    try:
        response = client.make_api_request(endpoint, method='GET')
        return response
    except Exception as e:
        raise Exception(f"Could not find ticket with system id {sys_id}. Error: {str(e)}") from e


def get_ticket(client: Client):
    """ Get a Beyond Trust Ticket
    Args:
        Client

    Returns:
        table formated ticket data
    """

    sys_id = demisto.args().get("sys_id")
    endpoint = f"/AuthorizationRequest/{sys_id}"
    try:
        response = client.make_api_request(endpoint, method='GET')
        ticket_data = {
            'ServiceNow Ticket Number': response.get('content').get('serviceTicket').get('ticketId'),
            'ServiceNow Ticket ID': response.get('content').get('serviceTicket').get('systemId'),
            'User': response.get('content').get('requestInfo').get('user'),
            'Date Created': response.get('content').get('requestInfo').get('created'),
            'Status': response.get('content').get('accessDecision').get('status')
        }
        table = tableToMarkdown("Ticket Data", ticket_data, headers=[
                                "Date Created", "ServiceNow Ticket ID", "ServiceNow Ticket Number", "Status", "User"])

        results = CommandResults(
            readable_output=table,
            outputs_prefix='BeyondTrust.Ticket',
            outputs_key_field='ticketId',
            outputs=response,
            ignore_auto_extract=True)

        return results
    except Exception as e:
        raise Exception(f"Could not find ticket with system id {sys_id}. Error: {str(e)}") from e


def action_ticket(client, args):
    """ Action a BT ticket.

    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        action message

    """
    sys_id = str(args.get("sys_id"))
    record_id = str(args.get("record_id"))
    decision = str(args.get("decision"))
    duration = str(args.get("duration"))
    user = str(args.get("user"))
    current_time = datetime.now()
    time = current_time.strftime('%Y-%m-%d %H:%M:%S')

    ticket_data = get_ticket_data(client)

    ticketURL = ticket_data.get("content").get("serviceTicket").get("url")
    ticketID = ticket_data.get("content").get("serviceTicket").get("ticketId")

    status_map = {
        "Denied": "2001",
        "Approved": "2000",
        "Pending": "1000"
    }

    message_map = {
        "Approved": "Authorization Request Was Approved",
        "Denied": "Authorization Request Was Denied"
    }
    status = status_map[decision]
    message = message_map[decision]

    body = {
        "itsmRequestId": record_id,
        "ticketUrl": ticketURL,
        "ticketId": ticketID,
        "systemId": sys_id,
        "decision": decision,
        "decisionTime": time,
        "duration": duration,
        "decisionPerformedByUser": user,
        "status": status,
        "message": message
    }

    try:
        response = client.make_api_request('/AuthorizationRequest/notification', method='POST', data=body)
        if response.get("status_code") == 200:
            return CommandResults(readable_output=f"Ticket was {decision}")
    except Exception as e:
        raise Exception(f"Could not make POST API request. Error: {str(e)}") from e


def main():
    params = demisto.params()
    base_url = params.get('base_url')
    token_url = params.get('token_url')
    client_id = params.get('client_id')
    client_secret = params.get('client_secret')
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    client = Client(base_url, token_url, client_id, client_secret, verify, proxy)

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        if command == 'test-module':
            result = test_module(client)
            return_results(result)
        elif command == 'bt-authorize-ticket':
            return_results(action_ticket(client, demisto.args()))
        elif command == 'bt-get-ticket':
            return_results(get_ticket(client))
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')
    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
