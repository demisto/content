import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool,
                 proxy: bool, headers):
        super().__init__(base_url=f'{base_url}', headers=headers, verify=False, proxy=proxy, timeout=20)
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None
        
        self._login()

    def _login(self):
        """
        Logs in to the Exabeam API using the provided username and password.
        This function must be called before any other API calls.
        Note: the session is automatically closed in BaseClient's __del__
        """
        data = {"client_id": self.client_id, "client_secret": self.client_secret, "grant_type": "client_credentials"}

        response = self._http_request(
            "POST",
            full_url=f"{self._base_url}/auth/v1/token",
            data=data,
        )
        self.access_token = response.get('access_token')

    def search_request(self):
        """
        Performs basic get request to check if the server is reachable.
        """
        data = {
            "limit": 50,
            "fields": ["*"],
            "startTime": "2023-12-08T13:05:07.774Z",
            "endTime": "2024-02-06T13:05:07.774Z",
            "filter": "alert_subject:\"Inhibit System Recovery\" AND tier:\"Tier 1\" AND process_blocked:TRUE"

        }
        full_url = f"{self._base_url}/search/v2/events"
        self._http_request(
            "POST",
            full_url=full_url,
            data=json.dumps(data),
            headers = {"Authorization": f"Bearer {self.access_token}", "Content-Type": "application/json"}
        )
        
''' HELPER FUNCTIONS '''

def get_date(time: str):
    """
    Get the date from a given time string.

    Args:
        time (str): The time string to extract the date from.

    Returns:
        str: The date extracted from the time string formatted in ISO 8601 format (YYYY-MM-DD),
        or None if the time string is invalid.
    """
    date_time = arg_to_datetime(arg=time, arg_name="Start time", required=True)
    if date_time:
        date = date_time.strftime(DATE_FORMAT)
    return date

''' COMMAND FUNCTIONS '''

def search_command(client: Client, args: dict):
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    query = args.get('query')
    fields = argToList(args.get('fields'))
    group_by = argToList(args.get('group_by'))
    limit = arg_to_number(args.get('limit'))
    
    start_time = get_date(args.get("start_time", "7 days ago"))
    end_time = get_date(args.get("end_time", "today"))



def test_module(client: Client):    # pragma: no cover
    """test function

    Args:
        client: Client

    Returns:
        ok if successful
    """
    # client.test_module_request()
    # ADD COMMENT THAT IF WE ARRIVED HERE IT MEANS THAT THE LOGIN SUCCEEDED
    return 'ok'


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    credentials = params.get('credentials', {})
    client_id = credentials.get('identifier')
    client_secret = credentials.get('password')
    base_url = params.get('url', '')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    headers = {'Accept': 'application/json', 'Csrf-Token': 'nocheck'}

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url.rstrip('/'),
            verify=verify_certificate,
            client_id=client_id,
            client_secret=client_secret,
            proxy=proxy,
            headers=headers)

        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'exabeam-platform-event-search':
            return_results(search_command(client, args))
        


    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
