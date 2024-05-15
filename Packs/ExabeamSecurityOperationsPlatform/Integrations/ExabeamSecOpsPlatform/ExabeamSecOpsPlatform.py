import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

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

    def test_module_request(self):
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

        res = self._http_request(
            "POST",
            full_url=f"{self._base_url}/search/v2/events",
            data=json.dumps(data),
            headers = {"Authorization": f"Bearer {self.access_token}", "Content-Type": "application/json"}
        )
        print(res)
        
''' HELPER FUNCTIONS '''

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

''' COMMAND FUNCTIONS '''



def test_module(client: Client):    # pragma: no cover
    """test function

    Args:
        client: Client

    Returns:
        ok if successful
    """
    client.test_module_request()
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
        


    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
