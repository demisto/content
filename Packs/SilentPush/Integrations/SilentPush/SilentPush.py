import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Base Integration for Cortex XSOAR (aka Demisto)

This is an integration to interact with the SilentPush API and provide functionality within XSOAR.

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting
"""

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()


def mock_debug(message):
    """Print debug messages to the XSOAR logs"""
    print(f"DEBUG: {message}")


demisto.debug = mock_debug

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the SilentPush API

    This Client implements API calls and does not contain any XSOAR logic.
    It should only perform requests and return data.
    It inherits from BaseClient defined in CommonServerPython.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def __init__(self, base_url: str, api_key: str, verify: bool = True, proxy: bool = False):
        """
        Initializes the client with the necessary parameters.
        
        Args:
            base_url (str): The base URL for the SilentPush API.
            api_key (str): The API key for authentication.
            verify (bool): Flag to determine whether to verify SSL certificates (default True).
            proxy (bool): Flag to determine whether to use a proxy (default False).
        """
        self.base_url = base_url.rstrip('/') + '/api/v1/merge-api/'
        self.api_key = api_key
        self.verify = verify
        self.proxy = proxy
        self._headers = {
            'X-API-Key': api_key,
            'Content-Type': 'application/json'
        }
        demisto.debug(f'Initialized client with base URL: {self.base_url}')

    def _http_request(self, method: str, url_suffix: str, params: dict = None, data: dict = None) -> Any:
        """
        Handles the HTTP requests to the SilentPush API.
        
        This function builds the request URL, adds the necessary headers, and sends a request
        to the API. It returns the response in JSON format.
        
        Args:
            method (str): The HTTP method (GET, POST, etc.).
            url_suffix (str): The specific endpoint to be appended to the base URL.
            params (dict, optional): The URL parameters to be sent with the request.
            data (dict, optional): The data to be sent with the request.
        
        Returns:
            Any: The JSON response from the API.
        
        Raises:
            DemistoException: If there is an error in the API response.
        """
        full_url = f'{self.base_url}{url_suffix}'
        masked_headers = {k: v if k != 'X-API-Key' else '****' for k, v in self._headers.items()}
        demisto.debug(f'Headers: {masked_headers}')
        demisto.debug(f'Params: {params}')
        demisto.debug(f'Data: {data}')

        try:
            response = requests.request(
                method,
                full_url,
                headers=self._headers,
                verify=self.verify,
                params=params,
                json=data
            )
            demisto.debug(f'Response status code: {response.status_code}')
            demisto.debug(f'Response body: {response.text}')

            if response.status_code not in {200, 201}:
                raise DemistoException(f'Error in API call [{response.status_code}] - {response.text}')
            return response.json()
        except Exception as e:
            demisto.error(f'Error in API call: {str(e)}')
            raise

    def list_domain_information(self, domain: str) -> dict:
        """
        Fetches domain information such as WHOIS data, domain age, and risk scores.
        
        Args:
            domain (str): The domain to fetch information for.
        
        Returns:
            dict: A dictionary containing domain information fetched from the API.
        """
        demisto.debug(f'Fetching domain information for domain: {domain}')
        url_suffix = f'explore/domain/domaininfo/{domain}'
        return self._http_request('GET', url_suffix)


def test_module(client: Client) -> str:
    """
    Tests connectivity to the SilentPush API and checks the authentication status.
    
    This function will validate the API key and ensure that the client can successfully connect 
    to the API. It is called when running the 'Test' button in XSOAR.
    
    Args:
        client (Client): The client instance to use for the connection test.
    
    Returns:
        str: 'ok' if the connection is successful, otherwise returns an error message.
    """
    demisto.debug('Running test module...')
    try:
        client.list_domain_information('silentpush.com')
        demisto.debug('Test module completed successfully')
        return 'ok'
    except DemistoException as e:
        demisto.debug(f'Test module failed: {str(e)}')
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        raise e
    
    
''' COMMAND FUNCTIONS '''


def list_domain_information_command(client: Client, args: dict) -> CommandResults:
    """
    Command handler for fetching domain information.
    
    This function processes the command for 'silentpush-list-domain-information', retrieves the
    domain information using the client, and formats it for XSOAR output.
    
    Args:
        client (Client): The client instance to fetch the data.
        args (dict): The arguments passed to the command, including the domain.
    
    Returns:
        CommandResults: The command results containing readable output and the raw response.
    """
    domain = args.get('domain', 'silentpush.com')
    demisto.debug(f'Processing domain: {domain}')

    raw_response = client.list_domain_information(domain)
    demisto.debug(f'Response from API: {raw_response}')

    readable_output = tableToMarkdown('Domain Information', raw_response)

    return CommandResults(
        outputs_prefix='SilentPush.Domain',
        outputs_key_field='domain',
        outputs=raw_response,
        readable_output=readable_output,
        raw_response=raw_response
    )


''' MAIN FUNCTION '''


def main():
    """
    Main function to initialize the client and process the commands.
    
    This function parses the parameters, sets up the client, and routes the command to 
    the appropriate function.
    
    It handles the setup of authentication, base URL, SSL verification, and proxy configuration.
    Also, it routes the `test-module` and `silentpush-list-domain-information` commands to the
    corresponding functions.
    """
    try:
        params = demisto.params()
        api_key = params.get('credentials', {}).get('password')
        base_url = params.get('url', 'https://api.silentpush.com')
        verify_ssl = not params.get('insecure', False)
        proxy = params.get('proxy', False)

        demisto.debug(f'Base URL: {base_url}')
        demisto.debug('Initializing client...')

        client = Client(
            base_url=base_url,
            api_key=api_key,
            verify=verify_ssl,
            proxy=proxy
        )

        command = demisto.command()
        demisto.debug(f'Command being called is {command}')

        if command == 'test-module':
            result = test_module(client)
            return_results(result)
        
        elif command == 'silentpush-list-domain-information':
            return_results(list_domain_information_command(client, demisto.args()))
        
        else:
            raise DemistoException(f'Unsupported command: {command}')

    except Exception as e:
        demisto.error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
