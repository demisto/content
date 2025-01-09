import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import requests
from typing import Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


def mock_debug(message):
    print(f"DEBUG: {message}")


demisto.debug = mock_debug


class Client:
    def __init__(self, base_url: str, api_key: str, verify: bool = True, proxy: bool = False):

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
        """Generic HTTP request handler"""
        full_url = f'{self.base_url}{url_suffix}'
        demisto.debug(f'Making request to: {full_url}')
        demisto.debug(f'Headers: {self._headers}')
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
                raise Exception(f'Error in API call: {response.status_code} - {response.text}')
            return response.json()
        except Exception as e:
            demisto.error(f'Error in API call: {str(e)}')
            raise Exception(f'Error in API call: {str(e)}')

    def list_domain_information(self, domain: str) -> dict:
        """Get domain information with risk score and whois data"""
        # Updated to match the API structure from documentation
        url_suffix = f'explore/domain/domaininfo/{domain}'
        return self._http_request('GET', url_suffix)


def list_domain_information_command(client: Client, args: dict) -> CommandResults:
    """Command handler for domain information listing"""

    domain = args.get('domain', 'silentpush.com')

    demisto.debug(f'Processing domain: {domain}')

    raw_response = client.list_domain_information(domain)

    readable_output = tableToMarkdown('Domain Information', raw_response)

    return CommandResults(
        outputs_prefix='SilentPush.Domain',
        outputs_key_field='domain',
        outputs=raw_response,
        readable_output=readable_output,
        raw_response=raw_response
    )


def main():
    """Main function for handling the command execution"""
    try:

        api_key = 'SPJZ5-8MWWDQ-ZAEBWWTGB_ZQPSN6QEI-OOM3ZVO2INPORMNPBIYR9A'
        base_url = 'https://api.silentpush.com'

        demisto.debug(f'Base URL: {base_url}')
        demisto.debug('Initializing client...')

        client = Client(
            base_url=base_url,
            api_key=api_key,
            verify=True,
            proxy=False
        )

        command = demisto.command()
        demisto.debug(f'Command being called is {command}')

        if command == 'silentpush-list-domain-information':
            return_results(list_domain_information_command(client, demisto.args()))

    except Exception as e:
        return_results(
            CommandResults(
                readable_output=f'Failed to execute {command} command. Error: {str(e)}'
            )
        )


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
