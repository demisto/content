import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    @logger
    def __init__(self, base_url: str, verify: bool, proxy: bool, fetch_limit: int,
                 first_fetch_time: str, headers):
        super().__init__(base_url, verify=verify, proxy=proxy)
        self.first_fetch_time = first_fetch_time
        self.fetch_limit = fetch_limit
        self.headers = headers


''' HELPER FUNCTIONS '''

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions
    """
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    base_url: str = params['url'].rstrip('/')
    api_key = params.get('credentials', {}).get('password')
    verify_certificate = not params.get('insecure', False)
    first_fetch_time = params.get('first_fetch', '3 days').strip()
    fetch_limit = int(params.get('fetch_limit', '1000'))
    proxy = demisto.params().get('proxy', False)

    headers = {'Authorization': f'Bearer {api_key}'}

    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            fetch_limit=fetch_limit,
            first_fetch_time=first_fetch_time)

        commands = {
            'test-module': test_module
        }

        if command in commands:
            return_results(commands[command](client, **args))
        else:
            return_error(f'Command {command} is not available in this integration')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
