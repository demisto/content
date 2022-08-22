import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
from typing import Dict, Any
from jbxapi import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR


''' HELPER FUNCTIONS '''

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

''' COMMAND FUNCTIONS '''


def test_module(client: JoeSandbox) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``JoeSandbox``
    :param JoeSandbox: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    if client.server_online():
        return 'ok'


def is_online(client: JoeSandbox) -> CommandResults:
    result = client.server_online()
    status = 'online' if result.get('online') == 'true' else 'offline'
    return CommandResults(readable_output=f"Joe server is {status}")


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    api_key = demisto.get(demisto.params(), 'credentials.password')
    base_url = demisto.params()['url']
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    command = demisto.command()

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = JoeSandbox(apikey=api_key, apiurl=base_url, accept_tac=True, verify_ssl=verify_certificate,
                            proxies=proxy)

        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'joe-is-online':
            return_results(is_online(client))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
