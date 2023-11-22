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
from typing import Any, Optional

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

    # TODO RETURNS LIST
    def get_events(self, limit: Optional[str], after_checkpoint: Optional[str], created_after: Optional[str]) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/api/v1/events',
            data=(
                ('limit', limit),
                ('after_checkpoint', after_checkpoint),
                ('created_after', created_after)
            ),
            resp_type='json',
            ok_codes=(200,)
        )


''' HELPER FUNCTIONS '''

''' COMMAND FUNCTIONS '''


def get_events_command(client: Client, args: dict[str, Any]) -> CommandResults:
    pass
    limit = args.get('limit', None)
    after_checkpoint = args.get('after_checkpoint', None)
    created_after = args.get('created_after', None)

    result = client.get_events(limit, after_checkpoint, created_after)
    output_results = {
        "checkpoint": result['checkpoint'],
        "additional_results": result['additional_results'],
    }
    raw_results = result['results']

    return CommandResults(
        outputs_prefix='Tessian',
        outputs_key_field='EventsOutput',
        outputs=output_results,
        raw_response=raw_results
    )


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication'
    Returning 'ok' indicates that connection to the service is successful.
    Raises exceptions if something goes wrong.
    """

    try:
        response = client.get_events('2', None, None)

        success = demisto.get(response, 'success.total')  # Safe access to response['success']['total']
        if success != 1:
            return f'Unexpected result from the service: success={success} (expected success=1)'

        return 'ok'
    except Exception as e:
        exception_text = str(e).lower()
        if 'forbidden' in exception_text or 'authorization' in exception_text:
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # TODO: make sure you properly handle authentication
    # api_key = demisto.params().get('credentials', {}).get('password')

    # get the service API url
    params = demisto.params()
    base_url = params.get('url')
    api_key = params.get('api_key')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        headers: dict = {}
        headers["Authorization"] = f"API-Token {api_key}"

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
        )

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)
        elif demisto.command() == 'get_events':
            return_results(get_events_command(client, demisto.args()))
        else:
            raise NotImplementedError(f"Either the command, {demisto.command}, is not supported yet or it does not exist.")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
