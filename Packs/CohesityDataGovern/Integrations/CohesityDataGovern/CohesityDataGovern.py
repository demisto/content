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

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


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

    # TODO: ADD HERE THE FUNCTIONS TO INTERACT WITH YOUR PRODUCT API
    def get_was_alerts(self) -> Dict[str, Any]:
        """Gets the Wide Access Shield Alerts.

        :return: dict containing the Wide Access Shields alerts
        returned from the API
        :rtype: ``Dict[str, Any]``
        """
        return self._http_request(
            method='GET',
            url_suffix='/shields',
        )


''' HELPER FUNCTIONS '''

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

''' COMMAND FUNCTIONS '''


def get_was_alerts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """get_was_alerts command: Returns Wide Access Sheild Alerts.

    :type client: ``Client``
    :param Client: CohesityDataGovern client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains Wide Access Shield Alerts.

    :rtype: ``CommandResults``
    """

    # INTEGRATION DEVELOPER TIP
    # Reputation commands usually support multiple inputs (i.e. arrays), so
    # they can be invoked once in XSOAR. In this case the API supports a single
    # IP at a time, so we will cycle this for all the members of the array.
    # We use argToList(), implemented in CommonServerPython.py to automatically
    # Initialize an empty list of CommandResults to return
    # each CommandResult will contain context standard for IP
    resp = client.get_was_alerts()

    # CohesityTBD: Write a better readable_output.
    alert_data = {}
    idx = 0
    for shield in resp['shields']:
        idx = idx + 1
        alert_data[str(idx)] = str(shield)

    readable_output = tableToMarkdown('Alerts', alert_data)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CohesityWASAlerts',
        outputs_key_field='Alerts',
        outputs=resp,
    )


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
        client.get_was_alerts()
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message

# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # TODO: make sure you properly handle authentication
    api_key = demisto.params().get('apikey')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/mcm/argus/api/v1/public')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})
        headers: Dict = {
            'apikey': api_key
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        # TODO: ADD command cases for the commands you will implement
        elif demisto.command() == 'cohesity-get-was-alerts':
            return_results(get_was_alerts_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
