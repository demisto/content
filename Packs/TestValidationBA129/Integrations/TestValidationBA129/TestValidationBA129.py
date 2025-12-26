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

from typing import Any, Dict, Optional

import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    # TODO: REMOVE the following dummy function:
    def baseintegration_dummy(
        self, dummy: str, dummy2: Optional[int]
    ) -> Dict[str, str]:
        """Returns a simple python dict with the information provided
        in the input (dummy).

        Args:
            dummy: string to add in the dummy dict that is returned. This is a required argument.
            dummy2: int to limit the number of results. This is an optional argument.

        Returns:
            The dict with the arguments
        """
        return {"dummy": dummy, "dummy2": dummy2}

    # TODO: ADD HERE THE FUNCTIONS TO INTERACT WITH YOUR PRODUCT API


""" HELPER FUNCTIONS """

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises:
     exceptions if something goes wrong.

    Args:
        Client: client to use

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    # TODO: ADD HERE some code to test connectivity and authentication to your service.
    # This  should validate all the inputs given in the integration configuration panel,
    # either manually or by using an API that uses them.
    client.baseintegration_dummy("dummy", 10)  # No errors, the api is working
    return "ok"


# TODO: REMOVE the following dummy command function
def baseintegration_dummy_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    dummy = args.get("dummy")  # dummy is a required argument, no default
    dummy2 = args.get("dummy2")  # dummy2 is not a required argument

    # Call the Client function and get the raw response
    result = client.baseintegration_dummy(dummy, dummy2)

    return CommandResults(
        outputs_prefix="BaseIntegration",
        outputs_key_field="",
        outputs=result,
    )


# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client


def main():
    """main function, parses params and runs command functions"""

    # TODO: make sure you properly handle authentication
    # api_key = params.get('apikey')

    params = demisto.params()
    # get the service API url
    base_url = urljoin(params.get("url"), "/api/v1")

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not argToBoolean(params("insecure", False))

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = argToBoolean(params.get("proxy", False))

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:

        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})
        headers = {}

        client = Client(
            base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy
        )
        args = demisto.args()
        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
        # TODO: REMOVE the following dummy command case:
        elif command == "baseintegration-dummy":
            result = baseintegration_dummy_command(client, args)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
        return_results(
            result
        )  # Returns either str, CommandResults and a list of CommandResults
    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
