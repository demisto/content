"""
Vectra Event Collector XSIAM Integration

This is an Integration script for XSIAM to retrieve Audits and Detections from Vectra AI
into Cortex XSIAM.

It uses version 2.2 of Vectra AI REST API.
See https://support.vectra.ai/s/article/KB-VS-1174 for more the API reference.
"""

import demistomock as demisto
from CommonServerPython import *
from typing import Dict, Any


""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
VECTRA_API_VERSION = "2.2"

""" CLIENT CLASS """


class VectraClient(BaseClient):




""" HELPER FUNCTIONS """


""" COMMAND FUNCTIONS """


def test_module(client: VectraClient) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ""
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        message = "ok"
    except DemistoException as e:
        if "Forbidden" in str(e) or "Authorization" in str(
            e
        ):  # TODO: make sure you capture authentication errors
            message = "Authorization Error: make sure API Key is correctly set"
        else:
            raise e
    return message


# TODO: REMOVE the following dummy command function
def baseintegration_dummy_command(client: VectraClient, args: Dict[str, Any]) -> CommandResults:

    dummy = args.get("dummy", None)
    if not dummy:
        raise ValueError("dummy not specified")

    # Call the Client function and get the raw response
    result = client.baseintegration_dummy(dummy)

    return CommandResults(
        outputs_prefix="BaseIntegration",
        outputs_key_field="",
        outputs=result,
    )


# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # Handle configuration
    api_key = demisto.params().get("credentials", {}).get("password")
    base_url = urljoin(demisto.params()["url"], f"/api/{VECTRA_API_VERSION}/")
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)
    first_fetch = demisto.params().get("first_fetch", "3 days")

    demisto.debug(f"Command being called is {demisto.command()}")
    try:

        headers: Dict[str, Any] = {
            "Content-Type": "application/json",
            "Authorization": f"Token {api_key}"
        }

        client = VectraClient(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy
        )

        if demisto.command() == "test-module":
            result = test_module(client)
            return_results(result)

        elif demisto.command() == "baseintegration-dummy":
            return_results(baseintegration_dummy_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
