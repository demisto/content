"""
Vectra Event Collector XSIAM Integration

This is an Integration script for XSIAM to retrieve Audits and Detections from Vectra AI
into Cortex XSIAM.

It uses version 2.2 of Vectra AI REST API.
See https://support.vectra.ai/s/article/KB-VS-1174 for more the API reference.
"""

import demistomock as demisto

# TODO remove requests, used for BaseClient
# import requests
from CommonServerPython import *
from typing import Dict, Any
import json


""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


""" CLIENT CLASS """


class VectraClient(BaseClient):

    api_version = "2.2"

    def __init__(self, config_url: str, verify: bool, proxy: bool, api_key: str):

        headers: Dict[str, Any] = {
            "Content-Type": "application/json",
            "Authorization": f"Token {api_key}",
        }
        base_url = urljoin(config_url, f"/api/v{self.api_version}/")
        super().__init__(base_url, verify=verify, proxy=proxy, headers=headers)

    def check_auth(self) -> None:

        """
        Sends a request to the API root to check the authentication.
        If the authentication succeeds, the API responds with an empty `Dict`.
        If the authentication fails, we get back `{"detail": "Invalid token."}`

        Returns:
            - Empty `Dict` if the authentication is successful, the error `Dict` otherwise
        """

        self._http_request(method="GET")


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

    try:

        client.check_auth()

    except Exception as e:
        return f"Error authenticating: {str(e)}"

    return "ok"


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # Handle configuration

    # Handle Authentication
    # If credentials are not chosen,
    demisto.debug(demisto.params().get("credentials"))

    api_key = demisto.params().get("credentials", {}).get("password")
    config_url = demisto.params().get("url")
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)
    # first_fetch = demisto.params().get("first_fetch", "3 days")

    demisto.debug(f"Command being called is {demisto.command()}")
    try:

        client = VectraClient(
            config_url=config_url, api_key=api_key, verify=verify_certificate, proxy=proxy
        )

        if demisto.command() == "test-module":
            result = test_module(client)
            return_results(result)

        # elif demisto.command() == "baseintegration-dummy":
        #     pass
        # return_results(baseintegration_dummy_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
