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
from typing import Dict, Any, Tuple

# import json
from urllib.parse import urlparse


""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
INTEGRATION_CONFIG_KEY_URL = "url"
INTEGRATION_CONFIG_KEY_FIRST_FETCH = "first_fetch"
INTEGRATION_CONFIG_VALUE_FIRST_FETCH_DEFAULT = "3 days"
INTEGRATION_CONFIG_KEY_MAX_FETCH = "fetch_limit"
INTEGRATION_CONFIG_VALUE_MAX_FETCH = 100
VENDOR = "Vectra"

""" CLIENT CLASS """


class VectraClient(BaseClient):

    api_version = "2.2"

    def __init__(self, config: Dict[str, Any] = demisto.params()):

        # Check the integration config is valid
        url = config.get(INTEGRATION_CONFIG_KEY_URL)
        self.validate_url(url)

        self.api_key = config.get("credentials", {}).get("password")
        self.verify_certificate = not config.get("insecure", False)
        self.proxy = config.get("proxy", False)
        self.max_fetch = config.get(
            INTEGRATION_CONFIG_KEY_MAX_FETCH, INTEGRATION_CONFIG_VALUE_MAX_FETCH
        )

        self.base_url = urljoin(url, f"/api/v{self.api_version}/")
        super().__init__(
            self.base_url,
            verify=self.verify_certificate,
            proxy=self.proxy,
            headers=self.create_headers(),
        )

    def check_auth(self) -> None:

        """
        Sends a request to the API root to check the authentication.
        If the authentication succeeds, the API responds with an empty `Dict`.
        If the authentication fails, we get back `{"detail": "Invalid token."}`

        Returns:
            - Empty `Dict` if the authentication is successful, the error `Dict` otherwise
        """

        self._http_request(method="GET")

    def validate_url(self, url: str):

        """
        Helper function to check whether the supplied URL is valid or not.

        Raises:
            - `ValueError` when the URL cannot be parsed.
        """

        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except ValueError:
            demisto.error(f"URL '{url}' is invalid.")
            raise

    def create_headers(self) -> Dict[str, str]:
        # TODO
        """ """

        return {
            "Content-Type": "application/json",
            "Authorization": f"Token {self.api_key}",
        }


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


def get_events(client: VectraClient, last_run: Dict[str, str] = demisto.getLastRun()):
    pass


def fetch_events(
    client: VectraClient, first_fetch_ts: int
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    pass


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    cmd = demisto.command()
    args = demisto.args()

    demisto.debug(f"Command being called is '{cmd}'")
    try:

        client = VectraClient()

        if cmd == "test-module":
            result = test_module(client)
            return_results(result)

        elif cmd in ("vectra-get-events", "fetch-events"):
            if cmd == "vectra-get-events":
                should_push_events = argToBoolean(args.pop("should_push_events"))
                events, results = get_events(client)
                return_results(results)

            else:
                should_push_events = True
                first_fetch_time = arg_to_datetime(
                    arg=demisto.params().get("first_fetch", "3 days"),
                    arg_name="First fetch time",
                    required=True,
                )
                first_fetch_ts = int(first_fetch_time.timestamp()) if first_fetch_time else None
                next_run, events = fetch_events(client=client, first_fetch_time=first_fetch_ts)
                demisto.setLastRun(next_run)

            if should_push_events:
                send_events_to_xsiam(events, vendor=VENDOR, product=VENDOR)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
