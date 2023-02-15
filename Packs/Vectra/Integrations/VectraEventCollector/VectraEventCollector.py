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
VENDOR = "Vectra"

""" CLIENT CLASS """


class VectraClient(BaseClient):

    api_version = "2.2"
    endpoints = ("detections", "audits")

    def __init__(
        self,
        url: str,
        api_key: str,
        max_fetch: int = 100,
        insecure: bool = False,
        proxy: bool = False,
    ):

        self.api_key = api_key
        self.max_fetch = max_fetch

        self.base_url = urljoin(url, f"/api/v{self.api_version}/")
        super().__init__(
            base_url=self.base_url,
            verify=not insecure,
            proxy=proxy,
            headers=self.create_headers(),
        )

    def get_endpoints(self) -> Dict[str, str]:
        """
        Sends a request to the API root to check the authentication. The API root responds with a `Dict[str,str]`
        of API endpoints and URLs.
        """

        return self._http_request(method="GET")

    def create_headers(self) -> Dict[str, str]:
        """
        Generates the necessary HTTP headers.

        Arguments:
            - `api_key` (``str``): The API token.

        Returns:
            `Dict[str, str]` of the HTTP headers.
        """

        return {
            "Content-Type": "application/json",
            "Authorization": f"Token {self.api_key}",
        }


""" COMMAND FUNCTIONS """


def test_module(client: VectraClient) -> str:
    """Tests API connectivity and authentication'

    `

        Since the event collection works with the audit and detection APIs, we want to ensure that the user has access
        to them so we check if these endpoints exist in the response.

        Arguments:
            - ``client` (``VectraClient``): An instance of a Vectra API HTTP client.

        Returns:
            `str` `'ok'` if test passed, anything else will raise an exception.
    """

    demisto.debug(f"Testing connection and authentication to {client._base_url}...")

    try:
        endpoints: Dict[str, str] = client.get_endpoints()

        demisto.debug(
            f"User has access to the following endpoints returned: {list(endpoints.keys())}"
        )

        # Checks that the authenticated user has access to the required endpoints
        if all(ep in endpoints for ep in client.endpoints):
            demisto.debug("User has access to the all required endpoints.")
            return "ok"
        else:
            return f"""User doesn't have access to endpoints {client.endpoints}, only to {','.join(list(endpoints.keys()))}.
                    Check with your Vectra account administrator."""

    except Exception as e:
        return f"Error authenticating: {str(e)}"


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
    config = demisto.params()

    demisto.debug(f"Command being called is '{cmd}'")
    try:

        client = VectraClient(
            url=config.get("url"),
            api_key=config.get("credentials", {}).get("password"),
            fetch_limit=arg_to_number("fetch_limit"),
            insecure=config.get("insecure"),
            proxy=config.get("proxy"),
        )

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
                    arg=config.get("first_fetch", "3 days"),
                    arg_name="First fetch time",
                    required=True,
                )
                first_fetch_ts = int(first_fetch_time.timestamp()) if first_fetch_time else None
                next_run, events = fetch_events(client=client, first_fetch_time=first_fetch_ts)
                demisto.setLastRun(next_run)

            if should_push_events:
                demisto.debug(f"Sending events {len(events)} to XSIAM...")
                send_events_to_xsiam(events, vendor=VENDOR, product=VENDOR)
                demisto.debug(f"{len(events)} events sent to XSIAM.")

        else:
            raise NotImplementedError(f"command '{cmd}' is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
