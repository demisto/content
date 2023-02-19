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

# from urllib.parse import quote

""" CONSTANTS """

VENDOR = "Vectra"
# DETECTION_FIRST_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT = "%Y-%m-%dT%H%M"
AUDIT_FIRST_TIMESTAMP_FORMAT = "%Y-%md%d"
MOST_RECENT_DETECTION_FIRST_KEY = "first_timestamp"

""" CLIENT CLASS """


class VectraClient(BaseClient):
    api_version = "2.2"
    endpoints = ("detections", "audits")

    def __init__(
        self,
        url: str,
        api_key: str,
        fetch_limit: int = 100,
        insecure: bool = False,
        proxy: bool = False,
    ):

        self.api_key = api_key
        self.max_fetch = fetch_limit

        self.base_url = urljoin(url, f"/api/v{self.api_version}/")
        super().__init__(
            base_url=self.base_url,
            verify=not insecure,
            proxy=proxy,
            headers=self._create_headers(),
        )

    def _create_headers(self) -> Dict[str, str]:
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

    def get_detections(self, first_timestamp: str) -> Dict[str, Any]:
        """
        Retrieve detections. Detection objects contain all the information related to security events detected on the network.

        Arguments:
            - `first_timestamp` (``str``): The timestamp when the event was first detected.

        Returns:
            - `Dict[str, Any]` of detection objects.
        """

        demisto.log(
            str(
                {
                    "page_size": self.max_fetch,
                    "query_string": f"detection.first_timestamp:[{first_timestamp} to NOW]",
                }
            )
        )

        return self._http_request(
            method="GET",
            url_suffix=f"search/{self.endpoints[0]}",
            params={
                "page_size": self.max_fetch,
                "query_string": f"detection.first_timestamp:[{first_timestamp} to NOW]",
            },
        )

    def get_endpoints(self) -> Dict[str, str]:
        """
        Sends a request to the API root to check the authentication. The API root responds with a `Dict[str,str]`
        of API endpoints and URLs.
        """

        return self._http_request(method="GET")


""" HELPER FUNCTIONS """


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


def get_detections_cmd(
    client: VectraClient, first_timestamp: str
) -> Tuple[CommandResults, List[Dict[str, Any]]]:

    # TODO docstring

    detections: List[Dict[str, Any]] = client.get_detections(first_timestamp=first_timestamp).get(
        "results"
    )

    md = tableToMarkdown(
        "Detections",
        detections,
        headers=[
            "id",
            "is_triaged",
            "assigned_to",
            "detection",
            "src_ip",
            "state",
            "threat",
            "certainty",
        ],
    )

    results = CommandResults(
        outputs_prefix=f"{VENDOR}.Detections",
        outputs_key_field="id",
        outputs=detections,
        readable_output=md
        if detections
        else f"""
        No detections found from {first_timestamp} until now.
        Change the **First fetch time** in the integration settings and try again or
        try using a different integration instance using ***using=***.""",
    )

    return results, detections


def fetch_events(
    client: VectraClient, first_fetch: datetime = None
) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, str]]:

    """
    Fetch detections based on whether it's the first fetch or not.

    Arguments:
        - `first_fetch` (``datetime``): The date of the first fetch. Only used in the first fetch.

        The arguments default is set to `None` to enable a method overloading for this function.

    Returns:
        - `Dict[str, Any]` of the detections
        # - `Dict[str, Any]` of the audits
        - `Dict[str, str]` of the next_fetch
    """

    # TODO paging in case it's needed
    # use "next": "https://apitest.vectracloudlab.com/api/v2.2/detections?min_id=7234&ordering=id&page=2&page_size=10",

    detections: List[Dict[str, Any]] = []

    # First time fetching events

    if first_fetch:

        # Detections API expects minute resolution
        first_fetch_detection_time = first_fetch.strptime(
            DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT
        )
        detections = client.get_detections(first_timestamp=first_fetch_detection_time).get(
            "results"
        )

        # Audits API allows day resolution

    # First time fetching events
    else:
        last_max_first_fetch = demisto.getLastRun().get(MOST_RECENT_DETECTION_FIRST_KEY)
        detections = client.get_detections(first_timestamp=last_max_first_fetch).get("results")

    # detections are ordered by descending first_timestamp therefore we can take the first
    # detection first_timestamp as the next run
    if detections:
        last_run = detections[1].get("first_timestamp")
    else:
        last_run = datetime.now().strptime(DETECTION_FIRST_TIMESTAMP_FORMAT)

    return detections, [], {MOST_RECENT_DETECTION_FIRST_KEY: last_run}


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
            fetch_limit=arg_to_number(arg=config.get("fetch_limit")),
            insecure=config.get("insecure"),
            proxy=config.get("proxy"),
        )

        if cmd == "test-module":
            result = test_module(client)
            return_results(result)

        elif cmd in ("vectra-get-events", "fetch-events"):

            first_fetch: datetime = arg_to_datetime(
                arg=config.get("first_fetch", "3 days"), arg_name="First fetch time"
            )

            if cmd == "vectra-get-events":
                should_push_events = argToBoolean(args.pop("should_push_events"))

                detection_res, detections = get_detections_cmd(
                    client=client,
                    first_timestamp=first_fetch.strftime(
                        DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT
                    ),
                )

                return_results(detection_res)

            # fetch-events
            else:

                # We want to push events to XSIAM when fetch-events is called
                should_push_events = True

                detections, next_fetch = fetch_events(client=client, first_fetch=first_fetch)
                demisto.setLastRun(next_fetch)

            if should_push_events:
                demisto.debug(f"Sending {len(detections)} detections to XSIAM...")
                send_events_to_xsiam(detections, vendor=VENDOR, product=VENDOR)
                demisto.debug(f"{len(detections)} detections sent to XSIAM.")

        else:
            raise NotImplementedError(f"command '{cmd}' is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
