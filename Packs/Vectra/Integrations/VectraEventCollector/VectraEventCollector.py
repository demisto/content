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

    def get_detections(self, min_id: int = 1) -> Dict[str, Any]:
        """
        Retrieve detections. Detection objects contain all the information related to security events detected on the network.

        Arguments:
            - `min_id` (``int``): The detection ID used as an filter index to only pull new detections.

        Returns:
            - `Dict[str, Any]` of detection objects.
        """

        return self._http_request(
            method="GET",
            url_suffix="detections",
            params={"page_size": self.max_fetch, "ordering": "id", "min_id": min_id},
        )


""" HELPER FUNCTIONS """


def get_detection_id(detections: List[Dict[str, Any]]) -> int:
    """
    Retrieves the detection ID of the last detection in the list.

    We increment the `detection_id` since the detections API
    is inclusive when filtering for detections based on `min_id`.
    """

    return detections[-1].get("id") + 1


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


def get_events(client: VectraClient) -> CommandResults:

    # TODO docstring

    detections: List[Dict[str, Any]] = client.get_detections().get("results")

    md = tableToMarkdown(
        "Detections",
        detections,
        headers=["id", "url", "detection", "src_ip", "state", "t_score", "certainty"],
    )

    results = CommandResults(
        outputs_prefix=f"{VENDOR}.Detections",
        outputs_key_field="id",
        outputs=detections,
        readable_output=md,
    )

    return results


def fetch_events(
    client: VectraClient, first_fetch_ts: int = None, min_id: int = None
) -> Tuple[Dict[str, str], Dict[str, Any]]:

    """
    Fetch detections based on whether it's the first fetch or not.

    Arguments:
        - `first_fetch_ts` (``int``): The timestamp of the first fetch. Only used in the first fetch.
        - `min_id` (``int``): The minimum detection ID to filter by. We use `min_id` as an index to know which events to request.

        The arguments default is set to `None` to enable a method overloading for this function.

    Returns:
        - `Tuple[Dict[str, str], Dict[str, Any]]` of the largest detection ID and detections.
    """

    # TODO paging in case it's needed
    # use "next": "https://apitest.vectracloudlab.com/api/v2.2/detections?min_id=7234&ordering=id&page=2&page_size=10",

    detections: List[Dict[str, Any]]

    # First fetch
    if first_fetch_ts:
        detections = client.get_detections().get("results")

    elif min_id:
        detections = client.get_detections(min_id=min_id).get("results")

    else:
        raise TypeError("Neither 'first_fetch_ts' nor 'min_id' provided to fetch_events")

    return {"min_id": get_detection_id(detections)}, detections


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
            if cmd == "vectra-get-events":
                should_push_events = argToBoolean(args.pop("should_push_events"))
                return_results(get_events(client))

            else:
                should_push_events = True
                first_fetch_time = arg_to_datetime(
                    arg=config.get("first_fetch", "3 days"),
                    arg_name="First fetch time",
                    required=True,
                )
                first_fetch_ts = int(first_fetch_time.timestamp()) if first_fetch_time else None

                # Not the first fetch
                if demisto.getLastRun():

                    min_id, events = fetch_events(
                        client=client, min_id=demisto.getLastRun().get("min_id")
                    )
                else:
                    demisto.debug(
                        f"Running fetch_events for the first time from ts {first_fetch_ts}..."
                    )
                    min_id, events = fetch_events(client=client, first_fetch_time=first_fetch_ts)

                demisto.setLastRun(min_id)

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
