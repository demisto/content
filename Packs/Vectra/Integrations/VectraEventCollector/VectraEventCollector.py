"""
Vectra Event Collector XSIAM Integration

This is an Integration script for XSIAM to retrieve Audits and Detections from Vectra AI
into Cortex XSIAM.

It uses version 2.2 of Vectra AI REST API.
See https://support.vectra.ai/s/article/KB-VS-1174 for more the API reference.
"""

import demistomock as demisto
from CommonServerPython import *
from typing import Dict, Any, Tuple
import pytest

""" CONSTANTS """

VENDOR = "Vectra"
DETECTION_FIRST_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT = "%Y-%m-%dT%H%M"
AUDIT_START_TIMESTAMP_FORMAT = "%Y-%m-%d"
DETECTION_NEXT_RUN_KEY = "id"
AUDIT_NEXT_RUN_KEY = "start"
DETECTION_TIMESTAMP_KEY = "first_timestamp"
AUDIT_TIMESTAMP_KEY = "vectra_timestamp"
XSIAM_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"


""" CLIENT CLASS """


class VectraClient(BaseClient):
    def __init__(
        self,
        url: str,
        api_key: str,
        fetch_limit: int = 1000,
        insecure: bool = False,
        proxy: bool = False,
    ):
        self.api_version = "2.2"
        self.endpoints = ("detections", "audits")
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

        Returns:
        - `Dict[str, str]` of the HTTP headers.
        """

        return {
            "Content-Type": "application/json",
            "Authorization": f"Token {self.api_key}",
        }

    def get_detections(self, min_id: int = 0) -> Dict[str, Any]:
        """
        Retrieve detections. Detection objects contain all the information related to security events detected on the network.

        Arguments:
        - `min_id` (``int``): Filter for Detections with ID greater or equal to this.

        Returns:
        - `Dict[str, Any]` of detection objects.
        """

        params = {"page_size": self.max_fetch, "ordering": "-id"}

        if min_id != 0:
            params["min_id"] = min_id

        return self._http_request(
            method="GET",
            url_suffix=f"{self.endpoints[0]}",
            params=params,
        )

    def get_audits(self, start: str) -> Dict[str, Any]:
        """
        Retrieve audits. Audit objects contain data that lists requested accesses to resources. This information includes but
        is not limited to:
        - User
        - Message describing action
        - Result of action
        - Timestamp
        - Source IP

        Arguments:
        - `start` (``str``): The start range in YYYY-MM-DD format for which to look for detections.

        Returns:
        - `Dict[str, Any]` of audit objects.
        """

        return self._http_request(
            method="GET",
            url_suffix=self.endpoints[1],
            params={"start": start},
        )


""" HELPER FUNCTIONS """


def add_parsing_rules(event: Dict[str, Any]) -> Dict[str, Any]:

    """
    Helper method to add the Parsing Rules to an event.

    Arguments:
        - `event_type` (``str``): The type of event to parse, i.e. detection or audit

    Returns:
        - `Dict[str, Any]` with the added Parsing Rules.
    """

    parsing_rules_to_add = ["_time"]

    try:
        # Process detection
        if DETECTION_TIMESTAMP_KEY in event:
            event[parsing_rules_to_add[0]] = datetime.strptime(
                event.get(DETECTION_TIMESTAMP_KEY), DETECTION_FIRST_TIMESTAMP_FORMAT
            ).strftime(XSIAM_TIME_FORMAT)
        # Process Audit
        else:
            event[parsing_rules_to_add[0]] = timestamp_to_datestring(event.get(AUDIT_TIMESTAMP_KEY))

        return event

    except Exception as e:
        demisto.info(
            f"""Failed adding parsing rules {parsing_rules_to_add} to event '{str(event)}': {str(e)}.
            Will be added in ingestion time"""
        )
        pass


def get_audits_to_send(
    audits: List[Dict[str, Any]], is_first_fetch: bool, prev_fetch_timestamp: str
) -> List[Dict[str, Any]]:

    """
    Helper method to filter out audits that should not be sent. Since the API
    returns audits on a day resolution, we need to check the audit timestamp
    to ensure discard older audits.

    Args:
        - `audits` (``List[Dict[str, Any]]``): The audits returned from the endpoint.
        - `is_first_fetch` (``bool``): Whether it's the first fetch.
        - `prev_fetch_timestamp` (``str``): The previous fetch's most recent audit timestamp as a string.
    Return:
        - ``List[Dict[str, Any]]`` of filtered audits to send to XSIAM.
    """

    if not is_first_fetch:
        prev_fetch_timestamp_ts = datetime.fromtimestamp(float(prev_fetch_timestamp))
        filtered_audits = [
            a
            for a in audits
            if datetime.fromtimestamp(float(a.get(AUDIT_TIMESTAMP_KEY))) > prev_fetch_timestamp_ts
        ]

        return filtered_audits

    else:
        return audits


""" COMMAND FUNCTIONS """


@pytest.mark.skip("Not a pytest")
def test_module(client: VectraClient) -> str:
    """
    Tests API connectivity and authentication'
    Since the event collection works with the audit and detection APIs, we want to ensure that the user has access
    to them so we check if these endpoints exist in the response.

    Arguments:
    - ``client` (``VectraClient``): An instance of a Vectra API HTTP client.

    Returns:
    `str` `'ok'` if test passed, anything else will raise an exception.
    """

    demisto.info(f"Testing connection and authentication to {client._base_url}...")

    fetch_events(client)

    return "ok"


def get_detections_cmd(client: VectraClient) -> CommandResults:

    """
    Command function to retrieve detections.

    Arguments:
    - `client` (``VectraClient``): An instance of a Vectra API HTTP client.

    Returns:
    - `CommandResults` to War Room.
    """

    detections: List[Dict[str, Any]] = client.get_detections().get("results", [])  # type: ignore
    if detections:
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
            readable_output=md,
        )
    else:
        results = CommandResults(
            readable_output="""No detections found.
            Change the **First fetch time** in the integration settings and try again or try using a different integration
            instance using ***using=***."""
        )

    return results


def get_audits_cmd(client: VectraClient, start: str) -> CommandResults:

    """
    Command function to retrieve audits.

    Arguments:
    - `client` (``VectraClient``): An instance of a Vectra API HTTP client.
    - `start` (``str``): Parameter used as starting range to retrieve detections.

    Returns:
    - `CommandResults` to War Room.
    """

    audits: List[Dict[str, Any]] = client.get_audits(start=start).get("audits", [])  # type: ignore
    if audits:
        md = tableToMarkdown(f"Audits since {start}", audits)

        results = CommandResults(
            outputs_prefix=f"{VENDOR}.Audits", outputs=audits, readable_output=md
        )

    else:

        results = CommandResults(
            readable_output=f"""
            No audits found from {start} until now.
            Change the **First fetch time** in the integration settings and try again or
            try using a different integration instance using ***using=***.""",
        )

    return results


def fetch_events_cmd(client) -> None:

    """
    Command function to fetch events.

    Arguments:
    - `client` (``VectraClient``): An instance of a Vectra API HTTP client.
    - `config` (``Dict[str, Any]``): Integration configuration.

    Returns:
    - `CommandResults` to War Room.
    """

    detections, audits, next_fetch = fetch_events(client=client)

    demisto.info(f"Setting last run to {str(next_fetch)}...")
    demisto.setLastRun(next_fetch)

    parsed_events: List[Dict[str, Any]] = []

    demisto.info("Adding parsing rules to events...")
    for event in detections + audits:
        parsed_events.append(add_parsing_rules(event))
    demisto.info("Finished adding parsing rules.")

    demisto.info(
        f"Sending {len(parsed_events)} events to XSIAM ({len(detections)} detections, {len(audits)} audits)"
    )
    send_events_to_xsiam(parsed_events, vendor=VENDOR, product=VENDOR)  # type: ignore


def fetch_events(
    client: VectraClient,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, str]]:

    """
    Fetch detections based on whether it's the first fetch or not.

    Arguments:
    - `client` (``VectraClient``): The API client for the Vectra service.

    Returns:
    - `Dict[str, Any]` of the detections
    - `Dict[str, Any]` of the audits
    - `Dict[str, str]` of the next_fetch
    """

    is_first_fetch: bool = False if demisto.getLastRun() else True

    # The first fetch
    if is_first_fetch:
        demisto.info("First time fetching events")
        first_fetch: datetime = arg_to_datetime(  # type: ignore
            arg=demisto.params().get("first_fetch", "3 days"), arg_name="First fetch time"
        )

        start = first_fetch.strftime(AUDIT_START_TIMESTAMP_FORMAT)
        previous_fetch_most_recent_audit_timestamp_str = "0"
        min_id = 1

    # Next fetches
    else:

        min_id = int(demisto.getLastRun().get(DETECTION_NEXT_RUN_KEY))

        # If we're already fetching, we want only from today
        start = datetime.now().strftime(AUDIT_START_TIMESTAMP_FORMAT)
        previous_fetch_most_recent_audit_timestamp_str = demisto.getLastRun().get(
            AUDIT_NEXT_RUN_KEY
        )

    # Fetch Audits
    demisto.info(f"Fetching audits from {start} to now...")
    returned_audits: List[Dict[str, Any]] = client.get_audits(start=start).get("audits", [])

    audits = get_audits_to_send(
        returned_audits, is_first_fetch, previous_fetch_most_recent_audit_timestamp_str
    )

    demisto.info(f"Fetched {len(audits)} audits.")
    if audits:
        most_recent_audit = audits[-1]
        demisto.info(f"Most recent audit: {str(most_recent_audit)}")
        most_recent_audit_str = most_recent_audit.get(AUDIT_TIMESTAMP_KEY)

    else:
        demisto.info("No audits were fetched.")
        most_recent_audit_str = previous_fetch_most_recent_audit_timestamp_str

    if min_id != 1:
        demisto.info(f"Fetching detections ID greater or equal to {min_id}")
        detections = client.get_detections(min_id=min_id).get("results", [])
    else:
        detections = client.get_detections().get("results", [])

    if detections:
        most_recent_detection = detections[0]
        # The filter for detections by ID is inclusive so we need to increase it by 1
        next_run_detection_id = most_recent_detection.get("id") + 1

        demisto.info(f"{len(detections)} detections found.")
    # If no detections were fetched, we can reuse the current min_id
    else:
        next_run_detection_id = min_id
        demisto.info("No detections were found")

    return (
        detections,
        audits,
        {
            DETECTION_NEXT_RUN_KEY: str(next_run_detection_id),
            AUDIT_NEXT_RUN_KEY: most_recent_audit_str,
        },
    )


def get_events(
    client: VectraClient, first_fetch: datetime
) -> Tuple[CommandResults, CommandResults]:

    """
    Command function to retrieve detections and audits.

    Arguments:
    - `client` (``VectraClient``): An instance of a Vectra API HTTP client.
    - `first_fetch` (``datetime``): Parameter used as starting range to retrieve detections.

    Returns:
    - `CommandResults` of detections to War Room.
    - `CommandResults` of audits to War Room.
    """

    detection_res = get_detections_cmd(client=client)

    audits_res = get_audits_cmd(
        client=client, start=first_fetch.strftime(AUDIT_START_TIMESTAMP_FORMAT)
    )

    return detection_res, audits_res


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    cmd = demisto.command()
    args = demisto.args()
    config = demisto.params()

    demisto.info(f"Command being called is '{cmd}'")
    try:

        client = VectraClient(
            url=config.get("url"),
            api_key=config.get("credentials", {}).get("password"),
            fetch_limit=arg_to_number(arg=config.get("fetch_limit", 1000)),  # type: ignore
            insecure=config.get("insecure"),
            proxy=config.get("proxy"),
        )

        if cmd == "test-module":
            result = test_module(client)
            return_results(result)

        elif cmd in ("vectra-get-events", "fetch-events"):

            if cmd == "vectra-get-events":

                first_fetch: datetime = arg_to_datetime(
                    arg=config.get("first_fetch", "3 days"), arg_name="First fetch time"  # type: ignore
                )
                detections_cmd_res, audits_cmd_res = get_events(client, first_fetch)

                return_results(detections_cmd_res)
                return_results(audits_cmd_res)

                if argToBoolean(args.pop("should_push_events")):

                    parsed_events: List[Dict[str, Any]] = []

                    demisto.info("Adding parsing rules to events...")
                    for event in detections_cmd_res.outputs + audits_cmd_res.outputs:
                        parsed_events.append(add_parsing_rules(event))
                    demisto.info("Finished adding parsing rules.")

                    demisto.info(
                        f"""Sending {len(parsed_events)} events to XSIAM ({len(detections_cmd_res.outputs)} detections,
                        {len(audits_cmd_res.outputs)} audits)"""
                    )
                    send_events_to_xsiam(parsed_events, vendor=VENDOR, product=VENDOR)

            # fetch-events
            else:

                fetch_events_cmd(client)

        else:
            raise NotImplementedError(f"command '{cmd}' is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
