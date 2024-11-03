import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""
Vectra Event Collector XSIAM Integration

This is an Integration script for XSIAM to retrieve Audits and Detections from Vectra AI
into Cortex XSIAM.

It uses version 2.2 of Vectra AI REST API.
See https://support.vectra.ai/s/article/KB-VS-1174 for more the API reference.
"""

from typing import Any
from datetime import datetime, timedelta
from urllib.parse import urljoin  # type: ignore


""" CONSTANTS """

VENDOR = "Vectra"

DETECTION_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DETECTION_TIMESTAMP_QUERY_FORMAT = "%Y-%m-%dT%H%M"
DETECTION_TIMESTAMP_KEY = "first_timestamp"

AUDIT_START_TIMESTAMP_FORMAT = "%Y-%m-%d"
AUDIT_NEXT_RUN_KEY = "start"
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

    def _create_headers(self) -> dict[str, str]:
        """
        Generates the necessary HTTP headers.

        Returns:
        - `Dict[str, str]` of the HTTP headers.
        """

        return {
            "Content-Type": "application/json",
            "Authorization": f"Token {self.api_key}",
        }

    def get_detections(self, first_timestamp: str) -> dict[str, Any]:
        """
        Retrieve detections. Detection objects contain all the information related to security events detected on the network.

        Arguments:
        - `first_timestamp` (``str``): Filter for Detections by last updated. The date format is
        DETECTION_TIMESTAMP_QUERY_FORMAT.

        Returns:
        - `Dict[str, Any]` of detection objects.
        """

        params = {
            "page_size": self.max_fetch,
            "query_string": f"detection.first_timestamp:[{first_timestamp} to NOW]",
        }

        return self._http_request(
            method="GET",
            url_suffix=f"search/{self.endpoints[0]}",
            params=params,
        )

    def get_audits(self, start: str) -> dict[str, Any]:
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


def add_parsing_rules(event: dict[str, Any]) -> Any:
    """
    Helper method to add the Parsing Rules to an event.

    Arguments:
        - `event_type` (``str``): The type of event to parse, i.e. detection or audit

    Returns:
        - Event `Dict[str, Any]` with the added Parsing Rules or skip.
    """

    try:
        # Process detection
        if DETECTION_TIMESTAMP_KEY in event:
            event["_time"] = timestamp_to_datestring(
                datetime.strptime(
                    event.get(DETECTION_TIMESTAMP_KEY), DETECTION_TIMESTAMP_FORMAT  # type: ignore
                ).timestamp()
                * 1000,
                is_utc=True,
            )

        # Process Audit
        else:
            event["_time"] = timestamp_to_datestring(
                float(event.get(AUDIT_TIMESTAMP_KEY)) * 1000  # type: ignore
            )

        return event

    except Exception as e:
        demisto.debug(
            f"""Failed adding parsing rules to event '{str(event)}': {str(e)}.
            Will be added in ingestion time"""
        )

        return event


def get_audits_to_send(
    audits: list[dict[str, Any]], is_first_fetch: bool, prev_fetch_timestamp: str
) -> list[dict[str, Any]]:
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
            if datetime.fromtimestamp(float(a.get(AUDIT_TIMESTAMP_KEY))) > prev_fetch_timestamp_ts  # type: ignore
        ]

        return filtered_audits

    else:
        return audits


def get_most_recent_detection(detections: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Helper method to return the most recent detection.

    Args:
        - `detections` (``List[Dict[str, Any]]``): The list of detections

    Returns:
        - `Dict[str, Any]` representing the most recent detection according to first_timestamp.

    """
    return sorted(
        detections,
        key=lambda d: datetime.strptime(d.get(DETECTION_TIMESTAMP_KEY), DETECTION_TIMESTAMP_FORMAT),  # type: ignore
        reverse=True,
    )[0]


""" COMMAND FUNCTIONS """


def module_test(client: VectraClient) -> str:
    """
    Tests API connectivity and authentication'
    Since the event collection works with the audit and detection APIs, we want to ensure that the user has access
    to them so we check if these endpoints exist in the response.

    Arguments:
    - ``client` (``VectraClient``): An instance of a Vectra API HTTP client.

    Returns:
    `str` `'ok'` if test passed, anything else will raise an exception.
    """

    demisto.debug(f"Testing connection and authentication to {client._base_url}...")

    fetch_events(client)

    return "ok"


def get_detections_cmd(client: VectraClient, first_timestamp: str) -> CommandResults:
    """
    Command function to retrieve detections.

    Arguments:
    - `client` (``VectraClient``): An instance of a Vectra API HTTP client.

    Returns:
    - `CommandResults` to War Room.
    """

    detections: list[dict[str, Any]] = client.get_detections(first_timestamp=first_timestamp).get("results", [])  # type: ignore
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

    audits: list[dict[str, Any]] = client.get_audits(start=start).get("audits", [])  # type: ignore
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

    demisto.debug(f"Setting last run to {str(next_fetch)}...")
    demisto.setLastRun(next_fetch)

    parsed_events: list[dict[str, Any]] = []

    demisto.debug("Attempting to add parsing rules to event...")
    for event in detections + audits:
        parsed_events.append(add_parsing_rules(event))
    demisto.debug("Finished adding parsing rules.")

    demisto.debug(
        f"Sending {len(parsed_events)} events to XSIAM ({len(detections)} detections, {len(audits)} audits)"
    )
    send_events_to_xsiam(parsed_events, vendor=VENDOR, product=VENDOR)  # type: ignore


def fetch_events(
    client: VectraClient,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, str]]:
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
        demisto.debug("First time fetching events")
        first_fetch: datetime = arg_to_datetime(  # type: ignore
            arg=demisto.params().get("first_fetch", "3 days"), arg_name="First fetch time"
        )

        start = first_fetch.strftime(AUDIT_START_TIMESTAMP_FORMAT)
        first_timestamp = first_fetch.strftime(DETECTION_TIMESTAMP_QUERY_FORMAT)
        previous_fetch_most_recent_audit_timestamp_str = "0"

    # Next fetches
    else:
        first_timestamp = demisto.getLastRun().get(DETECTION_TIMESTAMP_KEY)

        # If we're already fetching, we want only from today
        start = datetime.now().strftime(AUDIT_START_TIMESTAMP_FORMAT)
        previous_fetch_most_recent_audit_timestamp_str = demisto.getLastRun().get(
            AUDIT_NEXT_RUN_KEY
        )

    # Fetch Audits
    demisto.debug(f"Fetching audits from {start} to now...")
    returned_audits: list[dict[str, Any]] = client.get_audits(start=start).get("audits", [])

    audits = get_audits_to_send(
        returned_audits, is_first_fetch, previous_fetch_most_recent_audit_timestamp_str
    )

    demisto.debug(f"Fetched {len(audits)} audits.")
    if audits:
        most_recent_audit = audits[-1]
        most_recent_audit_str = most_recent_audit.get(AUDIT_TIMESTAMP_KEY)

    else:
        demisto.debug("No audits were fetched.")
        most_recent_audit_str = previous_fetch_most_recent_audit_timestamp_str

    # Fetch Detections
    demisto.debug(f"Fetching detections from {first_timestamp} to now...")
    detections = client.get_detections(first_timestamp=first_timestamp).get("results", [])

    demisto.debug(f"{len(detections)} detections found.")

    if detections:
        most_recent_detection = get_most_recent_detection(detections)
        # The filter for detections by first_timestamp is inclusive so we need to increase it by 1 minute
        next_run_detection_first_timestamp = datetime.strftime(
            datetime.strptime(
                most_recent_detection.get(DETECTION_TIMESTAMP_KEY), DETECTION_TIMESTAMP_FORMAT  # type: ignore
            )
            + timedelta(minutes=1),
            DETECTION_TIMESTAMP_QUERY_FORMAT,
        )

    # If no detections were fetched, we can reuse the current min_id
    else:
        next_run_detection_first_timestamp = first_timestamp

    return (
        detections,
        audits,
        {
            DETECTION_TIMESTAMP_KEY: next_run_detection_first_timestamp,
            AUDIT_NEXT_RUN_KEY: most_recent_audit_str,  # type: ignore
        },
    )


def get_events(
    client: VectraClient, first_fetch: datetime
) -> tuple[CommandResults, CommandResults]:
    """
    Command function to retrieve detections and audits.

    Arguments:
    - `client` (``VectraClient``): An instance of a Vectra API HTTP client.
    - `first_fetch` (``datetime``): Parameter used as starting range to retrieve detections.

    Returns:
    - `CommandResults` of detections to War Room.
    - `CommandResults` of audits to War Room.
    """

    detection_res = get_detections_cmd(
        client=client, first_timestamp=first_fetch.strftime(DETECTION_TIMESTAMP_QUERY_FORMAT)
    )

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

    demisto.debug(f"Command being called is '{cmd}'")
    try:
        client = VectraClient(
            url=config.get("url"),
            api_key=config.get("credentials", {}).get("password"),
            fetch_limit=arg_to_number(arg=config.get("fetch_limit", 1000)),  # type: ignore
            insecure=config.get("insecure"),
            proxy=config.get("proxy"),
        )

        if cmd == "test-module":
            result = module_test(client)
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
                    parsed_events: list[dict[str, Any]] = []

                    demisto.debug("Attempting to add parsing rules to event...")
                    for event in detections_cmd_res.outputs + audits_cmd_res.outputs:  # type: ignore
                        parsed_events.append(add_parsing_rules(event))
                    demisto.debug("Finished adding parsing rules.")

                    demisto.debug(
                        f"Sending {len(parsed_events)} events to XSIAM, "
                        + f"({len(detections_cmd_res.outputs)} detections"  # type: ignore
                        + f"{len(audits_cmd_res.outputs)} audits)"  # type: ignore
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
