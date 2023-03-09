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
DETECTION_NEXT_RUN_KEY = "first_timestamp"
AUDIT_NEXT_RUN_KEY = "start"

""" CLIENT CLASS """


class VectraClient(BaseClient):
    def __init__(
        self,
        url: str,
        api_key: str,
        fetch_limit: int = 100,
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

    def get_detections(self, first_timestamp: str) -> Dict[str, Any]:
        """
        Retrieve detections. Detection objects contain all the information related to security events detected on the network.

        Arguments:
        - `first_timestamp` (``str``): The timestamp when the event was first detected.

        Returns:
        - `Dict[str, Any]` of detection objects.
        """

        return self._http_request(
            method="GET",
            url_suffix=f"search/{self.endpoints[0]}",
            params={
                "page_size": self.max_fetch,
                "query_string": f"detection.first_timestamp:[{first_timestamp} to NOW]",
            },
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


def is_eod(now: datetime) -> bool:
    """
    Checks whether it's the end of the day (UTC).
    We use this to check whether we should skip requesting audits as they are updated on a daily basis.

    Returns:
    - `bool` indicating whether we should skip audits.
    """
    return now.hour == 23 and now.minute == 59


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

    fetch_events(
        client,
        first_timestamp=datetime.now().strftime(DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT),
        start=datetime.now().strftime(AUDIT_NEXT_RUN_KEY),
        is_first_fetch=True,
    )

    return "ok"


def get_detections_cmd(client: VectraClient, first_timestamp: str) -> CommandResults:

    """
    Command function to retrieve detections.

    Arguments:
    - `client` (``VectraClient``): An instance of a Vectra API HTTP client.
    - `first_timestamp` (``str``): Parameter used as starting range to retrieve detections.

    Returns:
    - `CommandResults` to War Room.
    """

    detections: List[Dict[str, Any]] = client.get_detections(first_timestamp=first_timestamp).get("results", [])  # type: ignore
    if detections:
        md = tableToMarkdown(
            f"Detections since {first_timestamp}",
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
            readable_output=f"""No detections found from {first_timestamp} until now.
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


def fetch_events_cmd(client, config: Dict[str, Any]) -> None:

    """
    Command function to fetch events.

    Arguments:
    - `client` (``VectraClient``): An instance of a Vectra API HTTP client.
    - `config` (``Dict[str, Any]``): Integration configuration.

    Returns:
    - `CommandResults` to War Room.
    """

    # Not first time running fetch events
    is_first_fetch: bool = False if demisto.getLastRun() else True
    if not is_first_fetch:
        first_timestamp = demisto.getLastRun().get(DETECTION_NEXT_RUN_KEY)
        start = demisto.getLastRun().get(AUDIT_NEXT_RUN_KEY)

    # First time running fetch events
    else:
        demisto.info("First time fetching events")
        first_fetch: datetime = arg_to_datetime(  # type: ignore
            arg=config.get("first_fetch", "3 days"), arg_name="First fetch time"
        )
        first_timestamp = first_fetch.strftime(DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT)

        start = first_fetch.strftime(AUDIT_START_TIMESTAMP_FORMAT)

    detections, audits, next_fetch = fetch_events(
        client=client,
        first_timestamp=first_timestamp,
        start=start,
        is_first_fetch=is_first_fetch,
    )

    demisto.info(f"Setting last run to {str(next_fetch)}...")
    demisto.setLastRun(next_fetch)

    demisto.info(f"Sending {len(detections)} detections to XSIAM...")
    send_events_to_xsiam(detections, vendor=VENDOR, product=client.endpoints[0])
    demisto.info(f"{len(detections)} detections sent to XSIAM.")
    demisto.info(f"Sending {len(audits)} audits to XSIAM...")
    send_events_to_xsiam(audits, vendor=VENDOR, product=client.endpoints[1])
    demisto.info(f"{len(audits)} audits sent to XSIAM.")


def fetch_events(
    client: VectraClient, first_timestamp: str, start: str, is_first_fetch: bool
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, str]]:

    """
    Fetch detections based on whether it's the first fetch or not.

    Arguments:
    - `client` (``VectraClient``): The API client for the Vectra service.
    - `first_timestamp` (``str``): The detection filter.
    - `start` (``str``): The audit filter.
    - `is_first_fetch` (``bool``): Whether this is the first fetch or not.

    Returns:
    - `Dict[str, Any]` of the detections
    - `Dict[str, Any]` of the audits
    - `Dict[str, str]` of the next_fetch
    """

    # Fetch alerts if it's the end of the day or the first fetch
    now = datetime.utcnow()
    if is_eod(now) or is_first_fetch:
        demisto.info(f"Fetching audits from {start} to now...")
        audits = client.get_audits(start=start).get("audits", [])
        next_run_audit_str = now.strftime(AUDIT_START_TIMESTAMP_FORMAT)

    else:
        demisto.info(
            f"""Skipping audits since it's not the end of the day (UTC),
            it's {now.strftime(DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT)}"""
        )
        audits = []
        next_run_audit_str = start

    # detections are ordered by descending first_timestamp therefore we can take the first
    # detection first_timestamp as the next run

    demisto.info(f"Fetching detections from {first_timestamp} to now...")
    detections = client.get_detections(first_timestamp=first_timestamp).get("results", [])
    if detections:
        next_run_detection = datetime.strptime(
            detections[0].get("first_timestamp"), DETECTION_FIRST_TIMESTAMP_FORMAT  # type: ignore
        )

        # Need to add 1 minute since first_timestamp query parameter is inclusive
        next_run_detection_str = (next_run_detection + timedelta(minutes=1)).strftime(
            DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT
        )
        demisto.info(f"{len(detections)} detections found.")
    # If no detections were fetched, we can reuse the current first_timestamp
    else:
        next_run_detection_str = first_timestamp
        demisto.info("No detections were found")

    return (
        detections,
        audits,
        {
            DETECTION_NEXT_RUN_KEY: next_run_detection_str,
            AUDIT_NEXT_RUN_KEY: next_run_audit_str,
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

    detection_res = get_detections_cmd(
        client=client,
        first_timestamp=first_fetch.strftime(DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT),
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
                    demisto.info(
                        f"Sending {len(detections_cmd_res.outputs)} detections to XSIAM..."
                    )  # type: ignore
                    send_events_to_xsiam(
                        detections_cmd_res.outputs, vendor=VENDOR, product=client.endpoints[0]
                    )
                    demisto.info(f"{len(detections_cmd_res.outputs)} detections sent to XSIAM.")  # type: ignore
                    demisto.info(f"Sending {len(audits_cmd_res.outputs)} audits to XSIAM...")  # type: ignore
                    send_events_to_xsiam(
                        audits_cmd_res.outputs, vendor=VENDOR, product=client.endpoints[1]
                    )
                    demisto.info(f"{len(audits_cmd_res.outputs)} audits sent to XSIAM.")  # type: ignore

            # fetch-events
            else:

                fetch_events_cmd(client, config)

        else:
            raise NotImplementedError(f"command '{cmd}' is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
