"""Arista VeloCloud Event Collector Integration for Cortex XSIAM

This integration collects alerts from the Arista VeloCloud API and sends them to XSIAM.
It uses the alerts API endpoint to retrieve alerts for the specified enterprise.
"""

from typing import Any
import json
from datetime import datetime, timedelta, UTC
import dateparser

import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR/XSIAM
VENDOR = "arista"
PRODUCT = "velocloud"
MAX_PAGES = 100  # Safety limit to prevent infinite loops in pagination

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the Arista VeloCloud API

    This Client implements API calls to retrieve alerts from the Arista VeloCloud API.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def __init__(
        self,
        base_url: str,
        enterprise_id: str,
        verify: bool = True,
        headers: dict | None = None,
        proxy: bool = False,
    ):
        """Initialize the Client class

        Args:
            base_url: API base URL
            enterprise_id: Enterprise logical ID
            verify: Whether to verify SSL certificates
            headers: Headers to include in requests
            proxy: Whether to use the system proxy
        """
        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy)
        self.enterprise_id = enterprise_id

    def check_error(self, response: dict[str, Any]) -> None:
        """Check for errors in the API response.

        Args:
            response: API response dictionary

        Returns:
            Error message if an error is found, else an empty string
        """
        if "error" in response:
            error = response["error"]
            error_message = error.get("message", "Unknown error")
            error_code = error.get("code", -1)
            # TODO: Add error classes for different error types
            if error_code == -32000:
                raise ValueError(f"Authentication Error: {error_message}")
            raise ValueError(f"API Error: {error_message}")

    def get_events(self, start_time: str | None = None, end_time: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """Get alerts from Arista VeloCloud API

        Args:
            start_time: Start time for event query (ISO format)
            end_time: End time for event query (ISO format)
            limit: Maximum number of events to retrieve

        Returns:
            Response from the API containing events
        """

        # Build endpoint URL with enterprise ID
        endpoint = "/portal/rest/event/getEnterpriseEvents"
        metadata: dict[str, str] = {}
        events = []
        page_count = 0

        while (metadata and page_count < MAX_PAGES) or page_count == 0:
            page_count += 1

            request_json = {
                "enterpriseId": int(self.enterprise_id),
                "interval": {
                    "start": start_time,
                    "end": end_time,
                },
            }

            # Include limit if specified
            if limit:
                request_json.update(
                    {
                        "filter": {
                            "limit": limit,
                        }
                    }
                )

            # If not the first request, include nextPageLink for pagination
            if "nextPageLink" in metadata:
                demisto.debug(f"Fetching next page with link: {metadata['nextPageLink']}")
                request_json["nextPageLink"] = metadata["nextPageLink"]

            try:
                response = self._http_request(method="POST", url_suffix=endpoint, json_data=request_json)
                self.check_error(response)
            except DemistoException as e:
                # Handle rate limiting or other API errors gracefully
                if "rate limit" in str(e).lower() or "429" in str(e):
                    demisto.debug(f"Rate limit encountered on page {page_count}, stopping pagination")
                    break
                raise

            events.extend(response.get("data", []))
            metadata = response.get("metadata", {})

        demisto.debug(f"Fetched {len(events)} events across {page_count} pages")
        return events


""" HELPER FUNCTIONS """


def velocloud_parse_date_range(first_fetch: str, last_run_time: str) -> tuple[str, str]:
    """Parse the date range for event retrieval

    Args:
        first_fetch: First fetch time string
        last_run_time: Last run timestamp string

    Returns:
        Tuple with start and end time strings in ISO format
    """
    end_time = datetime.now(UTC)

    if last_run_time:
        start_time = dateparser.parse(last_run_time)
        if not start_time:
            start_time = dateparser.parse(first_fetch)
        else:
            # Increment by 1 second to avoid duplicates
            # VeloCloud's API does not support milliseconds
            start_time = start_time + timedelta(seconds=1)
    else:
        start_time = dateparser.parse(first_fetch)

    if not start_time:
        start_time = end_time - timedelta(days=1)

    # Set timezone to UTC if not specified
    if start_time.tzinfo is None:
        start_time = start_time.replace(tzinfo=UTC)
    if end_time.tzinfo is None:
        end_time = end_time.replace(tzinfo=UTC)

    return start_time.isoformat(), end_time.isoformat()


def format_events(events: list[dict]) -> list[dict]:
    """Format events for XSIAM ingestion by adding _time field

    Args:
        events: Raw events from the API

    Returns:
        Formatted events ready for XSIAM ingestion
    """
    if not events:
        demisto.debug("No events to format")
        return []

    formatted_events = []
    demisto.debug(f"Formatting {len(events)} events")
    demisto.debug(f"Sample event before formatting: {json.dumps(events[0])}")

    for event in events:
        # Extract the timestamp and convert to ISO format if needed
        timestamp = event.get("eventTime") or event.get("created")
        if not timestamp:
            demisto.debug(f"Warning: Event without timestamp found: {event.get('id', 'unknown')}")
            continue
        event.update({"_time": timestamp})
        formatted_events.append(event)

    demisto.debug(f"Formatted {len(formatted_events)} events successfully")
    if formatted_events:
        demisto.debug(f"Sample event after formatting: {json.dumps(formatted_events[0])}")

    return formatted_events


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises:
     exceptions if something goes wrong.

    Args:
        client: Client to use

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    try:
        # Make a simple request to validate connectivity and authentication
        demisto.debug("Testing API connectivity with a single event fetch")
        result = client.get_events(limit=1)
        demisto.debug(f"Test module received response: {json.dumps(result)}")
        demisto.debug(f"Test successful, received {len(result)} event(s)")
        return "ok"
    except DemistoException as e:
        error_msg = str(e)
        if "401" in error_msg or "403" in error_msg:
            return f"Authentication failed. Please verify your API key and enterprise ID.\nError: {error_msg}"
        elif "404" in error_msg:
            return f"API endpoint not found. Please verify the server URL.\nError: {error_msg}"
        else:
            return f"Error connecting to Arista VeloCloud API: {error_msg}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"


def get_events_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get events command

    Args:
        client: VeloCloud client
        args: Command arguments

    Returns:
        Command results
    """
    start_time = args.get("start_time", "1 day ago")
    end_time = args.get("end_time", "now")
    limit = arg_to_number(args.get("limit", 100))

    # Parse and validate inputs
    # Start time
    parsed_start_time = dateparser.parse(start_time)
    if parsed_start_time:
        parsed_start_time_str = parsed_start_time.isoformat()
    else:
        raise ValueError("Invalid start_time format")

    # End time
    parsed_end_time = dateparser.parse(end_time)
    if parsed_end_time:
        parsed_end_time_str = parsed_end_time.isoformat()
    else:
        raise ValueError("Invalid end_time format")

    # Validate limit
    if limit is None or limit < 0:
        raise ValueError("Limit must be a positive integer or zero")

    demisto.debug(f"Fetching events from {parsed_start_time_str} to {parsed_end_time_str} with limit {limit}")

    response = client.get_events(
        start_time=parsed_start_time_str,
        end_time=parsed_end_time_str,
        limit=limit,
    )

    return CommandResults(
        outputs_prefix="VeloCloud.Event",
        outputs_key_field="logicalId",
        outputs=response,
        raw_response=response,
    )


def fetch_events(
    client: Client,
    last_timestamp: str,
    first_fetch: str,
    limit: int = 1000,
) -> tuple[list[dict[str, Any]], str]:
    """Fetch new events since last_timestamp

    Args:
        client: VeloCloud client
        last_timestamp: Last event timestamp from past fetch
        first_fetch: First fetch time string for initial fetch
        limit: Maximum number of events to retrieve per page

    Returns:
        A tuple containing the list of new events and the new last timestamp

    Note:
        The function increments the start time by 1 second to minimize overlap.
    """
    start_time_str, end_time_str = velocloud_parse_date_range(first_fetch, last_timestamp)
    new_last_timestamp = end_time_str  # If no new events, set to end_time to avoid searching same range again

    demisto.debug(f"Calling client.get_events with start_time: {start_time_str} and end_time: {end_time_str}")

    response = client.get_events(start_time=start_time_str, end_time=end_time_str, limit=limit)

    events = format_events(response)

    demisto.debug(f"Events: {json.dumps(events)}")

    # Update last timestamp if events exist
    if events:
        # Filter out None values and get valid timestamps
        valid_timestamps = [ts for ts in [event.get("_time") for event in events] if ts and isinstance(ts, str)]
        if valid_timestamps:
            new_last_timestamp = max(valid_timestamps)

    demisto.debug(f"New last timestamp: {new_last_timestamp}")
    return events, new_last_timestamp


def fetch_events_command(client: Client) -> None:
    """Fetch events and send them to XSIAM

    Args:
        client: VeloCloud client
    """
    params = demisto.params()
    first_fetch = params.get("first_fetch", "1 day ago")
    limit = arg_to_number(params.get("max_fetch", 1000))

    last_run = demisto.getLastRun()
    last_timestamp = last_run.get("last_timestamp", "")

    if not last_timestamp:
        start_time, _ = velocloud_parse_date_range(first_fetch, "")
        last_timestamp = start_time

    demisto.debug(f"Last run dict: {last_run}")
    demisto.debug(f"Calling get_events with last_timestamp: {last_timestamp} and first_fetch: {first_fetch}")

    events, new_last_timestamp = fetch_events(
        client=client,
        last_timestamp=last_timestamp,
        first_fetch=first_fetch,
        limit=limit if limit is not None else 1000,
    )

    demisto.debug(f"Sending {len(events)} events to send_events_to_xsiam")
    send_events_to_xsiam(events, VENDOR, PRODUCT)

    new_last_run = {"last_timestamp": new_last_timestamp}
    demisto.debug(f"New last run: {json.dumps(new_last_run)}")
    demisto.setLastRun(new_last_run)


def main():
    """Main function, parses params and runs command functions"""
    params = demisto.params()

    # Get connection parameters
    base_url = params.get("url", "")
    enterprise_id = params.get("enterprise_id", "")
    api_key = params.get("api_key", {}).get("password", "")
    api_key = api_key.strip() if api_key else ""

    # Check required parameters based on auth type

    # Validate that enterprise_id is numeric
    try:
        int(enterprise_id)
    except (ValueError, TypeError):
        raise ValueError(f"Enterprise ID must be a numeric value, got: {enterprise_id}")

    if not base_url:
        raise ValueError("Server URL is required")

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Token {api_key}",
    }

    # Connection parameters
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=base_url,
            enterprise_id=enterprise_id,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
        )

        args = demisto.args()

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)
        elif command == "velocloud-get-events":
            return_results(get_events_command(client, args))
        elif command == "fetch-events":
            fetch_events_command(client)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
