import demistomock as demisto
from CommonServerPython import *
from typing import Any
from urllib.parse import urlencode
import requests

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
VENDOR = "beyondtrust"
PRODUCT = "pm_cloud"
DEFAULT_LIMIT = 1000
DEFAULT_PAGE_SIZE = 200
INTEGRATION_NAME = "BeyondTrust PM Cloud DEBUGGING"

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API

    Args:
        base_url (str): The base URL of the service.
        client_id (str): The client ID for authentication.
        client_secret (str): The client secret for authentication.
        verify (bool): Whether to verify the SSL certificate.
        proxy (bool): Whether to use a proxy.
    """

    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = None

    def get_token(self):
        """Retrieves the access token from the service."""
        demisto.debug(f"{INTEGRATION_NAME}: Attempting to get OAuth token")
        demisto.debug(f"{INTEGRATION_NAME}: Base URL: {self._base_url}")
        demisto.debug(f"{INTEGRATION_NAME}: Client ID length: {len(self.client_id) if self.client_id else 0}")
        secret_len = len(self.client_secret) if self.client_secret else 0
        demisto.debug(f"{INTEGRATION_NAME}: Client Secret length: {secret_len}")
        
        # Log first few chars for debugging (safe since these are partial)
        id_preview = self.client_id[:4] if self.client_id else 'N/A'
        demisto.debug(f"{INTEGRATION_NAME}: Client ID (first 4 chars): {id_preview}")
        
        secret_preview = 'N/A'
        if self.client_secret and len(self.client_secret) >= 4:
            secret_preview = self.client_secret[:4]
        demisto.debug(f"{INTEGRATION_NAME}: Client Secret (first 4 chars): {secret_preview}")

        # Build the OAuth token request data as a dict - requests will handle encoding
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }
        
        # Log encoded data length for debugging
        encoded_data = urlencode(data)
        demisto.debug(f"{INTEGRATION_NAME}: Encoded data length: {len(encoded_data)}")
        
        token_url = "/oauth/connect/token"
        full_url = f"{self._base_url}{token_url}"
        demisto.debug(f"{INTEGRATION_NAME}: Full token URL: {full_url}")
        
        # Log the actual encoded request body (secrets will be scrubbed by XSOAR)
        demisto.debug(f"{INTEGRATION_NAME}: Request body (URL-encoded): {encoded_data}")

        try:
            # Use requests directly to have full control over the OAuth request
            # This bypasses BaseClient which may have issues with form-encoded data
            req_headers = {"Content-Type": "application/x-www-form-urlencoded"}
            demisto.debug(f"{INTEGRATION_NAME}: Request headers: {req_headers}")
            
            # Use PreparedRequest to see exactly what will be sent
            from requests import Request, Session
            session = Session()
            req = Request('POST', full_url, data=data, headers=req_headers)
            prepared = session.prepare_request(req)
            
            # Log the prepared request details
            demisto.debug(f"{INTEGRATION_NAME}: Prepared request URL: {prepared.url}")
            demisto.debug(f"{INTEGRATION_NAME}: Prepared request headers: {dict(prepared.headers)}")
            demisto.debug(f"{INTEGRATION_NAME}: Prepared request body: {prepared.body}")
            demisto.debug(f"{INTEGRATION_NAME}: Prepared request body type: {type(prepared.body)}")
            
            # Send the prepared request
            response = session.send(prepared, verify=self._verify, timeout=30)
            
            demisto.debug(f"{INTEGRATION_NAME}: Token response status: {response.status_code}")
            demisto.debug(f"{INTEGRATION_NAME}: Token response headers: {dict(response.headers)}")
            
            if response.status_code != 200:
                demisto.debug(f"{INTEGRATION_NAME}: Token response body: {response.text}")
                raise DemistoException(
                    f"Error in API call [{response.status_code}] - {response.reason}\n"
                    f"{response.text}"
                )
            
            result = response.json()
            demisto.debug(f"{INTEGRATION_NAME}: Token request successful")
            return result.get("access_token")
        except requests.exceptions.RequestException as e:
            demisto.debug(f"{INTEGRATION_NAME}: Token request failed with error: {str(e)}")
            raise DemistoException(f"Failed to get OAuth token: {str(e)}")
        except Exception as e:
            demisto.debug(f"{INTEGRATION_NAME}: Token request failed with error: {str(e)}")
            raise

    def _http_request(  # type: ignore[override]
        self,
        method: str,
        url_suffix: str = "",
        params: dict | None = None,
        data: dict | str | None = None,
        headers: dict | None = None,
        resp_type: str = "json",
        timeout: int = 10,
        **kwargs,
    ) -> Any:
        """Wrapper for http_request to handle authentication and execution."""
        demisto.debug(f"{INTEGRATION_NAME}: Sending request: method={method}, url_suffix={url_suffix}, params={params}")
        if not headers:
            headers = {}

        if url_suffix != "/oauth/connect/token":
            if not self.token:
                self.token = self.get_token()
            headers["Authorization"] = f"Bearer {self.token}"

        return super()._http_request(
            method=method,
            url_suffix=url_suffix,
            params=params,
            data=data,
            headers=headers,
            resp_type=resp_type,
            timeout=timeout,
            **kwargs,
        )

    def get_events(self, start_date: str, limit: int = DEFAULT_LIMIT) -> dict:
        """Retrieves events from the service.

        Args:
            start_date (str): The start date to retrieve events from.
            limit (int): The maximum number of events to retrieve.

        Returns:
            dict: The response from the service.
        """
        params = {"StartDate": start_date, "RecordSize": limit}
        demisto.debug(f"{INTEGRATION_NAME}: Getting events with params: {params}")
        return self._http_request(method="GET", url_suffix="/management-api/v3/Events/FromStartDate", params=params)

    def get_audit_activity(
        self,
        page_size: int = DEFAULT_PAGE_SIZE,
        page_number: int = 1,
        filter_created_dates: list[str] | None = None,
        filter_created_selection_mode: str | None = None,
    ) -> dict:
        """Retrieves audit activity from the service.

        Args:
            page_size (int): The number of records per page.
            page_number (int): The page number to retrieve.
            filter_created_dates (list[str]): The dates to filter by.
            filter_created_selection_mode (str): The selection mode for the dates.

        Returns:
            dict: The response from the service.
        """
        params: dict[str, Any] = {"Pagination.PageSize": page_size, "Pagination.PageNumber": page_number}
        if filter_created_dates:
            params["Filter.Created.Dates"] = filter_created_dates
        if filter_created_selection_mode:
            params["Filter.Created.SelectionMode"] = filter_created_selection_mode

        demisto.debug(f"{INTEGRATION_NAME}: Getting audit activity with params: {params}")
        return self._http_request(method="GET", url_suffix="/management-api/v3/ActivityAudits/Details", params=params)


""" HELPER FUNCTIONS """


def get_dedup_key(event: dict) -> str:
    """Generates a deduplication key for an event.

    Args:
        event (dict): The event to generate the key for.

    Returns:
        str: The deduplication key.
    """
    # For Events, we can use the 'id' field if available, or a combination of fields.
    # Based on documentation, 'id' seems available in both event types.
    if "id" in event:
        return str(event["id"])
    # Fallback to hashing the event content if no ID is present (unlikely based on docs but good practice)
    return str(hash(json.dumps(event, sort_keys=True)))


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity.

    Args:
        client (Client): The client to use.

    Returns:
        str: 'ok' if the test passed, anything else otherwise.
    """
    try:
        client.get_token()
        return "ok"
    except Exception as e:
        return f"Failed to connect to the service: {e}"


def get_events_command(client: Client, args: dict) -> CommandResults:
    """Retrieves events from the service.

    Args:
        client (Client): The client to use.
        args (dict): The command arguments.

    Returns:
        CommandResults: The command results.
    """
    start_date = args.get("start_date")
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT)) or DEFAULT_LIMIT
    should_push_events = argToBoolean(args.get("should_push_events", False))

    if not start_date:
        # Default to 1 hour ago if not provided
        start_date = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime(DATE_FORMAT)

    response = client.get_events(start_date, limit)
    events = response.get("events", [])

    # Add XSIAM fields if pushing events
    if should_push_events:
        for event in events:
            event["_time"] = event.get("created") or event.get("@timestamp")
            event["source_log_type"] = "events"
            event["vendor"] = VENDOR
            event["product"] = PRODUCT
        send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

    return CommandResults(outputs_prefix="BeyondTrust.Event", outputs_key_field="id", outputs=events, raw_response=response)


def get_audit_activity_command(client: Client, args: dict) -> CommandResults:
    """Retrieves audit activity from the service.

    Args:
        client (Client): The client to use.
        args (dict): The command arguments.

    Returns:
        CommandResults: The command results.
    """
    page_size = arg_to_number(args.get("page_size", DEFAULT_PAGE_SIZE)) or DEFAULT_PAGE_SIZE
    page_number = arg_to_number(args.get("page_number", 1)) or 1
    filter_created_dates = argToList(args.get("filter_created_dates"))
    filter_created_selection_mode = args.get("filter_created_selection_mode")

    response = client.get_audit_activity(page_size, page_number, filter_created_dates, filter_created_selection_mode)
    audits = response.get("data", [])

    return CommandResults(outputs_prefix="BeyondTrust.Audit", outputs_key_field="id", outputs=audits, raw_response=response)


def fetch_pm_events(
    client: Client, last_run: dict, first_fetch: str, max_fetch: int, fetch_end_time: datetime
) -> tuple[dict, list[dict]]:
    """Fetches PM Cloud events from the Events API.

    Args:
        client (Client): The client to use.
        last_run (dict): The last run context.
        first_fetch (str): The first fetch time.
        max_fetch (int): The maximum number of events to fetch for this event type.
        fetch_end_time (datetime): The end time for this fetch cycle.

    Returns:
        tuple[dict, list[dict]]: The updated run context and the fetched events.
    """
    demisto.debug(
        f"{INTEGRATION_NAME}: Starting fetch_pm_events. " f"last_run={last_run}, first_fetch={first_fetch}, max_fetch={max_fetch}"
    )
    next_run = last_run.copy()
    last_event_time_str = last_run.get("last_event_time")

    if not last_event_time_str:
        last_event_time = dateparser.parse(first_fetch).replace(tzinfo=timezone.utc)  # type: ignore
    else:
        last_event_time = dateparser.parse(last_event_time_str).replace(tzinfo=timezone.utc)  # type: ignore

    # Format the start date as required by the API: ISO 8601
    start_date_str = last_event_time.strftime(DATE_FORMAT)

    response = client.get_events(start_date_str, max_fetch)
    fetched_events = response.get("events", [])
    demisto.debug(f"{INTEGRATION_NAME}: Fetched {len(fetched_events)} PM events.")
    if fetched_events:
        demisto.debug(f"{INTEGRATION_NAME}: Sample PM event (first): {fetched_events[0]}")
        if len(fetched_events) > 1:
            demisto.debug(f"{INTEGRATION_NAME}: Sample PM event (last): {fetched_events[-1]}")

    for event in fetched_events:
        # Add fields for XSIAM
        event["_time"] = event.get("created") or event.get("@timestamp")
        event["source_log_type"] = "events"
        event["vendor"] = VENDOR
        event["product"] = PRODUCT

    # Store the fetch end time as the next start time to ensure continuous coverage
    next_run["last_event_time"] = fetch_end_time.strftime(DATE_FORMAT)

    return next_run, fetched_events


def fetch_activity_audits(
    client: Client, last_run: dict, first_fetch: str, max_fetch: int, fetch_end_time: datetime
) -> tuple[dict, list[dict]]:
    """Fetches Activity Audit events from the Activity Audits API.

    Args:
        client (Client): The client to use.
        last_run (dict): The last run context.
        first_fetch (str): The first fetch time.
        max_fetch (int): The maximum number of events to fetch for this event type.
        fetch_end_time (datetime): The end time for this fetch cycle.

    Returns:
        tuple[dict, list[dict]]: The updated run context and the fetched audit events.
    """
    demisto.debug(
        f"{INTEGRATION_NAME}: Starting fetch_activity_audits. "
        f"last_run={last_run}, first_fetch={first_fetch}, max_fetch={max_fetch}"
    )
    next_run = last_run.copy()
    last_audit_time_str = last_run.get("last_audit_time")

    if not last_audit_time_str:
        last_audit_time = dateparser.parse(first_fetch).replace(tzinfo=timezone.utc)  # type: ignore
    else:
        last_audit_time = dateparser.parse(last_audit_time_str).replace(tzinfo=timezone.utc)  # type: ignore

    # Activity Audits API uses pagination and filtering.
    # We fetch from last_audit_time to fetch_end_time to ensure continuous coverage.
    # The API documentation says "Filter.Created.Dates: array of date-times".
    # And "Filter.Created.SelectionMode: Range" - this requires two dates for a range.

    start_date_str = last_audit_time.strftime("%Y-%m-%d %H:%M:%S.%f")
    end_date_str = fetch_end_time.strftime("%Y-%m-%d %H:%M:%S.%f")

    page_number = 1
    total_fetched_audits = 0
    fetched_audits_list: list[dict] = []

    while True:
        # Calculate remaining limit for this cycle
        remaining_limit = max_fetch - total_fetched_audits
        if remaining_limit <= 0:
            break

        current_page_size = min(DEFAULT_PAGE_SIZE, remaining_limit)

        demisto.debug(f"{INTEGRATION_NAME}: Fetching page {page_number} of audits. Page size: {current_page_size}")
        response = client.get_audit_activity(
            page_size=current_page_size,
            page_number=page_number,
            filter_created_dates=[start_date_str, end_date_str],
            filter_created_selection_mode="Range",
        )

        fetched_audits = response.get("data", [])
        if not fetched_audits:
            break

        for audit in fetched_audits:
            # Add fields for XSIAM
            audit["_time"] = audit.get("created")
            audit["source_log_type"] = "activity_audits"
            audit["vendor"] = VENDOR
            audit["product"] = PRODUCT

        fetched_audits_list.extend(fetched_audits)
        total_fetched_audits += len(fetched_audits)
        demisto.debug(
            f"{INTEGRATION_NAME}: Fetched {len(fetched_audits)} audits in this page. " f"Total so far: {total_fetched_audits}"
        )
        if fetched_audits:
            demisto.debug(f"{INTEGRATION_NAME}: Sample audit from page {page_number} (first): {fetched_audits[0]}")

        # Check if we have more pages
        # The response has "pageCount" and "totalRecordCount"
        if page_number >= response.get("pageCount", 0):
            break

        page_number += 1

    demisto.debug(f"{INTEGRATION_NAME}: Finished fetching activity audits. Total fetched: {total_fetched_audits}")
    if fetched_audits_list:
        demisto.debug(f"{INTEGRATION_NAME}: Sample audit (first overall): {fetched_audits_list[0]}")
        if len(fetched_audits_list) > 1:
            demisto.debug(f"{INTEGRATION_NAME}: Sample audit (last overall): {fetched_audits_list[-1]}")

    # Store the fetch end time as the next start time to ensure continuous coverage
    next_run["last_audit_time"] = fetch_end_time.strftime(DATE_FORMAT)

    return next_run, fetched_audits_list


def fetch_events(
    client: Client, last_run: dict, first_fetch: str, max_fetch: int, events_types_to_fetch: list[str]
) -> tuple[dict, list[dict]]:
    """Fetches events from the service.

    This is the main orchestrator function that calls the appropriate fetch functions
    based on the event types configured to fetch.

    Args:
        client (Client): The client to use.
        last_run (dict): The last run context.
        first_fetch (str): The first fetch time.
        max_fetch (int): The maximum number of events to fetch per event type.
        events_types_to_fetch (list[str]): The types of events to fetch.

    Returns:
        tuple[dict, list[dict]]: The next run context and the fetched events.
    """
    demisto.debug(f"{INTEGRATION_NAME}: Starting fetch_events. events_types_to_fetch={events_types_to_fetch}")
    events: list[dict] = []
    next_run = last_run.copy()

    # Capture the current time at the start of this fetch cycle
    # This will be used as the start time for the next fetch to ensure no gaps
    fetch_end_time = datetime.now(timezone.utc)

    # Handle Events - max_fetch applies per event type
    if "Events" in events_types_to_fetch:
        next_run, fetched_events = fetch_pm_events(client, next_run, first_fetch, max_fetch, fetch_end_time)
        events.extend(fetched_events)

    # Handle Activity Audits - max_fetch applies per event type
    if "Activity Audits" in events_types_to_fetch:
        next_run, fetched_audits = fetch_activity_audits(client, next_run, first_fetch, max_fetch, fetch_end_time)
        events.extend(fetched_audits)

    return next_run, events


""" MAIN FUNCTION """


def main():
    """Main function to handle the command execution."""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get("url")
    client_id: str = params.get("credentials", {}).get("identifier", "")
    client_secret: str = params.get("credentials", {}).get("password", "")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    client = Client(base_url=base_url, client_id=client_id, client_secret=client_secret, verify=verify, proxy=proxy)

    try:
        if command == "test-module":
            return_results(test_module(client))

        elif command == "beyondtrust-pm-cloud-get-events":
            return_results(get_events_command(client, args))

        elif command == "beyondtrust-pm-cloud-get-audit-activity":
            return_results(get_audit_activity_command(client, args))

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            first_fetch = params.get("first_fetch", "1 minute")
            max_fetch = arg_to_number(params.get("max_fetch", 6000)) or 6000
            events_types_to_fetch = argToList(params.get("events_types_to_fetch", "Activity Audits,Events"))

            next_run, events = fetch_events(client, last_run, first_fetch, max_fetch, events_types_to_fetch)

            # Deduplicate events
            deduped_events = {get_dedup_key(event): event for event in events}
            final_events = list(deduped_events.values())

            demisto.debug(f"{INTEGRATION_NAME}: Total events before dedup: {len(events)}, after dedup: {len(final_events)}")
            if final_events:
                demisto.debug(f"{INTEGRATION_NAME}: Sample final event (first): {final_events[0]}")
                if len(final_events) > 1:
                    demisto.debug(f"{INTEGRATION_NAME}: Sample final event (last): {final_events[-1]}")
            demisto.debug(f"{INTEGRATION_NAME}: Next run state: {next_run}")

            # Send events to XSIAM
            send_events_to_xsiam(vendor=VENDOR, product=PRODUCT, events=final_events)
            demisto.debug(f"{INTEGRATION_NAME}: Successfully sent {len(final_events)} events to XSIAM.")
            demisto.setLastRun(next_run)

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
