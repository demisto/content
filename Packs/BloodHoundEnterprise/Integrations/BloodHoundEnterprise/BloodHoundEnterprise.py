import hashlib
import hmac
import urllib.parse

import demistomock as demisto
from CommonServerPython import *
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
VENDOR = "BloodHound"
PRODUCT = "Enterprise"
FETCH_LIMIT = 5000
PAGE_LIMIT = 1000


class Credentials:
    def __init__(self, token_id: str, token_key: str) -> None:
        self.token_id = token_id
        self.token_key = token_key


""" CLIENT CLASS """


class Client(BaseClient):
    """
    A client to interact with the BloodHound Enterprise API.

    This client handles authentication and makes API requests to fetch audit events.
    It supports operations like searching events within a date range and limiting the number of results.

    Attributes:
        base_url (str): The base URL of the API.
        credentials (Credentials): Contains API credentials (token ID and token key).
        verify (bool): Whether to verify SSL certificates.
        proxy (bool): Whether to use a proxy.
    """

    def __init__(self, base_url, credentials: Credentials, verify, proxy):
        """
        Initializes the Client with the given API parameters.

        Args:
            base_url (str): The base URL of the API.
            credentials (Credentials): API credentials for authentication.
            verify (bool): SSL verification flag.
            proxy (bool): Proxy usage flag.
        """
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._credentials = credentials

    def _request(self, method: str, url_suffix: str, query_params: dict = {}) -> dict:
        """
        Makes an authenticated HTTP request to the API.

        Args:
            method (str): The HTTP method to use (e.g., 'GET', 'POST').
            url_suffix (str): The API endpoint to send the request to.
            query_params (Optional[Dict]): The query parameters to include in the request.

        Returns:
            Dict: The response data as a dictionary.
        """
        if query_params:
            encoded_params = urllib.parse.urlencode(query_params)
            url_suffix = f"{url_suffix}?{encoded_params}"

        # This code snippet (of the encryption form) is taken directly from the BloodHound documentation.
        digester = hmac.new(self._credentials.token_key.encode(), None, hashlib.sha256)
        digester.update(f"{method}{url_suffix}".encode())
        digester = hmac.new(digester.digest(), None, hashlib.sha256)
        datetime_formatted = datetime.now().astimezone().isoformat()
        digester.update(datetime_formatted[:13].encode())
        digester = hmac.new(digester.digest(), None, hashlib.sha256)

        headers = {
            "Authorization": f"bhesignature {self._credentials.token_id}",
            "RequestDate": datetime_formatted,
            "Signature": base64.b64encode(digester.digest()),
            "Content-Type": "application/json",
        }
        demisto.debug(f"executing API call with encrypted url: {url_suffix},")

        return self._http_request(method=method, url_suffix=url_suffix, headers=headers)

    def search_events(
        self,
        limit: int,
        from_date: str | None = None,
        until_date: str | None = None,
        offset: int | None = None,
    ) -> List[Dict]:
        """
        Searches for audit events using the API with pagination and optional date filtering.

        Args:
            limit (int): The maximum number of events to retrieve.
            from_date (Optional[str]): The start date to filter events (ISO 8601 format).
            until_date (Optional[str]): The end date to filter events (ISO 8601 format).
            skip (Optional[int]): The number of events to skip for pagination.

        Returns:
            List[Dict]: A list of events retrieved from the API.
        """
        method = "GET"
        url_suffix = "/api/v2/audit"
        query_params = {
            "limit": limit,
            "sort_by": "created_at",
            "after": from_date,
            "before": until_date,
            "skip": offset,
        }
        demisto.debug(f"Got the follow parameters to the query {query_params}")
        remove_nulls_from_dictionary(query_params)
        response = self._request(
            method=method, url_suffix=url_suffix, query_params=query_params
        )
        return response.get("data", {}).get("logs", [])


def test_module(client: Client) -> str:
    """
    Tests the connection to the BloodHound Enterprise API.

    Args:
        client (Client): The client object to interact with the API.

    Returns:
        str: "ok" if the connection is successful, or an authorization error message.
    """
    try:
        client.search_events(limit=1)

    except Exception as e:
        if "Unauthorized" in str(e):
            return "Authorization Error: make sure API token Key and API token id is correctly set"
        else:
            raise e

    return "ok"


def get_events_command(client: Client, args: dict) -> tuple[List[Dict], CommandResults]:
    """
    Retrieves events from the BloodHound Enterprise API based on provided parameters.

    Args:
        client (Client): The API client to use for the request.
        args (dict): Command arguments, including:
            - 'start' (str): Start date for event retrieval.
            - 'end' (str, optional): End date for event retrieval.
            - 'limit' (int, optional): Maximum number of events to retrieve.

    Returns:
        tuple[List[Dict], CommandResults]: A list of events and the command results with readable output.
    """
    limit = arg_to_number(args.get("limit", 10))
    from_date = (
        args.get("start_date")
        or (datetime.now().astimezone() - timedelta(minutes=1)).isoformat()
    )
    until_date = args.get("end_date") or datetime.now().astimezone().isoformat()
    events, _ = get_events_with_pagination(
        client, start_date=from_date, end_date=until_date, max_events=limit
    )
    hr = tableToMarkdown(name="Test Event", t=events, removeNull=True)
    return events, CommandResults(readable_output=hr, raw_response=events)


def fetch_events(
    client: Client,
    params: dict[str, str],
) -> tuple[Dict, List[Dict]]:
    """
    Fetches a set of events from the BloodHound Enterprise API.

    This function retrieves events based on the provided parameters and the last run state.
    It keeps track of the last event retrieved and pagination details to ensure that the
    next fetch operation continues from the correct point.

    Args:
        client (Client): The API client used to interact with BloodHound Enterprise.
        params (dict[str, str]): Configuration parameters, including:
            - 'max_events_per_fetch' (str): Maximum number of events to fetch per API call.

    Returns:
        tuple[Dict, List[Dict]]:
            - A dictionary containing the next run details (e.g., last event timestamp and ID).
            - A list of fetched events.
    """
    first_fetch_time = (datetime.now().astimezone() - timedelta(minutes=1)).isoformat()
    now = datetime.now().astimezone().isoformat()

    last_run = demisto.getLastRun()
    demisto.debug(f"Got the follow last run: {last_run}.")

    from_date = last_run.get("last_event_date", first_fetch_time)
    from_event = int(last_run.get("last_event_id", 0))
    last_run_skip = int(last_run.get("offset", 0))
    fetch_limit = arg_to_number(params.get("max_events_per_fetch")) or FETCH_LIMIT

    events, skip = get_events_with_pagination(
        client,
        start_date=from_date,
        end_date=now,
        max_events=fetch_limit,
        last_event_id=from_event,
        offset=last_run_skip,
    )

    fetch_id = int(last_run.get("fetch_id", 0)) + 1

    next_run = {
        "last_event_date": (
            events[-1].get("created_at") if events and not skip else from_date
        ),
        "last_event_id": events[-1].get("id") if events else from_event,
        "fetch_id": fetch_id,
        "offset": skip,
    }
    demisto.debug(
        f"returning {len(events)} events. in fetch No: {fetch_id}. and the follow details to the setLastRun function {next_run}."
    )
    return next_run, events


def get_events_with_pagination(
    client: Client,
    start_date,
    end_date,
    max_events,
    last_event_id: int = 0,
    offset: int = 0,
) -> tuple[list, int]:
    """
    Retrieves a paginated list of events from the BloodHound Enterprise API.

    This function fetches events in batches, handling pagination internally to ensure
    the correct number of events is retrieved. It also filters out events that have already
    been processed by checking against a provided last event ID.

    Args:
        client (Client): The API client used to interact with BloodHound Enterprise.
        start_date (str): The starting date for the event search (inclusive).
        end_date (str): The ending date for the event search (exclusive).
        max_events (int): Maximum number of events to fetch.
        last_event_id (int, optional): The ID of the last event processed. Defaults to 0.
        offset (int, optional): The initial number of events to skip. Defaults to 0.

    Returns:
        tuple[list, int]:
            - A list of events that were fetched.
            - An integer indicating the number of events to skip in the next fetch if applicable.
    """
    fetched_events: list = []
    pagination_offset = offset

    while len(fetched_events) < max_events:
        page_size = min(PAGE_LIMIT, max_events - len(fetched_events))
        response = client.search_events(
            limit=page_size,
            from_date=start_date,
            until_date=end_date,
            offset=pagination_offset,
        )
        if not response:
            demisto.debug("No new events received from the API")
            break
        demisto.debug(f"Got {len(response)} events before deduplication")
        # Added the offset before the dedup to avoid incorrect offset on the second page
        pagination_offset += len(response)
        filtered_events = [
            item for item in response if item.get("id", 0) > last_event_id
        ]
        demisto.debug(f"Got {len(filtered_events)} events after deduplication")
        fetched_events.extend(filtered_events)
    next_skip = offset + len(fetched_events) if len(fetched_events) == max_events else 0
    return fetched_events, next_skip


""" MAIN FUNCTION """


def add_time_to_events(events: List[Dict] | None):
    """
    Adds the _time key to the events.
    Args:
        events: List[Dict] - list of events to add the _time key to.
    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            if create_time := arg_to_datetime(arg=event.get("created_at")):
                event["_time"] = create_time.strftime(DATE_FORMAT)


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    credentials = Credentials(
        token_id=params.get("client", {}).get("identifier", ""),
        token_key=params.get("client", {}).get("password", ""),
    )
    base_url = params.get("server_url")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    try:
        client = Client(
            base_url=base_url,
            credentials=credentials,
            verify=verify_certificate,
            proxy=proxy,
        )

        if command == "test-module":
            return_results(test_module(client))

        elif command == "bloodhound-get-events":
            events, results = get_events_command(client, args)
            should_push_events = argToBoolean(args.get("should_push_events", "false"))
            if should_push_events:
                add_time_to_events(events)
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            return_results(results)

        elif command == "fetch-events":
            next_run, events = fetch_events(
                client=client,
                params=params,
            )

            add_time_to_events(events)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
