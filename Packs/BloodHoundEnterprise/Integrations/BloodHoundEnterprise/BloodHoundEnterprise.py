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
BASE_URL = "https://{server_url}.bloodhoundenterprise.io"


class Credentials(object):
    def __init__(self, token_id: str, token_key: str) -> None:
        self.token_id = token_id
        self.token_key = token_key


""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def __init__(self, base_url, credentials: Credentials, verify, proxy):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._credentials = credentials

    def _request(self, method: str, uri: str, query_params: dict = {}) -> dict:

        if query_params:
            encoded_params = urllib.parse.urlencode(query_params)
            uri_with_params = f"{uri}?{encoded_params}"
        else:
            uri_with_params = uri

        digester = hmac.new(self._credentials.token_key.encode(), None, hashlib.sha256)
        digester.update(f"{method}{uri_with_params}".encode())
        digester = hmac.new(digester.digest(), None, hashlib.sha256)
        datetime_formatted = datetime.now().astimezone().isoformat("T")
        digester.update(datetime_formatted[:13].encode())
        digester = hmac.new(digester.digest(), None, hashlib.sha256)

        headers = {
            "Authorization": f"bhesignature {self._credentials.token_id}",
            "RequestDate": datetime_formatted,
            "Signature": base64.b64encode(digester.digest()),
            "Content-Type": "application/json",
        }

        return self._http_request(
            method=method, url_suffix=uri_with_params, headers=headers
        )

    def search_events(
        self,
        prev_id: int,
        limit: int,
        from_date: str | None = None,
    ) -> List[Dict]:  # noqa: E501
        """
        Searches for HelloWorld alerts using the '/get_alerts' API endpoint.
        All the parameters are passed directly to the API as HTTP POST parameters in the request

        Args:
            prev_id: previous id that was fetched.
            limit: limit.
            from_date: get events from from_date.

        Returns:
            List[Dict]: the next events
        """
        method = "GET"
        uri = "/api/v2/audit"
        query_params = {"limit": limit, "sort_by": "created_at", "after": from_date}
        remove_nulls_from_dictionary(query_params)
        response = self._request(method, uri, query_params)
        return response.get("data", {}).get("logs", [])


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): HelloWorld client to use.
        params (Dict): Integration parameters.
        first_fetch_time(str): The first fetch time as configured in the integration params.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    try:
        method = "GET"
        uri = "/api/v2/audit"
        query_params = {"limit": "1"}
        client._request(method, uri, query_params)

    except Exception as e:
        if "Unauthorized" in str(e):
            return "Authorization Error: make sure API token Key and API token id is correctly set"
        else:
            raise e

    return "ok"


def get_events_command(client: Client, args: dict) -> tuple[List[Dict], CommandResults]:
    limit = args.get("limit", 50)
    from_date = args.get("from_date")
    events = client.search_events(
        prev_id=0,
        limit=limit,
        from_date=from_date,
    )
    hr = tableToMarkdown(name="Test Event", t=events)
    return events, CommandResults(readable_output=hr)


def aaa(client: Client):
    method = "GET"
    uri = "/api/v2/audit"
    query_params = {"limit": "3000"}
    client._request(method, uri, query_params)


def fetch_events(
    client: Client,
    last_run: dict[str, int],
    first_fetch_time,
    max_events_per_fetch: int,
) -> tuple[Dict, List[Dict]]:
    """
    Args:
        client (Client): HelloWorld client to use.
        last_run (dict): A dict with a key containing the latest event created time we got from last fetch.
        first_fetch_time: If last_run is None (first time we are fetching), it contains the timestamp in
            milliseconds on when to start fetching events.
        alert_status (str): status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.
        max_events_per_fetch (int): number of events per fetch
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """
    prev_id = last_run.get("prev_id", None)
    if not prev_id:
        prev_id = 0

    # events = client.search_events(
    #     prev_id=prev_id,
    #     limit=max_events_per_fetch,
    #     from_date=first_fetch_time,
    # )
    method = "GET"
    uri = "/api/v2/audit"

    events = client._request(method, uri)
    demisto.debug(f"Fetched event with id: {prev_id + 1}.")

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {"prev_id": prev_id + 1}
    demisto.debug(f"Setting next run {next_run}.")
    return next_run, events


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
            create_time = arg_to_datetime(arg=event.get("created_at"))
            event["_time"] = create_time.strftime(DATE_FORMAT) if create_time else None


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    credentials = Credentials(
        token_id=params.get("api_token_id", ""),
        token_key=params.get("api_token_key", ""),
    )
    server_url = params.get("server_url")
    base_url = BASE_URL.format(server_url=server_url)
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    # How much time before the first fetch to retrieve events
    first_fetch_time = datetime.now().isoformat()
    max_events_per_fetch = params.get("max_events_per_fetch", 1000)

    try:
        client = Client(
            base_url=base_url,
            credentials=credentials,
            verify=verify_certificate,
            proxy=proxy,
        )

        if command == "test-module":
            result = test_module(client)
            return_results(result)

        elif command == "bloodHound-get-events":
            should_push_events = argToBoolean(args.pop("should_push_events"))
            events, results = get_events_command(client, args)
            return_results(results)
            if should_push_events:
                add_time_to_events(events)
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            next_run, events = fetch_events(
                client=client,
                last_run=last_run,
                first_fetch_time=first_fetch_time,
                max_events_per_fetch=max_events_per_fetch,
            )

            add_time_to_events(events)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
