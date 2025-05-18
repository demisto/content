"""
Event Collector Source file for AppSentinels.ai API.
"""

from typing import Any

import demistomock as demisto
import urllib3
from CommonServerPython import *
from CommonServerUserPython import *

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """
VENDOR = "AppSentinels"
PRODUCT = "AppSentinels"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
BASE_EVENT_BODY: dict = {
    "aggregation": False,
    "api_id": 0,
    "category": [
        "CRS",
        "SchemaValidation",
        "SmartAlerts",
        "Reputation",
        "UsageAnomaly",
        "BehaviourAnomal",
        "GeolocationAler",
        "PassiveScan",
        "ActiveScan",
        "AutomatedThreat",
        "Governance",
    ],
    "include_runtime_scan": False,
    "severity": ["critical", "major", "minor", "info"],
    "type": ["security_events", "vulnerabilities"],
}

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API"""

    def __init__(
        self,
        base_url: str,
        user_key: str,
        api_key: str,
        organization: str,
        application: str,
        base_event_body: dict,
        verify: bool,
        use_proxy: bool,
    ) -> None:
        """
        Prepare constructor for Client class.

        Calls the constructor of BaseClient class and updates the header with the authentication token.

        Args:
            base_url: The url of AppSentinels.ai instance.
            user_key: The user key for AppSentinels.ai API.
            api_key: The Api key for AppSentinels.ai API - specific for every licensing.
            organization: The organization ID for AppSentinels.ai API.
            application: The application ID for AppSentinels.ai API.
            base_event_body: The base body for the http request.
            verify: True if verify SSL certificate is checked in integration configuration, False otherwise.
            use_proxy: True if the proxy server needs to be used, False otherwise.
        """

        super().__init__(base_url=base_url, verify=verify, proxy=use_proxy)
        self._headers = {
            "accept": "application/json",
            "apikey": api_key,
            "x-user-key": user_key,
            "Content-Type": "application/json",
        }
        self.organization = organization
        self.application = application
        self.base_event_body = base_event_body
        self.api_key = api_key
        self.user_key = user_key

    def get_events_request(self, params: dict) -> dict:
        """Retrieve the detections from AppSentinels.ai  API."""
        url_suffix = f"/api/v1/{self.organization}/{self.application}/events"
        body = self.base_event_body.copy()
        body.update(params)
        return self._http_request("POST", url_suffix=url_suffix, headers=self._headers, json_data=body, resp_type="json")


""" HELPER FUNCTIONS """


def remove_first_run_params(params: dict[str, Any]) -> None:
    """
    Remove the "First Run" items from the param dictionary.

    Args:
        params (Dict[str, Any]): Integration parameters.

    """
    for key in ("from_timestamp", "to_timestamp"):
        params.pop(key, None)


def fetch_events_list(client: Client, last_run: Dict, fetch_limit: int | None, use_last_run_as_params: bool) -> List[Dict]:
    """
    Fetches events from the AppSentinels.ai API, handling pagination and last_run.

    Args:
        client (Client): The client object for interacting with the AppSentinels.ai API.
        last_run (Dict): A dictionary containing the last processed event ID.
        fetch_limit (Optional[int]): The maximum number of events to fetch.
        use_last_run_as_params (bool): Flag that sign do we use the last-run as params for the API call

    Returns:
        List[Dict]: A list of fetched events.
    """
    events: List[Dict] = []

    params: Dict[str, Any] = {}  # Initialize params

    # Determine the fetch params
    if use_last_run_as_params:
        params.update(last_run)
    elif "last_event_id" not in last_run:
        # Initial fetch: from 1 minute before now to now
        current_time = get_current_time()
        start_time = (current_time - timedelta(minutes=1)).strftime(DATE_FORMAT)
        end_time = current_time.strftime(DATE_FORMAT)
        params["from_timestamp"] = start_time
        params["to_timestamp"] = end_time
        demisto.debug(f"Fetching events from date={start_time} to date={end_time}.")
    else:
        # Subsequent fetches: use last_event_id
        last_event_id_last = last_run["last_event_id"]
        params["last_event_id"] = last_event_id_last
        demisto.debug(f"Fetching with last_event_id: {last_event_id_last}")

    while True:
        try:
            # API call
            response_data = client.get_events_request(params=params)  # Use the client method
        except DemistoException as error:
            raise DemistoException(f"AppSentinels.ai: During fetch, exception occurred {str(error)}")

        if not response_data or not response_data.get("data"):
            demisto.debug("No events returned from API.")
            break  # Exit loop if no data

        new_events = response_data.get("data", [])

        if not new_events:
            break

        last_event_id = response_data.get("last_event_id")
        last_run["last_event_id"] = last_event_id
        more_records = response_data.get("more_records", False)

        for event in new_events:
            event["_TIME"] = event.get("timestamp")
            event["source_log_type"] = "event"

            events.append(event)

            if fetch_limit and len(events) >= fetch_limit:
                last_run["last_event_id"] = event["eventid"]
                return events

        if not more_records:
            break

        # Update Params for next call
        remove_first_run_params(params)
        params["last_event_id"] = last_event_id

    return events


def prepare_list_output(events: List[dict[str, Any]]) -> str:
    """Prepare human-readable output.

    Args:
        events: List of entities response from the API.

    Returns:
        markdown string to be displayed in the war room.
    """
    hr_outputs = []
    for event in events:
        hr_output = {
            "ID": event.get("eventid"),
            "Action": event.get("action"),
            "Category": event.get("category"),
            "Details": event.get("details"),
            "Type": event.get("type"),
            "Subcategory": event.get("subcategory"),
            "Time": event.get("timestamp"),
        }
        hr_outputs.append(hr_output)

    return tableToMarkdown(name="AppSentinels.ai Record(s)", t=hr_outputs, removeNull=True)


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """
    Tests the connection to the service by calling each one of the api endpoints.
    Args:
        client (Client): The client object used to interact with the service.
    Returns:
        str: 'ok' if the connection is successful. If an authorization error occurs, an appropriate error message is returned.
    """
    last_run: dict[str, Any] = {}
    fetch_events(client, last_run, fetch_limit=1)
    return "ok"


def fetch_events(
    client: Client, last_run: dict, fetch_limit: int | None = None, use_last_run_as_params: bool = False
) -> tuple[list[dict[str, Any]], dict]:
    """Fetch the specified AppSentinels.ai entity records.

     Args:
        client (Client): The client object used to interact with the AppSentinels.ai service.
        last_run (dict): The last_run dictionary having the state of previous cycle.
        fetch_limit (int | None): The maximum number of events to fetch.
        use_last_run_as_params (bool): Flag that sign do we use the last-run as params for the API call

    Returns:
        Tuple[list[dict[str, Any]], dict]: A tuple containing:
         - List of new records to be pushed into XSIAM.
         - Updated last_run dictionary.
    """
    demisto.debug("AppSentinels.ai fetch_events invoked")

    events = []

    output = fetch_events_list(client, last_run, fetch_limit, use_last_run_as_params)
    events.extend(output)

    demisto.debug(f"AppSentinels.ai next_run is {last_run}")

    return events, last_run


def get_events(client: Client, args: dict) -> CommandResults:
    """
    Inner Test Function to make sure the integration works
    Args:
        client: AppSentinels.ai client to be used.
        args: command arguments.

    Returns: Command results object that contain the results.
    """
    params_run = {}
    default_max = 50
    max_events = arg_to_number(args.get("limit")) or default_max
    # User start date in the get events arguments, else get from today
    first_fetch = arg_to_datetime(args.get("first_fetch"))

    if first_fetch:
        first_fetch_date = first_fetch.strftime(DATE_FORMAT)
        params_run.update({"from_timestamp": first_fetch_date})

    output, _ = fetch_events(client, params_run, max_events, use_last_run_as_params=True)
    human_readable = prepare_list_output(output)

    command_results = CommandResults(
        readable_output=human_readable,
        outputs=output,
        outputs_prefix="AppSentinels.ai.",
    )
    return command_results


def main():
    """main function, parses params and runs command functions"""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    # get the service API url
    base_url = params.get("url")
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    user_key = params.get("credentials", {}).get("identifier")
    api_key = params.get("credentials", {}).get("password")
    organization = params.get("organization", "")
    application = params.get("application", "")
    fetch_limit = arg_to_number(params.get("max_events_per_fetch")) or None
    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=base_url,
            user_key=user_key,
            api_key=api_key,
            organization=organization,
            application=application,
            base_event_body=BASE_EVENT_BODY,
            verify=verify_certificate,
            use_proxy=proxy,
        )
        events: List[dict[str, Any]]
        if command == "test-module":
            # Command made to test the integration
            result = test_module(client)
            return_results(result)
        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            events, next_run = fetch_events(client, last_run, fetch_limit)
            if len(events):
                demisto.debug(f"Sending {len(events)} events to XSIAM AppSentinels.ai, before server call.")
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)
            demisto.debug(f"Successfully saved last_run= {demisto.getLastRun()}")
        elif command == "appsentinels-get-events":
            command_results = get_events(client, args)
            events = cast(List[dict[str, Any]], command_results.outputs)
            if events and argToBoolean(args.get("should_push_events", False)):
                demisto.debug(f"Sending {len(events)} events.")
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            return_results(command_results)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
