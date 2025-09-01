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
DATE_FORMAT = "%Y-%m-%d %H:%M"
MAX_FETCH_AUDIT_LIMIT = 5000

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API"""

    def __init__(
        self,
        base_url: str,
        user_key: str,
        api_key: str,
        organization: str,
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
        self.api_key = api_key
        self.user_key = user_key

    def get_events_request(self, params_update: dict, body: dict) -> dict:
        """
        Retrieve the detections from AppSentinels.ai  API.

        Args:
            params_update (dict): The param update to add to the base params.
            body (dict): The body update to add to the base body.

        """
        url_suffix = f"/api/v1/{self.organization}/audit-logs"
        params = {"page": "0", "limit": "1000", "sort": "timestamp", "sort_by": "asc", "include_system": "false"}
        # Page can be updated
        params.update(params_update)
        return self._http_request(
            "POST", url_suffix=url_suffix, headers=self._headers, json_data=body.copy(), params=params, resp_type="json"
        )


""" HELPER FUNCTIONS """


def remove_first_run_params(params: dict[str, Any]) -> None:
    """
    Remove the "First Run" items from the param dictionary.

    Args:
        params (Dict[str, Any]): Integration parameters.

    """
    for key in ("from_date", "to_date"):
        params.pop(key, None)


def fetch_events_list(client: Client, last_run: Dict, fetch_limit: int | None, use_last_run_as_body: bool) -> List[Dict]:
    """
    Fetches events from the AppSentinels.ai API, handling pagination and last_run.

    Args:
        client (Client): The client object for interacting with the AppSentinels.ai API.
        last_run (Dict): A dictionary containing the last processed event ID.
        fetch_limit (Optional[int]): The maximum number of events to fetch.
        use_last_run_as_body (bool): Flag that sign do we use the last-run as params for the API call

    Returns:
        List[Dict]: A list of fetched events.
    """
    events: List[Dict] = []
    current_pagination: int = 0
    params: Dict[str, Any] = {}  # Initialize params
    body: Dict[str, Any] = {}  # Initialize body

    # Determine the fetch params

    if use_last_run_as_body:
        body.update(last_run)

    elif "last_log_id" not in last_run:
        # Initial fetch: from one minute ago to now
        current_time = get_current_time()
        body.update(
            {
                "from_date": (current_time - timedelta(minutes=1)).strftime(DATE_FORMAT),
                "to_date": current_time.strftime(DATE_FORMAT),
            }
        )

    else:
        # Subsequent fetches: use last_log_id
        body["last_log_id"] = last_run["last_log_id"]

    while True:
        try:
            # API call
            demisto.debug(f"AppSentinels.ai sending http requests with arguments: {params=} {body=}")
            response = client.get_events_request(params_update=params, body=body)  # Use the client method
        except DemistoException as error:
            raise DemistoException(f"AppSentinels.ai: During fetch, exception occurred {str(error)}")

        new_events = response.get("data") if response else []

        if not new_events:
            demisto.debug("AppSentinels.ai: No Audit logs returned from API.")
            break

        pagination = response.get("pagination")
        last_log_id = new_events[-1].get("id")
        last_run["last_log_id"] = last_log_id

        demisto.debug(f"AppSentinels.ai fetched events with: {last_log_id=}, {pagination=}, in length: {len(new_events)}")

        for event in new_events:
            event["_TIME"] = event.get("timestamp")
            event["source_log_type"] = "auditlog"

            events.append(event)

            if fetch_limit and len(events) >= fetch_limit:
                last_run["last_log_id"] = event["id"]
                return events

        if pagination and current_pagination + 1 >= pagination:
            break

        # First run - using timestamps
        if "last_log_id" not in body:
            remove_first_run_params(body)
            # we make a new call with new architecture - using last_log_id as filter
            # pagination stays the same
            body["last_log_id"] = last_log_id
        # Not first run -  we have used the "last_log_id" as a filter
        else:
            # Update Params for next call
            current_pagination += 1
            params["page"] = current_pagination

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
            "ID": event.get("id"),
            "Action": event.get("action"),
            "Category": event.get("category"),
            "Description": event.get("description"),
            "Type": event.get("type"),
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
    demisto.debug("AppSentinels.ai test_module invoked")
    last_run: dict[str, Any] = {}
    fetch_events(client, last_run, fetch_limit=1)
    return "ok"


def fetch_events(
    client: Client, last_run: dict, fetch_limit: int | None = None, use_last_run_as_body: bool = False
) -> tuple[list[dict[str, Any]], dict]:
    """Fetch the specified AppSentinels.ai entity records.

     Args:
        client (Client): The client object used to interact with the AppSentinels.ai service.
        last_run (dict): The last_run dictionary having the state of previous cycle.
        fetch_limit (int | None): The maximum number of events to fetch.
        use_last_run_as_body (bool): Flag that sign do we use the last-run as params for the API call

    Returns:
        Tuple[list[dict[str, Any]], dict]: A tuple containing:
         - List of new records to be pushed into XSIAM.
         - Updated last_run dictionary.
    """
    demisto.debug("AppSentinels.ai fetch_events invoked")

    events = []

    output = fetch_events_list(client, last_run, fetch_limit, use_last_run_as_body)
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
    demisto.debug("AppSentinels.ai get_events invoked")
    params_run = {}
    default_max = 50
    max_events = arg_to_number(args.get("limit")) or default_max
    # User start date in the get events arguments
    first_fetch = arg_to_datetime(args.get("first_fetch"))

    if first_fetch:
        first_fetch_date = first_fetch.strftime(DATE_FORMAT)
        params_run.update({"from_date": first_fetch_date})

    output, _ = fetch_events(client, params_run, max_events, use_last_run_as_body=True)
    human_readable = prepare_list_output(output)

    command_results = CommandResults(
        readable_output=human_readable,
        outputs=output,
        outputs_prefix="AppSentinels.ai.",
    )
    return command_results


def main():
    """main function, parses params and runs command functions"""
    demisto.debug("AppSentinels.ai has been called")
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
    fetch_limit = arg_to_number(params.get("max_audit_per_fetch")) or MAX_FETCH_AUDIT_LIMIT
    demisto.debug(f"AppSentinels.ai  - Command being called is {command}")

    try:
        client = Client(
            base_url=base_url,
            user_key=user_key,
            api_key=api_key,
            organization=organization,
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
