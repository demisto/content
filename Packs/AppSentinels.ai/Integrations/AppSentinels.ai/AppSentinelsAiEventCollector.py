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

BASE_EVENT_BODY: dict = {
    "aggregation": False,
    "api_id": 0,
    "category": [
        "CRS", "SchemaValidation", "SmartAlerts", "Reputation", "UsageAnomaly", "BehaviourAnomal",
        "GeolocationAler", "PassiveScan", "ActiveScan", "AutomatedThreat", "Governance"
    ],
    "include_runtime_scan": False,
    "severity": [
        "critical", "major", "minor", "info"
    ],
    "type": ["security_events", "vulnerabilities"]
}

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API"""

    def __init__(self, base_url: str, user_key: str, api_key: str, organization: str, application: str, base_event_body: dict,
                 verify: bool,
                 use_proxy: bool) -> None:
        """
        Prepare constructor for Client class.

        Calls the constructor of BaseClient class and updates the header with the authentication token.

        Args:
            base_url: The url of AppSentinels.ai instance.
            user_key: The user key for AppSentinels.ai API.
            api_key: The Api key for AppSentinels.ai API - specific for every licensing.
            organization: The organization ID for AppSentinels.ai API.
            application: The application ID for AppSentinels.ai API.
            verify: True if verify SSL certificate is checked in integration configuration, False otherwise.
            use_proxy: True if the proxy server needs to be used, False otherwise.
        """

        super().__init__(base_url=base_url, verify=verify, proxy=use_proxy)
        self._headers = {
            'accept': 'application/json',
            'apikey': api_key,
            'x-user-key': user_key,
            'Content-Type': 'application/json'
        }
        self.organization = organization
        self.application = application
        self.base_event_body = base_event_body

    def get_events_request(self, params: dict) -> dict:
        """Retrieve the detections from AdminByRequest  API."""
        url_suffix = f'/api/v1/{self.organization}/{self.application}/events'
        body = self.base_event_body.copy()
        body.update(params)
        return self._http_request("POST", url_suffix=url_suffix, headers=self._headers, json_data=body, resp_type="json")


""" HELPER FUNCTIONS """


def fetch_events_list(client: Client, last_run: dict, use_last_run_as_params) -> list[dict[str, Any]]:
    """
    Main Function that Handles the Fetch action to the API service of AppSentinels.ai.
    Args:
        client (Client): The client object used to interact with the AppSentinels.ai service.
        last_run (dict): The last_run dictionary having the state of previous cycle.
        event_type (EventType): Event Type to fetch from API
        use_last_run_as_params (bool): Flag that sign do we use the last-run as params for the API call

    Returns:
        list[dict[str, Any]]: List of records retrieved from the api call.
    """
    params, suffix, last_run_key = validate_fetch_events_params(last_run, event_type, use_last_run_as_params)
    time_field, source_log_type = event_type.time_field, event_type.source_log_type
    fetch_limit = event_type.max_fetch
    last_id: int = 0
    output: list[dict[str, Any]] = []
    while True:
        try:
            # API call
            events = list(client.get_events_request(url_suffix=suffix, params=params))
        except DemistoException as error:
            err_type = getattr(error, "exception", None)
            # If we have a Connection error with the server - return clean error message
            if isinstance(err_type, requests.exceptions.ConnectionError):
                clean_msg = str(error).split("\nError Type")[0]
                raise DemistoException(f"AppSentinels.ai: During fetch, exception occurred {clean_msg}")
            else:
                raise DemistoException(f"AppSentinels.ai: During fetch, exception occurred {str(error)}")

        if not events:
            break

        for event in events:
            #  Updates each records in the list with _TIME and source_log_type fields
            #  based on specific fields for each EventType.
            last_id = event["id"]
            event["_TIME"] = time_field
            event["source_log_type"] = source_log_type

            output.append(event)

            if len(output) >= fetch_limit:
                # update last run and return because we reach limit
                last_run.update({last_run_key: int(last_id + 1)})
                return output

        # If it was the first run, we have a first run "params values"
        remove_first_run_params(params)
        params["startid"] = last_id + 1

    # If we got at list one entity to add to output - update last ID
    if last_id:
        last_run.update({last_run_key: int(last_id + 1)})

    return output


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """
    Tests the connection to the service by calling each one of the api endpoints.
    Args:
        client (Client): The client object used to interact with the service.
    Returns:
        str: 'ok' if the connection is successful. If an authorization error occurs, an appropriate error message is returned.
    """
    event_types = list(EVENT_TYPES.values())
    for e in event_types:
        e.max_fetch = 1
    last_run: dict[str, Any] = {}
    fetch_events(client, last_run, event_types)
    return "ok"


def fetch_events(
    client: Client, last_run: dict, use_last_run_as_params: bool = False
) -> tuple[list[dict[str, Any]], dict]:
    """Fetch the specified AppSentinels.ai entity records.

     Args:
        client (Client): The client object used to interact with the AppSentinels.ai service.
        last_run (dict): The last_run dictionary having the state of previous cycle.
        use_last_run_as_params (bool): Flag that sign do we use the last-run as params for the API call

    Returns:
         - List of new records to be pushed into XSIAM.
         - Updated last_run dictionary.
    """
    demisto.debug("AppSentinels.ai fetch_events invoked")
    events = []

    output = fetch_events_list(client, last_run, event_type, use_last_run_as_params)
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
    max_events = arg_to_number(args.get("limit")) or None
    # User start date in the get events arguments, else get from today
    first_fetch = arg_to_datetime(args.get("first_fetch")) or get_current_time()
    first_fetch_date = first_fetch.strftime(DATE_FORMAT_CALLS)

    call_type: str = args.get("event_type", "")
    if not max_events:
        if call_type == "Auditlog":
            max_events = MAX_FETCH_AUDIT_LIMIT
        elif call_type == "Events":
            max_events = MAX_FETCH_EVENT_LIMIT
        else:
            max_events = MAX_FETCH_REQUEST_LIMIT

    event_type = EVENT_TYPES[call_type]
    event_type.max_fetch = max_events

    first_parm = {"startdate": first_fetch_date}

    last_run_to_use_as_params = {**event_type.default_params, **first_parm}

    output, _ = fetch_events(client, last_run_to_use_as_params, [event_type], use_last_run_as_params=True)
    human_readable = prepare_list_output(output)

    command_results = CommandResults(
        readable_output=human_readable,
        outputs=output,
        outputs_prefix="AppSentinels.ai." + call_type,
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
        client = Client(base_url=base_url, api_key=api_key, verify=verify_certificate, use_proxy=proxy)
        events: List[dict[str, Any]]
        if command == "test-module":
            # Command made to test the integration
            result = test_module(client)
            return_results(result)
        elif command == "fetch-events":
            fetch_events_types = set_event_type_fetch_limit(params)
            last_run = demisto.getLastRun()
            events, next_run = fetch_events(client, last_run, fetch_events_types)
            if len(events):
                demisto.debug(f"Sending {len(events)} events to XSIAM AppSentinels.ai, before server call.")
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)
            demisto.debug(f"Successfully saved last_run= {demisto.getLastRun()}")
        elif command == "AppSentinels.ai-get-events":
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
