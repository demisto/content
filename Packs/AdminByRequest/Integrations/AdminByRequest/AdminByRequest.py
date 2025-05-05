'''
Event Collector Source file for AdminByRequest API.
'''
from enum import EnumMeta
from typing import Any, Dict, Optional

import demistomock as demisto
import urllib3
from CommonServerPython import *
from CommonServerUserPython import *

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

VENDOR = 'Admin'
PRODUCT = 'ByRequest'
MAX_FETCH_AUDIT_LIMIT = 50000
MAX_FETCH_EVENT_LIMIT = 50000
MAX_FETCH_REQUEST_LIMIT = 5000
DEFAULT_TAKE_AUDIT_LOGS = 10000
DEFAULT_TAKE_REQUESTS = 1000
DEFAULT_TAKE_EVENTS = 10000
AUDIT_LOG_CALL_SUFFIX = "auditlog"
REQUESTS_CALL_SUFFIX = "requests"
EVENTS_CALL_SUFFIX = "events"

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API
    """

    def __init__(self, base_url: str, api_key: str, verify: bool, use_proxy: bool) -> None:
        """
          Prepare constructor for Client class.

          Calls the constructor of BaseClient class and updates the header with the authentication token.

          Args:
              # TODO: do I need this url? im not sure
              base_url: The url of ExtraHop instance.
              api_key: The Api key for AdminByRequest API - specific for every licensing.
              verify: True if verify SSL certificate is checked in integration configuration, False otherwise.
              use_proxy: True if the proxy server needs to be used, False otherwise.
          """

        super().__init__(base_url=base_url, verify=verify, proxy=use_proxy)

        self._api_key = api_key
        self._headers: dict[str, Any] = {
            "apiKey": self._api_key
        }

        # TODO: Is there expiration for the API KEY? it dosent seem that way - make sure of that

    def retrieve_from_api(self, url_suffix: str, params: dict) -> dict:
        """Retrieve the detections from AdminByRequest  API.
        """
        return self._http_request(
            "GET", url_suffix=url_suffix, params=params, resp_type="json"
        )


""" HELPER FUNCTIONS """


def get_field_mapping(suffix: str) -> tuple[str, str]:
    if suffix == AUDIT_LOG_CALL_SUFFIX:
        source_log_type = "auditlog"
        time_field = "startTimeUTC"
    elif suffix == REQUESTS_CALL_SUFFIX:
        source_log_type = "request"
        time_field = "requestTime"
    else:
        time_field = "startTimeUTC"
        source_log_type = "event"

    return source_log_type, time_field


# TODO: Delete this
# def fetch_audit_log(client: Client, last_run: dict) -> tuple[list[Any], dict]:
#     """Retrieve full audit log entries from AdminByRequest API using delta logic."""
#     today = get_current_time().strftime("%Y-%m-%d")
#     all_entries = []
#
#     if "start_time_audit_logs" in last_run:
#         start_time = last_run["start_time"]
#     else:
#         # Phase 1: Initial request to get timeNow
#         params = {"startdate": today, "enddate": today}
#         response = client.retrieve_audit_log(params=params)
#         entries = response.get("entries", [])
#         all_entries.extend(entries)
#         start_time = response.get("timeNow")
#
#     # Phase 2: Poll with deltaTime until no more entries
#     while True:
#         #updated params
#         params = {
#             "deltaTime": start_time
#         }
#         # API call
#         response = client.retrieve_audit_log(params=params)
#
#         start_time = response.get("timeNow")
#         new_entries = response.get("entries", [])
#         if not new_entries:
#             break
#         all_entries.extend(new_entries)
#
#     last_run["start_time_audit_logs"] = start_time
#
#     return all_entries, last_run

def remove_first_run_params(params: dict) -> None:
    if "startdate" in params:
        params.pop("startdate")
        params.pop("enddate")


def validate_fetch_events_params(last_run: dict, call_type: str, fetch_limit: int) -> tuple[dict, str, str]:
    today = get_current_time().strftime("%Y-%m-%d")
    # phase 1 Params  - use today date to get the last ID in the first run
    params = {"startdate": today, "enddate": today}

    if call_type == AUDIT_LOG_CALL_SUFFIX:
        suffix = "auditlog"
        take = DEFAULT_TAKE_AUDIT_LOGS
    elif call_type == REQUESTS_CALL_SUFFIX:
        suffix = "requests"
        take = DEFAULT_TAKE_REQUESTS
    else:
        take = DEFAULT_TAKE_EVENTS
        suffix = "events"

    key = "start_id_" + suffix
    # Phase 2 Params: If a call has already been executed then use the last run params.
    if last_run.get(key):
        params = {"startid": last_run[key]}

    take = min(take, fetch_limit)
    params["take"] = take

    return params, suffix, key


def fetch_events_list(client: Client, last_run: dict, call_type: str, fetch_limit: int) -> list[dict[str, Any]]:
    params, suffix, last_run_key = validate_fetch_events_params(last_run, call_type, fetch_limit)
    time_field, source_log_type = get_field_mapping(suffix=suffix)
    last_id: int = 0
    output: list[dict[str, Any]] = []
    while True:
        try:
            # API call
            events = list(client.retrieve_from_api(url_suffix=suffix, params=params))
        except DemistoException as e:
            if e.res.status_code == 429:
                retry_after = int(e.res.headers.get("x-ratelimit-reset", 2))
                demisto.debug(f"Rate limit reached. Waiting {retry_after} seconds before retrying.")
                time.sleep(retry_after)
                continue
            else:
                raise e

        if not events:
            break

        for event in events:
            last_id = event["id"]
            event["_TIME"] = time_field
            event["source_log_type"] = source_log_type

            output.append(event)

            if len(output) >= fetch_limit:
                # update last run and return because we reach limit
                last_run.update({
                    last_run_key: int(last_id + 1)
                })
                return output

        # If it was the first run, we have a first run "params values"
        remove_first_run_params(params)
        params["startid"] = last_id + 1

    last_run.update({
        last_run_key: int(last_id + 1)
    })

    return output


def get_event_type_fetch_limits(params: Dict[str, Any]) -> Dict[str, int]:
    """
    Parses the event types to fetch from parameters and returns a dictionary mapping
    each selected event type's suffix to its corresponding max fetch limit.

    Args:
        params (Dict[str, Any]): Integration parameters.

    Returns:
        Dict[str, int]: Mapping of event type suffix to max fetch count.
    """
    event_types_to_fetch = argToList(params.get("event_types_to_fetch", []))
    event_types_to_fetch = [event_type.strip() for event_type in event_types_to_fetch]

    max_auditlog_per_fetch = arg_to_number(params.get("max_auditlog_per_fetch")) or MAX_FETCH_AUDIT_LIMIT
    max_events_per_fetch = arg_to_number(params.get("max_events_per_fetch")) or MAX_FETCH_EVENT_LIMIT
    max_requests_per_fetch = arg_to_number(params.get("max_requests_per_fetch")) or MAX_FETCH_REQUEST_LIMIT

    fetch_limits = {}

    if "Auditlog" in event_types_to_fetch:
        fetch_limits[AUDIT_LOG_CALL_SUFFIX] = max_auditlog_per_fetch

    if "Events" in event_types_to_fetch:
        fetch_limits[EVENTS_CALL_SUFFIX] = max_events_per_fetch

    if "Requests" in event_types_to_fetch:
        fetch_limits[REQUESTS_CALL_SUFFIX] = max_requests_per_fetch

    return fetch_limits


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """
    Tests the connection to the service by calling each one of the api endpoints.
    Args:
        client (Client): The client object used to interact with the service.
    Returns:
        str: 'ok' if the connection is successful. If an authorization error occurs, an appropriate error message is returned.
    """
    last_run = {}
    fetch_specifications = {AUDIT_LOG_CALL_SUFFIX: 1, EVENTS_CALL_SUFFIX: 1, REQUESTS_CALL_SUFFIX: 1}
    fetch_events(client, last_run, fetch_specifications)
    return "ok"


def fetch_events(client: Client, last_run: dict, fetch_specifications: dict) -> tuple[list[dict[str, Any]], dict]:
    """Fetch the specified AdminByRequest entity.

     Args:
        client: ExtraHop client to be used.
        last_run: The last_run dictionary having the state of previous cycle.
        fetch_specifications : dictionary containing all the deatails of the AdminByRequest API calls tha should be execute
    """
    demisto.debug("AdminByRequest fetch_events invoked")
    events = []

    for api_call, fetch_limit in fetch_specifications.items():
        output = fetch_events_list(client, last_run, api_call, fetch_limit)
        events.extend(output)

    demisto.debug(f"AdminByRequest next_run is {last_run}")

    return events, last_run


def main():
    """main function, parses params and runs command functions"""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    # get the service API url
    base_url = params.get("url")
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    api_key = params.get("api_key", "")
    fetch_specifications = get_event_type_fetch_limits(params)

    demisto.debug(f"Command being called is {command}")
    try:

        client = Client(
            base_url=base_url, api_key=api_key, verify=verify_certificate, use_proxy=proxy
        )

        if command == "test-module":
            # Command made to test the integration
            result = test_module(client)
            return_results(result)
        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            events, next_run = fetch_events(client, last_run, fetch_specifications)
            if len(events):
                demisto.debug(f'Sending {len(events)} events.')
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)
            demisto.debug(f'Successfully saved last_run= {demisto.getLastRun()}')
        elif command == "admin_by_request_get-events":
            command_results = get_events(client, args, max_events)
            events = command_results.outputs
            if events and argToBoolean(args.get('should_push_events')):
                demisto.debug(f'Sending {len(events)} events.')
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            return_results(command_results)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
