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

    def retrieve_from_api(self, url_suffix: str, params:dict) -> dict:
        """Retrieve the detections from AdminByRequest  API.
        """
        return self._http_request(
            "GET", url_suffix="/" + url_suffix, params=params, resp_type="json"
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


def validate_fetch_events_params(last_run : dict, call_type: str, fetch_limit:int) -> tuple[dict, str, str]:
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


def fetch_events_list(client: Client, last_run: dict, call_type: str, fetch_limit: int) ->  list[dict[str, Any]]:

    params, suffix, last_run_key = validate_fetch_events_params(last_run, call_type, fetch_limit)
    time_field, source_log_type = get_field_mapping(suffix=suffix)
    last_id : int = 0
    output : list[dict[str, Any]] = []
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


def remove_first_run_params(params: dict) -> None:
    if "startdate" in params:
        params.pop("startdate")
        params.pop("enddate")


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises:
     exceptions if something goes wrong.

    Args:
        Client: client to use

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    # TODO: ADD HERE some code to test connectivity and authentication to your service.
    # This  should validate all the inputs given in the integration configuration panel,
    # either manually or by using an API that uses them.
    client.baseintegration_dummy("dummy", 10)  # No errors, the api is working
    return "ok"


# TODO: REMOVE the following dummy command function
def baseintegration_dummy_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    dummy = args.get("dummy")  # dummy is a required argument, no default
    dummy2 = args.get("dummy2")  # dummy2 is not a required argument

    # Call the Client function and get the raw response
    result = client.baseintegration_dummy(dummy, dummy2)

    return CommandResults(
        outputs_prefix="BaseIntegration",
        outputs_key_field="",
        outputs=result,
    )


# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client


def main():
    """main function, parses params and runs command functions"""

    # TODO: make sure you properly handle authentication
    # api_key = params.get('apikey')

    params = demisto.params()
    # get the service API url
    base_url = urljoin(params.get("url"), "/api/v1")

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not argToBoolean(params("insecure", False))

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = argToBoolean(params.get("proxy", False))

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:

        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})
        headers = {}

        client = Client(
            base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy
        )
        args = demisto.args()
        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
        # TODO: REMOVE the following dummy command case:
        elif command == "baseintegration-dummy":
            result = baseintegration_dummy_command(client, args)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
        return_results(
            result
        )  # Returns either str, CommandResults and a list of CommandResults
    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
