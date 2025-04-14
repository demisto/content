from typing import Any

import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

VENDOR = 'Extrahop'
PRODUCT = 'RevealX'
MAX_FETCH_LIMIT = 25000
DEFAULT_FETCH_LIMIT = 5000

""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(self, base_url: str, verify: bool, client_id: str, client_secret: str, use_proxy: bool, ok_codes: tuple) -> None:
        """
          Prepare constructor for Client class.

          Calls the constructor of BaseClient class and updates the header with the authentication token.

          Args:
              base_url: The url of ExtraHop instance.
              verify: True if verify SSL certificate is checked in integration configuration, False otherwise.
              client_id: The Client ID to use for authentication.
              client_secret: The Client Secret to use for authentication.
              use_proxy: True if the proxy server needs to be used, False otherwise.
          """

        super().__init__(base_url=base_url, verify=verify, ok_codes=ok_codes, proxy=use_proxy)

        self._client_id = client_id
        self._client_secret = client_secret

    def set_headers(self) -> None:
        """
        Sets headers for requests.
        """
        self._headers: dict[str, Any] = {
            "Authorization": f"Bearer {self.get_access_token()}",
        }

    def get_access_token(self) -> str:
        """Return the token stored in integration context.

        If the token has expired or is not present in the integration context
        (in the first case), it calls the Authentication function, which
        generates a new token and stores it in the integration context.

        Returns:
            str: Authentication token stored in integration context.
        """
        integration_context = get_integration_context()
        token = integration_context.get("access_token")
        valid_until = integration_context.get("valid_until")
        time_now = int(time.time())

        # If token exists and is valid, then return it.
        if (token and valid_until) and (time_now < valid_until):
            return token

        # Otherwise, generate a new token and store it.
        token, expires_in = self.authenticate(client_id=self._client_id, client_secret=self._client_secret)
        integration_context = {
            "access_token": token,
            "valid_until": time_now + expires_in,  # Token expiration time
        }
        set_integration_context(integration_context)

        return token

    def authenticate(self, client_id: str, client_secret: str) -> tuple[str, int]:
        """
        Get the access token from the ExtraHop API.

        Args:
            client_id: The Client ID to use for authentication.
            client_secret: The Client Secret to use for authentication.

        Returns:
            tuple[str,int]: The token and its expiration time in seconds received from the API.
        """
        demisto.debug("Generating new authentication token.")

        req_headers = {
            "cache-control": "no-cache",
            "content-type": "application/x-www-form-urlencoded",
        }
        req_body = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        response = self._http_request(
            method="POST",
            url_suffix="/oauth2/token",
            data=req_body,
            headers=req_headers
        )
        token = response.get("access_token")
        expires_in = response.get("expires_in")

        return token, expires_in

    def detections_list(self, body):
        """Retrieve the detections from Reveal(X).
        """
        # Make sure we have a valid token
        self.set_headers()
        return self._http_request("POST", url_suffix="/api/v1/detections/search", json_data=body)


""" HELPER FUNCTIONS """


def prepare_list_detections_output(detections) -> str:
    """Prepare human-readable output for list-detections command.

    Args:
        detections: List of detection response from the API.

    Returns:
        markdown string to be displayed in the war room.
    """
    hr_outputs = []
    headers = ["Detection ID", "Risk Score", "Description", "Categories", "Status", "Resolution", "Start Time"]
    for detection in detections:
        hr_output = {
            "Detection ID": detection.get("id"),
            "Risk Score": detection.get("risk_score"),
            "Description": detection.get("description"),
            "Categories": detection.get("categories"),
            "Status": detection.get("status"),
            "Start Time": detection.get("start_time"),
            "Mod Time": detection.get("mod_time"),
            "Resolution": detection.get("resolution"),
        }
        hr_outputs.append(hr_output)

    return tableToMarkdown(f"Found {len(hr_outputs)} Detection(s)", hr_outputs, headers=headers, removeNull=True)


def validate_fetch_events_params(last_run: dict) -> dict:
    """
    Validate the parameter list for fetch events.

    Args:
        last_run: last run returned by function demisto.getLastRun

    Returns:
        Dictionary containing validated configuration parameters in proper format.
    """
    detection_start_time = int(get_current_time().timestamp() * 1000)  # type: ignore
    if last_run and 'detection_start_time' in last_run:
        detection_start_time = last_run.get('detection_start_time')  # type: ignore

    offset = 0
    if last_run and 'offset' in last_run:
        offset = last_run.get("offset")  # type: ignore

    return {
        'detection_start_time': detection_start_time,
        'offset': offset,
        'limit': DEFAULT_FETCH_LIMIT
    }



def update_time_values_detections(detections: List[dict[str, Any]]) -> None:
    """
     Updates each detection in the list with _TIME and _ENTRY_STATUS fields based on mod_time, start_time, and update_time.
    Args:
        detections: Detections that came from Reveal(X).
    """
    for detection in detections:
        mod_time = detection.get("mod_time")
        start_time = detection.get("start_time")
        update_time = detection.get("update_time")

        if mod_time:
            detection["_TIME"] = mod_time
            if start_time:
                if mod_time == start_time:
                    detection["_ENTRY_STATUS"] = "new"
                elif mod_time > start_time or (update_time and update_time > start_time):
                    detection["_ENTRY_STATUS"] = "updated"


def get_detections_list(client: Client,
                            advanced_filter=None) -> List[dict[str, Any]]:
    """Retrieve the detections from ExtraHop-Reveal(X).

    Args:
        client: ExtraHop client to be used.
        advanced_filter: The advanced filter provided by user to fetch detections.

    Returns:
        CommandResults object.
    """
    body = advanced_filter
    detections = list(client.detections_list(body))
    # Add Time Params
    update_time_values_detections(detections)
    return detections


def fetch_extrahop_detections(
    client: Client,
    advanced_filter: dict,
    last_run: dict,
    max_events: int,
) -> tuple[List, dict]:
    """
    Fetch detections from ExtraHop according to the given filter.

    Args:
        max_events: Maximum number of events to fetch.
        client: ExtraHop client to be used.
        advanced_filter: The advanced_filter given by the user to filter out the required detections.
        last_run: Last run returned by function demisto.getLastRun.

    Returns:
        - List of new detections to be pushed into XSIAM.
        - Updated last_run dictionary.

    """
    try:
        already_fetched: List = last_run.get("already_fetched", [])
        detection_start_time = advanced_filter["mod_time"]
        events = []

        while True:
            detections = get_detections_list(client, advanced_filter=advanced_filter)

            if not detections:
                # Didn't get any detections or got all duplicates
                break

            # Check if all detections are already fetched
            new_detections = [detection for detection in detections if detection.get("id") not in already_fetched]

            if not new_detections:
                # If no new detections, break the loop to prevent an infinite loop
                demisto.debug("No new detections to fetch, exiting the loop.")
                break

            for detection in new_detections:
                detection_id = detection.get("id")
                already_fetched.append(detection_id)
                events.append(detection)

                if len(events) >= max_events:
                    break

            # hit max_events
            if len(events) >= max_events:
                last_event = events[-1]
                first_event = detections[0]
                # Compare mod_time of last event with the first in this batch
                if new_detections and last_event["mod_time"] == first_event["mod_time"]:
                    # Same mod_time: continue with next offset
                    advanced_filter["offset"] += len(detections)
                    detection_start_time = events[-1]["mod_time"]
                else:
                    # Different mod_time: reset offset and bump mod_time
                    detection_start_time = events[-1]["mod_time"] + 1
                    advanced_filter["offset"] = 0
                break  # We've hit the max, exit loop

            # didn't hit max_events, continue fetching
            # edge case where we got same mod_time for all detections
            if detections[-1]["mod_time"] == detections[0]["mod_time"] and len(detections) == advanced_filter["limit"]:
                advanced_filter["offset"] += len(detections)
            else:
                detection_start_time = events[-1]["mod_time"] + 1 if events else detection_start_time
                advanced_filter["mod_time"] = detection_start_time
                advanced_filter["offset"] = 0


    except Exception as error:
        raise DemistoException(f"extrahop: exception occurred {str(error)}")

    demisto.debug(f"Extrahop fetched {len(events)} events with the advanced filter: {advanced_filter}")

    last_run.update({
        "detection_start_time": int(detection_start_time),
        "offset": advanced_filter["offset"],
        "already_fetched": already_fetched
    })

    return events, last_run


""" COMMAND FUNCTIONS """

def test_module(client: Client) -> str:
    """
    Tests the connection to the service by creating an access token.
    Args:
        client (Client): The client object used to interact with the service.
    Returns:
        str: 'ok' if the connection is successful. If an authorization error occurs, an appropriate error message is returned.
    """
    last_run = {
        'detection_start_time': int(get_current_time().timestamp() * 1000) ,
        'offset': 0
    }
    fetch_events(client, last_run, 1)
    return "ok"


def fetch_events(client: Client, last_run: dict, max_events: int):
    """Fetch the specified ExtraHop entity and push into XSIAM.

     Args:
        max_events: max events to fetch
        client: ExtraHop client to be used.
        last_run: The last_run dictionary having the state of previous cycle.
    """
    demisto.debug("Extrahop fetch_events invoked")
    fetch_params = validate_fetch_events_params(last_run)

    advanced_filter = {"mod_time": fetch_params["detection_start_time"],
                       "limit": fetch_params["limit"], "offset": fetch_params["offset"],
                       "sort": [{"direction": "asc", "field": "mod_time"}]}

    events, next_run = fetch_extrahop_detections(client, advanced_filter, last_run, max_events)
    demisto.debug(f"Extrahop next_run is {next_run}")
    return events, next_run


def get_events(client: Client, args: dict, max_events: int) -> CommandResults:
    """
    Inner Test Function to make sure the integration works
    Args:
        client: ExtraHop client to be used.
        args: command arguments.
        max_events: Max events to fetch.

    Returns: Tuple that contains events that been fetched and the Command results.
    """
    max_events = arg_to_number(args.get("limit")) or max_events
    first_fetch = arg_to_datetime(args.get("first_fetch")) or get_current_time()

    # if the user limits in the get events arguments
    last_run = {
        'detection_start_time': int(first_fetch.timestamp() * 1000),
        'offset': 0,
    }

    output, _  = fetch_events(client, last_run, max_events)
    human_readable = prepare_list_detections_output(output)

    command_results = CommandResults(
        readable_output=human_readable,
        outputs=output,
        outputs_prefix="ExtraHop.Detections",
    )
    return command_results


def main():
    """main function, parses params and runs command functions"""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    demisto.debug(f"Command being called is {command}")
    try:
        base_url = params.get("server_url")
        verify_certificate = not argToBoolean(params.get("insecure", False))
        client_id = params.get("credentials", {}).get("identifier")
        client_secret = params.get("credentials", {}).get("password")
        use_proxy: bool = params.get('proxy', False)
        max_events = arg_to_number(params.get('max_events_per_fetch')) or MAX_FETCH_LIMIT

        client = Client(base_url=base_url,
                        verify=verify_certificate,
                        client_id=client_id,
                        client_secret=client_secret,
                        use_proxy=use_proxy,
                        ok_codes=(200, 201, 204))

        if command == "test-module":
            # Command made to test the integration
            result = test_module(client)
            return_results(result)
        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            events, next_run = fetch_events(client, last_run, max_events)
            if len(events):
                demisto.debug(f'Sending {len(events)} events.')
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)
            demisto.debug(f'Successfully saved last_run= {demisto.getLastRun()}')
        elif command == "revealx-get-events":
            command_results = get_events(client, args, max_events)
            events = command_results.outputs
            if events and argToBoolean(args.get('should_push_events')):
                demisto.debug(f'Sending {len(events)} events.')
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            return_results(command_results)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
