from typing import Any, Dict, Optional

import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
VENDOR = 'Extrahop'
PRODUCT = 'RevealX'
MAX_FETCH_LIMIT = 25000
DEFAULT_FETCH_LIMIT = 5000
BASE_TIME_CHECK_VERSION_PARAM = 1581852287000

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

        # Setting up access token in headers.
        self.set_headers()

    def set_headers(self):
        self._headers: Dict[str, Any] = {
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
        demisto.info("Generating new authentication token.")

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

    def get_extrahop_version(self):
        """Retrieve the ExtraHop version."""
        return self._http_request(method="GET", url_suffix="/api/v1/extrahop/version")

    def detections_list(self, body):
        """Retrieve the detections from Reveal(X).

        Returns:
            Response from the API.
        """
        # Make sure we have a valid token
        self.set_headers()
        return self._http_request("POST", url_suffix="/api/v1/detections/search", json_data=body)


""" HELPER FUNCTIONS """


def trim_spaces_from_args(args: Dict) -> Dict:
    """Trim spaces from values of the args dict.

    Args:
        args: Dict to trim spaces from.

    Returns:
        Arguments after trim spaces.
    """
    for key, val in args.items():
        if isinstance(val, str):
            args[key] = val.strip()

    return args


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


def validate_version(client, last_run):
    now = datetime.now()
    next_day = now + timedelta(days=1)
    if last_run.get("version_recheck_time", BASE_TIME_CHECK_VERSION_PARAM) < int(now.timestamp() * 1000):
        last_run["version_recheck_time"] = int(next_day.timestamp() * 1000)
        version = get_extrahop_server_version(client)
        if version < "9.3.0":
            raise DemistoException(
                "This integration works with ExtraHop firmware version greater than or equal to 9.3.0")

def validate_fetch_events_params(last_run: dict) -> Dict:
    """
    Validate the parameter list for fetch incidents.

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

    limit = DEFAULT_FETCH_LIMIT
    if last_run and 'limit' in last_run:
        limit = last_run.get("limit") # type: ignore

    return {
        'detection_start_time': detection_start_time,
        'offset': offset,
        'limit': limit
    }

def get_extrahop_server_version(client: Client):
    """Retrieve and parse the extrahop server version.

    Args:
        client: ExtraHop client to be used.

    Returns:
        The parsed version of the current extrahop server.

    """
    version = client.get_extrahop_version().get("version")
    temp = version.split(".")
    version = ".".join(temp[:3])
    return version


def update_time_values_detections(detections: List[Dict[str, Any]]) -> None:
    """
    Add Requested Time Fields to detections list.
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
                            advanced_filter=None) -> List[Dict[str, Any]]:
    """Retrieve the detections from Reveal(X).

    Args:
        client: ExtraHop client to be used.
        advanced_filter: The advanced filter provided by user to fetch detections.

    Returns:
        CommandResults object.
    """
    body = advanced_filter
    trim_spaces_from_args(body)
    detections = list(client.detections_list(body))
    # Add Time Params
    update_time_values_detections(detections)
    return detections


def fetch_extrahop_detections(
    client: Client,
    advanced_filter: Dict,
    last_run: Dict,
    max_events: int,
) -> tuple[List, Dict]:
    """
    Fetch detections from ExtraHop according to the given filter.

    Args:
        max_events: Maximum number of events to fetch.
        client: ExtraHop client to be used.
        advanced_filter: The advanced_filter given by the user to filter out the required detections.
        last_run: Last run returned by function demisto.getLastRun.

    Returns:
        List of incidents to be pushed into XSIAM.
    """
    try:
        already_fetched: List[str] = last_run.get("already_fetched", [])
        detection_start_time = advanced_filter["mod_time"]
        events = []

        while True:
            detections = get_detections_list(client, advanced_filter=advanced_filter)

            if not detections:
                # Didn't get any detections or got all duplicates
                break

            for detection in detections:  # type: ignore
                detection_id = detection.get("id")
                if detection_id in already_fetched:
                    demisto.info(f"Extrahop already fetched detection with id: {detection_id}")
                    continue

                already_fetched.append(detection_id)
                events.append(detection)

                if len(events) == max_events:
                    break

            # edge case where we got same mod_time for all detections
            if detections[-1]["mod_time"] == detections[0]["mod_time"] and detections[0]["mod_time"] == detection_start_time:
                advanced_filter["offset"] = advanced_filter["offset"] + len(detections)
            else:
                # Prepare for the next batch of detections
                detection_start_time = events[-1]["mod_time"] + 1  # type: ignore
                advanced_filter["mod_time"] = detection_start_time
                advanced_filter["offset"] = 0

            if len(events) == max_events:
                break



    except Exception as error:
        raise DemistoException(f"extrahop: exception occurred {str(error)}")

    demisto.info(f"Extrahop fetched {len(events)} events with the advanced filter: {advanced_filter}")

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
        'offset': 0,
        'limit': 1
    }
    fetch_events(client, last_run, 1)
    return "ok"


def fetch_events(client: Client, last_run: Dict, max_events: int):
    """Fetch the specified ExtraHop entity and push into XSIAM.

     Args:
        max_events: max events to fetch
        client: ExtraHop client to be used.
        last_run: The last_run dictionary having the state of previous cycle.
    """
    demisto.info(f"Extrahop fetch_events invoked")
    fetch_params = validate_fetch_events_params(last_run)

    validate_version(client, last_run)

    advanced_filter = {"mod_time": fetch_params["detection_start_time"],
                       "limit": fetch_params["limit"], "offset": fetch_params["offset"],
                       "sort": [{"direction": "asc", "field": "mod_time"}]}

    events, next_run = fetch_extrahop_detections(client, advanced_filter, last_run, max_events)
    demisto.info(f"Extrahop next_run is {next_run}")
    return events, next_run


def get_events(client: Client, args: dict, max_events: int) -> tuple[list, CommandResults]:
    """
    Inner Test Function to make sure the integration works
    Args:
        client: ExtraHop client to be used.
        args: command arguments.
        max_events: Max events to fetch.

    Returns: Tuple that contains events that been fetched and the Command results.
    """
    if args.get("first_fetch"):
        first_fetch = arg_to_datetime(args.get("first_fetch"))
    else:
        first_fetch = get_current_time()
    # if the user limits in the get events arguments
    last_run = {
        'detection_start_time': int(first_fetch.timestamp() * 1000),
        'offset': 0,
        'limit': DEFAULT_FETCH_LIMIT
    }

    output, _  = fetch_events(client, last_run, max_events)
    human_readable = prepare_list_detections_output(output)

    command_results = CommandResults(
        readable_output=human_readable,
        outputs=output,
        outputs_prefix="ExtraHop.Detections",
    )
    return output, command_results


def main():
    """main function, parses params and runs command functions"""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    demisto.debug(f"Command being called is {command}")
    try:
        base_url = params.get("server_url")
        verify_certificate = not argToBoolean(params.get("insecure", False))
        client_id = params.get("client_id", "")
        client_secret = params.get("client_secret", "")
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
            demisto.debug(f'Finish fetch_events with {len(events)} events')
            if len(events):
                demisto.debug(f'Sending {len(events)} events.')
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)
            demisto.debug(f'Successfully saved last_run= {demisto.getLastRun()}')
        elif command == "revealx-get-events":
            max_events = arg_to_number(args.get("max_events")) or max_events
            events, command_results = get_events(client, args, max_events)
            if events and argToBoolean(args.get('should_push_events')):
                demisto.debug(f'xuSending {len(events)} events.')
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            return_results(command_results)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
