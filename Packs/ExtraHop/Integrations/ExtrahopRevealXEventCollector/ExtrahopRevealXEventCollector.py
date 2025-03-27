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
PAGE_SIZE = 200
PAGE_NUMBER = 0
DEFAULT_FETCH_LIMIT = 5000 # TODO Niv: make sure with dar this is the correct value


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

        # Setting up access token in headers.
        self._headers: Dict[str, Any] = {
            "Authorization": f"Bearer {self.get_access_token(client_id=client_id, client_secret=client_secret)}",
            "ExtraHop-Integration": "XSOAR-6.5.0-ExtraHop-2.0.0"
        }

    def get_access_token(self, client_id: str, client_secret: str) -> str:
        """Return the token stored in integration context.

        If the token has expired or is not present in the integration context
        (in the first case), it calls the Authentication function, which
        generates a new token and stores it in the integration context.

        Args:
            client_id: The Client ID to use for authentication.
            client_secret: The Client Secret to use for authentication.

        Returns:
            str: Authentication token stored in integration context.
        """
        integration_context = get_integration_context()
        token = integration_context.get("access_token")
        valid_until = integration_context.get("valid_until")
        time_now = int(time.time())

        # If token exists and is valid, then return it.
        if (token and valid_until) and (time_now < valid_until):
            demisto.info("Extrahop token returned from integration context.")
            return token

        # Otherwise, generate a new token and store it.
        token, expires_in = self.authenticate(client_id=client_id, client_secret=client_secret)
        integration_context = {
            "access_token": token,
            "valid_until": time_now + expires_in,  # Token expiration time - 30 mins
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
        return self._http_request("POST", url_suffix="/api/v1/detections/search", json_data=body)


""" HELPER FUNCTIONS """


def iso8601_to_unix_milliseconds(iso8601_str):
    """
    Convert an ISO 8601 formatted date to a Unix timestamp in milliseconds.

    Parameters:
    iso8601_str (str): The ISO 8601 date string to convert.

    Returns:
    int: Unix timestamp in milliseconds.
    """
    # Parse the ISO 8601 date string to a datetime object
    dt = datetime.fromisoformat(iso8601_str)

    # Get the Unix timestamp in seconds and convert to milliseconds
    unix_timestamp_ms = int(dt.timestamp() * 1000)

    return unix_timestamp_ms

""" COMMAND FUNCTIONS """



def test_module(client: Client) -> str:
    """
    Tests the connection to the service by creating an access token.
    Args:
        client (Client): The client object used to interact with the service.
    Returns:
        str: 'ok' if the connection is successful. If an authorization error occurs, an appropriate error message is returned.
    """
    current_time = get_current_time()
    start_date = (current_time - timedelta(minutes=1)).strftime(DATE_FORMAT)
    end_date = current_time.strftime(DATE_FORMAT)
    fetch_events(client, 1, {'start_date': start_date, 'end_date': end_date})
    return "ok"

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


def detections_list_command(client: BaseClient, args: Dict[str, Any], on_cloud=False,
                            advanced_filter=None) -> CommandResults:
    """Retrieve the detections from Reveal(X).

    Args:
        client: ExtraHop client to be used.
        args: Arguments obtained from demisto.args().
        advanced_filter: The advanced filter provided by user to fetch detections.
        on_cloud: Check if ExtraHop instance is on cloud.

    Returns:
        CommandResults object.
    """
    version = get_extrahop_server_version(client)
    if version < "9.3.0":
        raise DemistoException(
            "This integration works with ExtraHop firmware version greater than or equal to 9.3.0")

    body = {}
    if advanced_filter:
        body = advanced_filter

    else:
        filter_query = args.get("filter")
        from_time = arg_to_number(args.get("from"))
        limit = arg_to_number(args.get("limit"), "200")
        offset = arg_to_number(args.get("offset"))
        sort = args.get("sort")
        until_time = arg_to_number(args.get("until"))
        mod_time = arg_to_number(args.get("mod_time"))
        if filter_query and filter_query.strip():
            try:
                filter_query = json.loads(filter_query)
                add_default_category_for_filter_of_detection_list(filter_query)
                body["filter"] = filter_query
            except json.JSONDecodeError:
                raise ValueError("Invalid json string provided for filter.")
        else:
            body["filter"] = {"categories": ["sec.attack"]}

        if isinstance(from_time, int):
            body["from"] = from_time

        if isinstance(limit, int):
            body["limit"] = limit

        if isinstance(offset, int):
            body["offset"] = offset

        if sort:
            sort_list = []
            sort_on_field = sort.split(",")

            for sort in sort_on_field:
                try:
                    field, direction = sort.split(" ")
                except ValueError:
                    raise DemistoException("Incorrect input provided for argument \"sort\". Please follow the format "
                                           "mentioned in description.")

                if direction not in SORT_DIRECTION:
                    raise DemistoException("Incorrect input provided for argument \"sort\". Allowed values for "
                                           "direction are: " + ", ".join(SORT_DIRECTION))

                prepared_sort_dict = {"direction": direction, "field": field}
                sort_list.append(prepared_sort_dict)

            body["sort"] = sort_list

        if isinstance(until_time, int):
            body["until"] = until_time

        if isinstance(mod_time, int):
            body["mod_time"] = mod_time

    validate_detections_list_arguments(body)

    detections = client.detections_list(body)

    base_url = client._base_url
    if on_cloud:
        base_url = remove_api_from_base_url(base_url)
    for detection in detections:
        if detection.get("description"):
            detection["description"] = modify_description(base_url, detection.get("description"))
    readable_output = prepare_list_detections_output(detections)

    return CommandResults(
        outputs_prefix="ExtraHop.Detections",
        outputs_key_field="id",
        outputs=remove_empty_elements(detections),
        readable_output=readable_output,
        raw_response=detections,
    )


def fetch_extrahop_detections(client: ExtraHopClient, advanced_filter: Dict, last_run: Dict, on_cloud: bool) -> \
        Tuple[List, Dict]:
    """Fetch detections from ExtraHop according to the given filter.

    Args:
        client:ExtraHop client to be used.
        advanced_filter: The advanced_filter given by the user to filter out the required detections.
        last_run: Last run returned by function demisto.getLastRun
        on_cloud: Indicator for the instance hosted on cloud.

    Returns:
        List of incidents to be pushed into XSOAR.
    """
    try:
        already_fetched: List[str] = last_run.get('already_fetched', [])
        incidents: List[Dict] = []
        detection_start_time = advanced_filter["mod_time"]

        detections = detections_list_command(client, {}, on_cloud=on_cloud, advanced_filter=advanced_filter)

        if detections.outputs:
            detections = append_participant_device_data(client, detections)

            for detection in detections.outputs:  # type: ignore
                detection_id = detection.get("id")
                if detection_id not in already_fetched:
                    detection.update(get_mirroring())
                    incident = {
                        'name': str(detection.get("type", "")),
                        'occurred': datetime.utcfromtimestamp(detection['start_time'] / 1000).strftime(
                            DATE_FORMAT),
                        'severity': next((severity for range_str, severity in TICKET_SEVERITY.items() if
                                          detection.get("risk_score") in range(*map(int, range_str.split("-")))), None),
                        'rawJSON': json.dumps(detection)
                    }
                    incidents.append(incident)
                    already_fetched.append(detection_id)

                else:
                    demisto.info(f"Extrahop already fetched detection with id: {detection_id}")

        if len(incidents) < advanced_filter["limit"]:
            offset = 0
            detection_start_time = \
                detections.outputs[-1]["mod_time"] + 1 if incidents else detection_start_time  # type: ignore
        else:
            offset = advanced_filter["offset"] + len(incidents)

    except Exception as error:
        raise DemistoException(f"extrahop: exception occurred {str(error)}")

    demisto.info(f"Extrahop fetched {len(incidents)} incidents where the advanced filter is {advanced_filter}")

    last_run["detection_start_time"] = int(detection_start_time)
    last_run["offset"] = offset
    last_run["already_fetched"] = already_fetched
    return incidents, last_run


def fetch_events(client: Client, fetch_limit: int, get_events_args: dict = None) -> tuple[list, dict]:
    last_run = demisto.getLastRun() or {}
    start_time = (get_events_args or last_run).get('start_date', '') or get_current_time().strftime(DATE_FORMAT)
    end_time = (get_events_args or {}).get('end_date', get_current_time().strftime(DATE_FORMAT))

    if not get_events_args:  # Only set token for fetch_events case
        client.set_token(last_run.get('audit_token', ''))

    demisto.debug(f'Fetching audit logs events from date={start_time} to date={end_time}.')

    output: list = []
    while True:
        try:
            response = client.get_audit_logs(start_time, end_time)
        except DemistoException as e:
            if e.res.status_code == 429:
                retry_after = int(e.res.headers.get('x-ratelimit-reset', 2))
                demisto.debug(f"Rate limit reached. Waiting {retry_after} seconds before retrying.")
                time.sleep(retry_after)  # pylint: disable=E9003
                continue
            if e.res.status_code == 401:
                demisto.debug("Regenerates token for fetching audit logs.")
                client.create_access_token_for_audit()
                continue
            else:
                raise e

        content: list = response.json().get('content', [])

        if not content:
            break

        events = sort_events_by_timestamp(content)
        for event in events:
            event_date = event.get('timestamp')
            event['_time'] = event_date
            output.append(event)

            if len(output) >= fetch_limit:
                start_time = add_millisecond(event_date)
                # Safe to add a millisecond and fetch since no two events share the same timestamp.
                new_last_run = {'start_date': start_time, 'audit_token': client.token}
                return output, new_last_run

        start_time = add_millisecond(event_date)

    new_last_run = {'start_date': start_time, 'audit_token': client.token}
    return output, new_last_run


def get_events(client: Client, args: dict) -> tuple[list, CommandResults]:
    start_date = args.get('start_date')
    end_date = args.get('end_date')
    limit: int = arg_to_number(args.get('limit')) or DEFAULT_FETCH_LIMIT

    output, _ = fetch_events(client, limit, {"start_date": start_date, "end_date": end_date})

    filtered_events = []
    for event in output:
        filtered_event = {'User ID': event.get('userId'),
                          'User Role': event.get('userRole'),
                          'Event': event.get('event'),
                          'Timestamp': event.get('timestamp')
                          }
        filtered_events.append(filtered_event)

    human_readable = tableToMarkdown(name='Audit Logs Events', t=filtered_events, removeNull=True)
    command_results = CommandResults(
        readable_output=human_readable,
        outputs=output,
        outputs_prefix='Celonis.Audit',
    )
    return output, command_results

def fetch_incidents(client: ExtraHopClient, params: Dict, last_run: Dict, on_cloud: bool):
    """Fetch the specified ExtraHop entity and push into XSOAR.

     Args:
        client: ExtraHop client to be used.
        params: Integration configuration parameters.
        last_run: The last_run dictionary having the state of previous cycle.
        on_cloud: Indicator for the instance hosted on cloud.
    """
    demisto.info(f"Extrahop fetch_incidents invoked with advanced_filter: {params.get('advanced_filter', '')}, "
                 f"first_fetch: {params.get('first_fetch', '')} and last_run: {last_run}")
    fetch_params = validate_fetch_incidents_params(params, last_run)

    now = datetime.now()
    next_day = now + timedelta(days=1)
    if last_run.get("version_recheck_time", 1581852287000) < int(now.timestamp() * 1000):
        version = get_extrahop_server_version(client)
        last_run["version_recheck_time"] = int(next_day.timestamp() * 1000)
        if version < "9.3.0":
            raise DemistoException(
                "This integration works with ExtraHop firmware version greater than or equal to 9.3.0")

    advanced_filter = params.get("advanced_filter")
    if advanced_filter and advanced_filter.strip():
        try:
            _filter = json.loads(advanced_filter)
            add_default_category_for_filter_of_detection_list(_filter)
        except json.JSONDecodeError as error:
            raise ValueError("Invalid JSON string provided for advanced filter.") from error
    else:
        _filter = {"categories": ["sec.attack"]}

    advanced_filter = {"filter": _filter, "mod_time": fetch_params["detection_start_time"], "until": 0,
                       "limit": MAX_FETCH, "offset": fetch_params["offset"],
                       "sort": [{"direction": "asc", "field": "mod_time"}]}

    incidents, next_run = fetch_extrahop_detections(client, advanced_filter, last_run, on_cloud)
    demisto.info(f"Extrahop next_run is {next_run}")
    return incidents, next_run


def main():
    """main function, parses params and runs command functions"""
    """main function, parses params and runs command functions"""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    demisto.debug(f"Command being called is {command}")
    try:
        base_url = params.get("server-url")
        verify_certificate = not argToBoolean(params.get("insecure", False))
        client_id = params.get("client_id", "")
        client_secret = params.get("client_secret", "")
        use_proxy: bool = params.get('proxy', False)
        fetch_limit = arg_to_number(params.get('max_events_per_fetch')) or DEFAULT_FETCH_LIMIT

        client = Client(base_url=base_url,
                        verify=verify_certificate,
                        client_id=client_id,
                        client_secret=client_secret,
                        use_proxy=use_proxy,
                        ok_codes=(200, 201, 204))

        if command == "test-module":
            # Command made to test the integration
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)
        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            incidents, next_run = fetch_incidents(client, params, last_run)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
            events, new_last_run_dict = fetch_events(client, fetch_limit)
            if events:
                demisto.debug(f'Sending {len(events)} events.')
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(new_last_run_dict)
            demisto.debug(f'Successfully saved last_run= {demisto.getLastRun()}')
        elif command == "revealx-get-events":
            events, command_results = get_events(client, args)
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
