from CommonServerPython import *
from CommonServerUserPython import *


''' CONSTANTS '''
VENDOR = 'Jamf'
PRODUCT = 'Protect'
ASSETS_PRODUCT = 'protect_computers'
ALERT_PAGE_SIZE = 200
AUDIT_PAGE_SIZE = 5000
COMPUTER_PAGE_SIZE = 100
DEFAULT_MAX_FETCH_ALERT = 1000
DEFAULT_MAX_FETCH_AUDIT = 20000
COMPUTER_MAX_FETCH = 500
DEFAULT_LIMIT = 10
MINUTES_BEFORE_TOKEN_EXPIRED = 2
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'


''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url: str, verify: bool, client_id: str = "", client_password: str = "", proxy: bool = False):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.token = self._login(client_id, client_password)

    def _login(self, client_id: str, client_password: str) -> str:
        """
        This method is used to log in to the client. It first checks if a valid token exists in the integration context.
        If a valid token is found, it returns the token. If not, it creates a new token.

        Args:
            client_id (str): The client ID used for authentication.
            client_password (str): The client password used for authentication.

        Returns:
            str: The authentication token.
        """
        integration_context = get_integration_context()
        if token := integration_context.get('token'):
            expires_date = integration_context.get('expires')
            if expires_date and not self._is_token_expired(expires_date):
                return token
        return self._create_new_token(client_id, client_password)

    def _is_token_expired(self, expires_date: str) -> bool:
        """
        This method checks if the token is expired.

        Args:
            expires_date (str): The expiration date of the token.

        Returns:
            bool: True if the token is expired, False otherwise.
        """
        utc_now = get_current_time()
        expires_datetime = arg_to_datetime(expires_date)
        return utc_now < expires_datetime

    def _create_new_token(self, client_id: str, client_password: str) -> str:
        """
        This method generates a new authentication token and stores it in the integration context.

        Args:
            client_id (str): The client ID used for authentication.
            client_password (str): The client password used for authentication.

        Returns:
            str: The newly generated authentication token.
        """
        try:
            res = self._generate_token(client_id, client_password)
        except DemistoException as e:
            if "Unauthorized" in str(e):
                raise DemistoException("Failed to generate a token. Either the Client ID or the Client Password is incorrect.")
            raise e
        new_token = res.get("access_token", "")
        expire_in = arg_to_number(res.get("expires_in")) or 1
        self._store_token_in_context(new_token, expire_in)
        return new_token

    def _store_token_in_context(self, token: str, expire_in: int) -> None:
        """
        This method stores the generated token and its expiration date in the integration context.

        Args:
            token (str): The generated authentication token.
            expire_in (int): The number of seconds until the token expires.

        Returns:
            None
        """
        expire_date = get_current_time() + timedelta(seconds=expire_in) - timedelta(minutes=MINUTES_BEFORE_TOKEN_EXPIRED)
        set_integration_context({"token": token, "expire_date": str(expire_date)})

    def _generate_token(self, client_id: str, client_password: str) -> dict:
        """
        This method generates a reusable access token to authenticate requests to the Jamf Protect API.

        Args:
            client_id (str): The client ID used for authentication.
            client_password (str): The client password used for authentication.

        Returns:
            dict: The response from the API, which includes the access token.
        """
        json_data = {
            "client_id": client_id,
            "password": client_password,
        }
        return self._http_request(
            method="POST",
            url_suffix="/token",
            json_data=json_data,
        )

    def handle_errors(self, res: dict) -> None:
        """
        Handles errors in the response from the Jamf Protect API.

        This method checks if the response contains any errors. If it does, it raises an exception with the error messages.

        Args:
            res (dict): The response from the Jamf Protect API.

        Raises:
            DemistoException: If the response contains any errors.
        """
        if "errors" in res:
            demisto.debug(f"Erroneous response: {res}")
            errors = "\n".join([error.get("message") for error in res.get("errors", [])])
            raise DemistoException(errors, res=res)

    def graphql(self, query: str, variables: dict) -> dict:
        """
        Sends a GraphQL query to the Jamf Protect API.

        Args:
            query (str): The GraphQL query string.
            variables (dict): The variables to be used in the GraphQL query.

        Returns:
            dict: The response from the API.
        """
        json_data = {
            "query": query,
            "variables": variables
        }
        headers = {"Authorization": self.token}
        res = self._http_request(
            method="POST",
            url_suffix="/graphql",
            headers=headers,
            json_data=json_data,
            retries=3
        )
        self.handle_errors(res)
        return res

    def get_data(self, event_type: str, next_page: str = "", args: dict = {}) -> dict:
        """
        Fetches data from the Jamf Protect API based on the event type.

        Args:
            event_type (str): The type of data to retrieve. Possible values: "alert", "computers", "audit".
            next_page (str): The token for the next page of results, used for pagination. Default is "".
            args (dict): A dictionary of arguments for the GraphQL query. Default is {}.

        Returns:
            dict: The API response containing the requested data and pagination information.
        """
        query = ""
        if event_type == "alert":
            query = """
            query listAlerts($created: AWSDateTime, $page_size: Int, $next: String) {
                listAlerts(
                    input: {
                        filter: {
                            created: {
                                greaterThan: $created
                            }
                        },
                        pageSize: $page_size,
                        next: $next
                    }
                ) {
                    items {
                        json
                        severity
                        computer {hostName}
                        created
                    }
                    pageInfo {
                        next
                        total
                    }
                }
            }
            """
            variables = assign_params(
                page_size=ALERT_PAGE_SIZE,
                next=next_page
            )
            if not next_page:
                variables["created"] = args.get("created")

        elif event_type == "audit":
            query = """
            query listAuditLogsByDate($input: AuditLogsDateQueryInput) {
                listAuditLogsByDate(input: $input) {
                    items {
                        date
                        args
                        error
                        ips
                        op
                        user
                        resourceId
                    }
                    pageInfo {
                        next
                        total
                    }
                }
            }
            """

            variables = {
                "input": assign_params(
                    pageSize=AUDIT_PAGE_SIZE,
                    next=next_page
                )
            }
            if not next_page:
                variables["input"]["condition"] = {
                    "dateRange": {
                        "startDate": args.get("created"),
                        "endDate": args.get("end_date"),
                    }
                }

        elif event_type == "computers":
            query = """
                query listComputers($page_size: Int, $next: String) {
                    listComputers( input: {
                        pageSize: $page_size
                        next: $next
                    }) {
                        items {
                            serial
                            uuid
                            provisioningUDID
                            updated
                            checkin
                            connectionStatus
                            lastConnection
                            lastConnectionIp
                            lastDisconnection
                            lastDisconnectionReason
                            insightsUpdated
                            insightsStatsFail
                            insightsStatsPass
                            insightsStatsUnknown
                            version
                            signaturesVersion
                            installType
                            plan {
                                hash
                                id
                                name
                                logLevel
                            }
                            scorecard {
                                uuid
                                label
                                section
                                pass
                                tags
                                enabled
                            }
                            osMajor
                            osMinor
                            osPatch
                            osString
                            arch
                            certid
                            configHash
                            created
                            hostName
                            kernelVersion
                            memorySize
                            modelName
                            label
                            webProtectionActive
                            fullDiskAccess
                            tags
                        }
                        pageInfo {
                            next
                            total
                        }
                    }
                }
            """
            variables = assign_params(
                page_size=COMPUTER_PAGE_SIZE,
                next=next_page
            )

        demisto.debug(f"fetching event type: '{event_type}' with variables: {variables}")

        return self.graphql(query, variables)


def test_module(client: Client, params) -> str:
    """
    Tests the connectivity and functionality of the client.

    Args:
        client (Client): The client object used to interact with the API.
        params (dict): Configuration parameters.

    Returns:
        str: "ok" if the client can interact with the API successfully, otherwise raises an exception.
    """
    is_fetch_events = params.get("isFetchEvents", False)
    is_fetch_assets = params.get("isFetchAssets", False)

    if not (is_fetch_events or is_fetch_assets):
        raise DemistoException("At least one option must be enabled: 'Fetch Events' or 'Fetch Assets'.")

    if is_fetch_events:
        fetch_events(client, max_fetch_audits=1, max_fetch_alerts=1)

    if is_fetch_assets:
        fetch_assets(client, max_fetch=1)

    return "ok"


def get_events(
    client,
    event_type,
    max_fetch: int,
    next_page: str = "",
    command_args: dict = {}
) -> tuple[list[dict], dict]:
    """
    Fetches events from the Jamf Protect API.

    Args:
        command_args (dict): The arguments to be used in the client function.
         It should contain keys representing the required arguments for the client function.
        client_event_type_func (Callable): The client function to be used for fetching the events.
        max_fetch (int): The maximum number of events to fetch.
        next_page (str, optional): The next page token for pagination. Defaults to "".

    Returns:
        tuple: A tuple containing two elements:
            - A list of dictionaries. Each dictionary represents an event.
            - A dictionary representing the page info for pagination.
    """
    events: list[dict] = []
    page_info = {}

    while True:
        if len(events) >= max_fetch:
            demisto.debug(f"Reached {event_type} max fetch ({max_fetch}).")
            break

        response = client.get_data(event_type, next_page, command_args)
        page_info, parsed_data = parse_response(response=response)

        events.extend(parsed_data)
        demisto.debug(f"Fetched {len(parsed_data)} events. Total so far: {len(events)}.")
        next_page = page_info.get("next", "")

        if not next_page:
            demisto.debug(f"No next page, stopping fetch loop, total fetched for type {event_type}: {len(events)}")
            break

    add_fields_to_events(events, event_type)

    return events, page_info


def get_events_for_type(
    client: Client, last_run: dict, event_type: str, max_fetch: int, start_date: str = "", end_date: str = ""
) -> tuple[list[dict], dict]:
    """
    Fetches events from the Jamf Protect API within a specified date range.

    This function fetches computer type events from the Jamf Protect API based on the provided start date.
    It fetches events up to the maximum number specified by max_fetch.
    The function also uses the information from the last run to continue fetching from where it left off in the previous run.

    Args:
        client (Client): An instance of the Client class for interacting with the API.
        start_date (str): The start date for fetching events in '%Y-%m-%dT%H:%M:%SZ' format.
        max_fetch (int): The maximum number of events to fetch.
        last_run (dict): A dictionary containing information about the last run.

    Returns:
        tuple: A tuple containing two elements:
            - A list of dictionaries. Each dictionary represents an event.
            - A dictionary with new last run values,
             the end date of the fetched events and a continuance token if the fetched reached the max limit.
    """
    created, current_date = calculate_fetch_dates(start_date, last_run, end_date)
    command_args = {"created": created, "end_date": current_date}
    next_page = last_run.get("next_page", "")

    events, page_info = get_events(client, event_type, max_fetch, next_page, command_args)
    filtered_events = [event for event in events if (event.get("date") or event.get(
        "created")) != last_run.get("last_fetch")] if events else events
    demisto.debug(f"Filtered out {len(events)-len(filtered_events)} duplicate events.")

    latest_event = max(filter(None, (arg_to_datetime(event.get("created") or event.get("date"), DATE_FORMAT)
                                     for event in filtered_events))).strftime(DATE_FORMAT) if filtered_events else current_date

    new_last_fetch_date = max(created, latest_event)
    new_last_run = {"last_fetch": new_last_fetch_date}

    if page_info.get("next") and filtered_events:
        new_last_run["next_page"] = page_info.get("next", "")

    return filtered_events, new_last_run


def fetch_events(client: Any, max_fetch_alerts: int, max_fetch_audits: int, last_run: dict = {}) -> tuple[list[dict], dict]:
    """
    Fetches events for multiple event types from the Jamf Protect API.

    Args:
        client (Any): API client instance.
        last_run (dict): Last run state.
        max_fetch_alerts (int): Max number of alerts to fetch.
        max_fetch_audits (int): Max number of audits to fetch.

    Returns:
        tuple: A tuple containing:
            - An updated last run state.
            - A combined list of fetched events.
    """
    events = []
    next_run: dict[str, Any] = {}
    event_types = {"alert": max_fetch_alerts, "audit": max_fetch_audits}

    for event_type, max_fetch in event_types.items():
        next_trigger_for = last_run.get("next_trigger_for", list(event_types.keys()))
        if event_type not in next_trigger_for:
            continue  # Skip event types not in the trigger list

        fetched_events, updated_last_run = get_events_for_type(client, last_run.get(event_type, {}), event_type, max_fetch)
        events.extend(fetched_events)
        next_run[event_type] = updated_last_run
        if updated_last_run.get("next_page"):
            next_run.setdefault("next_trigger_for", []).append(event_type)

    if "next_trigger_for" in next_run:
        next_run["nextTrigger"] = "0"

    return events, next_run


def fetch_assets(client, assets_last_run={}, max_fetch=COMPUTER_MAX_FETCH):
    """
    Fetches computers assets from the Jamf Protect API.

    Args:
        client (Any): API client instance.
        assets_last_run (dict): Last run state for assets.

    Returns:
        tuple: A tuple containing:
            - A list of fetched assets.
            - An updated last run state.
            - Total assets count.
            - Snapshot ID.
    """
    next_page = assets_last_run.get('next_page', '')
    snapshot_id = assets_last_run.get('snapshot_id', str(round(time.time() * 1000)))

    assets, page_info = get_events(client, "computers", max_fetch, next_page)

    next_run = {
        'next_page': page_info.get("next"),
        'snapshot_id': snapshot_id,
        'nextTrigger': "0",
        'type': 1
    } if page_info.get("next") else {}

    return assets, next_run, page_info.get("total", 0), snapshot_id


def get_events_command(
    client: Client,
    args: dict[str, str]
) -> tuple[list[dict], list[CommandResults]] | tuple[list, CommandResults]:
    """
     Fetches events from the Jamf Protect API within a specified date range and returns them along with the command results.

     This function fetches both alert and audit type events from the Jamf Protect API based on the provided start and end dates.
     It fetches events up to the maximum number specified by the 'limit' argument.
     If the 'should_push_events' argument is set to True, it sends the fetched events to XSIAM.

     Args:
         client (Client): An instance of the Client class for interacting with the API.
         args (dict): A dictionary containing the arguments for the command.
                      It should contain keys 'start_date', 'end_date', 'limit' and 'should_push_events'.

     Returns:
         tuple: A tuple containing two elements:
             - A list of dictionaries. Each dictionary represents an event.
             - A list of CommandResults objects. Each CommandResults object represents the command results for a type of event.
     """
    limit = arg_to_number(args.get('limit')) or DEFAULT_LIMIT
    event_types = {"alert": limit, "audit": limit}
    start_date, end_date = validate_start_and_end_dates(args)

    all_fetched_events: list[dict[str, Any]] = []
    command_results: list[CommandResults] = []

    for event_type, max_fetch in event_types.items():
        fetched_events, _ = get_events_for_type(
            client,
            last_run={},
            event_type=event_type,
            max_fetch=max_fetch,
            start_date=start_date,
            end_date=end_date
        )
        events = fetched_events[:max_fetch]
        all_fetched_events.extend(events)

        if events:
            command_results.append(CommandResults(
                readable_output=tableToMarkdown(f"Jamf Protect {event_type} Events", events),
                raw_response=events
            ))

    if not all_fetched_events:
        command_results.append(CommandResults(readable_output="No events found."))

    return all_fetched_events, command_results


def get_assets_command(client: Client, args: dict[str, str]):
    limit = arg_to_number(args.get('limit')) or DEFAULT_LIMIT

    fetched_assets, _, _, _ = fetch_assets(client, max_fetch=limit)
    assets = fetched_assets[:limit]

    command_results = CommandResults(
        readable_output=tableToMarkdown("Jamf Protect Computers Assets", assets),
        raw_response=assets
    ) if assets else CommandResults(readable_output="No computer assets found.")

    return assets, command_results


def parse_response(response: dict) -> tuple:
    """
    Parses the response from the Jamf Protect API.

    Args:
        response (dict): The response from the Jamf Protect API.

    Returns:
        tuple: A tuple containing two elements:
            - A dictionary which contains the page information from the response.
             This includes the next page token for pagination and the total number of items.
            - A list of items from the response.
             These items are either alerts or audit logs, depending on the API endpoint that was called.
    """
    data: dict = response.get("data", {})
    parsed_data = data.get("listAlerts") or data.get("listAuditLogsByDate") or data.get("listComputers") or {}
    page_info = parsed_data.get("pageInfo", {})
    items = parsed_data.get("items") or []
    return page_info, items


def calculate_fetch_dates(start_date: str, last_run: dict, end_date: str = "") -> tuple[str, str]:
    """
    Calculates the start and end dates for fetching events.

    This function takes the start date and end date provided as arguments.
    If these are not provided, it uses the last run information to calculate the start and end dates.
    If the last run information is also not available,
     it uses the current time as the end date and the time one minute before the current time as the start date.

    Args:
        start_date (str): The start date for fetching events in '%Y-%m-%dT%H:%M:%SZ' format.
        last_run_key (str): The key to retrieve the last fetch date from the last run dictionary.
        last_run (dict): A dictionary containing information about the last run.
        end_date (str, optional): The end date for fetching events in '%Y-%m-%dT%H:%M:%SZ' format. Defaults to "".

    Returns:
        tuple: A tuple containing two elements:
            - The start date as a string in the format '%Y-%m-%dT%H:%M:%SZ'.
            - The end date as a string in the format '%Y-%m-%dT%H:%M:%SZ'.
    """
    now_utc_time = get_current_time()
    # argument > last run > current time
    start_date = start_date or last_run.get('last_fetch') or (
        (now_utc_time - timedelta(minutes=1)).strftime(DATE_FORMAT))
    # argument > current time
    end_date = end_date or now_utc_time.strftime(DATE_FORMAT)
    return start_date, end_date


def validate_start_and_end_dates(args):
    """
    Validates the start and end dates provided in the arguments.

    This function checks if the start date is missing or if it is greater than the end date.
     If either of these conditions is true, it raises a ValueError. Otherwise, it returns the start and end dates.

    Args:
        args (dict): A dictionary containing the arguments for the command.
                     It should contain keys 'start_date' and 'end_date' with values representing the date range.

    Returns:
        tuple: A tuple containing two elements:
            - The start date as a string in the format '%Y-%m-%dT%H:%M:%SZ'.
            - The end date as a string in the format '%Y-%m-%dT%H:%M:%SZ'.

    Raises:
        ValueError: If the start date is missing or if it is greater than the end date.
    """
    start_date_str = ""
    end_date_str = ""
    if start_date := arg_to_datetime(args.get('start_date')):
        start_date_str = start_date.strftime(DATE_FORMAT)
    if end_date := arg_to_datetime(args.get("end_date")):
        end_date_str = end_date.strftime(DATE_FORMAT)
    if (end_date and not start_date) or (start_date and end_date and start_date >= end_date):
        raise ValueError("Either the start date is missing or it is greater than the end date. Please provide valid dates.")
    return start_date_str, end_date_str


def add_fields_to_events(events: list[dict[str, Any]], event_type: str) -> list:
    """
    Adds a '_time' field and a 'source_log_type' field to each event.

    For events that are not of type 'computer', the '_time' field is set to
    the value of the 'date' or 'created' field (if present).

    Args:
        events (List[Dict[str, Any]]): A list of dictionaries representing events.
        event_type (str): The type of event to assign to 'source_log_type'.

    Returns:
        List[Dict[str, Any]]: The updated list of events with added fields.
    """
    for event in events:
        event["source_log_type"] = event_type
        if event_type != "computers":
            event['_time'] = event.get('date') or event.get('created')

    return events


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions"""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    try:
        client_id = params.get('client', {}).get('identifier', '')
        client_password = params.get('client', {}).get('password', '')
        max_fetch_audits = arg_to_number(params.get('max_fetch_audits')) or DEFAULT_MAX_FETCH_AUDIT
        max_fetch_alerts = arg_to_number(params.get('max_fetch_alerts')) or DEFAULT_MAX_FETCH_ALERT

        demisto.debug(f'Command being called is {command}')

        client = Client(
            base_url=params.get('base_url', ''),
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
            client_id=client_id,
            client_password=client_password
        )

        if command == 'test-module':
            return_results(test_module(client, params))

        elif command == 'jamf-protect-get-events':
            events, results = get_events_command(client=client, args=args)
            return_results(results)
            if argToBoolean(args.get("should_push_events")):
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)

        elif command == 'jamf-protect-get-computer-assets':
            assets, results = get_assets_command(client=client, args=args)
            return_results(results)
            if argToBoolean(args.get("should_push_events")):
                send_data_to_xsiam(data=assets, vendor=VENDOR, product=ASSETS_PRODUCT, data_type='assets',
                                   items_count=str(len(assets)))

        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            demisto.debug(f'Starting fetch events with last run: {last_run}')

            events, new_last_run = fetch_events(
                client=client,
                max_fetch_alerts=max_fetch_alerts,
                max_fetch_audits=max_fetch_audits,
                last_run=last_run,
            )
            demisto.debug(f'Sending {len(events)} events to XSIAM API')
            send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)

            demisto.debug(f"Set last run: {new_last_run}")
            demisto.setLastRun(new_last_run)

        elif command == 'fetch-assets':
            last_run = demisto.getAssetsLastRun()
            demisto.debug(f'Starting fetch assets with last run: {last_run}')

            assets, new_last_run, total_assets_to_report, snapshot_id = fetch_assets(client=client, assets_last_run=last_run)

            demisto.debug(f"Sending {len(assets)} assets to XSIAM API "
                          f"with snapshot_id: {snapshot_id} and items_count: {total_assets_to_report}")

            send_data_to_xsiam(data=assets, vendor=VENDOR, product=ASSETS_PRODUCT, data_type='assets',
                               snapshot_id=snapshot_id, items_count=str(total_assets_to_report))

            demisto.debug(f"Set assets last run: {new_last_run}")
            demisto.setAssetsLastRun(new_last_run)

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
