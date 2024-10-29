import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

VENDOR = "servicenow"
PRODUCT = "servicenow"
LOGS_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"  # New format for processing events
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSIAM
AUDIT = "audit"
SYSLOG_TRANSACTIONS = "syslog transactions"
URL = {AUDIT: "table/sys_audit", SYSLOG_TRANSACTIONS: "table/syslog_transaction"}
VALID_EVENT_TITLES = ['Audit', 'Syslog Transactions']
""" CLIENT CLASS """


class Client:
    def __init__(self, use_oauth, credentials, client_id, client_secret, url, verify, proxy, api_server_url, fetch_limit_audit, 
                 fetch_limit_syslog):
        self.sn_client = ServiceNowClient(
            credentials=credentials,
            use_oauth=use_oauth,
            client_id=client_id,
            client_secret=client_secret,
            url=url,
            verify=verify,
            headers={},
            proxy=proxy,
        )
        self.fetch_limit_audit = fetch_limit_audit
        self.fetch_limit_syslog = fetch_limit_syslog
        self.api_server_url = api_server_url

    def search_events(self, from_time: str, log_type: str, limit: Optional[int] = None, offset: int = 0):
        """Make a request to the ServiceNow REST API to retrieve audit logs"""
        
        if limit is None:
            limit = self.fetch_limit_audit if log_type == AUDIT else self.fetch_limit_syslog
            
        params = {
            "sysparm_limit": limit,
            "sysparm_offset": offset,
            "sysparm_query": f"sys_created_on>{from_time}",
        }
        res = self.sn_client.http_request(
            method="GET",
            full_url=f"{self.api_server_url}{URL[log_type]}",
            url_suffix=None,
            params=remove_empty_elements(params),
        )
        return res.get("result")
    

""" HELPER METHODS """

def handle_log_types(event_types_to_fetch: list) -> list:
    """
    Args:
        event_types_to_fetch (list of str): A list of event type titles to be converted to log types.

    Raises:
        InvalidEventTypeError: If any of the event type titles are not found in the titles_to_types mapping.

    Returns:
        list: A list of log types corresponding to the provided event type titles.
              The list contains log types that have a matching title in the titles_to_types mapping.
              If an event type title is not found, an exception is raised.
    """
    log_types = []
    titles_to_types = {'Audit': AUDIT, 'Syslog Transactions': SYSLOG_TRANSACTIONS}
    for type_title in event_types_to_fetch:
        if log_type := titles_to_types.get(type_title):
            log_types.append(log_type)
        else:
            raise DemistoException(
                f"'{type_title}' is not valid event type, please select from the following list: {VALID_EVENT_TITLES}")

    return log_types

def update_last_run(last_run: dict[str, Any], log_type: str, last_event_time: str, previous_run_ids: list) -> dict:
    """
    Update the last run details for a specific log type.

    Args:
        last_run (dict[str, Any]): Dictionary containing the last run details for different log types.
        log_type (str): Type of log to update.
        last_event_time (int): Timestamp of the last event fetched.
        previous_run_ids (list): List of IDs from the previous fetch to track.

    Returns:
        Dict[str, Any]: Updated dictionary containing the last run details.
    """
    last_run[log_type] = {
        "last_fetch_time": last_event_time,
        "previous_run_ids": previous_run_ids
    }
    return last_run


def initialize_from_date(last_run: dict[str, Any], log_type: str) -> str:
    """
    Initialize the start timestamp for fetching logs based on provided parameters.

    Args:
        last_run (dict[str, Any]): Dictionary containing the last fetch timestamps for different log types.
        log_type (str): Type of log for which to initialize the start timestamp.
        
    Returns:
        str: The start timestamp for fetching logs.
    """
    start_timestamp = last_run.get(log_type, {}).get("last_fetch_time")
    if not start_timestamp:
        current_time = datetime.utcnow()
        first_fetch_time = current_time - timedelta(minutes=1)
        first_fetch_str = first_fetch_time.strftime(LOGS_DATE_FORMAT)
        from_date = first_fetch_str
    else:
        from_date = last_run.get("last_fetch_time", "")
    
    return from_date

def add_time_field(events: List[Dict[str, Any]], log_type) -> List[Dict[str, Any]]:
    """Adds time field to the events

    :param events: List of events to add the _time field to.
    """
    for event in events:
        event["_time"] = datetime.strptime(event["sys_created_on"], LOGS_DATE_FORMAT).strftime(DATE_FORMAT)
        event["source_log_type"] = log_type
        
    return events


def get_limit(args: dict, client: Client, log_type: str):
    if log_type == AUDIT:
        limit = arg_to_number(args.get("max_fetch_audit")) or client.fetch_limit_audit or 1000
    else:
        limit = arg_to_number(args.get("max_fetch_syslog_transactions")) or client.fetch_limit_syslog or 1000
        
    return limit

def process_and_filter_events(events: list, previous_run_ids: set, from_date: str, log_type: str):
    """
    Removing duplicates and creating a set of last fetched ids with the same time.

    :param events: events fetched from the API
    :param previous_run_ids: ids with time as the one in the from date param
    :param from_date: from date from last_run object
    :return: all unique events and a set of last ids of events with same time.
    """
    unique_events = []
    from_date_datetime = datetime.strptime(from_date, LOGS_DATE_FORMAT)
    for event in events:
        create_time = datetime.strptime(event.get("sys_created_on"), LOGS_DATE_FORMAT)
        event["_time"] = create_time.strftime(DATE_FORMAT)
        event["source_log_type"] = log_type
        if event.get("sys_id") in previous_run_ids:
            continue
        if create_time > from_date_datetime:
            previous_run_ids = set()
            from_date_datetime = create_time

        previous_run_ids.add(event.get("sys_id"))
        unique_events.append(event)

    return unique_events, previous_run_ids


""" COMMAND METHODS """


def get_events_command(client: Client, args: dict, log_types: list) -> tuple[list, CommandResults]:
    """

    Args:
        limit: The maximum number of logs to return.
        to_date: date to fetch events from.
        from_date: date to fetch events to.
        client: Client object.

    Returns:
        Sign on logs from Workday.
    """
    types_to_titles = {AUDIT: 'Audit', SYSLOG_TRANSACTIONS: 'Syslog Transactions'}
    all_events = []
    hr = ""
    for log_type in log_types:
        limit = get_limit(args, client, log_type)
        offset = args.get("offset", 0)
        from_date = args.get("from_date", "")
        logs = client.search_events(from_time=from_date, log_type=log_type, limit=limit, offset=offset)
        add_time_field(logs, log_type)  # Add the _time field to the events

        demisto.debug(f"Got a total of {len(logs)} events created after {from_date}")
        hr += tableToMarkdown(name=f'{types_to_titles[log_type]} Events', t=logs)
        all_events.extend(logs)

        # readable_output = tableToMarkdown(
        #     f"{log_type} Logs List:",
        #     logs,
        #     removeNull=True,
        #     headerTransform=lambda x: string_to_table_header(camel_case_to_underscore(x)),
        # )

    return all_events, CommandResults(readable_output=hr)


def fetch_events_command(client: Client, last_run: dict, log_types: list):
    """
    Fetches audit logs from Workday.
    Args:
        client: Client object.
        max_fetch: max logs to fetch set by customer.
        last_run: last run object.

    Returns:
          Audit logs from Workday.

    """
    collected_events = []
    for log_type in log_types:
        previous_run_ids = set(last_run.get(log_type, {}).get("previous_run_ids", set()))
        from_date = initialize_from_date(last_run, log_type)
        demisto.debug(f"Getting Audit Logs {from_date=}.")
        new_events = client.search_events(from_date, log_type)

        if new_events:
            demisto.debug(f"Got {len(new_events)} {log_type} events. Begin processing.")
            events, previous_run_ids = process_and_filter_events(
                events=new_events, previous_run_ids=previous_run_ids, from_date=from_date, log_type=log_type
            )

            demisto.debug(f"Done processing {len(events)} {log_type} events.")
            last_fetch_time = events[-1].get("sys_created_on") if events else from_date
            last_run = update_last_run(last_run, log_type, last_fetch_time, list(previous_run_ids))
            demisto.debug(f"Saving last run as {last_run}")
            collected_events.extend(events)

    return collected_events, last_run


def module_of_testing(client: Client, log_types: list) -> str:  # pragma: no cover
    """Tests API connectivity and authentication

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
   
    _, _ = fetch_events_command(client, {},  log_types=log_types)
    return "ok"


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions"""
    command = demisto.command()
    args = demisto.args()
    params = demisto.params()
    server_url = params.get("url")
    verify_certificate = params.get("insecure", False)
    proxy = params.get("proxy", False)
    use_oauth = params.get("use_oauth", False)
    client_id = params.get("client_credentials", {}).get("identifier", "")
    client_secret = params.get("client_credentials", {}).get("password", "")
    credentials = params.get("credentials", {})
    user_name = credentials.get("identifier")
    password = credentials.get("password")
    max_fetch_audit = arg_to_number(params.get("max_fetch_audit")) or 10000
    max_fetch_syslog = arg_to_number(params.get("max_fetch_syslog_transactions")) or 10000
    event_types_to_fetch = argToList(params.get('event_types_to_fetch', []))
    log_types = handle_log_types(event_types_to_fetch)
    isFetch = params.get('isFetchEvents')
    if isFetch and not log_types:
        raise DemistoException("At least one event type must be specified for fetching.")
    
    version = params.get("api_version")
    if version:
        api = f"/api/now/{version}/"
    else:
        api = "/api/now/"
    api_server_url = f"{server_url}{api}"

    demisto.debug(f"Command being called is {command}")
    
    try:
        client = Client(
            use_oauth=use_oauth,
            credentials=credentials,
            client_id=client_id,
            client_secret=client_secret,
            url=server_url,
            verify=verify_certificate,
            proxy=proxy,
            api_server_url=api_server_url,
            fetch_limit_audit=max_fetch_audit,
            fetch_limit_syslog=max_fetch_syslog
        )
        
        if client.sn_client.use_oauth and not get_integration_context().get("refresh_token", None):
            client.sn_client.login(username=user_name, password=password)
        
        if command == "test-module":
            return_results(module_of_testing(client, log_types))

        elif command == "service-now-get-events":
            audit_logs, results = get_events_command(client=client, args=args, log_types=log_types)
            return_results(results)

            if argToBoolean(args.get("should_push_events", "true")):
                send_events_to_xsiam(audit_logs, vendor=VENDOR, product=PRODUCT)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            demisto.debug(f"Starting new fetch with last_run as {last_run}")
            events, next_run = fetch_events_command(client=client, last_run=last_run, log_types=log_types)

            demisto.debug("Done fetching events, sending to XSIAM.")

            if events:
                # add_time_field(events)
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
                if next_run:
                    # saves next_run for the time fetch-events is invoked
                    demisto.debug(f"Setting new last_run to {next_run}")
                    demisto.setLastRun(next_run)
        else:
            raise NotImplementedError(f"command {command} is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        demisto.info(f"here {str(e)}")
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


from ServiceNowApiModule import *  # noqa: E402

""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
