import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

VENDOR = "servicenow"
PRODUCT = "servicenow"
LOGS_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"  # New format for processing events
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSIAM

""" CLIENT CLASS """


class Client:
    def __init__(self, use_oauth, credentials, client_id, client_secret, url, verify, proxy, fetch_limit, api_server_url):
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
        self.fetch_limit = fetch_limit
        self.api_server_url = api_server_url

    def get_audit_logs(self, from_time: str, limit: Optional[int] = None, offset: int = 0):
        """Make a request to the ServiceNow REST API to retrieve audit logs"""
        if limit is None:
            limit = self.fetch_limit
        params = {
            "sysparm_limit": limit,
            "sysparm_offset": offset,
            "sysparm_query": f"sys_created_on>{from_time}",
        }
        res = self.sn_client.http_request(
            method="GET",
            full_url=f"{self.api_server_url}table/sys_audit",
            url_suffix=None,
            params=remove_empty_elements(params),
        )
        return res.get("result")


""" HELPER METHODS """


def add_time_field(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Adds time field to the events

    :param events: List of events to add the _time field to.
    """
    for event in events:
        event["_time"] = datetime.strptime(event["sys_created_on"], LOGS_DATE_FORMAT).strftime(DATE_FORMAT)
    return events


def process_and_filter_events(events: list, previous_run_ids: set, from_date: str):
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
        if event.get("sys_id") in previous_run_ids:
            continue
        if create_time > from_date_datetime:
            previous_run_ids = set()
            from_date_datetime = create_time

        previous_run_ids.add(event.get("sys_id"))
        unique_events.append(event)

    return unique_events, previous_run_ids


""" COMMAND METHODS """


def get_audit_logs_command(client: Client, args: dict) -> tuple[list, CommandResults]:
    """

    Args:
        limit: The maximum number of logs to return.
        to_date: date to fetch events from.
        from_date: date to fetch events to.
        client: Client object.

    Returns:
        Sign on logs from Workday.
    """
    limit = args.get("limit", 1000)
    offset = args.get("offset", 0)
    from_date = args.get("from_date", "")

    audit_logs = client.get_audit_logs(from_time=from_date, limit=limit, offset=offset)
    add_time_field(audit_logs)  # Add the _time field to the events

    demisto.debug(f"Got a total of {len(audit_logs)} events created after {from_date}")

    readable_output = tableToMarkdown(
        "Audit Logs List:",
        audit_logs,
        removeNull=True,
        headerTransform=lambda x: string_to_table_header(camel_case_to_underscore(x)),
    )

    return audit_logs, CommandResults(readable_output=readable_output)


def fetch_events_command(client: Client, last_run: dict):
    """
    Fetches audit logs from Workday.
    Args:
        client: Client object.
        max_fetch: max logs to fetch set by customer.
        last_run: last run object.

    Returns:
          Audit logs from Workday.

    """
    events = []
    previous_run_ids = set(last_run.get("previous_run_ids", set()))

    if "last_fetch_time" not in last_run:
        current_time = datetime.utcnow()
        first_fetch_time = current_time - timedelta(minutes=1)
        first_fetch_str = first_fetch_time.strftime(LOGS_DATE_FORMAT)
        from_date = first_fetch_str
    else:
        from_date = last_run.get("last_fetch_time", "")

    demisto.debug(f"Getting Audit Logs {from_date=}.")
    audit_logs = client.get_audit_logs(from_date)

    if audit_logs:
        demisto.debug(f"Got {len(audit_logs)} audit_logs. Begin processing.")
        events, previous_run_ids = process_and_filter_events(
            events=audit_logs, previous_run_ids=previous_run_ids, from_date=from_date
        )

        demisto.debug(f"Done processing {len(events)} audit_logs.")
        last_fetch_time = events[-1].get("sys_created_on") if events else from_date
        last_run = {
            "last_fetch_time": last_fetch_time,
            "previous_run_ids": list(previous_run_ids),
        }
        demisto.debug(f"Saving last run as {last_run}")

    return events, last_run


def module_of_testing(client: Client) -> str:  # pragma: no cover
    """Tests API connectivity and authentication

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    _, _ = fetch_events_command(client, {})
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
    client_id = params.get("client_credentials", {}).get("identifier")
    client_secret = params.get("client_credentials", {}).get("password")
    credentials = params.get("credentials", {})
    user_name = credentials.get("identifier")
    password = credentials.get("password")
    max_fetch = arg_to_number(params.get("max_fetch")) or 10000

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
            fetch_limit=max_fetch,
            api_server_url=api_server_url,
        )

        if client.sn_client.use_oauth and not get_integration_context().get("refresh_token", None):
            client.sn_client.login(username=user_name, password=password)

        if command == "test-module":
            return_results(module_of_testing(client))

        elif command == "service-now-get-audit-logs":
            audit_logs, results = get_audit_logs_command(client=client, args=args)
            return_results(results)

            if argToBoolean(args.get("should_push_events", "true")):
                send_events_to_xsiam(audit_logs, vendor=VENDOR, product=PRODUCT)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            demisto.debug(f"Starting new fetch with last_run as {last_run}")
            audit_logs, new_last_run = fetch_events_command(client=client, last_run=last_run)

            demisto.debug("Done fetching events, sending to XSIAM.")

            if audit_logs:
                add_time_field(audit_logs)
                send_events_to_xsiam(audit_logs, vendor=VENDOR, product=PRODUCT)
                if new_last_run:
                    # saves next_run for the time fetch-events is invoked
                    demisto.debug(f"Setting new last_run to {new_last_run}")
                    demisto.setLastRun(new_last_run)
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
