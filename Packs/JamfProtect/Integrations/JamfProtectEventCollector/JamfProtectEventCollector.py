from collections.abc import Callable

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''
VENDOR = 'Jamf'
PRODUCT = 'Protect'
ALERT_PAGE_SIZE = 200
AUDIT_PAGE_SIZE = 5000
DEFAULT_MAX_FETCH_ALERT = 1000
DEFAULT_MAX_FETCH_AUDIT = 20000
DEFAULT_LIMIT = 10
MINUTES_BEFORE_TOKEN_EXPIRED = 2
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

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

    def handle_errors(self, res):
        """
        Handles errors in the response from the Jamf Protect API.

        This method checks if the response contains any errors. If it does, it raises an exception with the error messages.

        Args:
            res (dict): The response from the Jamf Protect API.

        Raises:
            DemistoException: If the response contains any errors.
        """
        if "errors" in res:
            errors = "\n".join([error.get("message") for error in res.get("errors")])
            raise DemistoException(errors)

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

    def get_alerts(self, args: dict, next_page: str) -> dict:
        """
        Fetches alerts from the Jamf Protect API.

        Args:
            args (dict): The arguments to be used in the GraphQL query.
             It should contain a key "created" with a value representing the creation date of the alerts.
            next_page (str): The next page token for pagination.

        Returns:
            dict: The response from the API.
        """
        query = """
        query listAlerts($created: AWSDateTime, $page_size: Int, $next: String) {
            listAlerts(
                input: {
                    filter: {
                        created: {
                            greaterThanOrEqual: $created
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
        variables = {
            "created": args.get("created"),
            "page_size": ALERT_PAGE_SIZE,
        }
        if next_page:
            variables["next"] = next_page
        return self.graphql(query, variables)

    def get_audits(self, args: dict, next_page: str) -> dict:
        """
        Fetches audit logs from the Jamf Protect API.

        Args:
            args (dict): The arguments to be used in the GraphQL query.
             It should contain keys "start_date" and "end_date" with values representing the date range of the audit logs.
            next_page (str): The next page token for pagination.

        Returns:
            dict: The response from the API.
        """
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
            "input":
                {
                    "pageSize": AUDIT_PAGE_SIZE,
                    "condition": {
                        "dateRange": {
                            "startDate": args.get("start_date"),
                            "endDate": args.get("end_date"),
                        }
                    }
                }
        }
        if next_page:
            variables["input"]["next"] = next_page
        return self.graphql(query, variables)


''' HELPER FUNCTIONS '''


def test_module(client: Client) -> str:
    """
    This method is used to test the connectivity and functionality of the client.

    Args:
        client (Client): The client object with methods for interacting with the API.

    Returns:
        str: Returns "ok" if the client is able to interact with the API successfully, raises an exception otherwise.
    """
    fetch_events(client, max_fetch_audits=1, max_fetch_alerts=1)
    return "ok"


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
    data = response.get("data", {})
    parsed_data = data.get("listAlerts") or data.get("listAuditLogsByDate") or {}
    page_info = parsed_data.get("pageInfo", {})
    items = parsed_data.get("items")
    return page_info, items


def get_events_alert_type(client: Client, start_date: str, max_fetch: int, last_run: dict) -> tuple:
    """
    Fetches alert type events from the Jamf Protect API within a specified date range.

    This function fetches alert type events from the Jamf Protect API based on the provided start date.
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
    created, current_date = calculate_fetch_dates(start_date, last_run=last_run, last_run_key="alert")
    command_args = {"created": created}
    client_event_type_func = client.get_alerts
    next_page = last_run.get("alert", {}).get("next_page", "")

    demisto.debug(f"Jamf Protect- Fetching alerts from {created}")
    events, next_page = get_events(command_args, client_event_type_func, max_fetch, next_page)
    for event in events:
        event["source_log_type"] = "alert"
    if next_page:
        demisto.debug(
            f"Jamf Protect- Fetched {len(events)} which is the maximum number of alerts."
            f" Will keep the fetching in the next fetch.")
        new_last_run_with_next_page = {"next_page": next_page, "last_fetch": created}
        return events, new_last_run_with_next_page
    # If there is no next page, the last fetch date will be the max end date of the fetched events.
    new_last_fetch_date = max([dt for dt in (arg_to_datetime(event.get("created"), DATE_FORMAT)
                                             for event in events) if dt is not None]).strftime(
        DATE_FORMAT) if events else current_date
    new_last_run_without_next_page = {"last_fetch": new_last_fetch_date}
    demisto.debug(f"Jamf Protect- Fetched {len(events)} alerts")
    return events, new_last_run_without_next_page


def get_events_audit_type(client: Client, start_date: str, end_date: str, max_fetch: int, last_run: dict) -> tuple:
    """
     Fetches audit type events from the Jamf Protect API within a specified date range.

     This function fetches audit type events from the Jamf Protect API based on the provided start and end dates.
     It fetches events up to the maximum number specified by max_fetch.
     The function also uses the information from the last run to continue fetching from where it left off in the previous run.

     Args:
         client (Client): An instance of the Client class for interacting with the API.
         start_date (str): The start date for fetching events in '%Y-%m-%dT%H:%M:%SZ' format.
         end_date (str): The end date for fetching events in '%Y-%m-%dT%H:%M:%SZ' format.
         max_fetch (int): The maximum number of events to fetch.
         last_run (dict): A dictionary containing information about the last run.

     Returns:
         tuple: A tuple containing two elements:
             - A list of dictionaries. Each dictionary represents an event.
             - A dictionary with new last run values,
              the end date of the fetched events and a continuance token if the fetched reached the max limit.
     """
    start_date, end_date = calculate_fetch_dates(start_date, end_date=end_date, last_run=last_run, last_run_key="alert")
    command_args = {"start_date": start_date, "end_date": end_date}
    client_event_type_func = client.get_audits
    next_page = last_run.get("audit", {}).get("next_page", "")

    demisto.debug(f"Jamf Protect- Fetching audits from {start_date} to {end_date}")
    events, next_page = get_events(command_args, client_event_type_func, max_fetch, next_page)
    for event in events:
        event["source_log_type"] = "audit"
    if next_page:
        demisto.debug(
            f" Jamf Protect - Fetched {len(events)}"
            f" which is the maximum number of audits. Will keep the fetching in the next fetch.")
        new_last_run_with_next_page = {"next_page": next_page, "last_fetch": start_date}
        return events, new_last_run_with_next_page

    # If there is no next page, the last fetch date will be the max end date of the fetched events.
    new_last_fetch_date = max([dt for dt in (arg_to_datetime(event.get("date"), DATE_FORMAT)
                                             for event in events) if dt is not None]).strftime(
        DATE_FORMAT) if events else end_date
    new_last_run_without_next_page = {"last_fetch": new_last_fetch_date}
    demisto.debug(f"Jamf Protect- Fetched {len(events)} audits")
    return events, new_last_run_without_next_page


def get_events(command_args: dict, client_event_type_func: Callable, max_fetch: int, next_page: str = "") -> tuple:
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
            - A string representing the next page token for pagination.
    """
    events: List[dict] = []
    has_next = True

    while has_next:
        has_next = False
        if len(events) >= max_fetch:
            return events, next_page
        response = client_event_type_func(command_args, next_page)
        page_info, parsed_data = parse_response(response=response)
        if next_page := page_info.get("next"):
            has_next = True
        events.extend(parsed_data)
    return events, ""


def calculate_fetch_dates(start_date: str, last_run_key: str, last_run: dict, end_date: str = "") -> tuple:
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
    start_date = start_date or last_run.get(last_run_key, {}).get('last_fetch') or (
        (now_utc_time - timedelta(minutes=1)).strftime(DATE_FORMAT))
    # argument > current time
    end_date = end_date or now_utc_time.strftime(DATE_FORMAT)
    return start_date, end_date


def fetch_events(client: Client, max_fetch_alerts: int, max_fetch_audits: int, start_date_arg: str = "",
                 end_date_arg: str = "") -> tuple:
    """
    Fetches events from the Jamf Protect API within a specified date range.

    Args:
        client (Client): An instance of the Client class.
        max_fetch (int): The maximum number of events to fetch.
        start_date_arg (str, optional): The start date for fetching events.
        end_date_arg (str, optional): The end date for fetching events.

    Returns:
        tuple[List[dict], dict]: A tuple containing two elements:
            - A list of dictionaries. Each dictionary represents an event.
            - A dictionary with the key 'last_fetch' and its value representing the end date of the fetched events.
    """
    last_run = demisto.getLastRun()
    alert_events, alert_next_run = [], {}
    audit_events, audit_next_run = [], {}
    alert_next_page = last_run.get("alert", {}).get("next_page", "")
    audit_next_page = last_run.get("audit", {}).get("next_page", "")

    if not (alert_next_page or audit_next_page) or alert_next_page:
        # The only case we don't trigger the alert event type cycle is when have only the audit next page token.
        alert_events, alert_next_run = get_events_alert_type(client, start_date_arg, max_fetch_alerts, last_run)
    if not (alert_next_page or audit_next_page) or audit_next_page:
        # The only case we don't trigger the audit event type cycle is when have only the alert next page token.
        audit_events, audit_next_run = get_events_audit_type(client, start_date_arg, end_date_arg, max_fetch_audits, last_run)
    next_run: Dict[str, Any] = {"alert": alert_next_run, "audit": audit_next_run}
    if "next_page" in (alert_next_run | audit_next_run):
        # Will instantly re-trigger the fetch command.
        next_run["nextTrigger"] = "0"
    return alert_events, audit_events, next_run


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


def get_events_command(client, args) -> tuple:
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
    results = []
    alert_events_with_time, audit_events_with_time = [], []
    start_date, end_date = validate_start_and_end_dates(args)

    alert_events, audit_events, _ = fetch_events(client=client, max_fetch_alerts=limit, max_fetch_audits=limit,
                                                 start_date_arg=start_date,
                                                 end_date_arg=end_date)

    if alert_events:
        alert_events = alert_events[:limit]
        alert_events_with_time = add_time_field(alert_events)
        results.append(
            CommandResults(readable_output=tableToMarkdown("Jamf Protect Alert Events", alert_events_with_time),
                           raw_response=alert_events_with_time))
    if audit_events:
        audit_events = audit_events[:limit]
        audit_events_with_time = add_time_field(audit_events)
        results.append(
            CommandResults(readable_output=tableToMarkdown("Jamf Protect Audit Events", audit_events_with_time),
                           raw_response=audit_events_with_time))
    events = alert_events_with_time + audit_events_with_time
    if events:
        return events, results
    return [], CommandResults(readable_output='No events found')


def add_time_field(events: List[Dict[str, Any]]) -> list:
    """
    Adds a '_time' field to each event in the list of events.

    This function iterates over the list of events.
     For each event, it adds a new field '_time' with the value of the 'date' or 'created' field of the event.

    Args:
        events (List[Dict[str, Any]]): A list of dictionaries. Each dictionary represents an event.

    Returns:
        list: The updated list of events. Each event now includes a '_time' field.
    """
    for event in events:
        event['_time'] = event.get('date') or event.get('created')
    return events


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions
    :return:
    :rtype:
    """
    params = demisto.params()
    args = demisto.args()
    try:
        client_id = params.get('client', {}).get('identifier', '')
        client_password = params.get('client', {}).get('password', '')
        max_fetch_audits = arg_to_number(params.get('max_fetch_audits')) or DEFAULT_MAX_FETCH_AUDIT
        max_fetch_alerts = arg_to_number(params.get('max_fetch_alerts')) or DEFAULT_MAX_FETCH_ALERT

        demisto.debug(f'Command being called is {demisto.command()}')

        client = Client(
            base_url=params.get('base_url'),
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
            client_id=client_id,
            client_password=client_password
        )

        if demisto.command() == 'test-module':
            return_results(test_module(client))
        elif demisto.command() == 'jamf-protect-get-events':
            events, results = get_events_command(client=client,
                                                 args=args)
            return_results(results)
            if argToBoolean(args.get("should_push_events")):
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)  # type: ignore
        elif demisto.command() == 'fetch-events':
            alert_events, audit_events, new_last_run = fetch_events(client=client,
                                                                    max_fetch_alerts=max_fetch_alerts,
                                                                    max_fetch_audits=max_fetch_audits)
            events = alert_events + audit_events
            if events:
                add_time_field(events)
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
                if new_last_run:
                    demisto.setLastRun(new_last_run)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
