import datetime
from typing import Tuple, Callable

import demistomock
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''
VENDOR = 'Jamf'
PRODUCT = 'Protect'
PAGE_SIZE = 200  # The maximum number of items the API allows to retrieve in a single request.
DEFAULT_MAX_FETCH = 10000
MINUTES_BEFORE_TOKEN_EXPIRED = 2
TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url: str, verify: bool, client_id: str = "", client_password: str = "", proxy: bool = False):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)

        """ due to deprecating the basic auth option from the classical API versions 10.35 and up
            the client will try to generate an auth token first, if it failed to do generate the token,
            the client will use basic auth instead.
        """
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
        res = self._generate_token(client_id, client_password)
        new_token = res.get("access_token")
        expire_in = res.get("expires_in")
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
        )
        self.handle_errors(res)
        return res

    def get_alerts(self, args: dict, next_page: str) -> dict:
        """
        Fetches alerts from the Jamf Protect API.

        Args:
            args (dict): The arguments to be used in the GraphQL query. It should contain a key "created" with a value representing the creation date of the alerts.
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
            "page_size": PAGE_SIZE,
        }
        if next_page:
            variables["next"] = next_page
        return self.graphql(query, variables)

    def get_audits(self, args: dict, next_page: str) -> dict:
        """
        Fetches audit logs from the Jamf Protect API.

        Args:
            args (dict): The arguments to be used in the GraphQL query. It should contain keys "start_date" and "end_date" with values representing the date range of the audit logs.
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
                    "pageSize": PAGE_SIZE,
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
    fetch_events(client, max_fetch=1)
    return "ok"


def parse_response(response: dict) -> Tuple[dict, List[dict]]:
    """
    Parses the response from the Jamf Protect API.

    Args:
        response (dict): The response from the Jamf Protect API.

    Returns:
        Tuple[dict, List[dict]]: A tuple containing two elements:
            - A dictionary which contains the page information from the response. This includes the next page token for pagination and the total number of items.
            - A list of items from the response. These items are either alerts or audit logs, depending on the API endpoint that was called.
    """
    data = response.get("data", {})
    parsed_data = data.get("listAlerts") or data.get("listAuditLogsByDate")
    page_info = parsed_data.get("pageInfo", {})
    items = parsed_data.get("items")
    return page_info, items


def get_events_alert_type(client: Client, created: str) -> List[dict]:
    """
    Fetches alerts from the Jamf Protect API.

    Args:
        client (Client): An instance of the Client class.
        created (str): The creation date of the alerts.

    Returns:
        List[dict]: A list of dictionaries. Each dictionary represents an alert.
    """
    args = {"created": created}
    client_event_type_func = client.get_alerts
    return get_events(args, client_event_type_func)


def get_events_audit_type(client: Client, start_date: str, end_date: str) -> List[dict]:
    """
    Fetches audit logs from the Jamf Protect API.

    Args:
        client (Client): An instance of the Client class.
        start_date (str): The start date of the audit logs.
        end_date (str): The end date of the audit logs.

    Returns:
        List[dict]: A list of dictionaries. Each dictionary represents an audit log.
    """
    args = {"start_date": start_date, "end_date": end_date}
    client_event_type_func = client.get_audits
    return get_events(args, client_event_type_func)


def get_events(args: dict, client_event_type_func: Callable) -> List[dict]:
    """
    Fetches alerts or audit logs from the Jamf Protect API.

    Args:
        args (dict): The arguments to be used in the GraphQL query. It should contain keys "start_date" and "end_date" with values representing the date range of the audit logs for fetching audit logs, or a key "created" with a value representing the creation date of the alerts for fetching alerts.
        client_event_type_func (Callable): A function reference to either get_alerts or get_audits method of the Client class.

    Returns:
        List[dict]: A list of dictionaries. Each dictionary represents an alert or an audit log.
    """
    events = []
    has_next = True
    next_page = ""
    while has_next:
        has_next = False
        response = client_event_type_func(args, next_page)
        page_info, parsed_data = parse_response(response=response)
        if next_page := page_info.get("next"):
            has_next = True
        events.extend(parsed_data)
    return events


def calculate_fetch_dates() -> Tuple[str, str]:
    """
    Calculates the start and end dates for fetching events.

    This function retrieves the last fetch date from the last run. If no last fetch date is found,
    it sets the start date to one minute before the current time. The end date is set to the current UTC time.

    Returns:
        Tuple[str, str]: A tuple containing two elements:
            - The start date in AWSDateTime format.
            - The end date in AWSDateTime format.
    """
    last_run = demistomock.getLastRun()
    now_utc_time = get_current_time()
    start_date = last_run.get('last_fetch') or ((now_utc_time - timedelta(minutes=1)).strftime(TIME_FORMAT))
    end_date = now_utc_time.strftime(TIME_FORMAT)
    return start_date, end_date


def fetch_events(client: Client, max_fetch: int) -> Tuple[List[dict], dict]:
    """
    Fetches events from the Jamf Protect API.

    Args:
        client (Client): An instance of the Client class.
        max_fetch (int): The maximum number of events to fetch.

    Returns:
        Tuple[List[dict], dict]: A tuple containing two elements:
            - A list of dictionaries. Each dictionary represents an event.
            - A dictionary which contains the last fetch date.
    """
    events = []
    start_date, end_date = calculate_fetch_dates()
    demisto.debug(f"Fetching events created after {start_date}")
    events.extend(get_events_alert_type(client, created=start_date))
    total_alerts = len(events)
    demisto.debug(f"Fetched {total_alerts} alert type events")
    events.extend(get_events_audit_type(client, start_date=start_date, end_date=end_date))
    demisto.debug(f"Fetched {len(events) - total_alerts} audit type events")
    if len(events) > max_fetch:
        demisto.info(f"Number of events fetched ({len(events)}) exceeds the maximum fetch limit ({max_fetch}).")
    return events[:max_fetch], {"last_fetch": end_date}


def add_time_field(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Adds time field to the events"""
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
        client_id = params.get('client_id', {}).get('password', '')
        client_password = params.get('client_password', {}).get('password', '')
        max_fetch = arg_to_number(params.get('max_fetch')) or DEFAULT_MAX_FETCH

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
        # elif demisto.command() == 'darktrace-get-events':
        #     events, results = get_events_command(client=client,
        #                                          args=args,
        #                                          first_fetch_time_timestamp=first_fetch_time_timestamp)
        #     return_results(results)
        #     if argToBoolean(args.get("should_push_events")):
        #         send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)  # type: ignore
        elif demisto.command() == 'fetch-events':
            events, new_last_run = fetch_events(client=client,
                                                max_fetch=max_fetch)
            if events:
                add_time_field(events)
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
                if new_last_run:
                    demisto.setLastRun(new_last_run)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
