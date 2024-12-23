import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

VENDOR = 'Cloudflare'
PRODUCT = 'ZeroTrust'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
ACCOUNT_AUDIT_PAGE_SIZE = 1000
USER_AUDIT_PAGE_SIZE = 1000
ACCESS_AUTHENTICATION_PAGE_SIZE = 1000
DEFAULT_MAX_FETCH_ACCOUNT_AUDIT = 5000
DEFAULT_MAX_FETCH_USER_AUDIT = 5000
DEFAULT_MAX_FETCH_ACCESS_AUTHENTICATION = 5000

ACCOUNT_AUDIT_TYPE = "account_audit_logs"
USER_AUDIT_TYPE = "user_audit_logs"
ACCESS_AUTHENTICATION_TYPE = "access_authentication_logs"

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def __init__(self, base_url, verify, proxy, headers, account_id):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.account_id = account_id
        self.headers = headers

    def get_events(self, start_date):
        params = {
            'per_page': ACCOUNT_AUDIT_PAGE_SIZE,
            'since': start_date,
            'direction': 'asc'
            # 'before': ''
        }
        return self._http_request(
            method="GET",
            url_suffix=f"/client/v4/accounts/{self.account_id}/audit_logs",
            headers=self.headers,
            params=params,
            retries=3
        )


#     def search_events(self, prev_id: int, alert_status: None | str, limit: int, from_date: str | None = None, default_Protocol: str = 'UDP') -> List[Dict]:  # noqa: E501
#         """
#         Searches for HelloWorld alerts using the '/get_alerts' API endpoint.
#         All the parameters are passed directly to the API as HTTP POST parameters in the request

#         Args:
#             prev_id: previous id that was fetched.
#             alert_status:
#             limit: limit.
#             from_date: get events from from_date.

#         Returns:
#             List[Dict]: the next event
#         """
#         # use limit & from date arguments to query the API
#         return [{
#             'id': prev_id + 1,
#             'created_time': datetime.now().isoformat(),
#             'description': f'This is test description {prev_id + 1}',
#             'alert_status': alert_status,
#             'protocol': default_Protocol,
#             't_port': prev_id + 1,
#             'custom_details': {
#                 'triggered_by_name': f'Name for id: {prev_id + 1}',
#                 'triggered_by_uuid': str(uuid.uuid4()),
#                 'type': 'customType',
#                 'requested_limit': limit,
#                 'requested_From_date': from_date
#             }
#         }]


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): HelloWorld client to use.
        params (Dict): Integration parameters.
        first_fetch_time(str): The first fetch time as configured in the integration params.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        fetch_events(
            client=client,
            last_run={},
            max_fetch_account_audit=1,
            max_fetch_user_audit=1,
            max_fetch_authentication=1,
            event_types_to_fetch=['account_audit_logs']
        )

    except Exception as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


def get_events(client: Client, last_run, max_fetch, event_type):
    events: list[dict] = []
    last_fetched_events = last_run.get("events_ids", [])
    start_date = calculate_fetch_dates(last_run)

    while len(events) < max_fetch:
        response = client.get_events(start_date)
        filtered_events = handle_duplicates(response, last_fetched_events)
        if not filtered_events:
            break
        events.extend(filtered_events)
        events = events[:max_fetch]
        start_date, last_fetched_events = prepare_next_run(events)

    new_last_run = {"last_fetch": start_date, "events_ids": last_fetched_events}
    return events, new_last_run


def fetch_events(client: Client, last_run: dict[str, Any], max_fetch_account_audit: int, max_fetch_user_audit,
                 max_fetch_authentication, event_types_to_fetch):
    events = []
    next_run = {}

    event_type_params = {
        ACCOUNT_AUDIT_TYPE: {"client": client, "last_run": last_run.get(ACCOUNT_AUDIT_TYPE, {}),
                             "max_fetch": max_fetch_account_audit, "event_type": ACCOUNT_AUDIT_TYPE},
        USER_AUDIT_TYPE: {"client": client, "last_run": last_run.get(USER_AUDIT_TYPE, {}),
                          "max_fetch": max_fetch_user_audit, "event_type": USER_AUDIT_TYPE},
        ACCESS_AUTHENTICATION_TYPE: {"client": client, "last_run": last_run.get(ACCESS_AUTHENTICATION_TYPE, {}),
                                     "max_fetch": max_fetch_authentication, "event_type": ACCESS_AUTHENTICATION_TYPE},
    }

    for event_type in event_types_to_fetch:
        # if event_type in event_type_params:
        fetched_events, updated_last_run = get_events(**event_type_params[event_type])
        next_run[event_type] = updated_last_run
        events.extend(fetched_events)

    return next_run, events


def calculate_fetch_dates(next_run):
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
    start_date = next_run.get('last_fetch') or (
        (now_utc_time - timedelta(minutes=1)).strftime(DATE_FORMAT))
    return start_date


def prepare_next_run(events):
    latest_time = events[-1].get('when') or events[-1].get('created_at')

    # Collect IDs of all events with the latest time
    latest_ids = [event['id'] for event in events if event.get('when') or event.get('created_at') == latest_time]

    return latest_time, latest_ids
    # return {"last_fetch": latest_time, "events_ids": latest_ids}


def handle_duplicates(response, last_fetched_events):
    return [event for event in response.get('result') if event.get('id') not in last_fetched_events]


def add_time_to_events(events: List[Dict] | None):
    """
    Adds the _time key to the events.
    Args:
        events: List[Dict] - list of events to add the _time key to.
    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            create_time = arg_to_datetime(arg=event.get('when') or event.get('created_at'))
            event['_time'] = create_time.strftime(DATE_FORMAT) if create_time else None


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """
    params = demisto.params()
    demisto.args()
    command = demisto.command()
    max_fetch_account_audit = arg_to_number(params.get('max_fetch_account_audit_logs') or DEFAULT_MAX_FETCH_ACCOUNT_AUDIT)
    max_fetch_user_audit = arg_to_number(params.get('max_fetch_user_audit_logs') or DEFAULT_MAX_FETCH_USER_AUDIT)
    max_fetch_authentication = arg_to_number(params.get('max_fetch_access_authentication_logs')
                                             or DEFAULT_MAX_FETCH_ACCESS_AUTHENTICATION)
    event_types_to_fetch = argToList(params.get('event_types_to_fetch'))

    demisto.debug(f'Command being called is {command}')
    credentials = params.get("credentials", {})
    try:
        headers = {
            'Authorization': f"Bearer {params.get('api_token', {}).get('password')}",
            'X-Auth-Email': credentials.get('identifier'),
            'X-Auth-Key': credentials.get('password'),
        }
        client = Client(
            base_url=params.get('url', 'https://api.cloudflare.com/'),
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
            account_id=params.get('account_id'),
            headers=headers
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        # elif command == 'hello-world-get-events':
        #     should_push_events = argToBoolean(args.pop('should_push_events'))
        #     events, results = get_events(client, demisto.args())
        #     return_results(results)
        #     if should_push_events:
        #         add_time_to_events(events)
        #         send_events_to_xsiam(
        #             events,
        #             vendor=VENDOR,
        #             product=PRODUCT
        #         )

        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            next_run, events = fetch_events(
                client=client,
                last_run=last_run,
                max_fetch_account_audit=max_fetch_account_audit,
                max_fetch_user_audit=max_fetch_user_audit,
                max_fetch_authentication=max_fetch_authentication,
                event_types_to_fetch=event_types_to_fetch
            )

            add_time_to_events(events)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
