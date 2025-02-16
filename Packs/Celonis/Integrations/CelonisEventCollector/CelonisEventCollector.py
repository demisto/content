import demistomock as demisto
import urllib3
from CommonServerPython import *
from CommonServerUserPython import *

urllib3.disable_warnings()

""" CONSTANTS """

VENDOR = 'Celonis'
PRODUCT = 'Celonis'
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
PAGE_SIZE = 200
PAGE_NUMBER = 0
DEFAULT_FETCH_LIMIT = 600

""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(self, base_url: str, verify: bool, client_id: str, client_secret: str):
        self.client_id = client_id
        self.client_secret = client_secret
        super().__init__(base_url=base_url, verify=verify)
        self.token: str = ''

    def set_token(self, token: str):
        """
        Sets the client token.
        """
        self.token = token

    def create_access_token_for_audit(self) -> None:
        """
        Creates an access token for audit log access using a specific scope and client credentials.
        """
        data = {
            "grant_type": "client_credentials",
            "scope": "audit.log:read"
        }
        results = self._http_request(
            method="POST",
            url_suffix="/oauth2/token",
            data=data,
            auth=(self.client_id, self.client_secret),
            retries=3
        )
        self.token = results.get('access_token', '')

    def get_audit_logs(self, start_date: str, end_date: str) -> requests.Response:
        """
        Retrieves audit logs for the given date range using the access token.
        Args:
            start_date (str): The start date of the logs in ISO 8601 format (e.g., "2025-02-05T14:30:00Z").
            end_date (str): The end date of the logs in ISO 8601 format (e.g., "2025-02-05T15:00:00Z").
        Returns:
            dict: The raw response.
        """
        results = self._http_request(
            method="GET",
            url_suffix=f"/log/api/external/audit?pageNumber={PAGE_NUMBER}&pageSize={PAGE_SIZE}&from={start_date}&to={end_date}",
            headers={
                'Authorization': f'Bearer {self.token}',
            },
            resp_type='response',
            retries=3
        )
        return results


""" HELPER FUNCTIONS """


def sort_events_by_timestamp(events: list) -> list:
    """
    Sorts a list of events by their date in ascending order.
    Args:
        events (list): A list of dictionaries.
    Returns:
        list: The sorted list of events based on the 'timestamp' field.
    """
    return sorted(events, key=lambda x: datetime.strptime(x['timestamp'], '%Y-%m-%dT%H:%M:%S.%f%z'))


def add_millisecond(timestamp: str) -> str:
    """
    Adds one millisecond to a given timestamp.
    Args:
        timestamp (str): The timestamp in ISO 8601 format (e.g., "2025-02-05T14:30:00.123Z").
    Returns:
        str: The new timestamp with one millisecond added, formatted in ISO 8601.
    """
    dt = datetime.strptime(timestamp, DATE_FORMAT)
    dt += timedelta(milliseconds=1)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


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
            event['_TIME'] = event_date
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


def main():  # pragma: no cover
    """main function, parses params and runs command functions"""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    demisto.debug(f"Command being called is {command}")
    try:
        base_url = params.get("url")
        verify_certificate = not argToBoolean(params.get("insecure", False))
        client_id = params.get('credentials', {}).get('identifier')
        client_secret = params.get('credentials', {}).get('password')
        fetch_limit = arg_to_number(params.get('max_events_per_fetch')) or DEFAULT_FETCH_LIMIT

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            client_id=client_id,
            client_secret=client_secret
        )
        if command == "test-module":
            result = test_module(client)
            return_results(result)
        elif command == "fetch-events":
            events, new_last_run_dict = fetch_events(client, fetch_limit)
            if events:
                demisto.debug(f'Sending {len(events)} events.')
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(new_last_run_dict)
            demisto.debug(f'Successfully saved last_run= {demisto.getLastRun()}')
        elif command == "celonis-get-events":
            events, command_results = get_events(client, args)
            if events and argToBoolean(args.get('should_push_events')):
                demisto.debug(f'Sending {len(events)} events.')
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            return_results(command_results)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
