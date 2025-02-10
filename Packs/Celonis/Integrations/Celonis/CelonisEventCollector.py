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
BEARER_PREFIX = 'Bearer '

""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(self, base_url: str, verify: bool, client_id: str, client_secret: str):
        self.client_id = client_id
        self.client_secret = client_secret
        super().__init__(base_url=base_url, verify=verify)
        self.token = None

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
            auth=(self.client_id, self.client_secret)
        )
        self.token = results.get('access_token', '')

    def get_audit_logs(self, start_date: str, end_date: str) -> dict:
        """
        Retrieves audit logs for the given date range using the access token.
        Args:
            start_date (str): The start date of the logs in ISO 8601 format (e.g., "2025-02-05T14:30:00Z").
            end_date (str): The end date of the logs in ISO 8601 format (e.g., "2025-02-05T15:00:00Z").
        Returns:
            dict: The audit logs in JSON format.
        """
        headers = {
            'Authorization': f'{BEARER_PREFIX}{self.token}',
        }
        results = self._http_request(
            method="GET",
            url_suffix=f"/log/api/external/audit?pageNumber={PAGE_NUMBER}&pageSize={PAGE_SIZE}&from={start_date}&to={end_date}",
            headers=headers
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
    client.create_access_token_for_audit()
    return "ok"


def fetch_events(client: Client, fetch_limit: int, get_events_args: dict = None) -> tuple[list, dict]:
    if get_events_args:  # handle get_event command
        start = get_events_args.get('start_date', '')
        end = get_events_args.get('end_date', '')
    else:  # handle fetch_events case
        last_run = demisto.getLastRun() or {}
        start = last_run.get('start_date', '')
        client.set_token(last_run.get('audit_token', ''))
        if not start:
            start = "2025-02-02T09:00:00"  # TODO
            # event_date = get_current_time().strftime(DATE_FORMAT)
        end = get_current_time().strftime(DATE_FORMAT)

    demisto.debug(f'Fetching audit logs events from date={start} to date={end}.')

    output: list = []
    while True:
        try:
            response = client.get_audit_logs(start, end)
        except Exception as e:
            if hasattr(e, "message") and '429' in e.message:
                demisto.debug(f"Rate limit reached. Returning {len(output)} instead of {fetch_limit}"
                              f" Audit logs. Wait for the next fetch cycle.")
                new_last_run = {'start_date': start, 'audit_token': client.token}
                # new_last_run = {'start_date': start}
                return output, new_last_run
            if hasattr(e, "message") and 'Unauthorized' in e.message:  # need to regenerate the token
                demisto.debug(f"Regenerates token for fetching audit logs.")
                client.create_access_token_for_audit()
                response = client.get_audit_logs(start, end)
            else:
                raise e

        if not response.get('content'):
            break

        events = sort_events_by_timestamp(response.get('content'))
        # event_date = ''
        for event in events:
            event_date = event.get('timestamp')
            event['_TIME'] = event_date
            output.append(event)

            if len(output) >= fetch_limit:
                start = add_millisecond(event_date)
                new_last_run = {'start_date': start, 'audit_token': client.token}
                # new_last_run = {'start_date': start}
                return output, new_last_run

        start = add_millisecond(event_date)
        demisto.debug("Waiting 10 seconds before calling the next request.")
        time.sleep(10)


    new_last_run = {'start_date': start, 'audit_token': client.token}
    # new_last_run = {'start_date': start}
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

    human_readable = tableToMarkdown(name='Celonis Audit Logs Events', t=filtered_events, removeNull=True)
    command_results = CommandResults(
        readable_output=human_readable,
        outputs=output,
        outputs_prefix='CelonisEventCollector',
    )
    return output, command_results


def main():
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
