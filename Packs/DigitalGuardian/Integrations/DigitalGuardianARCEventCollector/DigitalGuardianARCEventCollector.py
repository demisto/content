from CommonServerPython import *
import urllib3
from datetime import datetime, timedelta
import time
from typing import Any, Tuple

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'Digital Guardian'
PRODUCT = 'ARC'

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client class to interact with the service API
    implements get_token and get_events functions
    """

    def __init__(self, verify, proxy, auth_url, gateway_url, base_url, client_id, client_secret, export_profile, headers=None):
        self.auth_url = auth_url
        self.gateway_url = gateway_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.export_profile = export_profile

        super().__init__(base_url=base_url, headers=headers, verify=verify, proxy=proxy)

    def get_token(self):
        integration_context = get_integration_context()
        token = integration_context.get('token')
        valid_until = integration_context.get('valid_until')
        time_now = int(time.time())
        if token and valid_until:
            if time_now < valid_until:
                # Token is still valid - did not expire yet
                demisto.debug('Using cached token which is still valid')
                demisto.debug(f'time-now: {time_now}\n valid token until: {valid_until}')
                return token
        sec = self.client_secret
        response = self._http_request(
            method='POST',
            full_url=f'{self.auth_url}/as/token.oauth2',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            data=f'client_id={self.client_id}&client_secret={sec}&grant_type=client_credentials',
        )
        demisto.debug('Using new token which was just received from DG')
        integration_context = {
            'token': response.get("access_token"),
            'valid_until': time_now + int(response.get("expires_in")) - 100
        }
        set_integration_context(integration_context)
        return response.get("access_token")

    def get_events(self, time_of_last_event_str, current_time):
        token = self.get_token()
        time_param = f'dg_time:{time_of_last_event_str},{current_time}'
        headers = {
            'Authorization': 'Bearer ' + token
        }
        response = self._http_request(
            method='GET',
            headers=headers,
            params={'q': time_param}
        )
        return response


def test_module(client: Client, params: Dict[str, Any]) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): Digital Guardian client to use.
        params (Dict): Integration parameters.
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    try:
        limit = arg_to_number(params.get('number_of_events')) or 1000
        fetch_events(
            client=client,
            last_run={},
            limit=limit,
        )

    except Exception as e:
        if 'Forbidden' in str(e):
            raise DemistoException('Authorization Error: make sure API Key is correctly set')
        else:
            raise e
    return "ok"


def get_raw_events(client: Client, time_of_last_event: str) -> list:
    """
       helper function that is used in get-events and fetch-events to get the actual events and sort them
       Args:
           client (Client): DG client
           time_of_last_event: time of last ingested event
       Returns:
           list: list of events
    """
    outcome = []
    event_list = []
    if not time_of_last_event:
        time_of_last_event_datetime = datetime.now() - timedelta(hours=1)
        time_of_last_event_str = datetime_to_string(time_of_last_event_datetime)
    else:
        temp_time: datetime = arg_to_datetime(arg=time_of_last_event, required=True)  # type: ignore[assignment]
        time_of_last_event_str = temp_time.isoformat(sep=' ', timespec='milliseconds')
    current_time = datetime_to_string(datetime.now())
    events = client.get_events(time_of_last_event_str, current_time)
    for field_names in events["fields"]:
        outcome.append(field_names['name'])
    for event in events["data"]:
        result = dict(zip(outcome, event))
        event_list.append(result)
    event_list.sort(key=lambda item: (item["inc_mtime"], item["dg_guid"]))
    return event_list


def get_events_command(client: Client, args: dict) -> Tuple[list, CommandResults]:
    """
        Implement the get_events command
        Args:
            client (Client): DG client
            args (dict): Command arguments
        Returns:
            list: list of events
            commandresults: readable output
    """
    event_list = get_raw_events(client, "")
    limit = int(args.get("limit", 1000))
    if limit:
        event_list = event_list[:limit]
    hr = tableToMarkdown(name='Test Event', t=event_list)
    demisto.debug(f'get events command that ran with the limit: {limit}')
    return event_list, CommandResults(readable_output=hr)


def create_events_for_push(event_list: list, last_time: str, id_list: list, limit: int) -> Tuple[list, str, list]:
    """
       Create events for pushing them and prepares the values for next_run save
       Args:
           event_list (list): list of events
           last_time (str): time of last event from previous run
           id_list (list): list of id's ingested
           limit (int): max_fetch
       Returns:
           list: list of events
           last_time: updates time of last event
           id_list: list of id's
    """
    index = 0
    event_list_for_push = []
    demisto.debug('Checking duplications and creating events for pushing to XSIAM')
    for event in event_list:
        if last_time:
            last_time_date = arg_to_datetime(arg=last_time, required=True).date()   # type: ignore[union-attr]
            event_date = arg_to_datetime(arg=event.get("inc_mtime"), required=True).date()   # type: ignore[union-attr]
            if event.get("inc_mtime") < last_time or event.get("dg_guid") in id_list:
                continue
            if last_time_date == event_date:
                id_list.append(event.get("dg_guid"))
            else:
                id_list = [event.get("dg_guid")]
        else:
            id_list.append(event.get("dg_guid"))
        event_list_for_push.append(event)
        last_time = event.get("inc_mtime")
        index += 1
        if index == limit:
            break
    return event_list_for_push, last_time, id_list


def fetch_events(client: Client, last_run: dict[str, list], limit: int) -> Tuple[dict, list]:
    """
    Args:
        client (Client): DG client to use.
        last_run (dict): A dict with a key containing the latest event created time we got from last fetch.
        limit (int):

    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch and list of ID's
              of ingested id's
        list: List of events that will be created in XSIAM.
    """
    id_list = last_run.get('id_list', [])
    last_time = str(last_run.get('start_time') or "")
    demisto.debug('fetching events')
    event_list = get_raw_events(client, last_time)
    event_list_for_push, time_of_event, id_list = create_events_for_push(event_list, last_time, id_list, limit)

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'start_time': time_of_event, 'id_list': id_list}
    demisto.debug(f'Setting next run {next_run}.')
    return next_run, event_list_for_push


def add_time_to_events(events: list[dict]) -> None:
    """
    Adds the _time key to the events.
    Args:
        events: List[Dict] - list of events to add the _time key to.
    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            create_time = arg_to_datetime(arg=event.get('inc_mtime'))
            event['_time'] = create_time.strftime(DATE_FORMAT) if create_time else None


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    auth_url = params.get('auth_server_url')
    gateway_url = params.get('gateway_base_url')
    client_id = params.get('credentials', {}).get('identifier', '')
    client_secret = params.get('credentials', {}).get('password', '')
    export_profile = params.get('export_profile')
    verify_certificate = not params.get('insecure', False)
    base_url = urljoin(gateway_url, f'/rest/2.0/export_profiles/{export_profile}/export')
    demisto.debug(f'the base url is:{base_url}')
    next_run = None

    # How much time before the first fetch to retrieve events
    proxy = params.get('proxy', False)
    limit = arg_to_number(params.get('number_of_events')) or 1000

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            verify=verify_certificate,
            proxy=proxy,
            auth_url=auth_url,
            gateway_url=gateway_url,
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            export_profile=export_profile
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, params)
            return_results(result)

        elif command == 'digital-guardian-get-events':
            should_push_events = argToBoolean(args.pop('should_push_events'))
            events, results = get_events_command(client, args)
            return_results(results)
            if should_push_events:
                add_time_to_events(events)
                send_events_to_xsiam(
                    events,
                    vendor=VENDOR,
                    product=PRODUCT
                )
        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            next_run, events = fetch_events(
                client=client,
                last_run=last_run,
                limit=limit
            )
            add_time_to_events(events)
            send_events_to_xsiam(
                events,
                vendor=VENDOR,
                product=PRODUCT
            )
            # saves next_run for the time fetch-events is invoked
            demisto.setLastRun(next_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
