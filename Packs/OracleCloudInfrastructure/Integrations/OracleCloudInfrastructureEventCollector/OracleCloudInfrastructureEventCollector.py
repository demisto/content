import demistomock as demisto
from CommonServerPython import *
from typing import Any
from oci.regions import is_region
from oci.signer import Signer

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'  # ISO8601 format with UTC, default in XSOAR
VENDOR = 'oracle'
PRODUCT = 'cloud_infrastructure'
MAX_EVENTS_TO_FETCH = 100
FETCH_DEFAULT_TIME = '3 days'
PORT = 20190901


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the OCI SDK and API requests.
    Will validate the fetching related parameters and create an OCI Singer object which will be used to fetch audit events.
    """

    def __init__(self, verify_certificate: bool, proxy: bool, user_ocid: str, private_key: str, key_fingerprint: str,
                 tenancy_ocid: str, region: str, compartment_id: str, private_key_type: str):
        self.singer = self.build_singer_object(user_ocid, private_key, key_fingerprint, tenancy_ocid, private_key_type)
        self.base_url = self.build_audit_base_url(region)
        self.compartment_id = compartment_id if compartment_id else tenancy_ocid
        super().__init__(proxy=proxy, verify=verify_certificate, auth=self.singer, base_url=self.base_url)

    def build_singer_object(self, user_ocid: str, private_key: str, key_fingerprint: str, tenancy_ocid: str,
                            private_key_type: str) -> dict[str, str]:
        """Build a singer object.
        The Signer used as part of making raw requests.

        Args:
            user_ocid (str): User OCID parameter.
            private_key (str): Private Key parameter.
            key_fingerprint (str): API Key Fingerprint parameter.
            tenancy_ocid (str): Tenancy OCID parameter.
            private_key_type (str): The type of the private key.

        Raises:
            DemistoException: If the singer object is invalid.

        Returns:
            (dict): A config dictionary that can be used to create Audit clients.
        """
        try:
            validated_private_key = self.validate_private_key_syntax(private_key, private_key_type)

            singer = Signer(
                tenancy=tenancy_ocid,
                user=user_ocid,
                fingerprint=key_fingerprint,
                private_key_content=validated_private_key,
                private_key_file_location=None,
            )
        except Exception as e:
            raise DemistoException(
                'Could not create a valid OCI singer object, Please check the instance configuration parameters.',
                exception=e) from e

        return singer

    def build_audit_base_url(self, region: str) -> str:
        """Build the base URL for the client.

        Args:
            region (str): Region parameter.

        Raises:
            DemistoException: If the region is not valid.

        Returns:
            str: Base URL for the client.
        """
        if not is_region(region):
            raise DemistoException('Could not create a valid OCI configuration dictionary due to invalid region parameter. \
                Please check your OCI-related instance configuration parameters.')

        return f'https://audit.{region}.oraclecloud.com/{PORT}/auditEvents'

    def validate_private_key_syntax(self, private_key_parameter: str, private_key_type: str) -> str:
        """Validate private key parameter syntax.
        The Private Key parameter needs to be provided to the OCI SDK singer object in a specific format.
        The most common way to obtain the private key is to download a .pem file from the OCI console.
        If copied from a .pem file, the private key parameter may contain unnecessary spaces.
        Further more, since the format uses \n as part of the key,
        passing this value as a configuration parameter may result in escaped \n characters.

        This function will preform the following actions on the private key parameter:
            - Unescape the string.
            - Remove unnecessary spaces in the string.

        Example:
        Raw Private Key parameter: -----BEGIN PRIVATE KEY-----\\n\n THIS-IS-A\\n\n PRIVATE-KEY\\n\n -----END PRIVATE KEY-----
        Output: -----BEGIN PRIVATE KEY-----\nTHIS-IS-A\nPRIVATE-KEY\n-----END PRIVATE KEY-----

        Args:
            private_key_parameter (str): Private Key parameter.
            private_key_type(str): The type of the private key PKCS#1 and PKCS#8.
                More info about the types: https://stackoverflow.com/questions/48958304/pkcs1-and-pkcs8-format-for-rsa-private-key

        Returns:
            str: Private Key parameter unescaped and spaceless.
        """
        private_key = stringUnEscape(private_key_parameter)
        private_key = private_key.replace('\n\n', '\n')

        if ' ' not in private_key:
            return private_key

        demisto.debug(f'{private_key_type=}')
        if private_key_type == 'PKCS#8':
            prefix = '-----BEGIN PRIVATE KEY-----\n'
            postfix = '\n-----END PRIVATE KEY-----'
        else:
            prefix = '-----BEGIN RSA PRIVATE KEY-----\n'
            postfix = '\n-----END RSA PRIVATE KEY-----'

        private_key = private_key.replace(prefix, '').replace(postfix, '')

        private_key_sections = private_key.strip().split(' ')
        striped_private_key = ''.join(private_key_sections)
        return prefix + striped_private_key + postfix


''' Event related functions '''


def add_time_key_to_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Add the _time key to the events.
    It is the current decided solution for the _time data model field.
    Note:   _time used to be parsed as a parsing rule in XSIAM,
            but to avoid a lot of cases where parsing rules were created only for _time field,
            now the current acceptable solution is to "map" this attribute programmatically.
    Args:
        events (list[dict[str, Any]]): The events to add the time key to.
    Returns:
        list[dict[str, Any]]: The events with the _time key.
    """
    for event in events:
        if event_time := event.get("eventTime"):
            event["_time"] = event_time

    return events


def get_last_event_time(events: list, first_fetch_time: datetime) -> str:
    """Get the latest event time from the fetched events list for next fetch cycle.
    - Given a non empty list of events, the function will return the time of the last event (most recent event) + 1 milliseconds.
    - If the event list is empty, the function will return the current first fetch time.

    Args:
        events (list): list of fetched events.
        first_fetch_time (datetime): current first fetch time.

    Returns:
        str: first fetch time for next fetch cycle.
        - If the events list is not empty, return the time of the latest event + 1 milliseconds.
        - If the events list is empty, return the current first fetch time.
    """
    if not events:
        return first_fetch_time.strftime(DATE_FORMAT)

    last_event_time = events[-1].get('eventTime')
    if not isinstance(last_event_time, datetime):
        last_event_time = arg_to_datetime(arg=last_event_time, settings={'RETURN_AS_TIMEZONE_AWARE': False})

    return (last_event_time + timedelta(milliseconds=1)).strftime(DATE_FORMAT) if last_event_time \
        else first_fetch_time.strftime(DATE_FORMAT)


def get_fetch_time(last_run: str | None, first_fetch_param: str) -> datetime | None:
    """Calculates the time in which the current fetch should start from.

    Args:
        last_run (Optional[str]): Last run time from previous fetch.
        first_fetch_param (str): First fetch time parameter.

    Returns:
        Optional[datetime]: Maximum datetime value between last run from previous fetch and first fetch time parameter.
    """
    first_fetch_param_datetime = arg_to_datetime(arg=first_fetch_param)

    # if last_run is None (first time we are fetching) -> return first_fetch_arg datetime object
    if not last_run:
        return first_fetch_param_datetime
    else:
        last_run_datetime = arg_to_datetime(arg=last_run, settings={'RETURN_AS_TIMEZONE_AWARE': False})

    if last_run_datetime and first_fetch_param_datetime:
        return max(last_run_datetime, first_fetch_param_datetime)
    else:
        return arg_to_datetime(arg=FETCH_DEFAULT_TIME)


def events_to_command_results(events: list[dict[str, Any]]) -> CommandResults:
    """Returns a CommandResults object with a table of fetched events.

    Args:
        events (list[dict[str, Any]]): list of fetched events.

    Returns:
        CommandResults: CommandResults object with a table of fetched events.
    """
    return CommandResults(
        readable_output=tableToMarkdown(
            'Oracle Cloud Infrastructure Events', events, removeNull=True,
            headerTransform=pascalToSpace),
        raw_response=events)


def audit_log_api_request(client: Client, start_time: str, next_page: str | None = None) -> requests.Response:
    """Makes HTTP GET request to an OCI API endpoint.

    Args:
        client (Client): client object.
        start_time (str): start time query parameter.
        next_page (str | None, optional): next page query parameter for pagination. Defaults to None.

    Returns:
        requests.Response: raw response from the API.
    """
    params = {
        'compartmentId': client.compartment_id,
        'startTime': start_time,
        'endTime': datetime.now().strftime(DATE_FORMAT)}
    if next_page:
        params['opc-next-page'] = next_page
    return client._http_request(method='GET', params=params, resp_type='response')


def add_millisecond_to_timestamp(timestamp: str) -> str:
    """Add 1 millisecond to the given timestamp.

    Args:
        timestamp (str): Timestamp to add 1 millisecond to.

    Raises:
        DemistoException: If datetime conversion fails.

    Returns:
        str: Timestamp with 1 millisecond added.
    """
    try:
        timestamp_datetime = arg_to_datetime(arg=timestamp, settings={'RETURN_AS_TIMEZONE_AWARE': False})
        if isinstance(timestamp_datetime, datetime):
            return (timestamp_datetime + timedelta(milliseconds=1)).strftime(DATE_FORMAT)
        else:
            raise DemistoException('Datetime conversion failed.')
    except Exception as e:
        raise DemistoException(message=e) from e


def get_events(
        client: Client, first_fetch_time: datetime, max_fetch: int, push_events_on_error: bool) -> tuple[
        list[dict[str, Any]],
        str]:
    """Get events from an oracle cloud infrastructure tenant.
    - The request returns a maximum of 100 events per call by default.
    - This function uses pagination, meaning it will make multiple request as needed to reach the desired amount of events.

    Args:
        client (Client): Client object for requests.
        first_fetch_time (datetime): The start time to fetch events from.
        max_fetch (int): The limit of events to fetch.
        push_events_on_error (bool): Whether to push available fetched events to XSIAM if an error occurred while fetching events.

    Raises:
        DemistoException: If an error occurred while fetching events.

    Returns:
        tuple[list[dict[str, Any]], str]: A tuple of the events list and the last event time for next fetch cycle.
    """
    try:
        response = audit_log_api_request(client=client, start_time=first_fetch_time.strftime(DATE_FORMAT))
        events = json.loads(response.content)

        if not events:
            return [], first_fetch_time.strftime(DATE_FORMAT)

        if isinstance(events, dict):
            events = [events]

        # pagination handling
        while len(events) < max_fetch and (next_page := response.headers._store.get('opc-next-page')):  # type: ignore
            current_start_time = add_millisecond_to_timestamp(events[-1].get('eventTime'))
            response = audit_log_api_request(client=client, start_time=current_start_time, next_page=next_page[1])
            events.extend(json.loads(response.content))

        last_event_time = get_last_event_time(events, first_fetch_time)
        events = add_time_key_to_events(events)

    # handle the case where an error occurred while fetching events,
    # and there are currently available events that can and need to be sent to XSIAM.
    except Exception as e:
        if events and push_events_on_error:
            last_event_time = get_last_event_time(events, first_fetch_time)
            events = add_time_key_to_events(events)
            handle_fetched_events(events, last_event_time)
            raise DemistoException(f'Error while fetching events: {e}') from e

    demisto.info(f'OCI: {len(events)} Events fetched from start time: {first_fetch_time}.')
    return events, last_event_time


def handle_fetched_events(events: list[dict[str, Any]], last_event_time: str):
    """Handles fetched events.
    - Sends the events to XSIAM.
    - Sets the last run for next fetch cycle.

    Args:
        events (list[dict[str, Any]]): Fetched events.
        last_event_time (str): Last event time.
    """
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
    demisto.info(f'OCI: {len(events)} events were sent to XSIAM at {datetime.now()}.')
    if events:
        demisto.setLastRun({"lastRun": last_event_time})
        demisto.info(f'OCI: Set last run to {last_event_time}')
    else:
        demisto.info('OCI: No new events fetched, Last run was not updated.')


''' Test module '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication.

    Args:
        client (Client): Client for SDK interaction and api requests.

    Raises:
        DemistoException: If an error occurred while testing.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        datetime_now = datetime.now().strftime(DATE_FORMAT)
        params = {
            'compartmentId': client.compartment_id,
            'startTime': datetime_now,
            'endTime': datetime_now
        }
        client._http_request(method='GET', params=params)

    except Exception as e:
        if 'failed' in str(e):
            return 'Authorization Error: make sure OCI parameters are correctly set'
        else:
            raise DemistoException(f'Error while testing: {e}') from e

    return 'ok'


''' MAIN FUNCTION '''


def main():
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    last_run_time = demisto.getLastRun().get('lastRun')
    demisto.info(f'OCI: last_run_time value {last_run_time}')
    max_fetch = arg_to_number(params.get('max_fetch')) or MAX_EVENTS_TO_FETCH
    first_fetch = params.get('first_fetch', FETCH_DEFAULT_TIME)
    first_fetch_time = get_fetch_time(last_run=last_run_time, first_fetch_param=first_fetch)
    should_push_events = argToBoolean(args.get('should_push_events', False))
    private_key_type = params.get('private_key_type') or 'PKCS#8'
    demisto.info(f'OCI: Command being called is {command}')

    try:
        if not isinstance(first_fetch_time, datetime):
            raise DemistoException('Could not resolve First fetch time parameter.')

        client = Client(
            verify_certificate=not params.get('insecure', False),
            proxy=params.get('proxy', False),
            user_ocid=params.get('user_ocid'),
            private_key=params.get('credentials', {}).get('password'),
            key_fingerprint=params.get('credentials', {}).get('identifier'),
            tenancy_ocid=params.get('tenancy_ocid'),
            region=params.get('region'),
            compartment_id=params.get('compartment_id'),
            private_key_type=private_key_type
        )
        demisto.info('OCI: Client created successfully.')

        if command == 'test-module':
            return_results(test_module(client))

        elif command in ('oracle-cloud-infrastructure-get-events', 'fetch-events'):
            push_events = (command == 'fetch-events' or should_push_events)
            events, last_event_time = get_events(client, first_fetch_time, max_fetch, push_events_on_error=push_events)

            if push_events:
                handle_fetched_events(events, last_event_time)

            elif command == 'oracle-cloud-infrastructure-get-events':
                return_results(events_to_command_results(events))
        else:
            return_error(f'Command {command} does not exist for this integration.')
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
