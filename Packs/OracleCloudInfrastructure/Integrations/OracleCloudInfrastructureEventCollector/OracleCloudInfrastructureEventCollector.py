import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any, Dict, List, Optional
from oci.regions import is_region
from oci.signer import Signer

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'oracle'
PRODUCT = 'cloud_infrastructure'
MAX_EVENTS_TO_FETCH = 1000
FETCH_DEFAULT_TIME = '7 days'
PORT = 20190901


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the OCI SDK and API requests.
    Will validate the fetching related parameters and create an OCI Singer object which will be used to fetch audit events.
    """
    def __init__(self, verify_certificate: bool, proxy: bool, user_ocid: str, private_key: str, key_fingerprint: str,
                 tenancy_ocid: str, region: str):
        self.singer = self.build_singer_object(user_ocid, private_key, key_fingerprint, tenancy_ocid, region)
        self.base_url = self.build_audit_base_url(region)
        self.compartment_id = tenancy_ocid
        super().__init__(proxy=proxy, verify=verify_certificate, auth=self.singer, base_url=self.base_url)

    def build_singer_object(self, user_ocid: str, private_key: str, key_fingerprint: str, tenancy_ocid: str,
                            region: str) -> Dict[str, str]:
        """Build a singer object.
        The Signer used as part of making raw requests.

        Args:
            user_ocid (str): User OCID parameter.
            private_key (str): Private Key parameter.
            key_fingerprint (str): API Key Fingerprint parameter.
            tenancy_ocid (str): Tenancy OCID parameter.
            region (str): Region parameter.

        Raises:
            DemistoException: If the singer object is invalid.

        Returns:
            (dict): A config dictionary that can be used to create Audit clients.
        """
        try:
            validated_private_key = self.validate_private_key_syntax(private_key)

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
                exception=e,) from e

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
            raise DemistoException('Could not create a valid OCI configuration dictionary fou to invalid region parameter. \
                Please check your OCI related instance configuration parameters.')

        return f'https://audit.{region}.oraclecloud.com/{PORT}/auditEvents'

    def validate_private_key_syntax(self, private_key_parameter: str) -> str:
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
            private_key (str): Private Key parameter.

        Returns:
            str: Private Key parameter unescaped and spaceless.
        """
        private_key = stringUnEscape(private_key_parameter)
        private_key = private_key.replace('\n\n', '\n')

        if ' ' not in private_key:
            return private_key

        prefix = '-----BEGIN PRIVATE KEY-----\n'
        postfix = '\n-----END PRIVATE KEY-----'

        private_key = private_key.replace(prefix, '').replace(postfix, '')

        private_key_sections = private_key.strip().split(' ')
        striped_private_key = ''.join(private_key_sections)
        return prefix + striped_private_key + postfix


''' OCI Event Handler Class '''


class OCIEventHandler:
    """
    Oracle Cloud Infrastructure event handler class.
    Handles the logic for using the OCI Audit Client and fetching events.
    """

    def __init__(self, client: Client, last_run: Dict[str, Any], max_fetch: int, first_fetch_time: datetime):
        self.client: Client = client
        self.last_run = last_run
        self.max_fetch = max_fetch
        self.first_fetch_time: datetime = first_fetch_time

    def __str__(self):
        return f'OCIEventHandler: {self.last_run=}, {self.max_fetch=}, {self.first_fetch_time=}'

    def get_events(self, max_events: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get events from CIO client.
        - This method loads all audit events in the time range and it does
          have performance implications of lot of audit events.
        - The list_events function will return a maximum of 100 events per call.
          In order to get more events this function is wrapped with the list_call_get_all_results function,
          which will get all the events in a certain time range and than slice the events
          according to the desired amount of events.
        Args:
            max_events (int): Maximum number of events to fetch. If None, the default value will be max_fetch parameter.

        Returns:
            List[Dict[str, Any]]: List of events.
        """
        try:
            params = {
                'compartmentId': self.client.compartment_id,
                'startTime': self.first_fetch_time.isoformat(),
                'endTime': datetime.now().isoformat()
            }
            response = self.client._http_request(method='GET', params=params)

            if not response:
                return []

            events = response[:max_events] if max_events else response[:self.max_fetch]

            self.last_event_time = self.get_last_event_time(events)
            events = self.add_time_key_to_events(events)

        except Exception as e:
            raise DemistoException(f'Error while fetching events: {e}') from e

        # demisto.info(f'OCI: {len(events)} Events fetched from start time: {self.first_fetch_time}.')
        # return events
        return events

    def get_last_event_time(self, events: List) -> str:
        """Get the last event time from the events list for next fetch cycle.
        - Given a non empty list of events,
          the function will return the time of the last event (most recent event) + 1 microseconds.
        - If the event list is empty, the function will return the current first fetch time.

        Args:
            events (List[AuditEvent]): list of events.

        Returns:
            str: last event time for next fetch cycle in string format.
        """
        # if no events were fetched, return the current first fetch time.
        if not events:
            return self.first_fetch_time.isoformat()

        # get the event time of last event in the list (will always be the most recent event)
        last_event_time = events[-1].get('event_time')
        if not isinstance(last_event_time, datetime):
            last_event_time = arg_to_datetime(arg=last_event_time)

        # return the last event time + 1 microsecond, or the current first fetch time if the last event time is None.
        return (last_event_time + timedelta(microseconds=1)).isoformat() if last_event_time \
            else self.first_fetch_time.isoformat()

    def add_time_key_to_events(self, events: List[Dict[str, Any]]) -> List:
        """
        Add the _time key to the events.
        Args:
            events (List[Dict[str, Any]]): The events to add the time key to.
        Returns:
            List[Dict[str, Any]]: The events with the _time key.
        """
        for event in events:
            if event.get("eventTime"):
                event["_time"] = event.get("eventTime")

        return events


def test_module(client: Client, oci_event_handler: OCIEventHandler) -> str:
    """
    Tests API connectivity and authentication.
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): Client for SDK interaction and api requests.
        oci_event_handler (OCIEventHandler): OCI event handler object.
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    try:
        params = {
            'compartmentId': oci_event_handler.client.compartment_id,
            'startTime': datetime.now().isoformat(),
            'endTime': datetime.now().isoformat()
        }
        client._http_request(method='GET', params=params)

    except Exception as e:
        if 'failed' in str(e):
            return 'Authorization Error: make sure OCI parameters are correctly set'
        else:
            raise DemistoException(f'Error while testing: {e}') from e

    return 'ok'


def calculate_first_fetch_time(last_run: Optional[str], first_fetch_param: str) -> Optional[datetime]:
    """Calculates the first fetch time.

    Args:
        last_run (Optional[str]): Last run time from previous fetch.
        first_fetch_param (str): First Fetch Time integration parameter.

    Returns:
        Optional[datetime]: Maximum datetime value between last run from previous fetch and first fetch time parameter.
    """
    first_fetch_param_datetime = arg_to_datetime(arg=first_fetch_param)

    # if last_run is None (first time we are fetching) -> return first_fetch_arg datetime object
    if not last_run:
        return first_fetch_param_datetime
    else:
        last_run_datetime = arg_to_datetime(arg=last_run, settings={'RETURN_AS_TIMEZONE_AWARE': False})

    # if last_run is not None -> return max(last_run, first_fetch_arg)
    if last_run_datetime and first_fetch_param_datetime:
        return max(last_run_datetime, first_fetch_param_datetime)
    else:  # return default first fetch time datetime object
        return arg_to_datetime(arg=FETCH_DEFAULT_TIME)


''' MAIN FUNCTION '''


def main():
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    last_run = demisto.getLastRun()
    last_run_time = last_run.get('lastRun')
    demisto.info(f'last_run_time value {last_run_time}')
    max_fetch = arg_to_number(params.get('max_fetch')) or MAX_EVENTS_TO_FETCH
    first_fetch = params.get('first_fetch') or FETCH_DEFAULT_TIME
    first_fetch_time: Optional[datetime] = calculate_first_fetch_time(last_run=last_run_time, first_fetch_param=first_fetch)
    demisto.info(f'OCI: Command being called is {command}')

    try:
        if not isinstance(first_fetch_time, datetime):
            raise DemistoException('Could not resolve First fetch time parameter.')

        client = Client(
            verify_certificate=not params.get('insecure', False),
            proxy=params.get('proxy', False),
            user_ocid=params.get('user_ocid'),
            private_key=params.get('private_key'),
            key_fingerprint=params.get('key_fingerprint'),
            tenancy_ocid=params.get('tenancy_ocid'),
            region=params.get('region')
        )
        demisto.info('OCI: Client created successfully.')

        oci_event_handler = OCIEventHandler(client, last_run, max_fetch, first_fetch_time)
        demisto.info(f'OCI: OCI Event Handler created successfully. {oci_event_handler=}')

        if command == 'test-module':
            return_results(test_module(client, oci_event_handler))

        elif command in ('oracle-cloud-infrastructure-get-events', 'fetch-events'):
            events = oci_event_handler.get_events()

            if command == 'fetch-events' or args.get('should_push_events'):
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
                if events:
                    last_event_time = oci_event_handler.last_event_time
                    demisto.info(f'OCI: Set last run to {last_event_time}')
                    demisto.setLastRun({"lastRun": {last_event_time}})
                else:
                    demisto.info('OCI: No new events fetched, Last run was not updated.')

            elif command == 'oracle-cloud-infrastructure-get-events':
                command_results = CommandResults(
                    readable_output=tableToMarkdown(
                        'Oracle Cloud Infrastructure Events', events, removeNull=True, headerTransform=pascalToSpace),
                    raw_response=events,
                )
                return_results(command_results)
        else:
            return_error(f'Command {command} does not exist for this integration.')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
