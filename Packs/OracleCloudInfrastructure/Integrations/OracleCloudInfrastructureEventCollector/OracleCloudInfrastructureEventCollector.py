import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any, Dict, List, Optional
from oci.config import validate_config
from oci.regions import is_region
import oci.audit
import oci.pagination

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'oracle'
PRODUCT = 'cloud_infrastructure'
MAX_EVENTS_TO_FETCH = 1000
FETCH_DEFAULT_TIME = '3 days'


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the OCI SDK"""
    def __init__(self, verify_certificate: bool, proxy: bool, user_ocid: str, private_key: str, key_fingerprint: str,
                 tenancy_ocid: str, region: str):
        self.config = self.build_oci_config(user_ocid, private_key, key_fingerprint, tenancy_ocid, region)
        self.audit_client = oci.audit.AuditClient(self.config)
        super().__init__(proxy=proxy, verify=verify_certificate, base_url=None)

    def build_oci_config(
            self, user_ocid: str, private_key: str, key_fingerprint: str, tenancy_ocid: str, region: str) -> Dict[str, str]:
        """Build an OCI config object

        Args:
            user_ocid (str): User OCID parameter.
            private_key (str): Private Key parameter.
            key_fingerprint (str): API Key Fingerprint parameter.
            tenancy_ocid (str): Tenancy OCID parameter.
            region (str): Region parameter.

        Raises:
            DemistoException: If the config object is invalid.

        Returns:
            (dict): A config dictionary that can be used to create Audit clients.
        """
        config = {
            'user': user_ocid,
            'key_content': self.validate_private_key_syntax(private_key),
            'fingerprint': key_fingerprint,
            'tenancy': tenancy_ocid,
            'region': region
        }

        return config if self.validate_oci_config(config) else {}

    def validate_oci_config(self, config: Dict[str, str]) -> bool:
        """Validate the OCI config dictionary structure.

        Args:
            config (Dict[str, str]): A config dict that can be used to create Audit client using the oci.audit.AuditClient class.

        Raises:
            DemistoException: If the region is not valid.
            DemistoException: If the config  dictionary is invalid.

        Returns:
            bool: True if the config dictionary is valid, False otherwise.
        """

        if not is_region(config.get('region')):
            raise DemistoException('Could not create a valid OCI configuration dictionary fou to invalid region parameter. \
                Please check your OCI related instance configuration parameters.')
        try:
            validate_config(config)
        except Exception as e:
            raise DemistoException(
                'Could not create a valid OCI configuration dictionary, Please check OCI instance configuration parameters.',
                exception=e,
            ) from e
        return True

    def validate_private_key_syntax(self, private_key_parameter: str) -> str:
        """Validate private key parameter syntax.
        The Private Key parameter needs to be provided to the OCI SDK config object in a specific format.
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
    Handles the logic for creating and handling Audit client and fetching events.
    """

    def __init__(self, client: Client, last_run: Dict[str, Any], max_fetch: int, first_fetch_time: datetime):
        self.client: Client = client
        self.last_run = last_run
        self.max_fetch = max_fetch
        self.first_fetch_time = first_fetch_time

    def __str__(self):
        return f'OCIEventHandler: {self.last_run=}, {self.max_fetch=}, {self.first_fetch_time=}'

    def get_events(self, max_events: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get events from CIO client.
        - This method loads all audit events in the time range and it does
          have performance implications of lot of audit events.
        - The list_events function will return a maximum of 100 events per call,
          in order to get more events this function is wrapped with the list_call_get_all_results function,
          which will get all the events in a certain time range and than slice the events according to the desired amount of events.
        Args:
            prev_id (int): The id of the last event we got from the last run.
            alert_status (str): status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.

        Returns:
            List[Dict[str, Any]]: List of events.
        """
        try:
            response = oci.pagination.list_call_get_all_results(
                self.client.audit_client.list_events,
                compartment_id=self.client.config.get('tenancy'),
                start_time=self.first_fetch_time,
                end_time=datetime.now())

            events = json.loads(str(response.data[:max_events])) if max_events \
                else json.loads(str(response.data[:self.max_fetch]))

            self.last_event_time = self.get_last_event_time(events)
            events = self.add_time_key_to_events(events)

        except Exception as e:
            raise DemistoException(f'Error while fetching events: {e}') from e

        demisto.debug(f'{len(events)} Events fetched from start time: {self.first_fetch_time}.')
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
            return str(self.first_fetch_time)

        # get the event time of last event in the list (will always be the most recent event)
        last_event_time = events[-1].get('event_time')
        if not isinstance(last_event_time, datetime):
            last_event_time = arg_to_datetime(arg=last_event_time)

        # return the last event time + 1 microsecond, or the current first fetch time if the last event time is None.
        return str(last_event_time + timedelta(microseconds=1)) if last_event_time \
            else str(self.first_fetch_time)

    def add_time_key_to_events(self, events: List[Dict[str, Any]]) -> List:
        """
        Add the _time key to the events.
        Args:
            events (List[Dict[str, Any]]): The events to add the time key to.
        Returns:
            List[Dict[str, Any]]: The events with the _time key.
        """
        for event in events:
            if event.get("event_time"):
                event["_time"] = event.get("event_time")

        return events


def test_module(client: Client, oci_event_handler: OCIEventHandler) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): Client for SDK interaction and api requests.
        oci_event_handler (OCIEventHandler): OCI event handler.
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    client.validate_oci_config(client.config)

    try:
        oci_event_handler.get_events(max_events=1)
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
    max_fetch = arg_to_number(params.get('max_fetch')) or MAX_EVENTS_TO_FETCH
    first_fetch = params.get('first_fetch') or FETCH_DEFAULT_TIME
    first_fetch_time = calculate_first_fetch_time(last_run=last_run_time, first_fetch_param=first_fetch)
    demisto.debug(f'Command being called is {command}')

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
        demisto.debug('Client created successfully.')

        oci_event_handler = OCIEventHandler(client, last_run, max_fetch, first_fetch_time)
        demisto.debug(f'OCI Event Handler created successfully. {oci_event_handler=}')

        if command == 'test-module':
            return_results(test_module(client, oci_event_handler))

        elif command in ('oracle-cloud-infrastructure-get-events', 'fetch-events'):
            events = oci_event_handler.get_events()

            if command == 'fetch-events' or args.get('should_push_events'):
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
                if events:
                    last_event_time = oci_event_handler.last_event_time
                    demisto.debug(f'Set last run to {last_event_time}')
                    demisto.setLastRun({"lastRun": {last_event_time}})
                else:
                    demisto.debug('No new events fetched, Last run was not updated.')

            elif command == 'oracle-cloud-infrastructure-get-events':
                command_results = CommandResults(
                    readable_output=tableToMarkdown(
                        'Oracle Cloud Infrastructure Events', events, removeNull=True, headerTransform=pascalToSpace
                    ),
                    raw_response=events,
                )
                return_results(command_results)

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
