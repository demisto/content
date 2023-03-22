import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any, Dict, List, Optional
from oci.config import validate_config
from oci.regions import is_region
import oci.audit

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
            private_key (str): private key parameter.
            key_fingerprint (str): API Key Fingerprint parameter.
            tenancy_ocid (str): Tenancy OCID parameter.
            region (str): Region parameter.

        Raises:
            DemistoException: if the config object is invalid.

        Returns:
            (dict): a config dict that can be used to create clients.
        """
        config = {
            'user': user_ocid,
            'key_content': private_key,
            'fingerprint': key_fingerprint,
            'tenancy': tenancy_ocid,
            'region': region
        }

        return config if self.validate_oci_config(config) else {}

    def validate_oci_config(self, config: Dict[str, str]) -> bool:
        """Validate the OCI config dictionary structure.

        Args:
            config (Dict[str, str]): A config dict that can be used to create clients.

        Raises:
            DemistoException: if the region is not valid.
            DemistoException: if the config  dictionary is invalid.

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


''' OCI Event Handler Class '''


class OCIEventHandler:
    """
    Oracle Cloud Infrastructure event handler class.
    Handles the logic for fetching events.
    """

    def __init__(self, client: Client, last_run: Dict[str, Any], max_fetch: int, first_fetch_time: datetime):
        self.client: Client = client
        self.last_run = last_run
        self.max_fetch = max_fetch
        self.first_fetch_time = first_fetch_time

    def __str__(self):
        return f'OCIEventHandler: {self.last_run=}, {self.max_fetch=}, {self.first_fetch_time=}'

    def get_events(self) -> List[Dict[str, Any]]:
        """
        Get events from CIO client.

        Args:
            prev_id (int): The id of the last event we got from the last run.
            alert_status (str): status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.

        Returns:
            List[Dict[str, Any]]: List of events.
        """
        try:
            events = self.client.audit_client.list_events(
                compartment_id=self.client.config.get('tenancy'),
                start_time=self.first_fetch_time,
                end_time=datetime.now()
            ).data

        except Exception as e:
            raise DemistoException(f'Error while fetching events: {e}') from e

        demisto.debug(f'{len(events)} Events fetched from start time: {self.first_fetch_time}. {events=}')
        return events[:self.max_fetch]

    def remove_duplicates(self):
        ...

    def get_last_event_time(self, events: List[Dict[str, Any]]) -> Optional[datetime]:
        """Get the last event time from the events list.
        - Given a non empty list of events,
          the function will return the time of the last event (most recent) + 1 millisecond for next run.
        - If the event list is empty, the function will return the current first fetch time.

        Args:
            events (List[Dict[str, Any]]): list of events.

        Returns:
            Optional[datetime]: last event time in datetime format.
        """
        if not events:
            return arg_to_datetime(arg=self.first_fetch_time)
        last_event_time = events[-1].get("eventTime")
        last_event_time = arg_to_datetime(arg=last_event_time)
        return last_event_time + timedelta(milliseconds=1) if last_event_time else None


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
        oci_event_handler.get_events()
    except Exception as e:
        if 'failed' in str(e):
            return 'Authorization Error: make sure OCI parameters are correctly set'
        else:
            raise DemistoException(f'Error while testing: {e}') from e

    return 'ok'


def calculate_first_fetch_time(last_run: Optional[str], first_fetch_arg: str) -> Optional[datetime]:
    first_fetch_arg_datetime = arg_to_datetime(arg=first_fetch_arg)

    # if last_run is None (first time we are fetching) -> return first_fetch_arg datetime object
    if not last_run:
        return first_fetch_arg_datetime
    else:
        last_run_datetime = arg_to_datetime(arg=last_run)

    # if last_run is not None -> return max(last_run, first_fetch_arg)
    if last_run_datetime and first_fetch_arg_datetime:
        return max(last_run_datetime, first_fetch_arg_datetime)
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
    max_fetch = arg_to_number(params.get('max_fetch')) or MAX_EVENTS_TO_FETCH
    first_fetch = params.get('first_fetch') or FETCH_DEFAULT_TIME
    first_fetch_time = calculate_first_fetch_time(last_run=last_run.get('last_run'), first_fetch_arg=first_fetch)

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
                    last_event_time = oci_event_handler.get_last_event_time(events)
                    demisto.debug(f'Set last run to {last_event_time}')
                    demisto.setLastRun({"last_run": {last_event_time}})
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
