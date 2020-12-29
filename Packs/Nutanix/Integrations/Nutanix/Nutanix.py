import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import urllib3
import dateparser
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
vm_power_status_change_transition = {"ON", "OFF", "POWERCYCLE", "RESET", "PAUSE", "SUSPEND", "RESUME", "SAVE",
                                     "ACPI_SHUTDOWN", "ACPI_REBOOT"}
''' CLIENT CLASS '''


class Client(BaseClient):


# def get_ip_reputation(self, ip: str) -> Dict[str, Any]:
#     """Gets the IP reputation using the '/ip' API endpoint
#
#     :type ip: ``str``
#     :param ip: IP address to get the reputation for
#
#     :return: dict containing the IP reputation as returned from the API
#     :rtype: ``Dict[str, Any]``
#     """
#
#     return self._http_request(
#         method='GET',
#         url_suffix='/ip',
#         params={
#             'ip': ip
#         }
#     )


''' HELPER FUNCTIONS '''

''' COMMAND FUNCTIONS '''


def test_module(client: Client, first_fetch_time: int) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type name: ``str``
    :param name: name to append to the 'Hello' string

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    try:
        client.search_alerts(max_results=1, start_time=first_fetch_time, alert_status=None, alert_type=None,
                             severity=None)
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


# def say_hello_command(client: Client, args: Dict[str, Any]) -> CommandResults:
#     """helloworld-say-hello command: Returns Hello {somename}
#
#     :type client: ``Client``
#     :param Client: HelloWorld client to use
#
#     :type args: ``str``
#     :param args:
#         all command arguments, usually passed from ``demisto.args()``.
#         ``args['name']`` is used as input name
#
#     :return:
#         A ``CommandResults`` object that is then passed to ``return_results``,
#         that contains the hello world message
#
#     :rtype: ``CommandResults``
#     """
#
#     # INTEGRATION DEVELOPER TIP
#     # In this case 'name' is an argument set in the HelloWorld.yml file as mandatory,
#     # so the null check here as XSOAR will always check it before your code is called.
#     # Although it's not mandatory to check, you are welcome to do so.
#
#     name = args.get('name', None)
#     if not name:
#         raise ValueError('name not specified')
#
#     # Call the Client function and get the raw response
#     result = client.say_hello(name)
#
#     # Create the human readable output.
#     # It will  be in markdown format - https://www.markdownguide.org/basic-syntax/
#     # More complex output can be formatted using ``tableToMarkDown()`` defined
#     # in ``CommonServerPython.py``
#     readable_output = f'## {result}'
#
#     # More information about Context:
#     # https://xsoar.pan.dev/docs/integrations/context-and-outputs
#     # We return a ``CommandResults`` object, and we want to pass a custom
#     # markdown here, so the argument ``readable_output`` is explicit. If not
#     # passed, ``CommandResults``` will do a ``tableToMarkdown()`` do the data
#     # to generate the readable output.
#     return CommandResults(
#         readable_output=readable_output,
#         outputs_prefix='hello',
#         outputs_key_field='',
#         outputs=result
#     )


# def fetch_incidents(client: Client, max_results: int, last_run: Dict[str, int],
#                     first_fetch_time: Optional[int], alert_status: Optional[str],
#                     min_severity: str, alert_type: Optional[str]
#                     ) -> Tuple[Dict[str, int], List[dict]]:
#     """This function retrieves new alerts every interval (default is 1 minute).
#
#     This function has to implement the logic of making sure that incidents are
#     fetched only onces and no incidents are missed. By default it's invoked by
#     XSOAR every minute. It will use last_run to save the timestamp of the last
#     incident it processed. If last_run is not provided, it should use the
#     integration parameter first_fetch_time to determine when to start fetching
#     the first time.
#
#     :type client: ``Client``
#     :param Client: HelloWorld client to use
#
#     :type max_results: ``int``
#     :param max_results: Maximum numbers of incidents per fetch
#
#     :type last_run: ``Optional[Dict[str, int]]``
#     :param last_run:
#         A dict with a key containing the latest incident created time we got
#         from last fetch
#
#     :type first_fetch_time: ``Optional[int]``
#     :param first_fetch_time:
#         If last_run is None (first time we are fetching), it contains
#         the timestamp in milliseconds on when to start fetching incidents
#
#     :type alert_status: ``Optional[str]``
#     :param alert_status:
#         status of the alert to search for. Options are: 'ACTIVE'
#         or 'CLOSED'
#
#     :type min_severity: ``str``
#     :param min_severity:
#         minimum severity of the alert to search for.
#         Options are: "Low", "Medium", "High", "Critical"
#
#     :type alert_type: ``Optional[str]``
#     :param alert_type:
#         type of alerts to search for. There is no list of predefined types
#
#     :return:
#         A tuple containing two elements:
#             next_run (``Dict[str, int]``): Contains the timestamp that will be
#                     used in ``last_run`` on the next fetch.
#             incidents (``List[dict]``): List of incidents that will be created in XSOAR
#
#     :rtype: ``Tuple[Dict[str, int], List[dict]]``
#     """
#
#     # Get the last fetch time, if exists
#     # last_run is a dict with a single key, called last_fetch
#     last_fetch = last_run.get('last_fetch', None)
#     # Handle first fetch time
#     if last_fetch is None:
#         # if missing, use what provided via first_fetch_time
#         last_fetch = first_fetch_time
#     else:
#         # otherwise use the stored last fetch
#         last_fetch = int(last_fetch)
#
#     # for type checking, making sure that latest_created_time is int
#     latest_created_time = cast(int, last_fetch)
#
#     # Initialize an empty list of incidents to return
#     # Each incident is a dict with a string as a key
#     incidents: List[Dict[str, Any]] = []
#
#     # Get the CSV list of severities from min_severity
#     severity = ','.join(HELLOWORLD_SEVERITIES[HELLOWORLD_SEVERITIES.index(min_severity):])
#
#     alerts = client.search_alerts(
#         alert_type=alert_type,
#         alert_status=alert_status,
#         max_results=max_results,
#         start_time=last_fetch,
#         severity=severity
#     )
#
#     for alert in alerts:
#         # If no created_time set is as epoch (0). We use time in ms so we must
#         # convert it from the HelloWorld API response
#         incident_created_time = int(alert.get('created', '0'))
#         incident_created_time_ms = incident_created_time * 1000
#
#         # to prevent duplicates, we are only adding incidents with creation_time > last fetched incident
#         if last_fetch:
#             if incident_created_time <= last_fetch:
#                 continue
#
#         # If no name is present it will throw an exception
#         incident_name = alert['name']
#
#         # INTEGRATION DEVELOPER TIP
#         # The incident dict is initialized with a few mandatory fields:
#         # name: the incident name
#         # occurred: the time on when the incident occurred, in ISO8601 format
#         # we use timestamp_to_datestring() from CommonServerPython.py to
#         # handle the conversion.
#         # rawJSON: everything else is packed in a string via json.dumps()
#         # and is included in rawJSON. It will be used later for classification
#         # and mapping inside XSOAR.
#         # severity: it's not mandatory, but is recommended. It must be
#         # converted to XSOAR specific severity (int 1 to 4)
#         # Note that there are other fields commented out here. You can do some
#         # mapping of fields (either out of the box fields, like "details" and
#         # "type") or custom fields (like "helloworldid") directly here in the
#         # code, or they can be handled in the classification and mapping phase.
#         # In either case customers can override them. We leave the values
#         # commented out here, but you can use them if you want.
#         incident = {
#             'name': incident_name,
#             # 'details': alert['name'],
#             'occurred': timestamp_to_datestring(incident_created_time_ms),
#             'rawJSON': json.dumps(alert),
#             # 'type': 'Hello World Alert',  # Map to a specific XSOAR incident Type
#             'severity': convert_to_demisto_severity(alert.get('severity', 'Low')),
#             # 'CustomFields': {  # Map specific XSOAR Custom Fields
#             #     'helloworldid': alert.get('alert_id'),
#             #     'helloworldstatus': alert.get('alert_status'),
#             #     'helloworldtype': alert.get('alert_type')
#             # }
#         }
#
#         incidents.append(incident)
#
#         # Update last run and add incident if the incident is newer than last fetch
#         if incident_created_time > latest_created_time:
#             latest_created_time = incident_created_time
#
#     # Save the next_run as a dict with the last_fetch key to be stored
#     next_run = {'last_fetch': latest_created_time}
#     return next_run, incidents
def test_module_command():
    raise NotImplementedError


def fetch_incidents_command(args: Dict):

    resolved = argToBoolean(args.get('resolved'))
    auto_resolved = argToBoolean(args.get('auto_resolved'))
    acknowledged = argToBoolean(args.get('acknowledged'))
    alert_type_id = args.get('alert_type_id')  # maybe split , maybe ids?
    entity_ids = args.get('entity_ids')  # maybe split , in doc entity_id probably mistake
    impact_types = args.get('impact_types')  # maybe split ,
    classifications = args.get('classifications')  # maybe split ,
    entity_type_ids = args.get('entity_type_ids')  # maybe split ,

    raise NotImplementedError


def nutanix_hypervisor_hosts_list_command(args: Dict):
    context_path = 'NutanixHypervisor.Host'

    filter_ = args.get('filter')
    page = args.get('page')
    count = args.get('count')

    raise NotImplementedError


def nutanix_hypervisor_vms_list_command(args: Dict):
    context_path = 'NutanixHypervisor.VM'

    filter_ = args.get('filter')
    offset = args.get('offset')
    length = args.get('length')

    raise NotImplementedError


def nutanix_hypervisor_vm_power_status_change_command(args: Dict):
    context_path = 'NutanixHypervisor.VMPowerStatus'

    vm_uuid = args.get('vm_uuid')
    host_uuid = args.get('host_uuid')
    transition = args.get('transition')

    if transition not in vm_power_status_change_transition:
        raise DemistoException('invalid type of transition')

    raise NotImplementedError


def nutanix_hypervisor_task_poll_command(args: Dict):
    context_path = 'NutanixHypervisor.Task'

    task_ids = args.get('task_ids')

    raise NotImplementedError


def nutanix_alerts_list_command(args: Dict):
    context_path = 'NutanixHypervisor.Alerts'

    start_time = args.get('start_time')
    end_time = args.get('end_time')
    resolved = argToBoolean(args.get('resolved'))
    auto_resolved = argToBoolean(args.get('auto_resolved'))
    acknowledged = argToBoolean(args.get('acknowledged'))
    severity = args.get('severity')
    alert_type_id = args.get('alert_type_id')  # maybe split , maybe ids?
    entity_ids = args.get('entity_ids')  # maybe split ,
    impact_types = args.get('impact_types')  # maybe split ,
    classifications = args.get('classifications')  # maybe split ,
    entity_type_ids = args.get('entity_type_ids')  # maybe split ,
    page = args.get('page')
    count = args.get('count')

    raise NotImplementedError


def nutanix_alert_acknowledge_command(args: Dict):
    context_path = 'NutanixHypervisor.Alert'

    alert_id = args.get('alert_id')

    raise NotImplementedError


def nutanix_alert_resolve_command(args: Dict):
    context_path = 'NutanixHypervisor.Alert'

    alert_id = args.get('alert_id')

    raise NotImplementedError


def nutanix_alerts_acknowledge_by_filter_command(args: Dict):
    context_path = 'NutanixHypervisor.Alert'

    start_time = args.get('start_time')
    end_time = args.get('end_time')
    severity = args.get('severity')
    entity_ids = args.get('entity_ids')  # maybe split , currently entity_id in design but probably mistake
    impact_types = args.get('impact_types')  # maybe split ,
    classifications = args.get('classifications')  # maybe split ,
    entity_type_ids = args.get('entity_type_ids')  # maybe split ,
    count = args.get('count')

    raise NotImplementedError


def nutanix_alerts_resolve_by_filter_command(args: Dict):
    context_path = 'NutanixHypervisor.Alert'

    start_time = args.get('start_time')
    end_time = args.get('end_time')
    severity = args.get('severity')
    impact_types = args.get('impact_types')  # maybe split ,
    classifications = args.get('classifications')  # maybe split ,
    entity_type_ids = args.get('entity_type_ids')  # maybe split ,
    page = args.get('page')
    count = args.get('count')

    raise NotImplementedError

''' MAIN FUNCTION '''


def main() -> None:
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    api_key = params.get('apikey')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url="TODO",
            verify=verify_certificate,
            proxy=proxy)

        if command == 'test-module':
            test_module_command()

        elif command == 'fetch-incidents':
            fetch_incidents_command()

        elif command == 'nutanix-hypervisor-hosts-list':
            nutanix_hypervisor_hosts_list_command(args)

        elif command == 'nutanix-hypervisor-vms-list':
            nutanix_hypervisor_vms_list_command(args)

        elif command == 'nutanix-hypervisor-vm-powerstatus-change':
            nutanix_hypervisor_vm_power_status_change_command(args)

        elif command == 'nutanix-alerts-list':
            nutanix_alerts_list_command(args)

        elif command == 'nutanix-alert-acknowledge':
            nutanix_alert_acknowledge_command(args)

        elif command == 'nutanix-alert-acknowledge':
            nutanix_alert_resolve_command(args)

        elif command == 'nutanix-alert-acknowledge':
            nutanix_alert_resolve_command(args)

        elif command == 'nutanix-alerts-acknowledge-by-filter':
            nutanix_alerts_acknowledge_by_filter_command(args)

        elif command == 'nutanix-alerts-resolve-by-filter':
            nutanix_alerts_resolve_by_filter_command(args)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')

''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
