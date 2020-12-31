import traceback
from typing import Dict, List, Optional

import urllib3

from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()
''' CONSTANTS '''

DEFAULT_HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Connection': 'keep_alive',
}
# maybe useless
VM_POWER_STATUS_CHANGE_TRANSITIONS = {'ON', 'OFF', 'POWERCYCLE', 'RESET', 'PAUSE', 'SUSPEND', 'RESUME', 'SAVE',
                                      'ACPI_SHUTDOWN', 'ACPI_REBOOT'}

# maybe useless
SEVERITY_OPTIONS = {'CRITICAL', 'WARNING', 'INFO', 'AUDIT'}

accept_json_response = {'Accept': 'application/json'}

CONTENT_JSON = {'Content-Type': 'application/json'}

''' LOWER AND UPPER BOUNDS FOR INTEGER ARGUMENTS '''
MINIMUM_PAGE_VALUE = 1

MINIMUM_COUNT_VALUE = 1
MAXIMUM_COUNT_VALUE = 1000

MINIMUM_OFFSET_VALUE = 0

MINIMUM_LENGTH_VALUE = 1

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, base_url, verify, proxy, headers, auth):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers, auth=auth)
        pass

    def test_module(self):
        raise NotImplementedError

    def fetch_incidents(self):
        raise NotImplementedError

    # limit - maybe or maybe count
    def get_nutanix_hypervisor_hosts_list(self, filter_: str, limit: str, page: str):
        return self._http_request(
            method='GET',
            url_suffix='hosts',
            params=assign_params(
                filter_criteria=filter_,
                count=limit,
                page=page
            )
        )

    def get_nutanix_hypervisor_vms_list(self, filter_: str, offset: int, length: int):
        return self._http_request(
            method='GET',
            url_suffix='vms',
            params=assign_params(
                filter_criteria=filter_,
                offset=offset,
                length=length
            )
        )

    def nutanix_hypervisor_vm_power_status_change(self, uuid: str, host_uuid: str, transition: str):
        return self._http_request(
            method='POST',
            url_suffix=f'vms/{uuid}/set_power_state',
            headers=CONTENT_JSON,
            data=assign_params(
                host_uuid=host_uuid,
                transition=transition,
                uuid=uuid
            )
        )

    def nutanix_hypervisor_task_poll(self, completed_tasks: List[str]):
        return self._http_request(
            method='POST',
            url_suffix='tasks/poll',
            headers=CONTENT_JSON,
            data=assign_params(
                completed_tasks=completed_tasks
            )
        )

    def get_nutanix_alerts_list(self, start_time: int, end_time: int, resolved: bool, auto_resolved: bool,
                                acknowledged: bool, severity: str, alert_type_uuid, entity_ids: str, impact_types: str,
                                classifications: str, entity_type: str, page: int, limit: int):
        return self._http_request(
            method='GET',
            url_suffix='alerts',
            params=assign_params(
                start_time_in_usecs=start_time,
                end_time_in_usecs=end_time,
                resolved=resolved,
                auto_resolved=auto_resolved,
                acknowledged=acknowledged,
                severity=severity,
                alert_type_uuid=alert_type_uuid,
                entity_ids=entity_ids,
                impact_types=impact_types,
                classification=classifications,
                entity_type=entity_type,
                page=page,
                count=limit
            )
        )

    def post_nutanix_alert_acknowledge(self, alert_id: str):
        return self._http_request(
            method='POST',
            url_suffix=f'alerts/{alert_id}/acknowledge',
        )

    def post_nutanix_alert_resolve(self, alert_id: str):
        return self._http_request(
            method='POST',
            url_suffix=f'alerts/{alert_id}/resolve',
        )

    def post_nutanix_alerts_acknowledge_by_filter(self, start_time: int, end_time: int, severity: str,
                                                  impact_types: str, classifications: str, entity_type: str,
                                                  entity_type_ids: str, limit: int):
        return self._http_request(
            method='POST',
            url_suffix='alerts/acknowledge',
            params=assign_params(
                start_time_in_usecs=start_time,
                end_time_in_usecs=end_time,
                severity=severity,
                impact_types=impact_types,
                classification=classifications,
                entity_type=entity_type,
                entity_type_ids=entity_type_ids,
                count=limit
            )
        )

    def post_nutanix_alerts_resolve_by_filter(self, start_time: int, end_time: int, severity: str,
                                              impact_types: str, classifications: str, entity_type: str,
                                              entity_type_ids: str, limit: int):
        return self._http_request(
            method='POST',
            url_suffix='alerts/resolve',
            params=assign_params(
                start_time_in_usecs=start_time,
                end_time_in_usecs=end_time,
                severity=severity,
                impact_types=impact_types,
                classification=classifications,
                entity_type=entity_type,
                entity_type_ids=entity_type_ids,
                count=limit
            )
        )


''' HELPER FUNCTIONS '''


def get_and_validate_int_argument(args: Dict, argument_name: str, minimum: Optional[int] = None,
                                  maximum: Optional[int] = None) -> Optional[int]:
    """
    Extracts int argument from demisto arguments, and in case argument exists,
    validates that:
    - If min is not None, min <= argument
    - If max is not None, argument <= max

    Args:
        args (Dict): Demisto arguments.
        argument_name (str): The name of the argument to extract
        minimum (int): If specified, the minimum value the argument can have
        maximum (int): If specified, the maximum value the argument can have

    Returns:
        - If argument is None, returns None
        - If argument is not None and is not between min to max, raises DemistoException
        - If argument is not None and is between min to max, returns argument
    """
    argument_value = arg_to_number(args.get(argument_name), arg_name=argument_name)

    if argument_value and minimum and not minimum <= argument_value:
        raise DemistoException(f'{argument_name} should be equal or bigger than {minimum}')

    if argument_value and maximum and not argument_value <= maximum:
        raise DemistoException(f'{argument_name} should be equal or less than {maximum}')

    return argument_value


def get_page_argument(args: Dict) -> Optional[str]:
    """
    Extracts the 'page' argument from demisto arguments, and in case 'page'' exists,
    validates that argument 'count' exists.
    This validation is needed because Nutanix service returns an error when page argument
    is given but count argument is missing.
    (Nutanix error code 1202 - 'Page number cannot be specified without count').
    Args:
        args: Demisto arguments

    Returns:
        - If 'page' argument has value and 'count' argument has value, returns 'page' argument value
        - If 'page' argument has value and 'count' argument does not have  value, raises DemistoException
        - If 'page' argument does not have value, returns None
    """
    page_value = get_and_validate_int_argument(args, 'page', minimum=MINIMUM_PAGE_VALUE)
    if page_value and args.get('count') is None:
        raise DemistoException('Page argument cannot be specified without count argument')
    return page_value


# def encode_username_and_password(username, password):
#     sample_string = username + ":" + password
#     sample_string_bytes = sample_string.encode("ascii")
#     base64_bytes = base64.b64encode(sample_string_bytes)
#     encoded_value = base64_bytes.decode("ascii")
#     return encoded_value


''' COMMAND FUNCTIONS '''


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
    page = get_page_argument(args)
    count = get_and_validate_int_argument(args, 'count', minimum=MINIMUM_COUNT_VALUE, maximum=MAXIMUM_COUNT_VALUE)

    raise NotImplementedError


def nutanix_hypervisor_vms_list_command(args: Dict):
    context_path = 'NutanixHypervisor.VM'

    filter_ = args.get('filter')
    offset = get_and_validate_int_argument(args, 'offset', minimum=MINIMUM_OFFSET_VALUE)
    length = get_and_validate_int_argument(args, 'length', minimum=MINIMUM_LENGTH_VALUE)

    raise NotImplementedError


def nutanix_hypervisor_vm_power_status_change_command(args: Dict):
    context_path = 'NutanixHypervisor.VMPowerStatus'

    vm_uuid = args.get('vm_uuid')
    host_uuid = args.get('host_uuid')
    transition = args.get('transition')

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
    page = get_page_argument(args)
    count = get_and_validate_int_argument(args, 'count', minimum=MINIMUM_COUNT_VALUE, maximum=MAXIMUM_COUNT_VALUE)

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
    count = get_and_validate_int_argument(args, 'count', minimum=MINIMUM_COUNT_VALUE, maximum=MAXIMUM_COUNT_VALUE)

    raise NotImplementedError


def nutanix_alerts_resolve_by_filter_command(args: Dict):
    context_path = 'NutanixHypervisor.Alert'

    start_time = args.get('start_time')
    end_time = args.get('end_time')
    severity = args.get('severity')
    impact_types = args.get('impact_types')  # maybe split ,
    classifications = args.get('classifications')  # maybe split ,
    entity_type_ids = args.get('entity_type_ids')  # maybe split ,
    page = get_page_argument(args)
    count = get_and_validate_int_argument(args, 'count', minimum=MINIMUM_COUNT_VALUE, maximum=MAXIMUM_COUNT_VALUE)

    raise NotImplementedError


''' MAIN FUNCTION '''


def main() -> None:
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    username = params.get('username')
    password = params.get('password')

    base_url = params.get('baseurl')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url="TODO",
            verify=verify_certificate,
            proxy=proxy,
            auth=(username, password))

        if command == 'test-module':
            test_module_command()

        elif command == 'fetch-incidents':
            fetch_incidents_command(args)

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
