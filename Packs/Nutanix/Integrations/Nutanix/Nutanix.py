from typing import Dict

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

CONTENT_JSON = {'Content-Type': 'application/json'}

TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

''' LOWER AND UPPER BOUNDS FOR INTEGER ARGUMENTS '''
MINIMUM_PAGE_VALUE = 1

MINIMUM_LIMIT_VALUE = 1
MAXIMUM_LIMIT_VALUE = 1000

MINIMUM_OFFSET_VALUE = 0

MINIMUM_LENGTH_VALUE = 1

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, base_url, verify, proxy, auth):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, auth=auth)

    def fetch_incidents(self):
        raise NotImplementedError

    def get_nutanix_hypervisor_hosts_list(self, filter_: Optional[str], limit: Optional[str], page: Optional[str]):
        return self._http_request(
            method='GET',
            url_suffix='hosts',
            params=assign_params(
                filter_criteria=filter_,
                count=limit,
                page=page
            )
        )

    def get_nutanix_hypervisor_vms_list(self, filter_: Optional[str], offset: Optional[int], length: Optional[int]):
        return self._http_request(
            method='GET',
            url_suffix='vms',
            params=assign_params(
                filter_criteria=filter_,
                offset=offset,
                length=length
            )
        )

    # TODO TOM : figure real signature (Optionals or not)
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

    def get_nutanix_alerts_list(self, start_time: Optional[int], end_time: Optional[int], resolved: Optional[bool],
                                auto_resolved: Optional[bool], acknowledged: Optional[bool], severity: Optional[str],
                                alert_type_uuid: Optional[str], entity_ids: Optional[str], impact_types: Optional[str],
                                classification: Optional[str], entity_type: Optional[str], page: Optional[int],
                                limit: Optional[int]):
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
                classification=classification,
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

    # TODO TOM : figure real signature (Optionals or not)
    def post_nutanix_alerts_acknowledge_by_filter(self, start_time: int, end_time: int, severity: str,
                                                  impact_types: str, classification: str, entity_type: str,
                                                  entity_type_ids: str, limit: int):
        return self._http_request(
            method='POST',
            url_suffix='alerts/acknowledge',
            params=assign_params(
                start_time_in_usecs=start_time,
                end_time_in_usecs=end_time,
                severity=severity,
                impact_types=impact_types,
                classification=classification,
                entity_type=entity_type,
                entity_type_ids=entity_type_ids,
                count=limit
            )
        )

    # TODO TOM : figure real signature (Optionals or not)
    def post_nutanix_alerts_resolve_by_filter(self, start_time: int, end_time: int, severity: str,
                                              impact_types: str, classification: str, entity_type: str,
                                              entity_type_ids: str, page: int, limit: int):
        return self._http_request(
            method='POST',
            url_suffix='alerts/resolve',
            params=assign_params(
                start_time_in_usecs=start_time,
                end_time_in_usecs=end_time,
                severity=severity,
                impact_types=impact_types,
                classification=classification,
                entity_type=entity_type,
                entity_type_ids=entity_type_ids,
                page=page,
                count=limit
            )
        )


''' HELPER FUNCTIONS '''


def get_optional_time_parameter_as_epoch(args: Dict, argument_name: str) -> Optional[int]:
    argument_value = args.get(argument_name)

    if argument_value is None:
        return None

    date_to_timestamp(argument_value, TIME_FORMAT)


def get_and_validate_int_argument(args: Dict, argument_name: str, minimum: Optional[int] = None,
                                  maximum: Optional[int] = None) -> Optional[int]:
    """
    Extracts int argument from Demisto arguments, and in case argument exists,
    validates that:
    - If minimum is not None, min <= argument.
    - If maximum is not None, argument <= max.

    Args:
        args (Dict): Demisto arguments.
        argument_name (str): The name of the argument to extract.
        minimum (int): If specified, the minimum value the argument can have.
        maximum (int): If specified, the maximum value the argument can have.

    Returns:
        - If argument is None, returns None.
        - If argument is not None and is between min to max, returns argument.
        - If argument is not None and is not between min to max, raises DemistoException.

    """
    assert (minimum <= maximum if minimum and maximum else True)
    argument_value = arg_to_number(args.get(argument_name), arg_name=argument_name)

    if argument_value is None:
        return None

    if minimum and not minimum <= argument_value:
        raise DemistoException(f'{argument_name} should be equal or higher than {minimum}')

    if maximum and not argument_value <= maximum:
        raise DemistoException(f'{argument_name} should be equal or less than {maximum}')

    return argument_value


def get_optional_boolean_param(args: Dict, argument_name: str) -> Optional[bool]:
    """
    Extracts the argument from Demisto arguments, and in case argument exists,
    returns the boolean value of the argument.
    Args:
        args (Dict): Demisto arguments.
        argument_name (str): Name of the argument.

    Returns:
        - If argument exists and is boolean, returns its boolean value.
        - If argument does not exist, returns None.
        - If argument exists and is not boolean, raises DemistoException.
    """
    argument = args.get(argument_name)
    argument = argToBoolean(argument) if argument else None

    return argument


def get_page_argument(args: Dict) -> Optional[int]:
    """
    Extracts the 'page' argument from Demisto arguments, and in case 'page' exists,
    validates that 'limit' argument exists.
    This validation is needed because Nutanix service returns an error when page argument
    is given but limit(referred as count in Nutanix service) argument is missing.
    (Nutanix error code 1202 - 'Page number cannot be specified without count').
    Args:
        args (Dict): Demisto arguments.

    Returns:
        - If 'page' argument has value and 'limit' argument has value, returns 'page' argument value.
        - If 'page' argument has value and 'limit' argument does not have  value, raises DemistoException.
        - If 'page' argument does not have value, returns None.
    """
    page_value = get_and_validate_int_argument(args, 'page', minimum=MINIMUM_PAGE_VALUE)
    if page_value and args.get('limit') is None:
        raise DemistoException('Page argument cannot be specified without limit argument')
    return page_value


''' COMMAND FUNCTIONS '''


def test_module_command(client: Client):
    """
    Performs a basic GET request to check if the API is reachable and authentication is successful.

    Args:
        client (Client): Client object to perform request.

    Returns:
        CommandResults.
    """
    client.get_nutanix_hypervisor_hosts_list(None, None, None)
    demisto.results('ok')


def fetch_incidents_command(client: Client, args: Dict):
    auto_resolved = get_optional_boolean_param(args, 'auto_resolved')
    resolved = True if auto_resolved else get_optional_boolean_param(args, 'resolved')
    acknowledged = get_optional_boolean_param(args, 'acknowledged')
    alert_type_id = args.get('alert_type_id')  # maybe split , maybe ids?
    entity_ids = args.get('entity_ids')  # maybe split , in doc entity_id probably mistake
    impact_types = args.get('impact_types')  # maybe split ,
    classifications = args.get('classifications')  # maybe split ,
    entity_type_ids = args.get('entity_type_ids')  # maybe split ,

    raise NotImplementedError


def nutanix_hypervisor_hosts_list_command(client: Client, args: Dict):
    """
    List all physical hosts configured in the cluster.
    Args:
        client (Client): Client object to perform request.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    filter_ = args.get('filter')
    limit = get_and_validate_int_argument(args, 'limit', minimum=MINIMUM_LIMIT_VALUE, maximum=MAXIMUM_LIMIT_VALUE)
    page = get_page_argument(args)

    response = client.get_nutanix_hypervisor_hosts_list(filter_, limit, page)

    return CommandResults(
        outputs_prefix='NutanixHypervisor.Host',
        outputs_key_field='entities.uuid',
        outputs=response,
        readable_output=""
    )


def nutanix_hypervisor_vms_list_command(client: Client, args: Dict):
    """
    List all virtual machines.
    Args:
        client (Client): Client object to perform request.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    filter_ = args.get('filter')
    offset = get_and_validate_int_argument(args, 'offset', minimum=MINIMUM_OFFSET_VALUE)
    length = get_and_validate_int_argument(args, 'length', minimum=MINIMUM_LENGTH_VALUE)

    response = client.get_nutanix_hypervisor_vms_list(filter_, offset, length)

    return CommandResults(
        outputs_prefix='NutanixHypervisor.VM',
        outputs_key_field='entities.uuid',
        outputs=response,
        readable_output=""
    )


def nutanix_hypervisor_vm_power_status_change_command(client: Client, args: Dict):
    """
    Set power state of the virtual machine matching vm_uuid argument to power state given in transition argument.
    If the virtual machine is being powered on and no host is specified, the scheduler will pick the one with
    the most available CPU and memory that can support the Virtual Machine.
    If the virtual machine is being power cycled, a different host can be specified to start it on.
    Args:
        client (Client): Client object to perform request.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    context_path = 'NutanixHypervisor.VMPowerStatus'

    vm_uuid = args.get('vm_uuid')
    host_uuid = args.get('host_uuid')
    transition = args.get('transition')

    # TODO : are they required? optional?
    response = client.nutanix_hypervisor_vm_power_status_change(vm_uuid, host_uuid, transition)
    # TODO : what to return? whats the return value (currently cant reach the endpoint)
    raise NotImplementedError


def nutanix_hypervisor_task_poll_command(client: Client, args: Dict):
    """
    Poll tasks given by task_ids to check if they are ready.
    Args:
        client (Client): Client object to perform request.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    context_path = 'NutanixHypervisor.Task'

    task_ids = args.get('task_ids')

    response = client.nutanix_hypervisor_task_poll(task_ids)
    # TODO : what to return? whats the return value (currently cant reach the endpoint)
    raise NotImplementedError


def nutanix_alerts_list_command(client: Client, args: Dict):
    start_time = get_optional_time_parameter_as_epoch(args, 'start_time')
    end_time = get_optional_time_parameter_as_epoch(args, 'end_time')
    auto_resolved = get_optional_boolean_param(args, 'auto_resolved')
    resolved = True if auto_resolved else get_optional_boolean_param(args, 'resolved')
    acknowledged = get_optional_boolean_param(args, 'acknowledged')
    severity = args.get('severity')
    alert_type_id = args.get('alert_type_id')  # maybe split , maybe ids?
    entity_ids = args.get('entity_ids')  # maybe split ,
    impact_types = args.get('impact_types')  # maybe split ,
    classification = args.get('classifications')  # maybe split ,
    entity_type = args.get('entity_type')  # maybe split ,
    page = get_page_argument(args)
    limit = get_and_validate_int_argument(args, 'limit', minimum=MINIMUM_LIMIT_VALUE, maximum=MAXIMUM_LIMIT_VALUE)

    response = client.get_nutanix_alerts_list(start_time, end_time, resolved, auto_resolved, acknowledged, severity,
                                              alert_type_id, entity_ids, impact_types, classification, entity_type,
                                              page, limit)

    return CommandResults(
        outputs_prefix='NutanixHypervisor.Alerts',
        outputs_key_field='entities.id',
        outputs=response,
        readable_output=""
    )


def nutanix_alert_acknowledge_command(client: Client, args: Dict):
    """
    Acknowledge alert with the specified alert_id.
    Args:
        client (Client): Client object to perform request.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    context_path = 'NutanixHypervisor.Alert'

    alert_id = args.get('alert_id')

    # TODO TOM : what output returned? is it useless or not
    response = client.post_nutanix_alert_acknowledge(alert_id)

    raise NotImplementedError


def nutanix_alert_resolve_command(client: Client, args: Dict):
    """
    Resolve alert with the specified alert_id.
    Args:
        client (Client): Client object to perform request.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    context_path = 'NutanixHypervisor.Alert'

    alert_id = args.get('alert_id')

    # TODO TOM : what output returned? is it useless or not
    client.post_nutanix_alert_resolve(alert_id)
    raise NotImplementedError


def nutanix_alerts_acknowledge_by_filter_command(client: Client, args: Dict):
    context_path = 'NutanixHypervisor.Alert'

    start_time = get_optional_time_parameter_as_epoch(args, 'start_time')
    end_time = get_optional_time_parameter_as_epoch(args, 'end_time')
    severity = args.get('severity')
    impact_types = args.get('impact_types')  # maybe split ,
    classification = args.get('classifications')  # maybe split ,
    entity_type = args.get('entity_type')
    entity_type_ids = args.get('entity_type_ids')  # maybe split ,
    limit = get_and_validate_int_argument(args, 'limit', minimum=MINIMUM_LIMIT_VALUE, maximum=MAXIMUM_LIMIT_VALUE)

    # TODO : are they required? optional?
    response = client.post_nutanix_alerts_acknowledge_by_filter(start_time, end_time, severity, impact_types,
                                                                classification, entity_type, entity_type_ids, limit)
    # TODO : what to return? whats the return value (currently cant reach the endpoint)
    raise NotImplementedError


def nutanix_alerts_resolve_by_filter_command(client: Client, args: Dict):
    context_path = 'NutanixHypervisor.Alert'

    start_time = get_optional_time_parameter_as_epoch(args, 'start_time')
    end_time = get_optional_time_parameter_as_epoch(args, 'end_time')
    severity = args.get('severity')
    impact_types = args.get('impact_types')  # maybe split ,
    classification = args.get('classifications')  # maybe split ,
    entity_type = args.get('entity_type')
    entity_type_ids = args.get('entity_type_ids')  # maybe split ,
    page = get_page_argument(args)
    limit = get_and_validate_int_argument(args, 'limit', minimum=MINIMUM_LIMIT_VALUE, maximum=MAXIMUM_LIMIT_VALUE)

    # TODO : are they required? optional?
    client.post_nutanix_alerts_resolve_by_filter(start_time, end_time, severity,
                                                 impact_types, classification, entity_type, entity_type_ids, page,
                                                 limit)
    # TODO : what to return? whats the return value (currently cant reach the endpoint)
    raise NotImplementedError


''' MAIN FUNCTION '''


def main() -> None:
    command = demisto.command()
    params = demisto.params()

    commands = {
        'fetch-incidents': fetch_incidents_command,
        'nutanix-hypervisor-hosts-list': nutanix_hypervisor_hosts_list_command,
        'nutanix-hypervisor-vms-list': nutanix_hypervisor_vms_list_command,
        'nutanix-hypervisor-vm-powerstatus-change': nutanix_hypervisor_vm_power_status_change_command,
        'nutanix-hypervisor-task-poll': nutanix_hypervisor_task_poll_command,
        'nutanix-alerts-list': nutanix_alerts_list_command,
        'nutanix-alert-acknowledge': nutanix_alert_acknowledge_command,
        'nutanix-alert-resolve': nutanix_alert_resolve_command,
        'nutanix-alerts-acknowledge-by-filter': nutanix_alerts_acknowledge_by_filter_command,
        'nutanix-alerts-resolve-by-filter': nutanix_alerts_resolve_by_filter_command
    }

    username = params.get('username')
    password = params.get('password')

    base_url = params.get('base_url')

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            auth=(username, password))

        if command == 'test-module':
            test_module_command(client)

        elif command in commands:
            return_results(commands[command](client, demisto.args()))

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    a = date_to_timestamp('20aaaa1:14', TIME_FORMAT)
    print(a)
    main()
