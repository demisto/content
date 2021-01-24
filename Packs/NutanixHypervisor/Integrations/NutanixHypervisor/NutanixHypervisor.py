from typing import Dict

import dateutil.parser as dp
import pytz
import urllib3
import copy

from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
USECS_ENTRIES_MAPPING = {'boot_time_in_usecs': 'boot_time',
                         'create_time_usecs': 'create_time',
                         'start_time_usecs': 'start_time',
                         'complete_time_usecs': 'complete_time',
                         'last_updated_time_usecs': 'last_updated',
                         'created_time_stamp_in_usecs': 'created_time',
                         'last_occurrence_time_stamp_in_usecs': 'last_occurrence',
                         'acknowledged_time_stamp_in_usecs': 'acknowledged_time',
                         'resolved_time_stamp_in_usecs': 'resolved_time'}

TIMEOUT_INTERVAL = 1

MINIMUM_PAGE_VALUE = 1

MINIMUM_LIMIT_VALUE = 1
MAXIMUM_LIMIT_VALUE = 1000

MINIMUM_OFFSET_VALUE = 0

MINIMUM_LENGTH_VALUE = 1

''' CLIENT CLASS '''


class Client(BaseClient):
    CONTENT_JSON = {'content-type': 'application/json'}

    def __init__(self, base_url, verify, proxy, auth):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, auth=auth)

    def fetch_incidents(self, auto_resolved: Optional[bool], resolved: Optional[bool], acknowledged: Optional[bool],
                        severity: Optional[str], alert_type_ids: Optional[str], impact_types: Optional[str]):
        return self._http_request(
            method='GET',
            url_suffix='alerts',
            params=assign_params(
                resolved=resolved,
                auto_resolved=auto_resolved,
                acknowledged=acknowledged,
                severity=severity,
                alert_type_uuid=alert_type_ids,
                impact_types=impact_types
            )
        )

    def get_nutanix_hypervisor_hosts_list(self, filter_: Optional[str], limit: Optional[int], page: Optional[int]):
        try:
            return self._http_request(
                method='GET',
                url_suffix='hosts',
                params=assign_params(
                    filter_criteria=filter_,
                    count=limit,
                    page=page
                )
            )
        except DemistoException as e:
            if e.message and 'Invalid filter criteria specified.' in e.message:
                raise DemistoException(
                    'Filter criteria given to command nutanix-hypervisor-hosts-list is invalid, or is not written in '
                    'the correct format. Check your format is correct by looking in the description of filter argument '
                    'in the command')
            raise e

    def get_nutanix_hypervisor_vms_list(self, filter_: Optional[str], offset: Optional[int], limit: Optional[int]):
        try:
            return self._http_request(
                method='GET',
                url_suffix='vms',
                params=assign_params(
                    filter=filter_,
                    offset=offset,
                    length=limit
                )
            )
        except DemistoException as e:
            if e.message:
                if 'Unrecognized field' in e.message:
                    raise DemistoException('Filter criteria given to command nutanix-hypervisor-vms-list is invalid.')
                if 'General error parsing FIQL expression' in e.message:
                    raise DemistoException(
                        'Filter criteria given to command nutanix-hypervisor-vms-list is not written in the current '
                        'format. Check the correct format by looing in the description of filter argument in the '
                        'command.')
            raise e

    def nutanix_hypervisor_vm_power_status_change(self, uuid: str, host_uuid: Optional[str], transition: str):
        return self._http_request(
            method='POST',
            url_suffix=f'vms/{uuid}/set_power_state',
            headers=self.CONTENT_JSON,
            json_data=assign_params(
                uuid=uuid,
                host_uuid=host_uuid,
                transition=transition
            )
        )

    def nutanix_hypervisor_task_poll(self, completed_tasks: List[str]):
        return self._http_request(
            method='POST',
            url_suffix='tasks/poll',
            headers=self.CONTENT_JSON,
            json_data=assign_params(
                completed_tasks=completed_tasks,
                timeout_interval=TIMEOUT_INTERVAL
            )
        )

    def nutanix_hypervisor_task_details(self, task_id: str):
        return self._http_request(
            method='GET',
            url_suffix=f'tasks/{task_id}'
        )

    def get_nutanix_alerts_list(self, start_time: Optional[int], end_time: Optional[int], resolved: Optional[bool],
                                auto_resolved: Optional[bool], acknowledged: Optional[bool], severity: Optional[str],
                                alert_type_ids: Optional[str], impact_types: Optional[str],
                                entity_types: Optional[str], page: Optional[int],
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
                alert_type_uuid=alert_type_ids,
                impact_types=impact_types,
                entity_type=entity_types,
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

    def post_nutanix_alerts_acknowledge_by_filter(self, start_time: Optional[int], end_time: Optional[int],
                                                  severity: Optional[str], impact_types: Optional[str],
                                                  entity_types: Optional[str],
                                                  limit: Optional[int]):
        return self._http_request(
            method='POST',
            url_suffix='alerts/acknowledge',
            params=assign_params(
                start_time_in_usecs=start_time,
                end_time_in_usecs=end_time,
                severity=severity,
                impact_types=impact_types,
                entity_type=entity_types,
                count=limit
            )
        )

    def post_nutanix_alerts_resolve_by_filter(self, start_time: Optional[int], end_time: Optional[int],
                                              severity: Optional[str], impact_types: Optional[str],
                                              entity_types: Optional[str],
                                              limit: Optional[int]):
        return self._http_request(
            method='POST',
            url_suffix='alerts/resolve',
            params=assign_params(
                start_time_in_usecs=start_time,
                end_time_in_usecs=end_time,
                severity=severity,
                impact_types=impact_types,
                entity_type=entity_types,
                count=limit
            )
        )


''' HELPER FUNCTIONS '''


def get_optional_time_parameter_as_epoch(args: Dict, argument_name: str) -> Optional[int]:
    """
    Extracts time argument from Demisto arguments, expects that the time argument will be formatted
    by TIME_FORMAT global variable.
    Args:
        args (Dict): Demisto arguments.
        argument_name (str): The name of the argument to extract.

    Returns:
        - If argument is None, returns None.
        - If argument is exists and is formatted by TIME_FORMAT, returns the epoch time of the argument.
        - If argument exists and is not formatted by TIME_FORMAT, throws ValueError exception.

    """
    argument_value = args.get(argument_name)

    if argument_value is None:
        return None

    try:
        unaware_timezone_date = dp.parse(argument_value)
    except Exception:
        raise DemistoException(
            f'''date format of '{argument_name}' is not valid. Please enter a date format of YYYY-MM-DDTHH:MM:SS''')

    time_zone = pytz.timezone('utc')
    aware_timezone_date = time_zone.localize(unaware_timezone_date)
    return int(aware_timezone_date.timestamp() * 1000)


def get_and_validate_int_argument(args: Dict, argument_name: str, minimum: Optional[int] = None,
                                  maximum: Optional[int] = None, default_value: Optional[int] = None) -> Optional[int]:
    """
    Extracts int argument from Demisto arguments, and in case argument exists,
    validates that:
    - If minimum is not None, min <= argument.
    - If maximum is not None, argument <= max.

    Args:
        args (Dict): Demisto arguments.
        argument_name (str): The name of the argument to extract.
        minimum (Optional[int]): If specified, the minimum value the argument can have.
        maximum (Optional[int]): If specified, the maximum value the argument can have.
        default_value (Optional[int]): If specified, the default value to be returned if argument does not exist.

    Returns:
        - If argument is does not exist, returns 'default_value'. If 'default_value' is not specified returns None.
        - If argument is exists and is between min to max, returns argument.
        - If argument is exists and is not between min to max, raises DemistoException.

    """
    argument_value = arg_to_number(args.get(argument_name, default_value), arg_name=argument_name)

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
        - If argument exists and is not boolean, raises DemistoException.
        - If argument does not exist, returns None.
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
        - If 'page' argument exists and 'limit' argument exists, returns 'page' argument value.
        - If 'page' argument exists and 'limit' argument does not exist, raises DemistoException.
        - If 'page' argument does not exist, returns None.
    """
    page_value = get_and_validate_int_argument(args, 'page', minimum=MINIMUM_PAGE_VALUE)
    if page_value and args.get('limit') is None:
        raise DemistoException('Page argument cannot be specified without limit argument')
    return page_value


def convert_epoch_time_to_datetime(epoch_time: Optional[int]) -> Optional[str]:
    """
    Receives epoch time, and returns epoch_time representation as date with UTC timezone.
    If received epoch time is 0, or epoch_time does not exist, returns None.
    Args:
        epoch_time (int): The epoch_time to convert.

    Returns:
        - The date time with UTC timezone that matches the epoch time if 'epoch_time' is not 0.
        - None if 'epoch_time' is 0.
        - None if epoch_time is None.
    """
    if not epoch_time or epoch_time == 0:
        return None
    try:
        return datetime.utcfromtimestamp(epoch_time / 1000000.0).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    except TypeError:
        raise DemistoException(f'Unexpected epoch time received from Nutanix service response: {epoch_time}.')


def get_alert_status_filter(true_value: str, false_value: str, alert_status_filters: Optional[List[str]]) -> \
        Optional[bool]:
    """
    Args:
        true_value (str): The name of the argument that expresses true value.
        false_value (str): The name of the argument that expresses false value.
        alert_status_filters (List[str]): All the alert status filters chosen by the user.

    Returns:
        - Throws DemistoException if 'false_value' and 'true_value' are found in 'alert_status_filters' list.
        - False if 'false_value' was found in 'alert_status_filters' list.
        - True if 'true_value' was found in 'alert_status_filters' list.
        - None if both 'true_value' and 'false_value' were not found in 'alert_status_filters' list.
        - None if alert_status_filters is None.
    """
    if not alert_status_filters:
        return None
    if true_value in alert_status_filters and false_value in alert_status_filters:
        raise DemistoException(
            f'Invalid alert status filters configurations, only one of {true_value},{false_value} can be chosen.')
    return True if true_value in alert_status_filters else False if false_value in alert_status_filters else None


def update_dict_time_in_usecs_to_iso_entries(outputs: List[Dict]) -> None:
    for output in outputs:
        for old_entry_name, new_entry_name in USECS_ENTRIES_MAPPING.items():
            if old_entry_name not in output:
                continue
            output[new_entry_name] = convert_epoch_time_to_datetime(output.pop(old_entry_name))


def create_readable_output(outputs: List[Dict]) -> List[Dict]:
    """
    Recursively remove inner dict from each dictionary in the output list.
    Deletes any empty entry in the dict after removing inner dicts.
    Args:
        outputs (List[Dict]): Input list of dictionaries.

    Returns:
        Dictionary with all inner dictionaries and empty entries removed.
    """

    def remove_inner_dicts_recursively(entry: Any):
        if not isinstance(entry, (dict, list)):
            return entry
        elif isinstance(entry, list):
            return [v for v in (remove_inner_dicts_recursively(v) for v in entry) if not isinstance(v, dict)]

    readable_outputs = []
    for output in outputs:
        dict_without_inner_dicts = {k: v for k, v in ((k, remove_inner_dicts_recursively(v)) for k, v in output.items())
                                    if not isinstance(v, dict)}
        dict_without_empty_elements = remove_empty_elements(dict_without_inner_dicts)
        if dict_without_empty_elements:
            readable_outputs.append(dict_without_empty_elements)

    return readable_outputs


def task_id_is_found(client: Client, task_id: str):
    """

    Args:
        client:
        task_id:

    Returns:

    """
    try:
        client.nutanix_hypervisor_task_details(task_id)
    except DemistoException as e:
        if e.message and f'{task_id} is not found' in e.message:
            return False
        raise e


''' COMMAND FUNCTIONS '''


def fetch_incidents_command(client: Client, params: Dict, last_run: Dict):
    alert_status_filters = params.get('alert_status_filters')
    auto_resolved = get_alert_status_filter('Auto Resolved', 'Not Auto Resolved', alert_status_filters)
    resolved = get_alert_status_filter('Resolved', 'Unresolved', alert_status_filters)
    acknowledged = get_alert_status_filter('Acknowledged', 'Unacknowledged', alert_status_filters)
    if auto_resolved and not resolved:
        raise DemistoException(''''Resolved' must be set to true when 'Auto Resolved' is set to true.''')

    severity = params.get('severity')
    alert_type_ids = params.get('alert_type_ids')
    impact_types = params.get('impact_types')

    fetch_time = params.get('fetch_time', '5 days').strip()
    # to match the shape of the time returned by Nutanix service.
    first_fetch_time = int((dateparser.parse(fetch_time).timestamp()) * 1000000)
    last_fetch_epoch_time = last_run.get('last_fetch_epoch_time', first_fetch_time)

    response = client.fetch_incidents(auto_resolved, resolved, acknowledged, severity, alert_type_ids, impact_types)

    alerts = response.get('entities')

    if alerts is None:
        raise DemistoException('Unexpected returned results from Nutanix service.')

    current_run_max_epoch_time = 0
    incidents: List[Dict[str, Any]] = []

    for alert in alerts:
        last_occurrence_time = alert.get('last_occurrence_time_stamp_in_usecs', 0)
        alert_created_time = alert.get('created_time_stamp_in_usecs')
        if last_occurrence_time <= last_fetch_epoch_time:
            continue

        try:
            occurred = convert_epoch_time_to_datetime(alert_created_time)
        except TypeError:
            demisto.debug(f'The following incident was found invalid and was skipped: {alert}')
            continue

        current_run_max_epoch_time = max(current_run_max_epoch_time, last_occurrence_time)
        incident = {
            'name': 'Nutanix Hypervisor Alert',
            'type': 'Nutanix Hypervisor Alert',
            'occurred': occurred,
            'rawJSON': json.dumps(remove_empty_elements(alert))
        }

        incidents.append(incident)

    return incidents, {'last_fetch_epoch_time': max(current_run_max_epoch_time, last_fetch_epoch_time)}


def nutanix_hypervisor_hosts_list_command(client: Client, args: Dict):
    """
    Gets a list all physical hosts configured in the cluster by Nutanix service.
    Possible filters:
    - page: The offset page to start retrieving hosts.
            When page is specified, limit argument is required, else Nutanix service returns an error
            "Page number cannot be specified without count".
    - limit: The number of hosts to retrieve, has to be positive.
    - filter: Retrieve hosts that matches the filters given.
              - Each filter is written in the following way: filter_name==filter_value or filter_name!=filter_value.
              - Possible combinations of OR (using comma ',') and AND (using semicolon ';'), for Example:
                storage.capacity_bytes==2;host_nic_ids!=35,host_gpus==x is parsed by Nutanix the following way:
                Return all hosts s.t (storage.capacity_bytes == 2 AND host_nic_ids != 35) OR host_gpus == x.

    In case response was successful, response will be a of list of hosts details.

    Args:
        client (Client): Client object to perform request.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    filter_ = args.get('filter')
    limit = get_and_validate_int_argument(args, 'limit', minimum=MINIMUM_LIMIT_VALUE, default_value=50)
    page = get_page_argument(args)

    raw_response = client.get_nutanix_hypervisor_hosts_list(filter_, limit, page)

    if raw_response.get('entities') is None:
        raise DemistoException('Unexpected response for nutanix-hypervisor-hosts-list command')

    outputs = copy.deepcopy(raw_response.get('entities'))

    update_dict_time_in_usecs_to_iso_entries(outputs)

    return CommandResults(
        outputs_prefix='NutanixHypervisor.Host',
        outputs_key_field='uuid',
        outputs=outputs,
        readable_output=tableToMarkdown('Nutanix Hosts List', create_readable_output(outputs)),
        raw_response=raw_response
    )


def nutanix_hypervisor_vms_list_command(client: Client, args: Dict):
    """
    Gets a list all virtual machines by Nutanix service.
    Possible filters:
    - offset: The offset to start retrieving virtual machines.
    - limit: Maximum number of virtual machines to retrieve.
    - filter: Retrieve virtual machines that matches the filters given.
              - Each filter is written in the following way: filter_name==filter_value or filter_name!=filter_value.
              - Possible combinations of OR (using comma ',') and AND (using semicolon ';'), for Example:
                machine_type==pc;power_state!=off,ha_priority==0 is parsed by Nutanix the following way:
                Return all virtual machines s.t (machine type == pc AND power_state != off) OR ha_priority == 0.

    In case response was successful, response will be a list of virtual machines details.

    Args:
        client (Client): Client object to perform request.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    filter_ = args.get('filter')
    offset = get_and_validate_int_argument(args, 'offset', minimum=MINIMUM_OFFSET_VALUE)
    limit = get_and_validate_int_argument(args, 'limit', minimum=MINIMUM_LENGTH_VALUE, default_value=50)

    raw_response = client.get_nutanix_hypervisor_vms_list(filter_, offset, limit)

    outputs = raw_response.get('entities')

    if outputs is None:
        raise DemistoException('No entities were found in response for nutanix-hypervisor-vms-list command')

    return CommandResults(
        outputs_prefix='NutanixHypervisor.VM',
        outputs_key_field='uuid',
        outputs=outputs,
        readable_output=tableToMarkdown('Nutanix Virtual Machines List', create_readable_output(outputs)),
        raw_response=raw_response
    )


def nutanix_hypervisor_vm_power_status_change_command(client: Client, args: Dict):
    """
    Set power state of the virtual machine matching vm_uuid argument to power state given in transition argument.
    If the virtual machine is being powered on and no host is specified, the scheduler will pick the one with
    the most available CPU and memory that can support the Virtual Machine.
    If the virtual machine is being power cycled, a different host can be specified to start it on.

    This is also an asynchronous operation that results in the creation of a task object.
    The UUID of this task object is returned as the response of this operation.
    This task can be monitored by using the nutanix-hypervisor-task-poll command

    In case response was successful, response will be a dict {'task_uuid': int}.

    Args:
        client (Client): Client object to perform request.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    vm_uuid = args.get('vm_uuid', '')
    host_uuid = args.get('host_uuid')
    transition = args.get('transition', '')

    raw_response = client.nutanix_hypervisor_vm_power_status_change(vm_uuid, host_uuid, transition)

    return CommandResults(
        outputs_prefix='NutanixHypervisor.VMPowerStatus',
        outputs_key_field='task_uuid',
        outputs=raw_response,
        raw_response=raw_response
    )


def nutanix_hypervisor_task_poll_command(client: Client, args: Dict):
    """
    Poll tasks given by task_ids to check if they are ready.
    Returns all the tasks from 'task_ids' list that are ready at the moment
    Nutanix service was polled.
    In case no task is ready, waits 'TIMEOUT_INTERVAL' (1 second) seconds and in case no task had finished,
    returns a time out response.

    In case response was successful, response will be a dict containing key 'completed_tasks_info'
    which holds details about every completed task returned by Nutanix service.
    In case response timed out, response will be a dict {'timed_out': True}.

    Args:
        client (Client): Client object to perform request.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    tasks_id: List[str] = argToList(args.get('task_ids'))
    if not tasks_id:
        raise DemistoException('Task ids for command nutanix_hypervisor_task_poll_command cannot be empty.')

    raw_response = client.nutanix_hypervisor_task_poll(tasks_id)

    maybe_time_out = raw_response.get('timed_out')

    if raw_response.get('completed_tasks_info') is not None:

        outputs_key_field: Optional[str] = 'uuid'
        outputs = copy.deepcopy(raw_response['completed_tasks_info'])

        readable_task_details_output: List[Dict] = []
        for output in outputs:
            task_id = output.get('uuid', 'Unknown Task ID')
            if not task_id:
                raise DemistoException('Unexpected response from Nutanix, task_uuid should always be present')
            progress_status = output.get('progress_status')
            readable_task_details_output.append({'Task ID': task_id, 'Progress Status': progress_status})
            tasks_id.remove(task_id)

        for uncompleted_task_id in tasks_id:
            if task_id_is_found(client, uncompleted_task_id):
                progress_status = 'In Progress' if task_id_is_found(client, uncompleted_task_id) \
                    else 'Task Was Not Found'
                readable_task_details_output.append(
                    {'Task ID': uncompleted_task_id, 'Progress Status': progress_status})

        readable_output = tableToMarkdown('Nutanix Hypervisor Tasks Status', readable_task_details_output,
                                          headers=['Task ID', 'Progress Status'])

    elif maybe_time_out and argToBoolean(maybe_time_out):
        outputs_key_field = None
        outputs = raw_response
        readable_output = '### All given tasks are in progress'
    else:
        raise DemistoException('Unexpected response returned by Nutanix for nutanix-hypervisor-task-poll command')

    update_dict_time_in_usecs_to_iso_entries(outputs)

    return CommandResults(
        outputs_prefix='NutanixHypervisor.Task',
        outputs_key_field=outputs_key_field,
        readable_output=readable_output,
        outputs=outputs,
        raw_response=raw_response
    )


def nutanix_alerts_list_command(client: Client, args: Dict):
    """
    Get the list of Alerts generated in the cluster which matches the filters if given.
    Possible filters:
    - start_time: Retrieve alerts that their creation time have been after 'start_time'.
    - end_time: Retrieve alerts that their creation time have been before 'end_time'.
    - auto_resolved: If auto_resolved is True, retrieves alerts that have been resolved, and were auto_resolved.
                     If auto_resolved is False, retrieves alerts that have been resolved, and were not auto_resolved.
    - resolved: If resolved is True, retrieves alerts that have been resolved.
                If resolved is False, retrieves alerts that have not been resolved.
    - acknowledged: If acknowledged is True, retrieves alerts that have been acknowledged.
                    If acknowledged is False, retrieves alerts that have been acknowledged.
    - severity: Retrieve any alerts that their severity level matches one of the severities in severity list.
                Possible severities: [CRITICAL, WARNING, INFO, AUDIT].
    - alert_type_ids: Retrieve alerts that id of their type matches one alert_type_id in alert_type_id list.
                     For example, alert 'Alert E-mail Failure' has type id of A111066.
                     Given alert_type_ids = 'A111066', only alerts of 'Alert E-mail Failure' will be retrieved.
    - impact_types: Retrieve alerts that their impact type matches one of the impact_type in impact_types list.
                    Possible impact types: [Availability, Capacity, Configuration, Performance, SystemIndicator]
                    For example, alert 'Incorrect NTP Configuration' has impact type 'SystemIndicator'.
                    Given Impact Types = 'SystemIndicator',only alerts with impact type 'SystemIndicator',
                    such as 'Incorrect NTP Configuration' will be retrieved.
    - entity_types: Retrieve alerts that their entity_type matches one of the entity_type in entity_types list.
                   Examples for entity types: [VM, Host, Disk, Storage Container, Cluster].
                   If Nutanix service can't recognize the entity type, it returns 404 response.
    - page: The offset of page number in the query response to start retrieving alerts.
            When page is specified, 'limit' argument is required, else Nutanix service returns an error
            "Page number cannot be specified without count".
    - limit: Maximum number of alerts to retrieve. Must be between 1-1000 else Nutanix service returns an error
             "Number of alerts/events to retrieve cannot be greater than 1,000".

    In case response was successful, response will be a dict containing key 'entities' with value of list of alerts.
    Each element in the list contains data about the alert.

    Args:
        client (Client): Client object to perform request.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    start_time = get_optional_time_parameter_as_epoch(args, 'start_time')
    end_time = get_optional_time_parameter_as_epoch(args, 'end_time')

    auto_resolved = get_optional_boolean_param(args, 'auto_resolved')
    resolved = get_optional_boolean_param(args, 'resolved')
    if auto_resolved and not resolved:
        raise DemistoException(''''Resolved' must be set to true when 'Auto Resolved' is set to true.''')

    acknowledged = get_optional_boolean_param(args, 'acknowledged')
    severity = args.get('severity')
    alert_type_ids = args.get('alert_type_ids')
    impact_types = args.get('impact_types')
    entity_types = args.get('entity_types')
    page = get_page_argument(args)
    limit = get_and_validate_int_argument(args, 'limit', minimum=MINIMUM_LIMIT_VALUE,
                                          maximum=MAXIMUM_LIMIT_VALUE, default_value=50)

    raw_response = client.get_nutanix_alerts_list(start_time, end_time, resolved, auto_resolved, acknowledged, severity,
                                                  alert_type_ids, impact_types, entity_types,
                                                  page, limit)

    if raw_response.get('entities') is None:
        raise DemistoException('No entities were found in response for nutanix-alerts-list command')

    outputs = copy.deepcopy(raw_response.get('entities'))

    update_dict_time_in_usecs_to_iso_entries(outputs)

    return CommandResults(
        outputs_prefix='NutanixHypervisor.Alerts',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Nutanix Alert List', create_readable_output(outputs)),
        raw_response=raw_response
    )


def nutanix_alert_acknowledge_command(client: Client, args: Dict):
    """
    Acknowledge alert with the specified alert_id.

    In case response was successful, response will be a dict
    {'id': str, 'successful': bool, 'message': Optional[str]}
    In case of an invalid alert id, status code 422 - UNPROCESSED ENTITY
    will be returned by Nutanix service.

    Args:
        client (Client): Client object to perform request.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    alert_id = args.get('alert_id', '')

    raw_response = client.post_nutanix_alert_acknowledge(alert_id)

    return CommandResults(
        outputs_prefix='NutanixHypervisor.AcknowledgeAlerts',
        outputs_key_field='id',
        outputs=raw_response,
        raw_response=raw_response
    )


def nutanix_alert_resolve_command(client: Client, args: Dict):
    """
    Resolve alert with the specified alert_id.

    In case response was successful, response will be a dict
    {'id': str, 'successful': bool, 'message': Optional[str]}.
    In case of an invalid alert id, status code 422 - UNPROCESSED ENTITY
    will be returned by Nutanix service.

    Args:
        client (Client): Client object to perform request.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    alert_id = args.get('alert_id', '')

    raw_response = client.post_nutanix_alert_resolve(alert_id)

    return CommandResults(
        outputs_prefix='NutanixHypervisor.ResolveAlerts',
        outputs_key_field='id',
        outputs=raw_response,
        raw_response=raw_response
    )


def nutanix_alerts_acknowledge_by_filter_command(client: Client, args: Dict):
    """
    Acknowledges all of the Alerts which matches the filters if given.
    - start_time: Acknowledge alerts that their creation time have been after 'start_time'.
    - end_time: Acknowledge alerts that their creation time have been before 'end_time'.
    - severity: Acknowledge any alerts that their severity level matches one of the severities in severity list.
                Possible severities: [CRITICAL, WARNING, INFO, AUDIT].
    - impact_types: Acknowledge alerts that their impact type matches one of the impact_type in impact_types list.
                    Possible impact types: [Availability, Capacity, Configuration, Performance, SystemIndicator]
                    For example, alert 'Incorrect NTP Configuration' has impact type 'SystemIndicator'.
                    Given Impact Types = 'SystemIndicator',only alerts with impact type 'SystemIndicator',
                    such as 'Incorrect NTP Configuration' will be acknowledged.
    - entity_types: Acknowledge alerts that their entity_type matches one of the entity_type in entity_types list.
                   Example for entity types: [VM, Host, Disk, Storage Container, Cluster].
                   If Nutanix service can't recognize the entity type, it returns 404 response.
    - limit: Maximum number of alerts to acknowledge. Nutanix does not have max for limit, but a very high limit value
             will cause read timeout exception.

    In case response was successful, outputs will be a dict of
    {'num_successful_updates': int, 'num_failed_updates': int, 'alert_status_list' : List[Dict]}.
    where every element in 'alert_status_list' is {id: str, message: str, successful: bool}

    Args:
        client (Client): Client object to perform request.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    start_time = get_optional_time_parameter_as_epoch(args, 'start_time')
    end_time = get_optional_time_parameter_as_epoch(args, 'end_time')
    severity = args.get('severity')
    impact_types = args.get('impact_types')
    entity_types = args.get('entity_types')
    limit = get_and_validate_int_argument(args, 'limit', minimum=MINIMUM_LIMIT_VALUE, default_value=50)

    raw_response = client.post_nutanix_alerts_acknowledge_by_filter(start_time, end_time, severity, impact_types,
                                                                    entity_types,
                                                                    limit)

    return CommandResults(
        outputs_prefix='NutanixHypervisor.Alert',
        outputs=raw_response,
        raw_response=raw_response
    )


def nutanix_alerts_resolve_by_filter_command(client: Client, args: Dict):
    """
    Resolves all of the Alerts which matches the filters if given.
    Possible filters:
    - start_time: Resolve alerts that their creation time have been after 'start_time'.
    - end_time: Resolve alerts that their creation time have been before 'end_time'.
    - severity: Resolve any alerts that their severity level matches one of the severities in severity list.
    - impact_types: Resolve alerts that their impact type matches one of the impact_type in impact_types list.
                    Possible impact types: [Availability, Capacity, Configuration, Performance, SystemIndicator]
                    For example, alert 'Incorrect NTP Configuration' has impact type 'SystemIndicator'.
                    Given Impact Types = 'SystemIndicator',only alerts with impact type 'SystemIndicator',
                    such as 'Incorrect NTP Configuration' will be resolved.
    - entity_types: Resolve alerts that their entity_type matches one of the entity_type in entity_types list.
                   Example for entity types: [VM, Host, Disk, Storage Container, Cluster].
                   If Nutanix service can't recognize the entity type, it returns 404 response.
    - page: The offset of page number in the query response to start resolving alerts.
    - limit: Maximum number of alerts to resolve. Nutanix does not have max for limit, but a very high limit value
             will cause read timeout exception.

    In case response was successful, outputs will be a dict of
    {'num_successful_updates': int, 'num_failed_updates': int, 'alert_status_list' : List[Dict]}.
    where every element in 'alert_status_list' is {id: str, message: str, successful: bool}
    Args:
        client (Client): Client object to perform request.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    start_time = get_optional_time_parameter_as_epoch(args, 'start_time')
    end_time = get_optional_time_parameter_as_epoch(args, 'end_time')
    severity = args.get('severity')
    impact_types = args.get('impact_types')
    entity_types = args.get('entity_types')
    limit = get_and_validate_int_argument(args, 'limit', minimum=MINIMUM_LIMIT_VALUE, default_value=50)

    raw_response = client.post_nutanix_alerts_resolve_by_filter(start_time, end_time, severity, impact_types,
                                                                entity_types, limit)

    return CommandResults(
        outputs_prefix='NutanixHypervisor.Alert',
        outputs=raw_response,
        raw_response=raw_response
    )


''' MAIN FUNCTION '''


def main() -> None:
    command = demisto.command()
    params = demisto.params()

    commands = {
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

    credentials = params.get('credentials')
    username = credentials.get('identifier')
    password = credentials.get('password')

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
            fetch_incidents_command(client, params, {})
            return_results('ok')

        elif command == 'fetch-incidents':
            last_run = demisto.getLastRun()
            incidents, next_run = fetch_incidents_command(client, params, last_run)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command in commands:
            command_results: CommandResults = commands[command](client, demisto.args())
            command_results.outputs = remove_empty_elements(command_results.outputs)
            return_results(command_results)

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
